"""Control-plane logic (no networking): identity, registry, releases, staged rollouts, audit.
State lives in SQLite (see store.py); dicts below are an in-memory cache loaded at startup."""
import base64, hashlib, math, secrets, threading, time
from .audit import AuditLog
from .crypto import (verify_manifest, sha256_hex, request_message, verify_bytes, pub_from_b64)
from .store import Store

AUTH_WINDOW_SECONDS = 300


class FleetError(Exception):
    pass


class AuthError(FleetError):
    def __init__(self, msg, http=401):
        super().__init__(msg)
        self.http = http


def bucket(rollout_id: str, device_id: str) -> int:
    """Deterministic 0-99 bucket: a device is inside a stage if bucket < stage percent."""
    return int(hashlib.sha256(f"{rollout_id}:{device_id}".encode()).hexdigest(), 16) % 100


class FleetState:
    def __init__(self, publisher_pubkey, store: Store = None):
        self.pubkey = publisher_pubkey
        self.store = store or Store(":memory:")
        self.lock = threading.RLock()
        self.devices = self.store.load_devices()
        self.releases = self.store.load_releases()
        self.rollouts = self.store.load_rollouts()
        self.enrollments = self.store.load_enrollments()      # device_id -> sha256(token)
        self.audit = AuditLog(self.store.load_audit(), sink=self.store.append_audit)
        ok, bad = self.audit.verify()
        if not ok:
            raise FleetError(f"stored audit log is corrupted at entry #{bad}; refusing to start")
        self._seq = max((int(r.split("-")[1]) for r in self.rollouts), default=0)
        self._seen = {}                                        # (device, nonce) -> ts  (replay cache)

    # ---- identity -----------------------------------------------------------
    def create_enrollment_token(self, device_id: str) -> str:
        """Operator issues a single-use token binding a future device to this id."""
        with self.lock, self.store.tx():
            if device_id in self.devices:
                raise FleetError("device id already enrolled")
            token = secrets.token_urlsafe(16)
            h = sha256_hex(token.encode())
            self.enrollments[device_id] = h
            self.store.save_enrollment(device_id, h)
            self.audit.append("operator", "enrollment.token_issued", {"device": device_id})
            return token

    def enroll(self, device_id, token, pubkey_b64, hw, group, product, version):
        """Device presents the token + its OWN public key. The private key never leaves the device."""
        try:
            pub_from_b64(pubkey_b64)
        except Exception:
            raise FleetError("invalid public key")
        denied = False
        with self.lock, self.store.tx():
            expected = self.enrollments.get(device_id)
            if not expected or not secrets.compare_digest(expected, sha256_hex(token.encode())):
                self.audit.append("system", "enrollment.rejected", {"device": device_id})
                denied = True
            else:
                del self.enrollments[device_id]
                self.store.delete_enrollment(device_id)
                d = dict(id=device_id, hw=hw, group=group, product=product, version=version,
                         pubkey=pubkey_b64, revoked=False)
                self.devices[device_id] = d
                self.store.save_device(d)
                self.audit.append(f"device:{device_id}", "device.enrolled",
                                  {"hw": hw, "group": group, "product": product, "version": version})
        if denied:                      # raised after commit so the audit entry is kept
            raise AuthError("invalid or already used enrollment token")

    def authenticate(self, device_id, method, target, body: bytes, ts, nonce, signature, now=None):
        """Verify a signed device request. Raises AuthError (401 unknown/bad, 403 revoked)."""
        now = time.time() if now is None else now
        with self.lock, self.store.tx():
            fail = self._auth_check(device_id, method, target, body, ts, nonce, signature, now)
            if fail and fail[2]:
                self.audit.append("system", fail[2][0], fail[2][1])
        if fail:                        # raised after commit so the audit entry is kept
            raise AuthError(fail[0], fail[1])

    def _auth_check(self, device_id, method, target, body, ts, nonce, signature, now):
        """Returns None if authentic, else (public_message, http_code, (audit_action, detail) | None)."""
        d = self.devices.get(device_id)
        if not d:
            return ("authentication failed", 401, None)
        if d["revoked"]:
            return ("device revoked", 403, ("auth.revoked_device_denied", {"device": device_id}))
        try:
            ts = int(ts)
        except (TypeError, ValueError):
            return ("authentication failed", 401, None)
        if abs(now - ts) > AUTH_WINDOW_SECONDS:
            return ("timestamp outside allowed window", 401,
                    ("auth.rejected", {"device": device_id, "reason": "timestamp outside window"}))
        msg = request_message(device_id, method, target, ts, nonce, body)
        if not verify_bytes(pub_from_b64(d["pubkey"]), msg, signature or ""):
            return ("authentication failed", 401, ("auth.rejected", {"device": device_id, "reason": "bad signature"}))
        key = (device_id, nonce)
        if key in self._seen:
            return ("replayed request", 401, ("auth.rejected", {"device": device_id, "reason": "replayed request"}))
        self._seen[key] = ts
        if len(self._seen) > 20000:     # prune old nonces
            self._seen = {k: v for k, v in self._seen.items() if now - v <= AUTH_WINDOW_SECONDS}
        return None

    def revoke(self, device_id):
        with self.lock, self.store.tx():
            d = self.devices[device_id]
            d["revoked"] = True
            self.store.save_device(d)
            self.audit.append("operator", "device.revoked", {"device": device_id})

    # ---- releases ---------------------------------------------------------
    def publish(self, manifest: dict, signature: str, artifact: bytes):
        bad_sig = False
        with self.lock, self.store.tx():
            if not verify_manifest(self.pubkey, manifest, signature):
                self.audit.append("publisher", "release.rejected", {"reason": "invalid signature"})
                bad_sig = True
            else:
                if sha256_hex(artifact) != manifest["artifact_sha256"]:
                    raise FleetError("artifact does not match manifest hash")
                key = (manifest["product"], manifest["version"])
                if key in self.releases:
                    raise FleetError("release already exists (releases are immutable)")
                self.releases[key] = dict(manifest=manifest, signature=signature, artifact=artifact)
                self.store.save_release(key[0], key[1], manifest, signature, artifact)
                self.audit.append("publisher", "release.published", {
                    "product": key[0], "version": key[1], "sha256": manifest["artifact_sha256"],
                    "components": len(manifest["sbom"]["components"])})
        if bad_sig:
            raise FleetError("invalid signature")

    # ---- rollouts ---------------------------------------------------------
    def start_rollout(self, product, version, group="*", stages=(5, 25, 100), max_failure_rate=0.10):
        with self.lock, self.store.tx():
            if (product, version) not in self.releases:
                raise FleetError("unknown release")
            self._seq += 1
            rid = f"ro-{self._seq}"
            ro = dict(id=rid, product=product, version=version, group=group,
                      stages=list(stages), stage=0, status="running",
                      max_failure_rate=max_failure_rate, reports={}, previous={})
            self.rollouts[rid] = ro
            self.store.save_rollout(ro)
            self.audit.append("operator", "rollout.started", {
                "id": rid, "product": product, "version": version, "group": group,
                "stages": list(stages), "max_failure_rate": max_failure_rate})
            return rid

    def _matches(self, ro, d):
        return d["product"] == ro["product"] and ro["group"] in ("*", d["group"])

    def _eligible(self, ro):
        pct = ro["stages"][ro["stage"]]
        return [d for d in self.devices.values()
                if self._matches(ro, d) and bucket(ro["id"], d["id"]) < pct]

    def desired(self, device_id):
        """What should this device install right now? None = nothing."""
        with self.lock:
            d = self.devices[device_id]
            for ro in self.rollouts.values():
                if not self._matches(ro, d):
                    continue
                # A halted rollout pulls back the devices that already took the release.
                if ro["status"] == "halted" and d["version"] == ro["version"] and device_id in ro["previous"]:
                    rel = self.releases[(ro["product"], ro["previous"][device_id])]
                    return dict(rollout=f"{ro['id']}:rollback", manifest=rel["manifest"],
                                signature=rel["signature"],
                                artifact_b64=base64.b64encode(rel["artifact"]).decode())
                # "completed" keeps offering the release to stragglers (devices that were offline).
                if ro["status"] not in ("running", "completed"):
                    continue
                if d["version"] == ro["version"] or device_id in ro["reports"]:
                    continue
                if bucket(ro["id"], device_id) < ro["stages"][ro["stage"]]:
                    rel = self.releases[(ro["product"], ro["version"])]
                    return dict(rollout=ro["id"], manifest=rel["manifest"], signature=rel["signature"],
                                artifact_b64=base64.b64encode(rel["artifact"]).decode())
            return None

    def report(self, device_id, rollout_id, status, detail=""):
        """status: ok | failed | rejected"""
        with self.lock, self.store.tx():
            if rollout_id.endswith(":rollback"):
                ro = self.rollouts[rollout_id.split(":")[0]]
                d = self.devices[device_id]
                if status == "ok":
                    d["version"] = ro["previous"].pop(device_id)
                self.store.save_device(d)
                self.store.save_rollout(ro)
                self.audit.append(f"device:{device_id}", "update.rolled_back", {
                    "rollout": ro["id"], "restored": d["version"], "status": status})
                return
            ro = self.rollouts[rollout_id]
            d = self.devices[device_id]
            ro["reports"][device_id] = status
            if status == "ok":
                ro["previous"][device_id] = d["version"]
                d["version"] = ro["version"]
            self.audit.append(f"device:{device_id}", f"update.{status}", {
                "rollout": rollout_id, "target": ro["version"], "running": d["version"], "detail": detail})
            self._evaluate(ro)
            self.store.save_device(d)
            self.store.save_rollout(ro)

    def _evaluate(self, ro):
        while ro["status"] == "running":
            eligible = self._eligible(ro)
            n = max(len(eligible), 1)
            reps = ro["reports"]
            failed = sum(1 for s in reps.values() if s != "ok")
            if failed / n > ro["max_failure_rate"]:
                ro["status"] = "halted"
                self.audit.append("system", "rollout.halted", {
                    "id": ro["id"], "failed": failed, "eligible": len(eligible),
                    "stage_percent": ro["stages"][ro["stage"]]})
                return
            if len(reps) >= math.ceil(0.9 * n):
                if ro["stage"] == len(ro["stages"]) - 1:
                    ro["status"] = "completed"
                    self.audit.append("system", "rollout.completed", {"id": ro["id"], "reports": len(reps)})
                    return
                ro["stage"] += 1
                self.audit.append("system", "rollout.advanced", {
                    "id": ro["id"], "stage_percent": ro["stages"][ro["stage"]]})
                continue
            return

    # ---- evidence / compliance views ------------------------------------------
    def exposure(self, component: str, versions):
        """Which devices currently run a release whose SBOM contains component@version?"""
        with self.lock:
            hit = []
            for d in self.devices.values():
                rel = self.releases.get((d["product"], d["version"]))
                if rel and any(c["name"] == component and c["version"] in versions
                               for c in rel["manifest"]["sbom"]["components"]):
                    hit.append(d["id"])
            return sorted(hit)

    def status(self):
        with self.lock:
            by_version = {}
            for d in self.devices.values():
                by_version[d["version"]] = by_version.get(d["version"], 0) + 1
            return dict(devices=len(self.devices),
                        revoked=sum(1 for d in self.devices.values() if d["revoked"]),
                        by_version=by_version,
                        rollouts={r["id"]: dict(version=r["version"], status=r["status"],
                                                stage_percent=r["stages"][r["stage"]],
                                                reports=len(r["reports"]))
                                  for r in self.rollouts.values()})
