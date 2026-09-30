"""Control-plane logic (no networking): registry, releases, staged rollouts, audit."""
import base64, hashlib, math, threading
from .audit import AuditLog
from .crypto import verify_manifest, sha256_hex


class FleetError(Exception):
    pass


def bucket(rollout_id: str, device_id: str) -> int:
    """Deterministic 0-99 bucket: a device is inside a stage if bucket < stage percent."""
    return int(hashlib.sha256(f"{rollout_id}:{device_id}".encode()).hexdigest(), 16) % 100


class FleetState:
    def __init__(self, publisher_pubkey):
        self.pubkey = publisher_pubkey
        self.lock = threading.RLock()
        self.devices = {}     # id -> {id, hw, group, product, version}
        self.releases = {}    # (product, version) -> {manifest, signature, artifact}
        self.rollouts = {}    # id -> rollout dict
        self.audit = AuditLog()
        self._seq = 0

    # ---- inventory -------------------------------------------------------
    def register(self, device_id, hw, group, product, version):
        with self.lock:
            self.devices[device_id] = dict(id=device_id, hw=hw, group=group,
                                           product=product, version=version)

    # ---- releases ---------------------------------------------------------
    def publish(self, manifest: dict, signature: str, artifact: bytes):
        with self.lock:
            if not verify_manifest(self.pubkey, manifest, signature):
                self.audit.append("publisher", "release.rejected", {"reason": "invalid signature"})
                raise FleetError("invalid signature")
            if sha256_hex(artifact) != manifest["artifact_sha256"]:
                raise FleetError("artifact does not match manifest hash")
            key = (manifest["product"], manifest["version"])
            if key in self.releases:
                raise FleetError("release already exists (releases are immutable)")
            self.releases[key] = dict(manifest=manifest, signature=signature, artifact=artifact)
            self.audit.append("publisher", "release.published", {
                "product": key[0], "version": key[1], "sha256": manifest["artifact_sha256"],
                "components": len(manifest["sbom"]["components"])})

    # ---- rollouts ---------------------------------------------------------
    def start_rollout(self, product, version, group="*", stages=(5, 25, 100), max_failure_rate=0.10):
        with self.lock:
            if (product, version) not in self.releases:
                raise FleetError("unknown release")
            self._seq += 1
            rid = f"ro-{self._seq}"
            self.rollouts[rid] = dict(id=rid, product=product, version=version, group=group,
                                      stages=list(stages), stage=0, status="running",
                                      max_failure_rate=max_failure_rate, reports={}, previous={})
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
        with self.lock:
            if rollout_id.endswith(":rollback"):
                ro = self.rollouts[rollout_id.split(":")[0]]
                d = self.devices[device_id]
                if status == "ok":
                    d["version"] = ro["previous"].pop(device_id)
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
            return dict(devices=len(self.devices), by_version=by_version,
                        rollouts={r["id"]: dict(version=r["version"], status=r["status"],
                                                stage_percent=r["stages"][r["stage"]],
                                                reports=len(r["reports"]))
                                  for r in self.rollouts.values()})
