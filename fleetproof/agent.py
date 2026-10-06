"""Simulated device agent. Mirrors what a real agent must do:
  0. own a private key generated ON the device; enroll once with a single-use token
  1. sign every request to the hub   2. verify release signature + hash with a PINNED public key
  3. install into the inactive slot  4. run a health check   5. confirm, or keep the old version
Real firmware would keep the key in protected storage and use A/B partitions + bootloader rollback."""
import base64, json, secrets, time, urllib.request, urllib.error
from .crypto import (verify_manifest, sha256_hex, generate_keypair, pub_to_b64,
                     request_message, sign_bytes)


class HttpHub:
    def __init__(self, base_url, admin_token=None):
        self.base, self.token = base_url, admin_token

    def _call(self, method, path, body=None, admin=False, identity=None, ts=None):
        raw = json.dumps(body).encode() if body is not None else b""
        req = urllib.request.Request(self.base + path, data=raw or None, method=method)
        req.add_header("Content-Type", "application/json")
        if admin and self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if identity:
            did, priv = identity
            ts = int(time.time()) if ts is None else ts
            nonce = secrets.token_hex(8)
            sig = sign_bytes(priv, request_message(did, method, path, ts, nonce, raw))
            for k, v in (("X-Device-Id", did), ("X-Timestamp", str(ts)), ("X-Nonce", nonce), ("X-Signature", sig)):
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return dict(json.loads(e.read()), _http=e.code)

    # device side (signed)
    def enroll(self, **kw): return self._call("POST", "/enroll", kw)
    def desired(self, identity): return self._call("GET", "/desired", identity=identity)
    def report(self, identity, rollout, status, detail=""):
        return self._call("POST", "/report", dict(rollout=rollout, status=status, detail=detail), identity=identity)

    # operator side (admin token)
    def publish(self, manifest, signature, artifact):
        return self._call("POST", "/releases", dict(manifest=manifest, signature=signature,
                          artifact_b64=base64.b64encode(artifact).decode()), admin=True)
    def start_rollout(self, **kw): return self._call("POST", "/rollouts", kw, admin=True)
    def create_enrollment_token(self, device_id):
        return self._call("POST", "/admin/enrollment-tokens", {"id": device_id}, admin=True)["token"]
    def revoke(self, device_id): return self._call("POST", "/admin/revoke", {"id": device_id}, admin=True)
    def status(self): return self._call("GET", "/status", admin=True)
    def audit(self): return self._call("GET", "/audit", admin=True)
    def exposure(self, component, versions):
        return self._call("GET", f"/exposure?component={component}&versions={','.join(versions)}", admin=True)["devices"]


def health_check(artifact: bytes, hw: str) -> bool:
    """Simulated post-install self-test. A firmware containing b'BUG:<hw>' fails on that hardware."""
    return f"BUG:{hw}".encode() not in artifact


class Agent:
    def __init__(self, device_id, hw, hub, pinned_pubkey, enroll_token, group="eu",
                 product="sensor-node", version="1.0.0"):
        self.id, self.hw, self.hub, self.pub = device_id, hw, hub, pinned_pubkey
        self.group, self.product, self.version = group, product, version
        self.priv, my_pub = generate_keypair()            # this key never leaves the device
        self.identity = (device_id, self.priv)
        r = hub.enroll(id=device_id, token=enroll_token, pubkey=pub_to_b64(my_pub), hw=hw,
                       group=group, product=product, version=version)
        if r and "error" in r:
            raise RuntimeError(f"enrollment failed for {device_id}: {r['error']}")

    def poll_once(self):
        offer = self.hub.desired(self.identity)
        if not offer or offer.get("up_to_date") or "error" in offer:
            return None
        m, ro = offer["manifest"], offer["rollout"]
        artifact = base64.b64decode(offer["artifact_b64"])
        if not verify_manifest(self.pub, m, offer["signature"]):
            self.hub.report(self.identity, ro, "rejected", "bad signature")
            return "rejected"
        if sha256_hex(artifact) != m["artifact_sha256"]:
            self.hub.report(self.identity, ro, "rejected", "hash mismatch")
            return "rejected"
        if not health_check(artifact, self.hw):          # new slot failed -> stay on old slot
            self.hub.report(self.identity, ro, "failed", "health check failed, kept previous version")
            return "failed"
        self.version = m["version"]
        self.hub.report(self.identity, ro, "ok")
        return "ok"
