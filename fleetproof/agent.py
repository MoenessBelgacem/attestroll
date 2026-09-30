"""Simulated device agent. Mirrors what a real agent must do:
  1. ask the hub what to install   2. verify signature + hash with a PINNED public key
  3. install into the inactive slot 4. run a health check   5. confirm, or keep the old version
Real firmware would use A/B partitions and a bootloader-level rollback flag."""
import base64, json, urllib.request
from .crypto import verify_manifest, sha256_hex


class HttpHub:
    def __init__(self, base_url, admin_token=None):
        self.base, self.token = base_url, admin_token

    def _call(self, method, path, body=None, admin=False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if admin and self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return dict(json.loads(e.read()), _http=e.code)

    def register(self, **kw): return self._call("POST", "/register", kw)
    def desired(self, device): return self._call("GET", f"/desired?device={device}")
    def report(self, device, rollout, status, detail=""):
        return self._call("POST", "/report", dict(device=device, rollout=rollout, status=status, detail=detail))
    def publish(self, manifest, signature, artifact):
        return self._call("POST", "/releases", dict(manifest=manifest, signature=signature,
                          artifact_b64=base64.b64encode(artifact).decode()), admin=True)
    def start_rollout(self, **kw): return self._call("POST", "/rollouts", kw, admin=True)
    def status(self): return self._call("GET", "/status")
    def audit(self): return self._call("GET", "/audit")
    def exposure(self, component, versions):
        return self._call("GET", f"/exposure?component={component}&versions={','.join(versions)}")["devices"]


def health_check(artifact: bytes, hw: str) -> bool:
    """Simulated post-install self-test. A firmware containing b'BUG:<hw>' fails on that hardware."""
    return f"BUG:{hw}".encode() not in artifact


class Agent:
    def __init__(self, device_id, hw, hub, pinned_pubkey, group="eu", product="sensor-node", version="1.0.0"):
        self.id, self.hw, self.hub, self.pub = device_id, hw, hub, pinned_pubkey
        self.group, self.product, self.version = group, product, version
        hub.register(id=device_id, hw=hw, group=group, product=product, version=version)

    def poll_once(self):
        offer = self.hub.desired(self.id)
        if not offer or offer.get("up_to_date"):
            return None
        m, ro = offer["manifest"], offer["rollout"]
        artifact = base64.b64decode(offer["artifact_b64"])
        if not verify_manifest(self.pub, m, offer["signature"]):
            self.hub.report(self.id, ro, "rejected", "bad signature")
            return "rejected"
        if sha256_hex(artifact) != m["artifact_sha256"]:
            self.hub.report(self.id, ro, "rejected", "hash mismatch")
            return "rejected"
        if not health_check(artifact, self.hw):          # new slot failed -> stay on old slot
            self.hub.report(self.id, ro, "failed", "health check failed, kept previous version")
            return "failed"
        self.version = m["version"]
        self.hub.report(self.id, ro, "ok")
        return "ok"
