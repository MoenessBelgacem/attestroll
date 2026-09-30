"""Publisher side (runs in CI, holds the private key)."""
import datetime
from .crypto import sign_manifest, sha256_hex


def build_release(priv, product, version, artifact: bytes, components, support_years=5):
    until = (datetime.date(2026, 9, 30) + datetime.timedelta(days=365 * support_years)).isoformat()
    manifest = {
        "product": product, "version": version,
        "artifact_sha256": sha256_hex(artifact), "size": len(artifact),
        "sbom": {"format": "simplified-cyclonedx", "components": components},
        "support_until": until,
    }
    return manifest, sign_manifest(priv, manifest), artifact
