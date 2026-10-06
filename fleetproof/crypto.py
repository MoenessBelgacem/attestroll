"""Ed25519 signing of release manifests. The PRIVATE key stays with the publisher (CI);
the server and the devices only hold the PUBLIC key."""
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def pub_to_b64(pub) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def pub_from_b64(s: str):
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(s))


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_manifest(priv, manifest: dict) -> str:
    return base64.b64encode(priv.sign(canonical(manifest))).decode()


def verify_manifest(pub, manifest: dict, signature_b64: str) -> bool:
    try:
        pub.verify(base64.b64decode(signature_b64), canonical(manifest))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---- per-device request authentication ---------------------------------------
def request_message(device_id: str, method: str, target: str, ts: int, nonce: str, body: bytes) -> bytes:
    """Exact bytes a device signs: binds identity, verb, URL, time, nonce and body."""
    return f"{device_id}\n{method}\n{target}\n{ts}\n{nonce}\n{sha256_hex(body)}".encode()


def sign_bytes(priv, data: bytes) -> str:
    return base64.b64encode(priv.sign(data)).decode()


def verify_bytes(pub, data: bytes, signature_b64: str) -> bool:
    try:
        pub.verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False
