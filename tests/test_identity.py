import unittest, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fleetproof.crypto import generate_keypair, pub_to_b64, request_message, sign_bytes
from fleetproof.state import FleetState, AuthError, FleetError


def make():
    _, pub = generate_keypair()
    st = FleetState(pub)
    priv, dpub = generate_keypair()
    tok = st.create_enrollment_token("dev-1")
    st.enroll("dev-1", tok, pub_to_b64(dpub), "a", "eu", "p", "1.0.0")
    return st, priv, tok


def signed(priv, did="dev-1", method="GET", target="/desired", body=b"", ts=None, nonce="n1"):
    ts = int(time.time()) if ts is None else ts
    return dict(device_id=did, method=method, target=target, body=body, ts=ts, nonce=nonce,
                signature=sign_bytes(priv, request_message(did, method, target, ts, nonce, body)))


class T(unittest.TestCase):
    def test_enrollment_token_is_single_use(self):
        st, priv, tok = make()
        _, other = generate_keypair()
        with self.assertRaises(AuthError):
            st.enroll("dev-1", tok, pub_to_b64(other), "a", "eu", "p", "1.0.0")

    def test_wrong_token_rejected_and_audited(self):
        st, priv, _ = make()
        st.create_enrollment_token("dev-2")
        _, k = generate_keypair()
        with self.assertRaises(AuthError):
            st.enroll("dev-2", "not-the-token", pub_to_b64(k), "a", "eu", "p", "1.0.0")
        self.assertIn("enrollment.rejected", [e["action"] for e in st.audit.entries])
        self.assertNotIn("dev-2", st.devices)

    def test_valid_signature_accepted(self):
        st, priv, _ = make()
        st.authenticate(**signed(priv))

    def test_other_key_rejected(self):
        st, priv, _ = make()
        impostor, _ = generate_keypair()
        with self.assertRaises(AuthError):
            st.authenticate(**signed(impostor))

    def test_body_tampering_rejected(self):
        st, priv, _ = make()
        req = signed(priv, method="POST", target="/report", body=b'{"status":"ok"}')
        req["body"] = b'{"status":"failed"}'
        with self.assertRaises(AuthError):
            st.authenticate(**req)

    def test_replay_rejected(self):
        st, priv, _ = make()
        req = signed(priv)
        st.authenticate(**req)
        with self.assertRaises(AuthError):
            st.authenticate(**req)

    def test_stale_timestamp_rejected(self):
        st, priv, _ = make()
        with self.assertRaises(AuthError):
            st.authenticate(**signed(priv, ts=int(time.time()) - 3600))

    def test_revoked_device_gets_403_and_unknown_gets_401(self):
        st, priv, _ = make()
        st.revoke("dev-1")
        with self.assertRaises(AuthError) as c:
            st.authenticate(**signed(priv))
        self.assertEqual(c.exception.http, 403)
        with self.assertRaises(AuthError) as c:
            st.authenticate(**signed(priv, did="ghost"))
        self.assertEqual(c.exception.http, 401)

    def test_rejections_are_audited_and_chain_stays_valid(self):
        st, priv, _ = make()
        impostor, _ = generate_keypair()
        with self.assertRaises(AuthError):
            st.authenticate(**signed(impostor))
        self.assertIn("auth.rejected", [e["action"] for e in st.audit.entries])
        self.assertTrue(st.audit.verify()[0])


if __name__ == "__main__":
    unittest.main()
