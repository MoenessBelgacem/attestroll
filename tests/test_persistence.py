# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Moeness Belgacem
import unittest, sys, os, tempfile, sqlite3, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from attestroll.crypto import generate_keypair, pub_to_b64
from attestroll.state import FleetState, AuthError, FleetError
from attestroll.store import Store
from attestroll.publisher import build_release

COMP = [{"name": "mbedtls", "version": "3.4.0"}]


def populate(path):
    priv, pub = generate_keypair()
    st = FleetState(pub, Store(path))
    m, s, a = build_release(priv, "p", "1.0.0", b"v1", COMP)
    st.publish(m, s, a)
    for i in range(5):
        _, dpub = generate_keypair()
        st.enroll(f"d{i}", st.create_enrollment_token(f"d{i}"), pub_to_b64(dpub), "a", "eu", "p", "1.0.0")
    m2, s2, a2 = build_release(priv, "p", "1.1.0", b"v2", COMP)
    st.publish(m2, s2, a2)
    rid = st.start_rollout("p", "1.1.0", stages=(100,))
    st.report("d0", rid, "ok")
    return priv, pub, st, rid


class T(unittest.TestCase):
    def test_state_survives_restart(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = os.path.join(tmp, "hub.db")
            priv, pub, st, rid = populate(path)
            before = (st.status(), len(st.audit.entries), st.audit.entries[-1]["hash"])
            st.store.close()
            st2 = FleetState(pub, Store(path))
            self.assertEqual((st2.status(), len(st2.audit.entries), st2.audit.entries[-1]["hash"]), before)
            self.assertTrue(st2.audit.verify()[0])
            self.assertEqual(st2.devices["d0"]["version"], "1.1.0")
            self.assertEqual(st2.rollouts[rid]["reports"], {"d0": "ok"})
            self.assertEqual(st2.releases[("p", "1.1.0")]["artifact"], b"v2")
            # a new rollout id must not collide with the persisted one
            m3, s3, a3 = build_release(priv, "p", "1.2.0", b"v3", COMP)
            st2.publish(m3, s3, a3)
            self.assertNotEqual(st2.start_rollout("p", "1.2.0"), rid)
            st2.store.close()

    def test_rejection_audit_entries_persist_with_valid_chain(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = os.path.join(tmp, "hub.db")
            priv, pub, st, rid = populate(path)
            impostor, _ = generate_keypair()
            with self.assertRaises(AuthError):
                st.enroll("d9", "bad-token", pub_to_b64(impostor.public_key()), "a", "eu", "p", "1.0.0")
            n = len(st.audit.entries)
            st.store.close()
            st2 = FleetState(pub, Store(path))          # would raise if chain were broken
            self.assertEqual(len(st2.audit.entries), n)
            st2.store.close()

    def test_tampered_database_is_refused_at_startup(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = os.path.join(tmp, "hub.db")
            priv, pub, st, rid = populate(path)
            st.store.close()
            db = sqlite3.connect(path)
            row = db.execute("SELECT data FROM audit WHERE seq=3").fetchone()[0]
            e = json.loads(row); e["actor"] = "someone-else"
            db.execute("UPDATE audit SET data=? WHERE seq=3", (json.dumps(e),))
            db.commit(); db.close()
            with self.assertRaises(FleetError):
                FleetState(pub, Store(path))


if __name__ == "__main__":
    unittest.main()
