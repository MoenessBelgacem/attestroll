# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Moeness Belgacem
import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fleetproof.crypto import generate_keypair, verify_manifest
from fleetproof.state import FleetState, FleetError
from fleetproof.publisher import build_release

COMP = [{"name": "mbedtls", "version": "3.4.0"}]


class Local:
    """In-process hub so tests run without HTTP (HTTP auth is covered in test_identity)."""
    def __init__(self, st): self.st = st
    def enroll(self, **kw):
        self.st.enroll(kw["id"], kw["token"], kw["pubkey"], kw["hw"], kw["group"], kw["product"], kw["version"])
    def desired(self, ident): return self.st.desired(ident[0]) or {"up_to_date": True}
    def report(self, ident, r, s, det=""): self.st.report(ident[0], r, s, det)


def fleet(n=100):
    from fleetproof.agent import Agent
    priv, pub = generate_keypair()
    st = FleetState(pub)
    hub = Local(st)
    m, s, a = build_release(priv, "p", "1.0.0", b"v1", COMP)
    st.publish(m, s, a)
    agents = [Agent(f"d{i}", "b" if i % 2 else "a", hub, pub, st.create_enrollment_token(f"d{i}"), product="p")
              for i in range(n)]
    return priv, pub, st, agents


class T(unittest.TestCase):
    def test_signature_detects_manifest_tampering(self):
        priv, pub = generate_keypair()
        m, sig, _ = build_release(priv, "p", "1", b"x", COMP)
        self.assertTrue(verify_manifest(pub, m, sig))
        m["sbom"]["components"][0]["version"] = "9.9.9"
        self.assertFalse(verify_manifest(pub, m, sig))

    def test_publish_rejects_bad_signature_and_duplicates(self):
        priv, pub = generate_keypair()
        other, _ = generate_keypair()
        st = FleetState(pub)
        m, sig, a = build_release(other, "p", "1", b"x", COMP)
        with self.assertRaises(FleetError): st.publish(m, sig, a)
        m, sig, a = build_release(priv, "p", "1", b"x", COMP)
        st.publish(m, sig, a)
        with self.assertRaises(FleetError): st.publish(m, sig, a)

    def test_good_rollout_completes(self):
        priv, pub, st, agents = fleet()
        m, s, a = build_release(priv, "p", "1.1.0", b"v2", COMP); st.publish(m, s, a)
        rid = st.start_rollout("p", "1.1.0")
        for _ in range(10):
            for ag in agents: ag.poll_once()
        self.assertEqual(st.rollouts[rid]["status"], "completed")
        self.assertEqual(st.status()["by_version"], {"1.1.0": 100})

    def test_bad_release_is_halted_at_canary(self):
        priv, pub, st, agents = fleet()
        m, s, a = build_release(priv, "p", "1.2.0", b"v3 BUG:b", COMP); st.publish(m, s, a)
        rid = st.start_rollout("p", "1.2.0", stages=(10, 50, 100))
        for _ in range(10):
            for ag in agents: ag.poll_once()
        self.assertEqual(st.rollouts[rid]["status"], "halted")
        self.assertGreater(st.status()["by_version"]["1.0.0"], 85)   # most of fleet untouched

    def test_halt_pulls_back_devices_that_already_updated(self):
        priv, pub, st, agents = fleet()
        m, s, a = build_release(priv, "p", "1.2.0", b"v3 BUG:b", COMP); st.publish(m, s, a)
        st.start_rollout("p", "1.2.0", stages=(10, 50, 100))
        for _ in range(10):
            for ag in agents: ag.poll_once()
        self.assertEqual(st.status()["by_version"], {"1.0.0": 100})

    def test_swapped_artifact_is_rejected_by_devices(self):
        priv, pub, st, agents = fleet()
        m, s, a = build_release(priv, "p", "1.3.0", b"ok", COMP); st.publish(m, s, a)
        st.releases[("p", "1.3.0")]["artifact"] = b"evil"
        rid = st.start_rollout("p", "1.3.0")
        for _ in range(3):
            for ag in agents: ag.poll_once()
        self.assertEqual(st.rollouts[rid]["status"], "halted")
        self.assertEqual(st.status()["by_version"], {"1.0.0": 100})

    def test_audit_chain_detects_edits(self):
        priv, pub, st, agents = fleet(10)
        ok, _ = st.audit.verify(); self.assertTrue(ok)
        st.audit.entries[0]["detail"]["product"] = "hacked"
        ok, bad = st.audit.verify(); self.assertFalse(ok); self.assertEqual(bad, 0)

    def test_exposure_query(self):
        priv, pub, st, agents = fleet(20)
        self.assertEqual(len(st.exposure("mbedtls", ["3.4.0"])), 20)
        self.assertEqual(len(st.exposure("mbedtls", ["9.9.9"])), 0)


if __name__ == "__main__":
    unittest.main()
