# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Moeness Belgacem
"""End-to-end demo: 200 simulated devices with their own keys, persistent hub. Run: python demo.py"""
import os, shutil, tempfile, time
from fleetproof.crypto import generate_keypair, pub_to_b64
from fleetproof.state import FleetState
from fleetproof.store import Store
from fleetproof.server import make_server
from fleetproof.agent import HttpHub, Agent
from fleetproof.publisher import build_release

ADMIN = "demo-admin-token"            # in real life: a long random secret from the environment
tmp = tempfile.mkdtemp()
DB = os.path.join(tmp, "hub.db")

priv, pub = generate_keypair()        # publisher key: lives in CI, NOT on the hub
state = FleetState(pub, Store(DB))
srv = make_server(state, ADMIN)
hub = HttpHub(f"http://127.0.0.1:{srv.server_address[1]}", ADMIN)

BASE = [{"name": "mbedtls", "version": "3.4.0"}, {"name": "freertos", "version": "10.5.1"},
        {"name": "app", "version": "1.0.0"}]


def publish(version, artifact, mbedtls="3.4.0"):
    comps = [dict(c) for c in BASE]
    comps[0]["version"] = mbedtls
    comps[2]["version"] = version
    m, sig, art = build_release(priv, "sensor-node", version, artifact, comps)
    r = hub.publish(m, sig, art)
    assert "error" not in r, r


def count(rid, status):
    return sum(1 for e in state.audit.entries
               if e["action"] == f"update.{status}" and e["detail"]["rollout"] == rid)


def run_rollout(version, label):
    rid = hub.start_rollout(product="sensor-node", version=version, group="eu",
                            stages=[5, 25, 100], max_failure_rate=0.10)["id"]
    for _ in range(12):                            # each round: every device checks in once
        [a.poll_once() for a in agents]
        st = hub.status()["rollouts"][rid]
        if st["status"] == "halted":
            for _ in range(2):                     # let the pull-back reach devices already updated
                [a.poll_once() for a in agents]
        if st["status"] != "running":
            break
    print(f"  -> rollout {rid} [{label}] ended: {st['status'].upper()} at {st['stage_percent']}% stage "
          f"| updated={count(rid, 'ok')} failed={count(rid, 'failed')} rejected={count(rid, 'rejected')}")
    rb = sum(1 for e in state.audit.entries if e["action"] == "update.rolled_back" and e["detail"]["rollout"] == rid)
    if rb:
        print(f"  -> {rb} device(s) that had already updated were automatically pulled back")
    print(f"  -> fleet now: {hub.status()['by_version']}")


def title(t):
    print(f"\n=== {t} " + "=" * max(0, 70 - len(t)))


# --- fleet: 200 devices, each enrolls with a single-use token and its OWN key -----------------
publish("1.0.0", b"FIRMWARE-1.0.0")
agents = []
for i in range(200):
    did = f"dev-{i:03d}"
    agents.append(Agent(did, "rev-b" if i % 10 < 3 else "rev-a", hub, pub, hub.create_enrollment_token(did)))

title("0. Baseline: 200 enrolled devices, a vulnerable library on every one")
print(f"  Devices enrolled with their own key: {hub.status()['devices']}")
print(f"  Devices exposed to a (hypothetical) flaw in mbedtls 3.4.0: {len(hub.exposure('mbedtls', ['3.4.0']))}/200")

title("1. Good release 1.1.0 (fixes mbedtls) - staged 5% -> 25% -> 100%")
publish("1.1.0", b"FIRMWARE-1.1.0", mbedtls="3.6.0")
run_rollout("1.1.0", "good release")
print(f"  Devices still exposed to mbedtls 3.4.0: {len(hub.exposure('mbedtls', ['3.4.0']))}/200")

title("2. Buggy release 1.2.0 (crashes on hardware rev-b) - caught at the canary")
publish("1.2.0", b"FIRMWARE-1.2.0 BUG:rev-b")
run_rollout("1.2.0", "buggy release")
print(f"  Only {len(state.rollouts['ro-2']['reports'])} of 200 devices ever attempted the bad version.")

title("3. Compromised server: attacker swaps the firmware image after signing")
publish("1.3.0", b"FIRMWARE-1.3.0")
state.releases[("sensor-node", "1.3.0")]["artifact"] = b"MALICIOUS-IMAGE"   # simulated breach
run_rollout("1.3.0", "tampered artifact")
print("  Devices verified the signed hash themselves and refused the swapped image.")

title("4. Hub restart: nothing is lost")
before, n_before = hub.status(), len(state.audit.entries)
srv.shutdown(); state.store.close()
state = FleetState(pub, Store(DB))                       # fresh process, same database file
srv = make_server(state, ADMIN)
hub = HttpHub(f"http://127.0.0.1:{srv.server_address[1]}", ADMIN)
for a in agents:
    a.hub = hub
after = hub.status()
print(f"  before: {before['devices']} devices {before['by_version']}, {n_before} audit entries")
print(f"  after : {after['devices']} devices {after['by_version']}, {len(state.audit.entries)} audit entries, "
      f"chain valid: {state.audit.verify()[0]}")
print(f"  rollouts remembered: { {k: v['status'] for k, v in after['rollouts'].items()} }")
print(f"  a device still authenticates with its own key: {hub.desired(agents[0].identity)}")

title("5. Identity: every device has its own key")
fake, _ = generate_keypair()
r = hub._call("GET", "/desired", identity=("dev-007", fake))
print(f"  Impostor claiming to be dev-007 with another key -> HTTP {r['_http']}: {r['error']}")
r = hub._call("GET", "/desired", identity=agents[7].identity, ts=int(time.time()) - 3600)
print(f"  Request signed an hour ago (replay attempt)       -> HTTP {r['_http']}: {r['error']}")
r = hub._call("GET", "/status")
print(f"  Reading fleet status without the admin token      -> HTTP {r['_http']}: {r['error']}")
tok = hub.create_enrollment_token("dev-new")
Agent("dev-new", "rev-a", hub, pub, tok)
r = hub.enroll(id="dev-new", token=tok, pubkey=pub_to_b64(generate_keypair()[1]), hw="rev-a",
               group="eu", product="sensor-node", version="1.0.0")
print(f"  Re-using an enrollment token                      -> HTTP {r['_http']}: {r['error']}")
hub.revoke("dev-042")
r = hub.desired(agents[42].identity)
print(f"  Revoked device dev-042 tries to poll              -> HTTP {r['_http']}: {r['error']}")

title("6. Audit trail (evidence)")
rej = sum(1 for e in state.audit.entries if e["action"].startswith(("auth.", "enrollment.rejected")))
res = hub.audit()
print(f"  {len(res['entries'])} entries ({rej} security rejections recorded), hash chain valid: {res['valid']}")
state.audit.entries[10]["detail"]["edited"] = "after the fact"              # tamper with history
ok, bad = state.audit.verify()
print(f"  After editing entry #10 -> chain valid: {ok}, first bad entry: #{bad}")

srv.shutdown(); state.store.close()
shutil.rmtree(tmp, ignore_errors=True)
