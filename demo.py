"""End-to-end demo: 200 simulated devices, 4 scenarios. Run: python demo.py"""
from fleetproof.crypto import generate_keypair
from fleetproof.state import FleetState
from fleetproof.server import make_server, ADMIN_TOKEN
from fleetproof.agent import HttpHub, Agent
from fleetproof.publisher import build_release

priv, pub = generate_keypair()
state = FleetState(pub)
srv = make_server(state)
url = f"http://127.0.0.1:{srv.server_address[1]}"
hub = HttpHub(url, ADMIN_TOKEN)

BASE = [{"name": "mbedtls", "version": "3.4.0"}, {"name": "freertos", "version": "10.5.1"},
        {"name": "app", "version": "1.0.0"}]


def publish(version, artifact, mbedtls="3.4.0"):
    comps = [dict(c) for c in BASE]
    comps[0]["version"] = mbedtls
    comps[2]["version"] = version
    m, sig, art = build_release(priv, "sensor-node", version, artifact, comps)
    r = hub.publish(m, sig, art)
    assert "error" not in r, r


def run_rollout(version, label):
    rid = hub.start_rollout(product="sensor-node", version=version, group="eu",
                            stages=[5, 25, 100], max_failure_rate=0.10)["id"]
    for rnd in range(1, 12):                       # each round: every device checks in once
        results = [a.poll_once() for a in agents]
        st = hub.status()["rollouts"][rid]
        if st["status"] == "halted":
            for _ in range(2):                     # let the pull-back reach devices already updated
                [a.poll_once() for a in agents]
        if st["status"] != "running":
            break
    ok, failed, rejected = (results_count(rid, s) for s in ("ok", "failed", "rejected"))
    print(f"  -> rollout {rid} [{label}] ended: {st['status'].upper()} at {st['stage_percent']}% stage "
          f"| updated={ok} failed={failed} rejected={rejected}")
    rb = sum(1 for e in state.audit.entries if e["action"] == "update.rolled_back" and e["detail"]["rollout"] == rid)
    if rb:
        print(f"  -> {rb} device(s) that had already updated were automatically pulled back")
    print(f"  -> fleet now: {hub.status()['by_version']}")
    return st["status"]


def results_count(rid, status):
    return sum(1 for e in state.audit.entries
               if e["action"] == f"update.{status}" and e["detail"]["rollout"] == rid)


def title(t):
    print(f"\n=== {t} " + "=" * max(0, 70 - len(t)))


# --- fleet: 200 devices, 30% are hardware revision B ---------------------------------
publish("1.0.0", b"FIRMWARE-1.0.0")
agents = [Agent(f"dev-{i:03d}", "rev-b" if i % 10 < 3 else "rev-a", hub, pub) for i in range(200)]

title("0. Baseline: a vulnerable library is on every device")
exposed = hub.exposure("mbedtls", ["3.4.0"])
print(f"  Devices exposed to a (hypothetical) flaw in mbedtls 3.4.0: {len(exposed)}/200")

title("1. Good release 1.1.0 (fixes mbedtls) - staged 5% -> 25% -> 100%")
publish("1.1.0", b"FIRMWARE-1.1.0", mbedtls="3.6.0")
run_rollout("1.1.0", "good release")
print(f"  Devices still exposed to mbedtls 3.4.0: {len(hub.exposure('mbedtls', ['3.4.0']))}/200")

title("2. Buggy release 1.2.0 (crashes on hardware rev-b) - caught at the canary")
publish("1.2.0", b"FIRMWARE-1.2.0 BUG:rev-b")
run_rollout("1.2.0", "buggy release")
touched = len(state.rollouts["ro-2"]["reports"])
print(f"  Only {touched} of 200 devices ever attempted the bad version.")

title("3. Compromised server: attacker swaps the firmware image after signing")
publish("1.3.0", b"FIRMWARE-1.3.0")
state.releases[("sensor-node", "1.3.0")]["artifact"] = b"MALICIOUS-IMAGE"   # simulated breach
run_rollout("1.3.0", "tampered artifact")
print("  Devices verified the signed hash themselves and refused the swapped image.")

title("4. Audit trail (evidence)")
res = hub.audit()
print(f"  {len(res['entries'])} entries, hash chain valid: {res['valid']}")
state.audit.entries[10]["detail"]["detail"] = "edited after the fact"        # tamper with history
ok, bad = state.audit.verify()
print(f"  After editing entry #10 -> chain valid: {ok}, first bad entry: #{bad}")
srv.shutdown()
