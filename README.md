# Attestroll (working name)

**Update IoT device fleets safely - and keep the evidence.**

An early, open-source prototype of an over-the-air (OTA) update hub for connected devices.
It combines signed releases, staged rollouts with automatic halt and rollback, per-device identity,
and a tamper-evident audit trail that records which version ran on which device and when.

> **Status: prototype, not production software.** The hub is simulated against 200 virtual devices.
> There is an ESP32 firmware skeleton that builds, but it has not yet been flashed to hardware
> or connected to the hub. See [Limitations](#limitations). Not ready to protect real devices.

## Why this exists (and what we have not proven)

Updating devices in the field is risky: a failed update can leave a device unusable, and new
regulation (for example the EU Cyber Resilience Act) expects manufacturers to handle
vulnerabilities, ship security updates and keep documentation such as a software bill of materials.

**Established alternatives exist.** Mender, balena and Qbee, among others, already offer OTA
updates and fleet management; Mender states on its site that it supports CRA compliance
for Linux and real-time systems. We have not benchmarked them. We do not claim to be unique or
better; this project is published to find out whether a simpler, auditable, evidence-first
approach is useful to small hardware teams. **If you build connected products, your feedback is
the most valuable contribution: see [CONTRIBUTING.md](CONTRIBUTING.md).**

## What works today

| Capability | Where | Demonstrated by |
|---|---|---|
| Releases signed with Ed25519; the private key never touches the hub | `attestroll/crypto.py`, `publisher.py` | `demo.py` scenario 3 |
| Devices verify signature and hash themselves against a pinned public key | `attestroll/agent.py` | a compromised hub cannot push a swapped image |
| Staged rollout (5% > 25% > 100%) with automatic halt on failures | `attestroll/state.py` | scenario 2 |
| Automatic pull-back of devices that already took a halted release | `attestroll/state.py` | scenario 2 |
| SBOM inside each signed release; "which devices run component X at version Y?" | `attestroll/state.py` | scenarios 0-1 |
| SQLite persistence; a restart loses nothing; a tampered database refuses to start | `attestroll/store.py` | scenario 4, `tests/test_persistence.py` |
| Per-device keys, single-use enrollment tokens, signed requests (replay and tampering rejected), revocation | `attestroll/server.py`, `state.py` | scenario 5, `tests/test_identity.py` |
| Hash-chained audit log (any edit to history is detected) | `attestroll/audit.py` | scenario 6 |
| ESP32 firmware skeleton: two OTA slots, rollback enabled, builds with ESP-IDF 6.1 | `firmware/fleet_agent/` | build only, not flashed |

## Quick start

Requires Python 3.10+ and one dependency.

```bash
pip install cryptography
python -m unittest discover -s tests -v    # 20 tests
python demo.py                             # 200 simulated devices, 7 scenarios
python demo.py --step                      # same, pausing between scenes (for screen recording)
```

## Limitations

- **No TLS.** The server speaks plain HTTP; signatures protect identity and integrity, not confidentiality. Put TLS in front of it.
- Single static admin token, single node (SQLite), no key rotation, no roles or users.
- The replay-protection cache lives in memory (replays are possible for the 5-minute window after a restart).
- Enrollment tokens must be delivered to devices through a trusted channel that is not modelled here.
- Devices are simulated. The health check is a stub; the real one is the hard part.
- The SBOM is hand-written in the demo; a real one must be generated at build time.
- The ESP32 agent does not yet talk to the hub.
- Deployment state is rewritten in full on each report: this will not scale to thousands of devices without a storage redesign.
- **Nothing here is legal advice or a guarantee of regulatory compliance.** The project can help
  produce evidence (installed version per device, signed history, exposure per component); whether it
  satisfies any regulation is for you and your advisers to determine.

## Roadmap

1. ESP32 agent: HTTPS update with bootloader rollback, then verification of the Ed25519 signature on-device.
2. Linux agent (Raspberry Pi class).
3. TLS, secret handling from the environment, key rotation.
4. CI action that signs releases and generates the SBOM at build time.
5. Minimal dashboard.

## License

Licensed per component. Code that runs on devices or in your build pipeline (device agent,
firmware, signing tools) is **Apache-2.0**; the hub (server) is **AGPL-3.0-only**. See
[LICENSE](LICENSE), the [LICENSES/](LICENSES/) folder, and the SPDX header at the top of each file.
The author may offer the hub under a separate commercial license. The name "Attestroll" is a working
name; no trademark clearance has been done.

A French README is available in [README.fr.md](README.fr.md).
