# Security Policy

Fleetproof is an **early prototype, not production software**. Do not use it to protect real devices.
See the Limitations section of the README (no TLS, static admin token, simulated devices).

## Reporting a vulnerability

Please report privately through GitHub: open the **Security** tab of this repository and choose
**Report a vulnerability**. Do not open a public issue for an undisclosed vulnerability.

Include the affected file or commit, a description, steps to reproduce, and the impact you see.

This project has a single maintainer and responds on a best-effort basis; I aim to acknowledge a
report within 7 days. There is no bug bounty.

## Scope

In scope: release signature verification, device enrollment and request authentication, the audit
hash chain, and the integrity of persisted state.

Out of scope: weaknesses already listed as limitations in the README (plain HTTP, single static admin
token, simulated devices and health check), and denial of service against the prototype.

## Supported versions

Only the latest commit on the `main` branch.

## Disclosure

Please allow reasonable time to fix an issue before publishing details. Reporters are credited if they wish.
