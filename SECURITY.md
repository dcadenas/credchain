# Security policy

credchain stores and injects credentials. Reports about secret exposure,
plaintext handling, filesystem race safety, or bypassing the fail-closed paths
are security issues.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

https://github.com/dcadenas/credchain/security/advisories/new

Please do not open a public issue before a fix is available.

Include what you can reproduce, the credchain commit or version, the systemd
version, and a minimal example.

## Scope

The threat model and the guarantees credchain does and does not provide are in
[docs/SECURITY.md](docs/SECURITY.md).

credchain is not a sandbox. Processes the target spawns can read the injected
environment variables, and anything that can run as your user can read the
credentials. Those are documented limits, not vulnerabilities.
