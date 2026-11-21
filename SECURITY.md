# Security Policy

## Reporting a vulnerability

Please report security issues privately by email to **support@agenticcli.dev** (the same address as on the [contact page](https://agenticcli.dev/contact)). Put "ShipGuard security" in the subject.

Include what you found, the ShipGuard version (`shipguard --version`), and steps to reproduce. Please do not open a public issue for a vulnerability.

We aim to acknowledge reports within 3 business days and will keep you updated until the issue is resolved. Please give us reasonable time to fix a problem before disclosing it publicly.

## Scope

- The `@agenticcli/shipguard` CLI and the packages in this repository.
- ShipGuard checks your code on your machine and never uploads your source code. Rules come down; code never goes up.

## Known advisories in dependencies

- Status statements for advisories that touch our dependency tree are published as OpenVEX in [`docs/security/shipguard.openvex.json`](docs/security/shipguard.openvex.json). The first one covers the picomatch advisory GHSA-fc5q-39xc-vjpf (pulled in through `fast-glob`; GitHub withdrew it on 2026-11-18). Each release re-checks the file.
- The release gate runs `npm audit` on the production dependencies and fails on any high or critical advisory that is not listed, with a reason and an expiry date, in `docs/security/audit-allow.txt`.
