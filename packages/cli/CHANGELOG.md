# @agenticcli/shipguard

## 0.8.1 — first public release with npm provenance (0.8.0 was tagged but never published: release workflow fix)

## 0.8.0 — first public release (2026-10-19)

ShipGuard is a CLI-first release gate for AI-built apps. It scans your project locally and tells you whether it is safe to ship.

- Runs entirely on your machine. Your code, file paths and secrets are never uploaded.
- Free local checks for hardcoded secrets, auth gaps, payment webhook risks, destructive database migrations and deployment misconfigurations.
- Pro rules (after `shipguard login`) add deeper checks. Pro rule bundles are signed and verified before use.
- Clear verdict and exit codes for CI: `0` scan completed (read the `recommendation` field), `1` blocked with `--strict`, `2` configuration error, `3` runtime error.
- Machine-readable output with `--json`, and SARIF output with `--sarif`.
- `shipguard hook` installs the gate at the merge boundary (git hook, Claude Code hook or CI job).
- Inline suppressions with `// shipguard-ignore: <ruleId> -- <reason>`.
- A clear message when ShipGuard's hosted service is temporarily unavailable: the CLI says so plainly, shows the suggested wait, and `--json` carries the stable code `PLATFORM_UNAVAILABLE` with `retryAfterSeconds` when known. Exit code is 3; `--allow-degraded` still works.
- Links printed by the CLI (docs, site, pricing, billing, dashboard) use `agenticcli.dev/go/<slot>` short links that the site tags for analytics, and the README and npm page links carry fixed UTM tags. No install id, version, path or scan data is ever added to a link.
- Anonymous usage ping with simple opt-outs: `SHIPGUARD_TELEMETRY=0`, `DO_NOT_TRACK=1` or `shipguard telemetry disable`.
