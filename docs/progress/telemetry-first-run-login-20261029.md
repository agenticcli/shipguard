# telemetry-first-run-login-20261029

- Added `cli_first_run` (once per install, marker `telemetry-first-run-sent`) and `cli_login` (after successful login), schema 3, matching the relay in agenticcli apps/web/convex/lib/cliTelemetryRelay.ts.
- Merged main (#15 README rewrite); README Privacy and docs/privacy.md list every ping, key and opt-out.
- Added optional `traffic` key (SHIPGUARD_TRAFFIC=test|internal; invalid omitted; dev builds default test) in schema 2 and 3.
- Tests: 3398 passed, 7 skipped; tsc clean; build ok. No publish, no tag, no version bump (no changeset tooling in repo).
