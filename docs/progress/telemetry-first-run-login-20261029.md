# telemetry-first-run-login-20261029

- Added `cli_first_run` (once per install, marker `telemetry-first-run-sent`) and `cli_login` (after successful login), schema 3, matching the relay in agenticcli apps/web/convex/lib/cliTelemetryRelay.ts.
- Root README now has a Telemetry section.
- Tests: 3398 passed, 7 skipped; tsc clean; build ok. No publish, no tag, no version bump (no changeset tooling in repo).
