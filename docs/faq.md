# FAQ

## What is ShipGuard?
The deterministic check that runs inside your agent loop: same diff, same verdict, a real exit code your agent can read. It also works as a release gate in CI. It checks your project for leaked secrets, unprotected routes, destructive migrations, unverified payment webhooks and risky deploy settings before you ship. It is not a code reviewer and not a general security scanner.

## Does my code leave my machine?
No. Scans run locally. The CLI downloads rules from the rulebook; your code never leaves your machine; only usage telemetry is sent (off with `--offline` or the existing opt-out). See [privacy](privacy.md).

## Can I run it with nothing sent and nothing written?
Yes: `shipguard scan --offline` (or `SHIPGUARD_OFFLINE=1`). It sends no usage ping and makes no rulebook, login or token call, writes no files, and leaves `.gitignore` alone. It cannot be combined with `--pro`, and `login`, `status` and `rate` refuse to run while `SHIPGUARD_OFFLINE` is on.

## Do I need an account?
No. Local scans need no account. A free sign-in unlocks full-rulebook scans (`--pro`).

## What does it cost?
- **Free**: unlimited local scans, plus 5 full-rulebook scans a month.
- **Plus**: $19 a month, 10 full-rulebook scans a month.
- **Pro**: $29 a month, or $19 a month billed yearly ($228 a year), 100 full-rulebook scans a month, agent-pay support and shared credits.
- **Enterprise**: contact us.

The `--strict` CI gate is free on every plan, and every signed-in plan gets the same current rule set. Plans differ in full-rulebook scan volume. Current prices are on the [pricing page](https://agenticcli.dev/pricing).

## Why did my CI job pass when ShipGuard found problems?
Without `--strict`, the exit code is `0` whenever the scan completes. Add `--strict`, or read `recommendation` in the JSON. See [exit codes](exit-codes.md).

## Should I use `--changed` in CI?
No. Use the full scan in CI. `--changed` compares to the last commit, so a clean CI checkout has nothing to scan. It suits local runs, pre-commit hooks and agent loops.

## Which AI coding tools does it work with?
It is a normal command, so it works with Claude Code, Codex CLI and Cursor, and in any CI. See [CI and agent setup](ci-setup.md).

## What license is it under?
[Elastic License 2.0](../LICENSE). It is source-available, not OSI open source. You may use it commercially; you may not offer it as a hosted service or resell it.

## How do I report a security problem or get help?
See [SECURITY.md](../SECURITY.md) for vulnerabilities, or the [contact page](https://agenticcli.dev/contact) for help.
