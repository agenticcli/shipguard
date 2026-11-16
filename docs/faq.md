# FAQ

## What is ShipGuard?
ShipGuard by AgenticCLI is the security scanner your coding agent runs before every commit. It checks your project for leaked secrets, unprotected routes, destructive migrations, unverified payment webhooks and risky deploy settings. Same code, same answer, and a real exit code your agent can read. It also runs in CI. It is not a code reviewer and not a full SAST tool.

## Does my code leave my machine?
No. ShipGuard checks your code on your machine. Rules come down; your code never goes up. The only data sent is small usage pings, which you can turn off. See [privacy](privacy.md).

## Do I need an account?
No. Local scans need no account. A free sign-in adds rulebook scans, which download the full current rulebook before checking on your machine.

## What does it cost?
- **Free**: unlimited local scans, plus 5 rulebook scans a month.
- **Plus**: $19 a month, 10 rulebook scans a month.
- **Pro**: $29 a month, or $19 a month billed yearly ($228 a year), 100 rulebook scans a month, agent-pay support and shared credits.
- **Enterprise**: contact us.

The `--strict` CI gate is free on every plan, and every signed-in plan gets the same full current rulebook. Plans differ in rulebook-scan volume. When your rulebook scans run out, ShipGuard falls back to a local scan. Current prices are on the [pricing page](https://agenticcli.dev/pricing).

## Why did my CI job pass when ShipGuard found problems?
Without `--strict`, the exit code is `0` whenever the scan completes. Add `--strict`, or read `recommendation` in the JSON. See [exit codes](exit-codes.md).

## Should I use `--changed` in CI?
No. Use the full scan in CI. `--changed` compares to the last commit, so a clean CI checkout has nothing to scan. It suits local runs, pre-commit hooks and coding agents.

## Which AI coding tools does it work with?
It is a normal command, so it works with Claude Code, Codex and Cursor, and in any CI. See [CI and agent setup](ci-setup.md).

## What license is it under?
[Elastic License 2.0](../LICENSE). It is source-available, not an OSI-approved license. You may use it commercially; you may not offer it as a hosted service or resell it.

## How do I report a security problem or get help?
See [SECURITY.md](../SECURITY.md) for vulnerabilities, or the [contact page](https://agenticcli.dev/contact) for help.
