# FAQ

## What is ShipGuard?
ShipGuard by AgenticCLI is the security scanner your coding agent runs before every commit. It checks your project for leaked secrets, unprotected routes, destructive migrations, unverified payment webhooks and risky deploy settings. Same code, same answer, and a real exit code your agent can read. It also runs in CI. It is not a code reviewer and not a full SAST tool.

## Does my code leave my machine?
No. ShipGuard checks your code on your machine. Rules come down; your code never goes up. No code, file paths or file contents are ever sent. The data it does send is small product usage telemetry, which helps us understand how people use ShipGuard and make the next release better. You can switch it off any time: `shipguard telemetry disable` or `DO_NOT_TRACK=1`. See [privacy](privacy.md).

## Do I need an account?
No. Local scans need no account. Pro adds rulebook scans, which download the full current rulebook before checking on your machine.

## What does it cost?
Local scans are free and unlimited, and `--strict` needs no account. Pro adds rulebook scans with the full current rulebook. What Pro includes and what it costs is on the [pricing page](https://agenticcli.dev/pricing), and `shipguard status` shows your own usage as the server reports it. This repository does not list prices or counts, so it cannot go out of date. When a rulebook scan is not available, ShipGuard runs a local scan and says so.

## How do I set it up for my agent, and remove it again?
`shipguard setup --agent claude|codex|cursor|ci` writes the hook or workflow for that agent after listing every file and asking you to confirm. `shipguard setup --dry-run` lists and writes nothing. `shipguard uninstall` removes what setup wrote (only if you have not edited it) and prints what it kept. See [CI and agent setup](ci-setup.md#setup-and-uninstall).

## Does ShipGuard make network requests besides product usage telemetry?
Two more, and neither carries code: a signed-out scan in a terminal may fetch the public rule counts for your stack names once a week, and `shipguard status` reads your account and plan. Hooks, CI, `--quiet` and safe mode never make the weekly request. Every call is listed with its file in [REBUILD.md](../REBUILD.md).

## Why did my CI job pass when ShipGuard found problems?
Without `--strict`, the exit code is `0` whenever the scan completes. Add `--strict`, or read `recommendation` in the JSON. See [exit codes](exit-codes.md).

## Should I use `--changed` in CI?
No. Use the full scan in CI. `--changed` compares to the last commit, so a clean CI checkout has nothing to scan. It suits local runs, pre-commit hooks and coding agents.

## Which AI coding tools does it work with?
It is a normal command, so it works with Claude Code, Codex and Cursor, and in any CI. See [CI and agent setup](ci-setup.md).

## What license is it under?
[Apache License 2.0](../LICENSE). It is an open source CLI: you may use it, change it and share it, including commercially. The ShipGuard and AgenticCLI names are not part of the license (see [TRADEMARKS.md](../TRADEMARKS.md)).

## How do I report a security problem or get help?
See [SECURITY.md](../SECURITY.md) for vulnerabilities, or the [contact page](https://agenticcli.dev/contact) for help.
