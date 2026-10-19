# @agenticcli/shipguard

CLI-first release gate for AI-built apps.

Catches secrets leaks, auth gaps, payment webhook risks, destructive migrations, and deployment misconfigurations — before your code ships.

## 30-second quickstart

```bash
# Zero install — scan right now
npx @agenticcli/shipguard scan

# Or install globally
npm install -g @agenticcli/shipguard

# Then run from any project directory
shipguard scan
```

> **PATH gotcha:** `npm install` (without `-g`) does NOT put `shipguard` on your PATH.
> Use `npx @agenticcli/shipguard scan` or install with `npm install -g @agenticcli/shipguard`.

## Usage

```bash
shipguard scan            # Scan current project (rich output; verdict in JSON `recommendation`)
shipguard scan --strict   # CI hard gate: exit 1 on blocking findings (opt-in)
shipguard scan --json     # Machine-readable output for agents/CI
shipguard scan --quiet    # One-line verdict only
shipguard scan --pro      # Pro rules — requires login
shipguard login           # Authenticate for Pro rules
shipguard init            # Generate .shipguard.yml policy file
shipguard hook            # Install the gate at the merge boundary (git / claude / ci)
shipguard schema --json   # The machine-readable contract: verdict values, exit codes, limits
```

### Put the gate where merges happen

ShipGuard never blocks on its own. Installing a hook is the deliberate act that turns the
hard stop on:

```bash
shipguard hook                    # git pre-push + pre-merge-commit
shipguard hook --target claude    # Claude Code hook — runs outside the model
shipguard hook --target ci        # GitHub Actions verdict job
```

Copy-paste snippets for `AGENTS.md`, `CLAUDE.md` and CI: [docs/placement-kit.md](docs/placement-kit.md).

## Exit codes

ShipGuard is triggered by an agent; output is read machine-readably (`--json`).
**ShipGuard informs — the caller chooses soft vs hard gating.** The exit code
is verdict-neutral by default: it does NOT tell you whether findings are
blocking, or whether the scan was degraded — read the JSON `recommendation`
and `degraded`/`degradedReasons` fields for that.

| Code | Meaning |
|------|---------|
| `0`  | Scan completed — verdict is in the JSON `recommendation` field. Returned even if findings are blocking, and even if the scan is degraded/partial. |
| `1`  | Blocked — **only** with `--strict`, and then on either a blocking finding **or** a scan that did not finish (`degraded: true`). An unfinished scan cannot clear a hard gate. |
| `2`  | Config error, strictly (bad policy file, bad flags, non-project directory). Never doubles as "degraded scan." |
| `3`  | Runtime error — the scan could not meaningfully run at all. |

A degraded/partial scan (e.g. pro rules unavailable, an oversized file skipped)
is exit `0` with `degraded: true` and a `degradedReasons[]` array in `--json`
output — it never hijacks exit `2`, which is reserved for genuine config errors.

**A degraded scan is always `DO_NOT_SHIP`.** The report tells the truth about what it could
not check; the exit code stays 0 because ShipGuard is passive by default. Pass `--strict`
when you want that truthful verdict to actually stop something.

## Telemetry

Published ShipGuard builds send one pseudonymous usage ping after each scan: CLI version, verdict (safe / review / blocked / error), a scan-duration bucket, a CI flag, the build type, and a random install id (a pseudonym stored in `~/.config/shipguard/telemetry.json`; not created or sent in CI, never linked to an account). Never file contents, paths, repo names, branches or commits, or user identity. `shipguard telemetry status` shows what is set, `shipguard telemetry reset` forgets the id (earlier pings can be deleted on request), `SHIPGUARD_TELEMETRY_DEBUG=1` prints the exact payload without sending. Builds from a source checkout never send anything.

Before the first ping on a machine, ShipGuard prints a one-line notice to stderr (in every mode, including `--json` and CI, so stdout stays clean). Turn pings off any of these ways:

- `SHIPGUARD_TELEMETRY=0` or `DO_NOT_TRACK=1` in the environment (wins over everything)
- `shipguard telemetry disable` (saved per user; `enable` turns it back on, `status` shows the state and why)
- `telemetry: { enabled: false }` in `shipguard.policy.yml` or `.shipguard.yml` (per project)

To see exactly what would be sent without sending it: `SHIPGUARD_TELEMETRY_DEBUG=1 shipguard scan`.

Details: [agenticcli.dev/docs#telemetry](https://agenticcli.dev/docs?utm_source=npm_readme&utm_medium=package&utm_campaign=shipguard_evergreen&utm_content=telemetry#telemetry)

## Documentation

See [full docs](https://agenticcli.dev/docs?utm_source=npm_readme&utm_medium=package&utm_campaign=shipguard_evergreen&utm_content=docs) for policy configuration, CI setup, and agent integration.

## License

MIT
