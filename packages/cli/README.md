# ShipGuard by AgenticCLI (`@agenticcli/shipguard`)

**The security scanner your coding agent runs before every commit. On your machine. Flat price, no seats.**

Review code with a rulebook to build secure code. Same code, same answer: same diff, same verdict, a real exit code your agent can read.

Checks for leaked secrets, auth gaps, payment webhook risks, destructive migrations, and deployment misconfigurations — before your code ships.

**Open source CLI. Your code never leaves your machine.** ShipGuard sends only product usage telemetry (no code, no file paths, no file contents) to help us understand how people use it and make the next release better. You can switch it off any time: `shipguard telemetry disable` or `DO_NOT_TRACK=1`. [What is sent](https://github.com/agenticcli/shipguard/blob/main/docs/privacy.md)

## Quickstart

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

ShipGuard is a security scanner, not a code reviewer and not a full SAST tool. It runs on your machine and uses plain pattern rules (no AI model). Rules come down; your code never goes up. Source: [github.com/agenticcli/shipguard](https://github.com/agenticcli/shipguard).

## Usage

```bash
shipguard scan            # Scan current project (rich output; verdict in JSON `recommendation`)
shipguard scan --strict   # CI hard gate: exit 1 on blocking findings (opt-in)
shipguard scan --json     # Machine-readable output for agents/CI
shipguard scan --quiet    # One-line verdict only
shipguard scan --pro      # Download the full current rulebook for this scan (needs login)
shipguard login           # Sign in (Pro accounts run rulebook scans)
shipguard init            # Generate .shipguard.yml policy file
shipguard hook            # Install the hook at the merge boundary (git / claude / ci)
shipguard setup           # Set up the gate for your agent (--dry-run lists every file first)
shipguard uninstall       # Remove what setup wrote and name what stays
shipguard schema --json   # The machine-readable contract: verdict values, exit codes, limits
```

### Run it where merges happen

ShipGuard never blocks on its own. Installing a hook is the deliberate act that turns the
hard stop on:

```bash
shipguard hook                    # git pre-push + pre-merge-commit
shipguard hook --target claude    # Claude Code hook — runs outside the model
shipguard hook --target ci        # GitHub Actions verdict job
```

Copy-paste snippets for `AGENTS.md`, `CLAUDE.md` and CI: [docs/placement-kit.md](docs/placement-kit.md).

The CLI downloads rules from the rulebook; your code never leaves your machine; only usage telemetry is sent (off with the opt-outs below), plus a signed-out terminal scan may ask once a week for public rule counts for your stack names (names only, no code; never in hooks, CI, quiet or safe mode). Prices and plan details are not listed here: see `shipguard status` and [agenticcli.dev/pricing](https://agenticcli.dev/pricing?utm_source=npm_readme&utm_medium=package&utm_campaign=shipguard_evergreen).

## Exit codes

ShipGuard is triggered by an agent; output is read machine-readably (`--json`).
**ShipGuard informs — the caller chooses soft vs hard gating.** The exit code
is verdict-neutral by default: it does NOT tell you whether findings are
blocking, or whether the scan was degraded — read the JSON `recommendation`
and `degraded`/`degradedReasons` fields for that.

| Code | Meaning |
|------|---------|
| `0`  | Scan completed — verdict is in the JSON `recommendation` field. Returned even if findings are blocking, and even if the scan is degraded/partial. **Not "safe".** |
| `1`  | Blocked — **only** with `--strict`, and then on either a blocking finding **or** a scan that did not finish (`degraded: true`). An unfinished scan cannot clear a hard gate. |
| `2`  | Config error, strictly (bad policy file, bad flags, non-project directory). Never doubles as "degraded scan." |
| `3`  | Runtime error — the scan could not meaningfully run at all. |

So that a `0` is never read as "passed": when blocking findings exist and `--strict` is off, the terminal output ends with `exit 0 = scan finished, not safe. Add --strict to fail on blocking findings.`, and `--json` carries the same sentence in `exitMeaning`. `shipguard --help` lists the codes too.

A degraded/partial scan (e.g. rulebook unavailable, an oversized file skipped)
is exit `0` with `degraded: true` and a `degradedReasons[]` array in `--json`
output — it never hijacks exit `2`, which is reserved for genuine config errors.

**A degraded scan is always `DO_NOT_SHIP`.** The report tells the truth about what it could
not check; the exit code stays 0 because ShipGuard is passive by default. Pass `--strict`
when you want that truthful verdict to actually stop something.

### What was actually scanned

Every `--json` result (schemaVersion 7) has a `coverage` object: files discovered, scanned,
and skipped, with the reason for each skip (real binary, too large, symlink, unknown binary,
invalid text, unreadable, special file), plus text read as UTF-16 or with stray NUL bytes
turned into spaces. Real binaries (images, fonts, archives) are counted and are not a
problem. A scan that read **nothing** (`NO_FILES_SCANNED`, for example an empty folder or a
`--changed` scan where every changed file was ignored), an unknown binary blob (`UNSCANNED_UNKNOWN_BINARY`), and a
truncated scan are `degraded` and so `DO_NOT_SHIP`. To clear a blob you trust, add its path to
`ignore.paths`. `--changed` when nothing changed at all is the same: nothing was scanned, so it is `degraded`
(`NO_FILES_SCANNED`, `DO_NOT_SHIP`, `--strict` exits `1`) and also sets `coverage.changed.nothingToCheck: true`
(`filesScanned` is `0`). It is never a pass: run a full `shipguard scan` for that. Some formats are counted but their contents are not scanned: SQLite files
outside the ASCII reading, compressed archives, and string tables inside ELF, PE, class and WASM files.

## Telemetry

**The CLI downloads rules from the rulebook; your code never leaves your machine; only product usage telemetry is sent (off with the opt-outs below).** Published ShipGuard builds send one pseudonymous product usage telemetry message after each scan, plus a one-off message on the first run on an install and one after a successful `shipguard login` (7 keys: `schema`, `event`, `eventId`, `installId`, `cliVersion`, `provenance`, `ci`; the first-run message is never sent in CI). A scan message carries 12 keys: `schema` (`5`), `eventId`, `installId` (random pseudonym), `cliVersion`, `provenance` (build type), `verdict` (safe / review / blocked / error), `durationBucket`, `ci`, and four about how ShipGuard was run: `agent` (`claude_code`, `codex`, `cursor`, `gemini_cli`, `copilot`, `opencode`, `other_agent` or `none`, from the variables the agent itself sets in your environment; only the label is sent, never a value), `interactive` (is the output a terminal) `output` (`json`, `human` or `sarif`) and `gateKind` (`claude`, `git`, `ci` or `none`: which gate ran the scan). Pings go to `agenticcli.dev/api/cli-telemetry` (host agenticcli.dev). Every `--json` result shows `"telemetry": "on"` or `"off"`. An optional `traffic` key (`test` or `internal`) is added only if you set `SHIPGUARD_TRAFFIC`; any other value is ignored. The install id is a pseudonym stored in `~/.config/shipguard/telemetry.json`; not created or sent in CI, never linked to an account. Never file contents, paths, repo names, branches or commits, or user identity. `shipguard telemetry status` shows what is set, `shipguard telemetry reset` forgets the id (earlier messages can be deleted on request), `SHIPGUARD_TELEMETRY_DEBUG=1` prints the exact payload without sending. Builds from a source checkout never send anything.

Before the first telemetry message on a machine, ShipGuard prints a one-line notice to stderr (in every mode, including `--json` and CI, so stdout stays clean). Turn telemetry off any of these ways:

- `SHIPGUARD_TELEMETRY=0` or `DO_NOT_TRACK=1` in the environment (wins over everything)
- `shipguard telemetry disable` (saved per user; `enable` turns it back on, `status` shows the state and why)
- `telemetry: { enabled: false }` in `shipguard.policy.yml` or `.shipguard.yml` (per project)

To see exactly what would be sent without sending it: `SHIPGUARD_TELEMETRY_DEBUG=1 shipguard scan`.

Details: [docs/privacy.md](https://github.com/agenticcli/shipguard/blob/main/docs/privacy.md) and [agenticcli.dev/privacy](https://agenticcli.dev/privacy?utm_source=npm_readme&utm_medium=package&utm_campaign=shipguard_evergreen).

## Verify this package

The package ships source maps (`dist/*.js.map`) that point to the public source at the tagged commit. To rebuild it from its tag and compare hashes, and for the list of every network call in the CLI, see [REBUILD.md](https://github.com/agenticcli/shipguard/blob/main/REBUILD.md).

## Documentation

See the [ShipGuard docs](https://agenticcli.dev/shipguard/docs?utm_source=npm_readme&utm_medium=package&utm_campaign=shipguard_evergreen) for policy configuration, CI setup, and agent integration. Product page: [agenticcli.dev/shipguard](https://agenticcli.dev/shipguard?utm_source=npm_readme&utm_medium=package&utm_campaign=shipguard_evergreen).

## Help

- Help, billing, bugs and security reports: support@agenticcli.dev
- General and press: contact@agenticcli.dev
- Issues: [github.com/agenticcli/shipguard/issues](https://github.com/agenticcli/shipguard/issues)

## License

[Apache License 2.0](LICENSE). Use it, change it and share it, including commercially. See [NOTICE](NOTICE). The ShipGuard and AgenticCLI names are not part of the license.
