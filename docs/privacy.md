# Privacy

- **Rules come down. Code never goes up.** ShipGuard checks your code on your machine. A local scan uses the rules built into the CLI. A rulebook scan (after `shipguard login`) first downloads the full current rulebook over a signed-in session, then checks your code the same way, on your machine. Your code, file paths and file contents are never uploaded.
- **Product usage telemetry.** The only data sent is small product usage telemetry, sent to help us understand how people use ShipGuard and make the next release better. Published builds send three kinds of small pseudonymous message: one after each scan, one the first time ShipGuard runs on an install (never in CI), and one after a successful `shipguard login`. First-run and login messages carry 7 keys: `schema`, `event`, `eventId` (random, per message), `installId` (random, null in CI), `cliVersion`, `provenance` (published or dev build) and `ci` (true/false). A scan message carries 12 keys: `schema` (`5`), `eventId`, `installId`, `cliVersion`, `provenance`, `verdict`, `durationBucket` (a coarse range, not the exact time), `ci`, and three that say how ShipGuard was run: `agent` (which coding agent started it: `claude_code`, `codex`, `cursor`, `gemini_cli`, `copilot`, `opencode`, `other_agent` or `none`), `interactive` (true or false: is the output a terminal) and `output` (`json`, `human` or `sarif`; `--quiet` counts as `human`), and `gateKind` (`claude`, `git`, `ci` or `none`: which gate ran the scan, so hook runs can be told from plain scans). `agent` is worked out on your machine from the environment variables the agent itself sets (for example `CLAUDECODE`, `CODEX_SANDBOX`, `CURSOR_AGENT`, `GEMINI_CLI`, `COPILOT_CLI`, `OPENCODE`, or a generic `AI_AGENT` / `AGENT` for an agent we have no label for); only the label is sent, never a variable's value, a path or any text. The scan message has no `event`. An optional `traffic` key is added only if you set `SHIPGUARD_TRAFFIC` (see below). Never file contents, paths, repo names, branches, commits or your identity.
- **Where telemetry goes.** To `https://agenticcli.dev/api/cli-telemetry` and nowhere else. If the request fails, ShipGuard does nothing: no retry, no other host.
- **Two more requests, no code in either.** (1) A signed-out scan in a terminal may fetch the public rule counts for your detected stack names (stack names only: no files, no paths, no login), at most once every 7 days, and `shipguard setup` may fetch the generic public offer once with no stack names. Hooks, the gate, CI, `--quiet`, `--dry-run`, safe mode, `DO_NOT_TRACK` and a signed-in account make no such request. (2) `shipguard status` and `shipguard login` read your account and plan from the server. Both go to `https://agenticcli.dev` only, and every call is listed with its file in [REBUILD.md](../REBUILD.md).
- **Safe mode.** `shipguard --safe-mode` (or `SHIPGUARD_SAFE_MODE=1`) sends no telemetry and writes nothing outside the project except the sign-in token.
- **See the state.** Every `--json` scan result has `"telemetry": "on"` or `"off"` (off when you have opted out). The first-run notice line starts with `usage pings: on` and says how to turn them off.

## Turn product usage telemetry off

Any one of these turns off all three kinds:

- `SHIPGUARD_TELEMETRY=0` or `DO_NOT_TRACK=1` in the environment
- `shipguard telemetry disable`
- `telemetry: { enabled: false }` in your policy file

`shipguard telemetry status` shows the current setting and why. `SHIPGUARD_TELEMETRY_DEBUG=1 shipguard scan` prints exactly what would be sent, without sending it.

## Testing ShipGuard yourself

If you run ShipGuard in tests or automation of your own and want those runs kept apart from real usage, set `SHIPGUARD_TRAFFIC=test` or `SHIPGUARD_TRAFFIC=internal`. The message then carries `"traffic": "test"` (or `"internal"`). Any other value is ignored and nothing extra is sent. Builds made from a source checkout use `test` by default. Opting out of telemetry still turns everything off.

`shipguard telemetry reset` forgets your install id. Questions or deletion requests: support@agenticcli.dev.

Full policy: [agenticcli.dev/privacy](https://agenticcli.dev/privacy).
