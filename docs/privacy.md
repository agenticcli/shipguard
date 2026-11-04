# Privacy

- **Your code stays on your machine.** A scan reads your files locally. File contents, file paths and secrets are never sent to a server. The local scan does not upload anything.
- **Cloud scans** (after `shipguard login`) download rules over a signed-in session. Rules come down; code never goes up.
- **Pings.** Published builds send three kinds of small pseudonymous ping: one after each scan, one the first time ShipGuard runs on an install (never in CI), and one after a successful `shipguard login`. First-run and login pings carry 7 keys: `schema`, `event`, `eventId` (random, per ping), `installId` (random, null in CI), `cliVersion`, `provenance` (published or dev build) and `ci` (true/false). A scan ping carries 8 keys: `schema`, `eventId`, `installId`, `cliVersion`, `provenance`, `verdict`, `durationBucket` (a coarse range, not the exact time) and `ci`; it has no `event`. An optional `traffic` key is added only if you set `SHIPGUARD_TRAFFIC` (see below). Never file contents, paths, repo names, branches, commits or your identity.

## Turn the pings off

Any one of these turns off all three kinds:

- `SHIPGUARD_TELEMETRY=0` or `DO_NOT_TRACK=1` in the environment
- `shipguard telemetry disable`
- `telemetry: { enabled: false }` in your policy file

`shipguard telemetry status` shows the current setting and why. `SHIPGUARD_TELEMETRY_DEBUG=1 shipguard scan` prints exactly what would be sent, without sending it.

## Testing ShipGuard yourself

If you run ShipGuard in tests or automation of your own and want those runs kept apart from real usage, set `SHIPGUARD_TRAFFIC=test` or `SHIPGUARD_TRAFFIC=internal`. The ping then carries `"traffic": "test"` (or `"internal"`). Any other value is ignored and nothing extra is sent. Builds made from a source checkout use `test` by default. Opting out of pings still turns everything off.

`shipguard telemetry reset` forgets your install id. Questions or deletion requests: support@agenticcli.dev.

Full policy: [agenticcli.dev/privacy](https://agenticcli.dev/privacy).
