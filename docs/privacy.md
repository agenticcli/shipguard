# Privacy

- **Your code stays on your machine.** A scan reads your files locally. File contents, file paths and secrets are never sent to a server. The local scan does not upload anything.
- **Cloud scans** (after `shipguard login`) download rules over a signed-in session. Rules come down; code never goes up.
- **Usage ping.** Published builds send one small pseudonymous ping after a scan: CLI version, verdict, a duration bucket, whether it ran in CI, the build type and a random install id. Never file contents, paths, repo names, branches, commits or your identity.

## Turn the ping off

Any one of these works:

- `SHIPGUARD_TELEMETRY=0` or `DO_NOT_TRACK=1` in the environment
- `shipguard telemetry disable`
- `telemetry: { enabled: false }` in your policy file

`shipguard telemetry status` shows the current setting and why. `SHIPGUARD_TELEMETRY_DEBUG=1 shipguard scan` prints exactly what would be sent, without sending it.

Full policy: [agenticcli.dev/privacy](https://agenticcli.dev/privacy).
