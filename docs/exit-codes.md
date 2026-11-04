# Exit codes and JSON output

ShipGuard's exit code is verdict-neutral by default. The verdict is in the JSON `recommendation` field, so read it with `shipguard scan --json`.

| Code | Meaning |
|------|---------|
| `0` | The scan completed. Returned even when findings are blocking, and even when the scan is degraded. Read `recommendation`. |
| `1` | Blocked. Only with `--strict`: a blocking finding, a scan that did not finish (`degraded: true`), or a `DO_NOT_SHIP` verdict. Also with `--check-regressions` when a rule that passed before now fails. |
| `2` | Config error: a bad policy file, an unknown flag, or a folder that is not a project (use `--all` to scan one anyway). |
| `3` | Runtime error: the scan could not run at all (for example, no rules applied, or `--pro` could not fetch its rules). |

Exit `0` does not mean "safe". Never use it alone as a pass.

## Degraded scans

If ShipGuard could not read everything (an oversized file, an unreadable file, a skipped symlink, lost Pro rules, or a scan that read no files), the scan is `degraded` and the verdict is `DO_NOT_SHIP`. The reasons are in `degradedReasons`.

## JSON output

`shipguard scan --json` prints one JSON object with, among others: `recommendation` (`SAFE_TO_SHIP`, `REVIEW_BEFORE_SHIP` or `DO_NOT_SHIP`), `findings`, `riskScore`, `filesScanned`, `coverage`, `degraded`, `degradedReasons` and `schemaVersion` (`"6"`). Each finding has `id`, `title`, `severity`, `category`, `file`, `line`, `explanation`, `recommendation`, `blocking` and an optional `fix`.

Run `shipguard schema --json` to print the exact contract of the version you have installed.
