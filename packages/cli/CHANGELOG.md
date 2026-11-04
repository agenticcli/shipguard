# @agenticcli/shipguard

## 0.10.0 - 2026-11-04

- Added: published builds now send a small anonymous ping the first time ShipGuard runs on an install (`cli_first_run`, never in CI) and after a successful `shipguard login` (`cli_login`), as well as after each scan. First-run and login pings carry 7 keys: `schema`, `event`, `eventId`, `installId`, `cliVersion`, `provenance`, `ci`. The scan ping carries 8: `schema`, `eventId`, `installId`, `cliVersion`, `provenance`, `verdict`, `durationBucket`, `ci`. Never file contents, paths, repo names, branches, commits or identity.
- Added: a one-line notice on stderr before the first ping on a machine, in every mode (stdout stays clean for `--json`).
- Opt out any of these ways: `SHIPGUARD_TELEMETRY=0`, `DO_NOT_TRACK=1`, `shipguard telemetry disable`, or `telemetry: { enabled: false }` in your policy file. `shipguard telemetry status` shows the state; `SHIPGUARD_TELEMETRY_DEBUG=1` prints the exact payload without sending it; `shipguard telemetry reset` forgets the install id. Builds from a source checkout send nothing.
- Added: `SHIPGUARD_TRAFFIC=test` or `internal` for people testing ShipGuard. It adds an optional `traffic` key to the pings so test runs are kept apart from real usage. Any other value is ignored.
- Docs: new README, `docs/` pages (getting started, checks, CI setup, exit codes, privacy, FAQ), and the npm README now match each other, with the contact addresses support@agenticcli.dev and contact@agenticcli.dev.
- Changed: package metadata (author, homepage, keywords) updated.
- Changed: GitHub Actions and npm dependencies updated to their latest compatible versions. (The re2js update is planned separately and is not part of this release.)
- Release process: publishing is only through the GitHub release workflow (npm trusted publishing with provenance). This version is first published as the `0.10.0-rc.0` pre-release under the `next` tag.

## 0.9.0 - 2026-11-02

- Fixed: a scan can no longer say `SAFE_TO_SHIP` over files it did not read. UTF-16 files (with or without a byte-order mark) and text files with a stray NUL byte are now scanned (each NUL is read as a space, so line numbers do not move). Before, one NUL byte next to a secret hid the whole file.
- Fixed: a scan that read nothing (an empty folder, only ignored or binary files, or `--changed` on a clean checkout) is now `degraded` with `NO_FILES_SCANNED`, so the verdict is `DO_NOT_SHIP` and `--strict` exits 1. Run `shipguard scan` for the whole tree.
- Added: a new degrade code `UNSCANNED_UNKNOWN_BINARY` for NUL-heavy files with no sign of being a real binary. Add the path to `ignore.paths` to clear it. A file's name and extension are never used to decide.
- Added: `coverage` in the `--json` output: discovered, scanned, skipped by reason, decoded as UTF-16, NUL-substituted, ignored by default rules, ignored by your `ignore.paths`, and the cap that truncated the scan. `schemaVersion` is now `6` (additive). Real binaries are counted, not degraded.
- Added: real binaries under the size cap (images, PDFs and similar, found by their magic bytes) are still counted as binary, but their printable text (runs of 8 or more ASCII characters) is also scanned, so a key hidden behind an image header is found. A finding there reports the run number as its line. `coverage.decoded.binaryStringsScanned` counts these files. Binaries over the size cap are still checked by their first 4 KiB only.
- Added: `coverage.selfArtifacts` counts ShipGuard's own files that a scan never reads as your project: anything under a `.shipguard/` folder at any depth, and a `.gitignore` (at any depth) that holds only the `.shipguard/` line the history store adds. Before, a second scan of an empty folder could look scanned because of that `.gitignore`.
- Fixed: folders that fast-glob lists but cannot enter (for example a name with a line break in it) are now listed directly instead of being dropped with everything inside; a folder name that is not valid UTF-8, or a folder git could not open under `--changed` ("could not open directory"), degrades the scan as `UNREADABLE_FILE`. Symlinks report `SYMLINK_SKIPPED` under `--changed`, like the full scan.
- Known limit, counted but not scanned: SQLite files outside the ASCII reading, compressed archives (zip, gzip and similar), and string tables inside ELF, PE, class and WASM files. A secret split by an embedded NUL byte is also not matched.
- Changed: `treeDigest` now differs for trees that contain NUL or UTF-16 files (they enter the digest now), and for `--changed` scans whose file names had odd whitespace.
- Changed: `--changed` now uses exact file names (no trimming), honours `ignore.paths`, follows the same default ignore list as the full scan (changed `*.log`, `*.min.js`, `vendor/`, `tmp/` and `out/` files, which it used to scan, are now skipped and counted), reads the right file when run from a sub-folder, and degrades on a git file name that is not valid UTF-8.
- Changed: images, PDFs, archives and other media are no longer dropped by file extension; they are read by content, so a text file named `x.png` is scanned.
- Fixed: `shipguard scan --json --strict` no longer loses piped output. The CLI now sets the exit code and lets Node finish writing, instead of exiting with output still queued (a slow reader used to get cut JSON). A closed pipe (`| head`) keeps the scan's exit code.

## 0.8.1 — first public release with npm provenance (0.8.0 was tagged but never published: release workflow fix)

- Fixed: npm trusted publishing in the release workflow, so 0.8.1 is published with provenance.
- Fixed: if the login link from the server cannot be trusted, `shipguard login` now points you to `/auth/device` (the page that exists) instead of a missing `/activate` page.
- Fixed: a rate-limited (429), server-error (5xx) or unreachable token refresh no longer tells you to log in again. The CLI retries up to 3 times (honouring `Retry-After`, up to 10 s), keeps your login, then stops with exit code 3 and a "try again in N s" message. Only a refusal such as 401 still asks you to log in.

## 0.8.0 — first public release (2026-10-19)

ShipGuard is a CLI-first release gate for AI-built apps. It scans your project locally and tells you whether it is safe to ship.

- Runs entirely on your machine. Your code, file paths and secrets are never uploaded.
- Free local checks for hardcoded secrets, auth gaps, payment webhook risks, destructive database migrations and deployment misconfigurations.
- Pro rules (after `shipguard login`) add deeper checks. Pro rule bundles are signed and verified before use.
- Clear verdict and exit codes for CI: `0` scan completed (read the `recommendation` field), `1` blocked with `--strict`, `2` configuration error, `3` runtime error.
- Machine-readable output with `--json`, and SARIF output with `--sarif`.
- `shipguard hook` installs the gate at the merge boundary (git hook, Claude Code hook or CI job).
- Inline suppressions with `// shipguard-ignore: <ruleId> -- <reason>`.
- A clear message when ShipGuard's hosted service is temporarily unavailable: the CLI says so plainly, shows the suggested wait, and `--json` carries the stable code `PLATFORM_UNAVAILABLE` with `retryAfterSeconds` when known. Exit code is 3; `--allow-degraded` still works.
- Links printed by the CLI (docs, site, pricing, billing, dashboard) use `agenticcli.dev/go/<slot>` short links that the site tags for analytics, and the README and npm page links carry fixed UTM tags. No install id, version, path or scan data is ever added to a link.
- Anonymous usage ping with simple opt-outs: `SHIPGUARD_TELEMETRY=0`, `DO_NOT_TRACK=1` or `shipguard telemetry disable`.
