# @agenticcli/shipguard

## 0.13.0 - 2026-11-24

- Clearer scans: the scan screen now opens with a verdict (safe to ship or not), then lists what to fix in plain words, shows what was not scanned, and ends with the one command to run next. Every finding says how to fix it, and secret values are hidden (only the length is shown).
- Helpful next steps: new `shipguard status` (what is installed and when the gate last ran), `shipguard upgrade` (what Pro adds for the stacks you scan) and `shipguard login` (cancel with Ctrl-C exits 130). They suggest the command to re-run your last scan.
- Agent contract: `--json` scan results are now schema 7. Every outcome and every error has a stable code, a plain message and a ready re-run command, so a coding agent can act without guessing. Running the same scan again on the same commit keeps the same scan id.
- New `shipguard setup` and `shipguard uninstall`: setup adds the commit/agent hook and CI file after showing a preview and asking once; uninstall removes only what setup created, shows what stays active, and refuses to follow symlinks or edited records. Your own settings layout is kept byte for byte.
- Hook gate: `shipguard gate` stops an agent from running unsafe commits and lets you ignore a finding only with a written reason. Unknown command forms fail closed. A health line shows if the gate is not working.
- Free to Pro plan data now comes from the server as a signed reply: the CLI shows your plan, scans left and what Pro adds, and checks the signature. An expired or future-dated reply is treated as plain Free. The CLI holds no prices or plan numbers of its own. The new network calls (weekly public offer fetch, signed plan read) are listed in REBUILD.md and docs/privacy.md, and are off in safe mode, hooks, CI and quiet runs.
- Better scan accuracy: loud rules fire more reliably, `sk_test_` and placeholder values are skipped, git-ignored files are respected, sign-in checks and 401 handling are detected more correctly, and React and Firebase projects are detected (stacks with no rule, such as fastify and drizzle, are no longer reported as detected). The free rules are now corpus version 29.
- Safe mode: when set, ShipGuard writes nothing under `~/.config` and makes no optional network call.
- Release checks: the release gate now checks package size (packed 800 KB, unpacked 3 MiB), an npm audit, the picomatch pin and that no generic cloud wording is in the package. `scripts/release-facts.sh` makes sure the version, CHANGELOG date, CITATION.cff, security statement and pinned versions in the docs all agree before publish, and writes a release-facts file afterwards.
- Changed: the `jose` dependency is removed.
- Safer in a cloned repo: `report.output` and `history.path` in `shipguard.policy.yml` must stay inside the project (anything else is refused with a warning and the default is used); `shipguard uninstall` never follows a symbolic link or a foreign install record out of the project; the scan never edits your `.gitignore` (it writes `.shipguard/.gitignore` instead); a policy file of the wrong shape is refused as INVALID_POLICY (the gate blocks with that code) instead of crashing the scan; scan-id reuse (no double charge on a re-run) now also works on Node older than 22.5; a `.shipguard` that is a symbolic link is never written through (one warning, the scan still prints), and `.shipguard/` stays out of git through its own `.gitignore`.

## 0.12.1 - unreleased

- Faster scans: a rule is now skipped for a file when a text it must contain is absent, before the slow pattern engine runs. Scans use 4 to 7 times less CPU on large projects. Findings are identical: checked over all 259 free rules against the previous scanner (golden equality tests).
- Added: the package now ships source maps (`dist/*.js.map`, real `src/` files embedded), so you can read the code behind the bundle, and error traces point at real source lines. The package is about 360 kB larger packed (528 kB; was 167 kB).
- Added: REBUILD.md in the public repo: how to rebuild the published package from its tag and compare file hashes (`scripts/rebuild-verify.sh 0.12.1`), and a list of every network call in the CLI with file names. CI now checks that two publish builds are byte-identical and that every source map resolves.
- Changed: the CLI now accepts Pro rule freshness tokens that stay valid for up to 72 hours (it accepted up to 25 hours before). Tokens that are longer-lived, or issued more than 5 minutes in the future, are still rejected.
- Changed: when the signed freshness token of the Pro rules has expired, `shipguard scan --pro` now says "Pro rules are temporarily unavailable. Retry later, or run with --allow-degraded to scan with local rules only." (JSON `code` `FRESHNESS_EXPIRED`). Exit code stays 3; `--allow-degraded` still falls back to the free rules, marked degraded.

## 0.12.0 - unreleased

- Better detection: the free rules now catch more real holes in Next.js, Supabase and Stripe projects, for example pages and API routes that look protected but never actually stop a signed-out visitor, and sign-in checks that test the wrong value.
- Far fewer false alarms: example values, placeholders and look-alike text are no longer flagged, and a rule now only fires where the problem can really happen.
- Look-alike keys are no longer flagged: strings that only resemble a real key (test samples, docs, examples) are ignored, while real keys are still caught. A `.env` file that is tracked by git is still reported.
- Fixed: a scan could run forever (using a lot of CPU) if the folder being scanned was deleted or moved while it ran. It now stops with an error (exit code 3), never a "safe" result.
- Updated the bundled free rules to corpus version 28.
- Added: exit codes are spelled out so a `0` is not read as "safe". When blocking findings exist and `--strict` is off, the terminal output ends with `exit 0 = scan finished, not safe. Add --strict to fail on blocking findings.`; `--json` carries the same sentence for this run in `exitMeaning`; `shipguard --help` has an "Exit codes" section. The exit-code contract itself (0 scan completed, 1 blocked only with `--strict`, 2 config error, 3 runtime error) is unchanged. The new JSON field `exitMeaning` is additive (`schemaVersion` stays `6`).
- Changed: the scan usage ping is now schema 4 and goes to `https://agenticcli.dev/api/cli-telemetry`. It adds three fields: `agent` (which coding agent started the scan, or `none`; only a label, worked out from the agent's own environment variables), `interactive` (is the output a terminal) and `output` (`json`, `human` or `sarif`). Nothing else changes: same opt-outs, no code, paths or account data. If the request fails the CLI does nothing.
- Added: every `--json` scan result has `"telemetry": "on"` or `"off"` (off with an opt-out; `schemaVersion` stays `6`). The first-run notice line now starts with `usage pings: on` and names the opt-outs.
- Docs: the privacy and CI pages now say plainly how data flows: the CLI downloads rules from the rulebook, your code never leaves your machine, and only usage telemetry is sent (off with the opt-outs in the privacy page).
- Fixed: `shipguard scan --changed` with no changed files no longer reports `SAFE_TO_SHIP` (0.11.0 did, even on a repo with a critical issue). Nothing was scanned, so it now reports degraded `NO_FILES_SCANNED` (`DO_NOT_SHIP`, `--strict` exits 1, plain run exits 0), says "Nothing was scanned: no files changed. This is NOT a safe-to-ship result." and still sets `coverage.changed.nothingToCheck: true`. The `--quiet` line ends with `nothing-scanned=yes`. `schemaVersion` stays `6` (no new fields).
- Fixed: an empty or near-empty folder said "No findings detected - clean scan" in the terminal while `--quiet`, `--json` and the usage ping said `DO_NOT_SHIP`. All modes now say "Nothing to scan: no readable files were found. This is NOT a clean result."
- Fixed: `shipguard hook` git hook fell back to `npx --no-install shipguard`, which is an unrelated npm package. Every hook now finds ShipGuard in `node_modules/.bin`, then on PATH, then runs `npx --yes @agenticcli/shipguard@0`; the Claude Code hook no longer needs a global install. If ShipGuard cannot be started the hook still blocks (the gate did not run) but says so and prints the fix (`npm i -D @agenticcli/shipguard`). Re-run `shipguard hook` to update installed hooks.
- Fixed: the "What now?" footer no longer suggests the non-existent `shipguard report`; it points to `shipguard hook --target git`, and the `rate` examples use the real syntax (`shipguard rate 1 helpful`).
- Tests: clean real-shaped Next.js 15 (`middleware.ts`), Next.js 16 (`proxy.ts`) and Stripe apps now have fixtures that must exit 0 under `--strict`.

## 0.11.0 - 2026-11-08

- Security: updated the regular-expression engine `re2js` from 2.8.3 to 2.8.7. Versions before 2.8.7 have a high-severity slow-matching flaw in lookbehind handling (GHSA-gg6h-894w-4m9c, CVE-2026-116795). ShipGuard keeps lookbehinds switched off, so it was not reachable through normal scans, but the fixed version is now the only one used. Because the engine version is part of the signed rules identity, this release needs rules bundles signed for the new engine: Pro rules published before the update are not accepted by 0.11.0, and the re-signed rules are not accepted by older versions. A rejected Pro bundle makes `shipguard scan --pro` stop with exit code 3 (or, with `--allow-degraded`, fall back to the free rules, marked degraded). The free rules are not affected.
- Fixed: `shipguard scan --changed` when nothing changed no longer reports `DO_NOT_SHIP` with no findings. If git ran fine and the only changes are ShipGuard's own `.shipguard/` files (or there are none), there is nothing to check: the scan is not degraded, the normal verdict applies, `filesScanned` is `0` and `coverage.changed.nothingToCheck` is `true`. This is not proof the project is safe, so run a plain `shipguard scan` for that. Every other scan that reads nothing still reports `NO_FILES_SCANNED` and `DO_NOT_SHIP` (an empty folder, everything ignored or binary, or changed files that were all ignored, outside the scanned folder or unreadable). `schemaVersion` stays `6` (additive field).
- Fixed: `shipguard login` that is never approved in the browser (or whose code expires) now says "Sign-in timed out. Run `shipguard login` again." instead of the bare "Auth timed out". Exit code stays 2.
- Changed: the npm description, README opening line and keywords now match the product line "The security scanner your coding agent runs before every commit."
- Tests: removed the branch-only check that failed on any change to the matcher contract (it was meant for one earlier branch).

## 0.10.0 - 2026-11-05

- Added: published builds now send a small pseudonymous ping the first time ShipGuard runs on an install (`cli_first_run`, never in CI) and after a successful `shipguard login` (`cli_login`), as well as after each scan. First-run and login pings carry 7 keys: `schema`, `event`, `eventId`, `installId`, `cliVersion`, `provenance`, `ci`. The scan ping carries 8: `schema`, `eventId`, `installId`, `cliVersion`, `provenance`, `verdict`, `durationBucket`, `ci`. Never file contents, paths, repo names, branches, commits or identity.
- Added: a one-line notice on stderr before the first ping on a machine, in every mode (stdout stays clean for `--json`).
- Opt out any of these ways: `SHIPGUARD_TELEMETRY=0`, `DO_NOT_TRACK=1`, `shipguard telemetry disable`, or `telemetry: { enabled: false }` in your policy file. `shipguard telemetry status` shows the state; `SHIPGUARD_TELEMETRY_DEBUG=1` prints the exact payload without sending it; `shipguard telemetry reset` forgets the install id. Builds from a source checkout send nothing.
- Added: `SHIPGUARD_TRAFFIC=test` or `internal` for people testing ShipGuard. It adds an optional `traffic` key to the pings so test runs are kept apart from real usage. Any other value is ignored.
- Docs: new README, `docs/` pages (getting started, checks, CI setup, exit codes, privacy, FAQ), and the npm README now match each other, with the contact addresses support@agenticcli.dev and contact@agenticcli.dev.
- Changed: package metadata (author, keywords) updated.
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
- Pseudonymous usage ping with simple opt-outs: `SHIPGUARD_TELEMETRY=0`, `DO_NOT_TRACK=1` or `shipguard telemetry disable`.
