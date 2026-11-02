# Session: scan-honest-coverage-20261102

- Repo: agenticcli/shipguard (public, npm 0.8.1), base 2bf3a7d. Branch: scan-honest-coverage-20261102.
- Stakes: HIGH (security control in a release gate).
- Phase: PLANS ONLY. No code changed. Plan: docs/plans/scan-honest-coverage-20261102.md.

## Goal
1. BUG 1: `shipguard scan` must never say SAFE_TO_SHIP over files it did not read. JSON always reports coverage counts; UTF-16 and NUL-bearing text files are scanned; real binaries are counted; unclassifiable blobs, truncation and "nothing scanned" are degraded (DO_NOT_SHIP).
2. BUG 2: `scan --json --strict` must not lose piped stdout (re-implement archive PR #71 in this repo with its own test).

## Choices made in the plan
- NUL-bearing text: scan with each NUL replaced by one space; not degraded. NUL-heavy unknown blobs: skipped and degraded (`UNSCANNED_UNKNOWN_BINARY`).
- BOM-less UTF-16: detected only for ASCII-dominant text (NUL parity signature) and validated by strict decode; anything else falls to the degraded path.
- Zero scanned: `degraded:true` with `NO_FILES_SCANNED`, verdict DO_NOT_SHIP via the existing fail-closed rule. No new verdict value.
- `--strict`: unchanged function; every degraded case exits 1, non-degraded counts never change the exit code.
- matcher-contract: not touched (no byte-identity risk; the platform vendors the 0.5.1 tarball and uses only selector and canonical).
- JSON: new top-level `coverage` object, schemaVersion 5 to 6.

## Open questions for the main session
Q1 default-ignored text files (`*.log`, `*.min.js`, `vendor/`); Q2 `--changed` with zero diff; Q3 schema bump; Q4 extension list. See plan section E.

## Not done
No PR, no version bump, no tag, no publish.

## Round 2 (after NO-GO from the Opus judge and Codex)
Plan revised: magic bytes only for flagged, binary-dominant files and never by extension; no empty-diff exemption for `--changed`; `git -z` exact names plus one shared ignore helper; UTF-16 validated before NUL-to-space; bug 2 never calls `process.exit` with queued output (exitCode and return, EPIPE handler, handshake test); `--check-regressions` needs `--strict`; behavioural mutation matrix over both read paths; mandatory tarball rehearsal before publish. Map in plan section R.
Round 3 (final): plan revised again; see plan section R3. Decisions: check-regressions kept as is, EPIPE handlers at startup, probe without touching exitCode, ambiguity union, UTF-8-aware Gate 3, strict-UTF-8 head shortcut, nested-root and Buffer filename handling.

## Build phase: old tests updated (they pinned the silent behaviour)
Each change keeps the test and asserts the new honest behaviour. Full suite after this step: 3512 passed, 7 skipped (baseline 3381 + the new tests).
- `tests/core/scanner.test.ts`, `ws2-core-orchestration.test.ts`, `scanner-changed-symlink.test.ts`: the git mock now also exports `getChangedFilesDetailed` (scan() calls it for exact names and the nested root); it is derived from the existing `getChangedFiles` mock so tests still control the list and git failures. Reason: the code under test changed its git entry point, not the behaviour under test.
- `scanner.test.ts` zero-diff test: was "genuinely zero changed files is NOT degraded". Plan Q2 reversed this: nothing read means `NO_FILES_SCANNED`, degraded. The test still proves it is not a git error.
- `fs-bounds.test.ts`: "a NUL byte means skipped binary" was the silent hole. Split into (a) a text file with a stray NUL is scanned, NUL becomes a space, counted in `nulSubstituted`; (b) a real PNG-style binary is still `skippedBinary`.
- `fs-symlink-skip-reporting.test.ts`, `scanner-edge1-symlink-degradation.test.ts`, `scan-degraded-on-skip.test.ts`: the "binary" fixture was a tiny NUL blob with no magic. It is now a real PNG-signature binary (still a normal, non-degraded skip, counted). A new test in the last two files proves the old tiny NUL blob now degrades with `UNSCANNED_UNKNOWN_BINARY`.
- `scan-json-schema-freeze.test.ts`: schemaVersion `'6'`, `coverage` required at top level, plus a new test that pins the exact `coverage` key sets (including `decoded.multiReading`). `_skipped*` still must not leak.
- `secret-evidence-redaction.test.ts` and `json-stdout-purity.test.ts`: the pinned top-level key set gains `coverage`; schemaVersion expectation `'6'`.
- Named in the brief but unchanged because they already pass on the new behaviour: `scan-ux`, `ux-overhaul`, `scan-bounds`, `schema-contract`, `cli-exit-codes` (the last is revisited in the bug 2 step). `fs-special-files` FIFO test run alone: 2 passed.

## Build phase: BUG 2 (strict JSON pipe)
- `utils/exit.ts`: `setExitCode` only sets `process.exitCode` (no timer, no process.exit). `installStreamErrorHandlers` runs at startup in `cli.ts` and keeps the computed code on EPIPE. `exitWhenDrained` (called after parseAsync) is the one permitted exit: from inside empty-write callbacks on stdout and stderr, only when both `writableLength` are 0. It was needed: the telemetry test with a hung mock endpoint kept the process alive 25 s otherwise.
- `scan.ts`: `exitWithError` returns `Promise<void>`; every call site now has `return`.
- Old in-process tests that mocked `process.exit` to throw (scan, scan-bounds, scan-ux, scan-pro-fetch-failure) now assert `process.exitCode` and that `process.exit` was not called; each afterEach clears `process.exitCode` so it cannot leak into the worker.
- Pipe tests B12 (fast), B13 (slow, 5.7 MB, 12 s hold, plus SARIF), B14, B16, B21 added. Fixture size: a spawned child gets a unix socket pair (about 200 KB buffer), not a 64 KiB shell pipe, so B12 uses about 580 KB; the handshake asserts `queued > 0`.
- Fail-before (reverted scan.ts and cli.ts): `docs/testlab/2026-11-02/fail-before/U4-bug2-pipe-tests-on-reverted-code.txt`. B12 fails (219,264 bytes received, expected over 300,000); B13 fails (both variants: process died during the hold). B16 PASSES on the reverted code: `console.log` adds a no-op error listener while it writes, so EPIPE never became uncaught in this tree. B16 is therefore a guard, as the plan already said for the bare-exit proof; the handlers are belt and braces and are unit-tested in B14.

## Build phase: docs, C0, accepted residuals and notes
- Docs: CHANGELOG "Unreleased" (names the counted-but-not-scanned formats, treeDigest change, `--changed` behaviour change, schemaVersion 6, strict JSON fix), README "What was actually scanned", llms.txt json line. The `scan.ts` exit-code doc comment already says `--strict` and `--check-regressions` are the two opt-in conditions. G8 needed no edit: the shipped-tree self-scan slow test passes on the publish build.
- C0 rehearsal (`docs/testlab/2026-11-02/C0-tarball-rehearsal.txt`): `SHIPGUARD_PUBLISHED_BUILD=1` build, `npm pack`, `npm install --ignore-scripts` in a temp dir, `SHIPGUARD_CLI` set to the installed `dist/cli.js`. All 8 e2e files (62 tests: matrix, binary tree, coverage json, default-ignore, limits incl. large-asset rows, strict pipe, EPIPE, check-regressions guard) pass; B13 slow pair passes; 4 real host assets over 512 KiB (jpg, pdf, mp4, png) give `skipped.binary` 4, not degraded, SAFE; G8 passes.
- Accepted residuals (recorded, not fixed): (1) an over-cap JPEG whose head has a real marker and invalid UTF-8 but hides text later is skipped as binary (`binaryHeadOnly`), counted, not degraded; (2) magic-verified binaries below the cap that are mostly non-printable are skipped and counted, not degraded; (3) counted but not scanned: SQLite outside the ASCII reading, compressed archives, string tables inside ELF/PE/class/WASM; (4) a key split by an embedded NUL.
- Rule added beyond the plan text: a BOM-less UTF-16 reading is only tried when the NUL bytes sit on one byte parity (one parity at least 4x the other; `UTF16_PARITY_DOMINANCE`), as well as passing the decode and plausibility tests. This keeps NUL-padded blobs from being read as UTF-16 text.
- All-CJK note: a BOM-less UTF-16 file made only of CJK characters has no NUL bytes, so it never reaches the UTF-16 step. It goes to strict UTF-8 and fails, so it is degraded `INVALID_UTF8` (loud, fixable with `ignore.paths`), never silently skipped. CJK followed by ASCII (a key) has NULs on one parity and is decoded.
- B16 (EPIPE) passes on the pre-fix code (see BUG 2 section); it is a guard. The fix proof is B12/B13.
- Not verified here: Node 20 and 22 for the probe self-test (only Node 24.22.1 on this box; CI matrix will cover).
- Out of scope, tracked: `--changed` counts a deleted file as UNREADABLE_FILE (false degrade; consider `--diff-filter=d`); direct `process.exit` in `cli.ts`/`handlers.ts`/other commands (short output only).

## After code review: binary strings reading (main decision)
- Residual closed: PNG magic + 4000 NULs + a key, under the size cap, used to be SAFE with the key unread. Now `classifyFile` returns `{kind:'binary', strings}` and `fs.ts` feeds the strings (printable ASCII runs of 8+, one per line, line number = run index) through the normal rules. The file still counts once as `skipped.binary`; new counter `coverage.decoded.binaryStringsScanned` (in `decoded`, so the discovered/skipped invariant is untouched). Over-cap binaries are unchanged (head-only, accepted residual).
- Tests `tests/commands/scan-binary-strings.test.ts`: (a) key found, full and `--changed`; (b) synthetic JPEG/PNG/PDF and real host jpg, pdf, png (under the cap, copied to a temp dir) give zero findings with the full rule set (no mp4 under the cap on this host; the repo has no committed image fixtures); (c) mutation: disabling the strings feed turns both (a) tests red (run and restored).
- Plan line 336 reworded (no "deliberate attacker" reasoning). `ignore.ts` purpose comment moved to line 1. CHANGELOG and freeze test updated. The accepted-residual list above now reads: only the over-cap head-only case, and text in a below-cap binary that is not printable ASCII runs of 8+.

## After QA FAIL-BLOCK (chain 0bb8bb33): fixes
- Folder names that are not valid UTF-8 (full scan): `d\xFF/` was never listed, so nothing flagged it. `readFiles` now takes the directory entries of its second fast-glob pass (objectMode) whose lossy name contains U+FFFD and re-lists their parents as bytes (the same `resolveUndecodableNames` used for files). A folder whose real name is not valid UTF-8 is `UNREADABLE_FILE` (degraded, `coverage.skipped.unreadable`, one entry per folder, in `discovered`), the same code as `--changed`, which already handled it. No new code: the folder exists but its contents cannot be addressed by an exact path, which is what UNREADABLE_FILE already says.
- Repeat scans: the first scan writes a root `.gitignore` holding `.shipguard/` (`src/core/history/identity.ts` `ensureGitignored(cwd, '.shipguard/')`). A `.gitignore` that contains only ShipGuard's own line(s) is now a self-artifact: counted in the new `coverage.selfArtifacts`, removed from `discovered`, never scanned. Chosen over `ignoredByDefault` because that list is path-pattern based and this test is content based (a user's real `.gitignore` with other lines is still scanned). Done in the shared `readCandidate`, so full and `--changed` agree. Empty folder twice and real-binary-only folder twice give NO_FILES_SCANNED both times.
- NEEDS A DECISION (not changed): ShipGuard writes a `.gitignore` INTO the user's scan root (and creates `.shipguard/repo-id`) as a side effect of a scan. A scan tool modifying the scanned project is surprising. Fix limited to coverage, per the brief.
- M11 note: on Node 24 the B16 guard is blind (console.log's no-op error listener hides EPIPE), so QA's startup-handler test (`tests/commands/stream-error-handlers-at-startup.test.ts`) is what covers the startup EPIPE handlers (mutation M11).
- Full suite 3547 passed, 7 skipped. C0 rerun on code head 703d0093: `docs/testlab/2026-11-02/C0-rerun-703d0093.txt` (84 e2e tests and 3 slow tests pass on the installed tarball).

## After QA re-check (chain 83945016): class-level fixes
- Seen but not entered folders: `readFiles` compares the objectMode directory entries with the folders that have entries under them. A folder with none is re-listed with its own fast-glob run (cwd = that folder), recursively, and its files join the scan; if that listing throws, the folder is `UNREADABLE_FILE` (degraded, counted). No character is special-cased (LF, CR, U+2028/2029 at any depth, and anything else fast-glob's matcher cannot enter). U+FFFD names still go through the bytes re-listing.
- Own artifacts at any depth: any path with a `.shipguard` folder segment, and any `.gitignore` holding only the `.shipguard/` line, counts in `coverage.selfArtifacts` and is never scanned, on both paths (shared `isShipguardArtifactPath`, shared `readCandidate`).
- `--changed` and unreadable folders: `git ls-files --others` exits 0 and prints "could not open directory" on stderr. The untracked listing now captures stderr (private temp file) and each such warning degrades the scan as `UNREADABLE_FILE` with the path.
- Symlinks under `--changed` are `lstat`ed first and reported `SYMLINK_SKIPPED`, like the full scan.
- CI: the host-asset row of `scan-binary-strings.test.ts` (it ran `find /usr` four times) is opt-in with `SHIPGUARD_TEST_HOST_ASSETS=1`; the synthetic jpg/png/pdf zero-false-positive row always runs.
- Behaviour to know: `--changed` follows git's ignore rules (like other changed-file tools: a gitignored file is never listed); the full scan still reads gitignored files.
