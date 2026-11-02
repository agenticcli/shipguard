# Plan: honest scan coverage (BUG 1) + strict JSON pipe fix (BUG 2)

- Branch: `scan-honest-coverage-20261102`, off `agenticcli/shipguard@2bf3a7d` (public repo, npm 0.8.1).
- Stakes: HIGH (a security control inside a release gate that ships to users). Route: plans judged (Opus, max 3 rounds) + one Codex review; build with code review; QA agent adds checks; an agent runs the test plan.
- Status: PLAN ONLY. No code is written by this document. No PR, no tag, no publish (a release is the owner's call).
- Source-line form: `repo@commit:path:line`. `public` = `agenticcli/shipguard`. `archive` = `agenticcli/shipguard-archive`.
  - `public@2bf3a7d` is the base of this branch.
  - `archive@8a55f4e` is the head of `fix-strict-json-truncation-20261101` (PR #71), read as reference only.
- Evidence reused: `agenticcli/agenticcli:docs/testlab/2026-11-01/BOUNDARY-REPORT.md` (called BR below) and the captures under `agenticcli/agenticcli:tests/test-lab/boundary/runs/2026-11-01/`. BR measured cli 0.8.0 at archive `0f66db3`, not this tree; BR section 1 confirms `fs.ts:49` is the same line in public `2bf3a7d`. Every behaviour claim below that rests on BR must be re-proved against this tree by the fail-before step of its test (section B).

---

## 0. What the code does today (verified against `public@2bf3a7d`)

- Classification: `public@2bf3a7d:packages/cli/src/utils/fs.ts:323` and `public@2bf3a7d:packages/cli/src/core/scanner.ts:294` both call `detectBinary()` from `public@2bf3a7d:packages/matcher-contract/src/normalize.ts:217-243`. Any NUL byte anywhere returns true (normalize.ts:222-224); a second rule treats more than 30% control bytes in the first 32 KiB as binary (normalize.ts:226-242). Every UTF-16 file contains NULs, so every UTF-16 file is "binary". Binary files only bump `skippedBinary` (fs.ts:323-330, scanner.ts:294-298). The same gate exists TWICE (normal path and `--changed` path); both must change together.
- Count loss: `public@2bf3a7d:packages/cli/src/commands/scan.ts:752-758` deletes every `_skipped*` and `_truncated` field from the JSON. The counts survive only in the human text (scan.ts:667-673, 811-870). So the JSON never carries discovered, skipped or truncated numbers.
- `filesScanned` is `files.length` (accepted files only) at `public@2bf3a7d:packages/cli/src/core/scanner.ts:536`.
- Zero scanned is never degraded: degraded reasons are built at scanner.ts:467-531 and none fires for an empty `files`. `computeVerdict` (`public@2bf3a7d:packages/cli/src/core/verdict.ts`) then returns SAFE_TO_SHIP for score 0.
- Existing degrade codes: `FILE_TOO_LARGE`, `OUTPUT_TRUNCATED`, `SYMLINK_SKIPPED`, `INVALID_UTF8`, `UNREADABLE_FILE`, `CODEREF_SKIPPED`, `PRO_RULES_UNAVAILABLE`, `COMPILE_FAILURE` (`public@2bf3a7d:packages/shared/src/types.ts:211-219`). Degraded forces `DO_NOT_SHIP` (verdict.ts, `computeVerdict`, first branch). The verdict enum is documented as deliberately closed at 3 values (verdict.ts doc comment: `SAFE_TO_SHIP_INCOMPLETE` / `INDETERMINATE` were rejected as a fail-open trap).
- `--strict` already blocks on `degraded === true` (`public@2bf3a7d:packages/cli/src/commands/scan.ts`, `resolveExitCode`, the `opts.degraded === true` term). So every new degrade code automatically becomes exit 1 under `--strict`, with no change to `resolveExitCode`.
- Drain race: `public@2bf3a7d:packages/cli/src/commands/scan.ts:367` (`return process.exit(exitCode)` in `exitWithError`) and `:989` (`process.exit(exitCode)` after the JSON `console.log` at ~:788-790) discard queued pipe output.

## 1. Decisions (each with its reason and its strongest counterargument)

### D1. Verdict for "nothing was really scanned"
- Choice: set `degraded:true` with a new named code `NO_FILES_SCANNED`; the existing fail-closed rule then yields `DO_NOT_SHIP`. No new verdict value.
- Why: the contract already says degraded implies DO_NOT_SHIP and rejected extra enum values; reusing it keeps one rule in one place (`computeVerdict`) and keeps `recommendation !== 'DO_NOT_SHIP'` parsers safe. `REVIEW_BEFORE_SHIP` was considered and rejected: it would break the documented invariant "degraded implies DO_NOT_SHIP" and let a parser that treats REVIEW as "ok with caution" pass an unread tree.
- Counterargument: DO_NOT_SHIP for an empty or all-image repo reads as an accusation. Mitigation: `degradedReasons[].detail` states plainly "0 files were scanned (N candidates: N skipped, 0 readable)".
- Fires when `filesScanned === 0`, whether discovered was 0 or all candidates were skipped. A tree of only real binaries is therefore degraded by this code alone, not by an "unscanned" code.

### D2. Files that contain NUL bytes but look like text
- Choice: SCAN them, with each NUL byte replaced by one space (U+0020). Do not skip them. Count them in `coverage.scanned.nulSubstituted`. Not degraded, as long as the file passes the text-likeness test below. A NUL-bearing file that does NOT pass is skipped and DEGRADED with code `UNSCANNED_UNKNOWN_BINARY`.
- Text-likeness test (all must hold): no known-binary magic bytes; NUL bytes are at most 1% of the file; after the substitution the bytes decode as strict UTF-8 (`decodeUtf8Strict`); control bytes other than TAB/LF/FF/CR are at most 5% of the first 32 KiB.
- Why scan and not "skip and degrade": the B1 attack is "plant one NUL byte next to a secret". Skip-and-degrade gives `--strict` an exit 1 but a human sees "DO_NOT_SHIP, 0 findings" and no key; scanning finds the key (BR B1 control: the same key in a plain file gives 2 findings). A single-byte substitution keeps every line number and column unchanged, so findings point at the right place. A real secret cannot contain a NUL, so substitution cannot hide one that tooling would use.
- Why not degrade the scanned file too: the file was read in full; no content is missing. Degrading it would put every stray-NUL `.env` into DO_NOT_SHIP and train users to ignore the flag. It is reported (count plus capped file names), so it is not silent.
- Counterargument: a secret split by an embedded NUL could be missed (`AKIA<NUL>IOSF...`). Answer: that string is not a usable AWS key; and a tool that strips NULs before use is the case the fail-closed `UNSCANNED_UNKNOWN_BINARY` path does not cover. Accepted residual, recorded in section D.
- Files that fail the test (NUL-heavy, no magic, no recognised extension) are skipped AND degraded: an unknown blob is the one case where we cannot tell text from binary, so we fail closed. The user clears it by adding the path to `ignore.paths` in `shipguard.policy.yml` (an explicit, visible choice, counted under `ignoredByUser`).

### D3. UTF-16 (LE and BE)
- With a BOM (`FF FE` = LE, `FE FF` = BE): decode and scan, always. `FF FE 00 00` (UTF-32LE) is NOT treated as UTF-16: it falls through to the triage and ends as `UNSCANNED_UNKNOWN_BINARY` (degraded), because decoding it as UTF-16 would be wrong.
- Without a BOM: decode and scan when ALL hold: length is even and at least 4; in the first 32 KiB, for one byte parity the share of NUL bytes is at least 40% of that parity's positions and the other parity has at most 2% NULs (the ASCII-dominant UTF-16 signature: LE has NUL at odd offsets, BE at even offsets); the strict decode succeeds with no lone surrogates; the decoded text has at most 1% U+0000 and at most 5% other control characters.
- Why detect BOM-less at all: PowerShell 5.1 `>` / `Out-File` and Windows tools write UTF-16LE with a BOM, but `iconv -t UTF-16LE`, some editors and some exporters write none. The heuristic is cheap and each guess is validated by a strict decode, so a wrong guess can only fall to the fail-closed path, never to a silent skip.
- Why not guess further: BOM-less UTF-16 that is mostly non-ASCII (CJK) has no NUL signature; guessing it is a coin flip. It falls to D2's rule and ends as `UNSCANNED_UNKNOWN_BINARY` (degraded) unless it carries a known-binary magic. Fail closed, not silent.
- BE is decoded by `Buffer.swap16()` then the same strict `utf-16le` `TextDecoder` (does not depend on a `utf-16be` decoder being present). The strict (`fatal:true`) flag depends on ICU exactly as the existing `decodeUtf8Strict` already does (normalize.ts:116-133); no new platform assumption.
- Findings in a UTF-16 file report line and column in the DECODED text (characters), not byte offsets. `treeDigest` (scanner.ts:`computeTreeDigest`) hashes the decoded, normalized content, as it does for every file today (documented at scanner.ts:~110-125). Both are stated in the CHANGELOG.

### D4. Real binaries
- Skipped, counted under `skipped.binary`, NOT degraded. Identified by magic bytes first, extension second:
  - Magic (checked on the first 16 bytes): PNG `89 50 4E 47`, JPEG `FF D8 FF`, GIF `47 49 46 38`, WEBP (`RIFF....WEBP`), ICO `00 00 01 00`, PDF `25 50 44 46`, ZIP/JAR/DOCX `50 4B 03 04`, GZIP `1F 8B`, BZIP2 `42 5A 68`, XZ `FD 37 7A 58 5A 00`, 7z `37 7A BC AF 27 1C`, TAR (`ustar` at offset 257, needs 262 bytes), ELF `7F 45 4C 46`, Mach-O (`FE ED FA CE/CF`, `CE FA ED FE`, `CF FA ED FE`), PE `4D 5A`, WASM `00 61 73 6D`, SQLite `SQLite format 3`, WOFF `77 4F 46 46`, WOFF2 `77 4F 46 32`, TTF `00 01 00 00`, OTF `4F 54 54 4F`, MP4/MOV (`ftyp` at offset 4), Java class `CA FE BA BE`.
  - Extension (only used when the file is NUL/density-binary AND does not pass the text-likeness test of D2/D3): `.png .jpg .jpeg .gif .webp .ico .pdf .zip .gz .tar .tgz .bz2 .xz .7z .mp4 .mov .mp3 .wav .woff .woff2 .ttf .otf .eot .wasm .node .so .dll .dylib .exe .class .jar .pyc .o .a .bin .dat .db .sqlite .sqlite3`.
- Order inside the classifier (this order is the evasion defence): (1) magic match => binary; (2) BOM / D3 / D2 text tests => scan; (3) known extension => binary; (4) otherwise => `UNSCANNED_UNKNOWN_BINARY`. A text file renamed `secrets.png` is therefore scanned, not skipped.
- Counterargument: the extension list is hand-made and will be incomplete. Answer: an unlisted binary format is not silent and not wrongly "safe": it degrades (step 4) and the user excludes it by path. We prefer a false degrade to a false SAFE in a release gate.

### D5. Default-ignored files (BR I1, I2, I4)
- Today `fs.ts:30-67` drops a fixed list with no signal: directories at the project root (`node_modules`, `dist`, `build`, `.next`, `coverage`, `.git`, `.cache`, `.turbo`, `.venv`, `venv`, `vendor`, `tmp`, `out`), lockfiles, and extensions (`*.log *.min.js *.map` plus media/binary extensions). `scanner.ts:34-42` carries a second, shorter list.
- Choice:
  1. Remove the media/binary EXTENSIONS from the ignore list (`*.png *.jpg *.jpeg *.gif *.webp *.ico *.pdf *.zip *.gz *.tar *.mp4 *.mov *.wasm *.node`). They are now discovered and classified by D4, so a text file named `x.png` is scanned (closes an evasion the ignore list opened) and real images are counted under `skipped.binary`. To avoid reading big images in full and avoid a `FILE_TOO_LARGE` degrade on a 3 MB logo: for a file whose extension is on the D4 list and whose size is over the cap, read only the first 262 bytes; magic match => `skipped.binary`; no magic => `FILE_TOO_LARGE` as today. For such a file at or under the cap, also read 262 bytes first and skip the full read on a magic match.
  2. KEEP ignoring the rest (dependency/build/VCS directories, lockfiles, `*.map`, `*.min.js`, `*.log`, `vendor tmp out .cache .venv venv`), but COUNT them: `coverage.ignoredByDefault` lists each rule that matched with a file count (rules that name a directory report `present:true` without enumerating it, so `node_modules` is never walked). Not degraded.
  3. Do NOT change which paths are scanned beyond item 1. Whether `*.log`, `*.min.js`, `vendor/`, `tmp/`, `out/` should be scanned is a product decision (owner item 12 class, and `*.min.js` over 512 KiB would add `FILE_TOO_LARGE` degrades). Out of scope, listed as OPEN QUESTION Q1.
- Why not degrade: they are documented, deterministic exclusions the user can see in the counts; degrading them would make nearly every real project DO_NOT_SHIP (every repo has a lockfile).
- Counterargument: `*.log` and `vendor/` can hold real secrets or first-party source, so "counted" is weaker than "scanned". Accepted for this branch; it moves silent to visible, and Q1 asks the owner to decide scan vs ignore.

### D6. Limits (BR L1, L3, L4)
- Truncation by `maxFiles` or `maxTotalBytes` stays `degraded:true` with `OUTPUT_TRUNCATED`. Improve the payload: `coverage.truncated` = `{ by: "maxFiles" | "maxTotalBytes", notReached: N }` and the detail text names the cap and N. Today the text names neither (BR section 5).
- `--changed` path uses the same counters (scanner.ts:230-233 is a second copy of the cap check).
- L4 (binary files do not use the file cap, BR 3a): unchanged behaviour by design; now visible because binary is counted.
- Invariant (asserted in tests): `discovered = scanned + sum(skipped.*) + notReached`, where `discovered` counts candidate files after the default/user ignore step.

### D7. Other silent paths
- FIFO / socket / device (BR S4): `fast-glob` `onlyFiles:true` drops them silently. The existing second pass in `fs.ts` (`objectMode`, `onlyFiles:false`, used for symlinks, fs.ts:~218-236) already sees the dirent; also count `dirent.isFIFO() / isSocket() / isCharacterDevice() / isBlockDevice()` as `skipped.special`. NOT degraded: such a node holds no stored content, so nothing readable was missed. Counted, and named (capped at 50 like the others).
- Deleted-mid-scan (BR S10, NOT_MEASURED): the `stat` or `readFile` throws ENOENT, which already lands in the `catch` at fs.ts:~355 and becomes `UNREADABLE_FILE` (degraded). The plan only ADDS a deterministic test (mock the read) to prove it; not a behaviour change.

## 2. The ten silent-drop paths (BR section 3f: L4, B1, B2, B3, B4, I1, I2, I4, S4, O2)

| BR id | What was silent | Disposition | Where |
|---|---|---|---|
| L4 | Binary files do not use the file cap; 6000 files with 2000 NUL files reported 4000 and no code | FIXED (visible): `skipped.binary`/`nul` counts + invariant. Cap behaviour unchanged by design | D6, section A1-A3 |
| B1 | One NUL byte next to a key: `SAFE_TO_SHIP`, 0 findings | FIXED: scanned with NUL to space (D2) | A2 |
| B2 | UTF-16LE with key: skipped | FIXED: decoded and scanned (D3) | A2 |
| B3 | UTF-16BE with key: skipped | FIXED: decoded and scanned (D3) | A2 |
| B4 | 500 binary files, 0 scanned, `SAFE_TO_SHIP` | FIXED: counts + `NO_FILES_SCANNED` (D1); NUL+text ones are now scanned (D2) | A2, A3 |
| I1 | `*.min.js` dropped | DISCLOSED, not changed: counted in `ignoredByDefault`. Scan-vs-ignore is Q1 (product call) | D5 |
| I2 | Root `node_modules/dist/build/vendor/tmp/out`, lockfile, `.map`, `.wasm` dropped | PARTLY FIXED: `.wasm` now classified (D4/D5.1); the rest DISCLOSED by count, scan-vs-ignore is Q1 | D5 |
| I4 | `*.log` dropped | DISCLOSED, not changed; Q1 | D5 |
| S4 | FIFO dropped | DISCLOSED: `skipped.special`, not degraded (D7) | A1 |
| O2 | `--strict --json` stdout cut at 65,536 bytes | FIXED: BUG 2 port (section A5) | A5 |

Also touched, though not among the ten: BR section 5 (OUTPUT_TRUNCATED names neither cap nor count) fixed by D6; BR S10 test-only (D7).
Explicitly out of scope (listed under RISKS in the report, not fixed): `.gitignore` not honoured (BR I5, over-scanning not a drop); no scan timeout (BR O3); nested-ignore asymmetry (BR I3); `.shipguardignore` not implemented (BR I6).

---

## A. Implementation plan, file by file

All paths are in `public` (`agenticcli/shipguard`). Do the work in this order; one commit per step, each with its tests.

### A1. `packages/cli/src/utils/classify.ts` (NEW) - the single classifier
- `classifyFile(buffer: Uint8Array, relativePath: string): ClassifyResult`, a pure function, no I/O. Result is a tagged union:
  - `{ kind: 'text', text: string, encoding: 'utf8' | 'utf16le' | 'utf16be', nulSubstituted: boolean }`
  - `{ kind: 'binary' }` (real binary, D4, not degraded)
  - `{ kind: 'unknown-binary' }` (degraded, D2/D3/D4 step 4)
  - `{ kind: 'invalid-utf8', reason: string }` (existing `INVALID_UTF8` path, so the two read sites stay symmetric)
- `hasBinaryMagic(head: Uint8Array): boolean` and the extension set live here. Constants for the thresholds (1%, 5%, 40%/2%, 32 KiB) are named and exported for tests.
- Reuses `detectBinary`, `decodeUtf8Strict`, `stripBom`, `normalizeNewlines` from `@agenticcli/matcher-contract`. It does NOT modify the matcher-contract (see A9).
- Flow: empty => text; BOM check (utf8 strips later; FF FE not followed by 00 00 => utf16le; FE FF => utf16be); magic => binary; if `detectBinary` is false => strict UTF-8 as today; else triage in D4 order using D3 then D2 then extension.
- Result text for every `text` kind goes through `stripBom` then `normalizeNewlines` exactly as Gate 5 does now.

### A2. `packages/cli/src/utils/fs.ts` and `packages/cli/src/core/scanner.ts` - use the classifier in both read paths
- `fs.ts:323-343` (Gates 3-5 in `readFiles`) and `scanner.ts:294-312` (the `--changed` copy) are replaced by one call to `classifyFile`. Both paths then fill the same counters, so they cannot drift again.
- `ReadFilesResult` (fs.ts:~76-160) gains: `skippedUnknownBinary: string[]` (capped names plus a true count), `skippedSpecial` (count and capped names), `nulSubstitutedFiles` (count and capped names), `utf16Decoded` (count), `notReached` (number), `truncatedBy?: 'maxFiles' | 'maxTotalBytes'`, `discovered` (number), `ignoredByDefault: Array<{ pattern: string; files?: number; present?: boolean }>`, `ignoredByUser` (count).
- Head-read short-cut for D5.1 (known-binary extension files): open, read the first 262 bytes, magic match => binary without a full read.
- `DEFAULT_IGNORE` (fs.ts:30-67): remove the 14 media/binary extension entries named in D5.1. Keep everything else. Add the `ignoredByDefault` counting pass: positive patterns are the remaining ignore entries that are NOT directory rules, with the directory rules excluded from the walk (`ignore`) so `node_modules` is not traversed; directory rules are reported with `present:true` after a single `stat`.
- `scanner.ts:34-42` (the short list) is left as is (a subset of the fs.ts list).
- Caps (fs.ts:293, scanner.ts:230): record `truncatedBy` and `notReached = total - processed` at the break.

### A3. `packages/cli/src/core/scanner.ts` - the degrade codes and the coverage object
- New degrade reasons next to scanner.ts:467-531, same style as `INVALID_UTF8`:
  - `UNSCANNED_UNKNOWN_BINARY` (one entry, detail names up to 10 files and the count; says how to exclude them via `ignore.paths`).
  - `NO_FILES_SCANNED` when `files.length === 0`, evaluated last; detail "0 files scanned: N discovered, X binary, Y too large, ...".
  - `OUTPUT_TRUNCATED` detail rewritten to name `truncatedBy` and `notReached`.
- New `ScanResultWithMeta` public field `coverage` (assembled here, replacing the `_skipped*` private fields):

```
coverage: {
  discovered: number,            // candidates after ignore rules
  scanned: number,               // == filesScanned
  skipped: {
    binary: number,              // real binaries (not degraded)
    tooLarge: number,            // degraded FILE_TOO_LARGE
    symlink: number,             // degraded SYMLINK_SKIPPED
    unknownBinary: number,       // degraded UNSCANNED_UNKNOWN_BINARY
    invalidUtf8: number,         // degraded INVALID_UTF8
    unreadable: number,          // degraded UNREADABLE_FILE
    special: number              // FIFO/socket/device (not degraded)
  },
  decoded: { utf16: number, nulSubstituted: number },
  truncated: false | { by: 'maxFiles' | 'maxTotalBytes', notReached: number },
  ignoredByDefault: Array<{ pattern: string, files?: number, present?: boolean }>,
  ignoredByUser: number,
  files: { binary: string[], tooLarge: string[], symlink: string[], unknownBinary: string[], special: string[], nulSubstituted: string[] }  // each capped at 50 names, sorted
}
```
- Why a nested object and not many top-level keys: one new top-level key (`coverage`) is the whole additive change for consumers; the freeze test allow-list (A6) gains one entry.
- `filesScanned` keeps today's meaning (accepted files).
- Counts exclude nothing: `discovered = scanned + sum(skipped.*) + notReached` (invariant, asserted).
- Paths in `coverage.files` are project-relative, as `skippedTooLargeFiles` already are. The telemetry payload is NOT extended (it must never carry paths or counts beyond today's fields; `public@2bf3a7d:packages/cli/src/commands/scan.ts` telemetry block).

### A4. `packages/shared/src/types.ts`, `packages/cli/src/commands/schema.ts`, `packages/cli/src/commands/scan.ts`
- `shared/src/types.ts:211-219`: add `'UNSCANNED_UNKNOWN_BINARY' | 'NO_FILES_SCANNED'` to `DegradeCode`; document them in the comment block above; add `coverage?: ScanCoverage` to `ScanResult` with the type above.
- `commands/schema.ts`: `CURRENT_SCHEMA_VERSION` `'5'` to `'6'` (additive field; precedent: 4 to 5 for additive receipt fields, per the note at `public@2bf3a7d:packages/cli/src/commands/scan.ts:~672-676`); add the two codes and `SYMLINK_SKIPPED` (currently missing from `degradeCodes`, BR section 7) to `degradeCodes`; rewrite `unanalyzableTypes` (the `binary` entry says "Deliberately no degrade signal"; update to "counted in coverage.skipped.binary, no degrade, except when nothing at all was scanned"); add `utf16`, `nul-in-text`, `unknown-binary`, `special` entries.
- `commands/scan.ts`:
  - 667-673 and 752-758: stop deleting the counts. Build `publicResult` WITHOUT the underscore fields but WITH `coverage`. The private `_skipped*` fields are removed from `ScanResultWithMeta` (single source: `coverage`), so there is nothing left to delete.
  - `result.schemaVersion = '6'` (scan.ts:~679).
  - Human output (scan.ts:811-870 and the verdict panel call at :893): one line "Coverage: scanned X of Y files; skipped: binary a, too large b, symlink c, unknown d; decoded: utf16 e; NUL-substituted f" printed before the panel on EVERY run (not only when something was skipped); the binary line stays info level but now always prints the count; add named warnings for `UNSCANNED_UNKNOWN_BINARY`, `NO_FILES_SCANNED` and the improved truncation text. `verdictPanel(..., skippedCount, ...)` (render.ts:469) receives the total of skipped.* as it does now; `quietVerdict` (render.ts:707) is unchanged except the existing degraded wording already covers the new codes.
  - Exit-code section: `resolveExitCode` is NOT changed. Exact `--strict` behaviour for the new cases, to be pinned by tests:
    - `NO_FILES_SCANNED`, `UNSCANNED_UNKNOWN_BINARY`, `OUTPUT_TRUNCATED`, `FILE_TOO_LARGE`, `SYMLINK_SKIPPED` (all `degraded:true`) => `--strict` exit 1; without `--strict` exit 0.
    - `skipped.binary`, `skipped.special`, `decoded.utf16`, `decoded.nulSubstituted`, `ignoredByDefault` (not degraded) => never change the exit code.
    - Findings from a newly scanned UTF-16/NUL file count like any finding (blocking finding => exit 1 under `--strict`).
    - Exit 2 and 3 untouched.
  - Update the `Exit codes` help text in scan.ts (the `1  Blocked` bullet) and the doc comment at scan.ts:50-122 to list the new degraded cases.
  - `--sarif`: `toSarif(publicResult)` (scan.ts:~786) is unchanged; confirm in a test that `coverage` does not leak into SARIF.

### A5. BUG 2 port: `packages/cli/src/utils/exit.ts` (NEW) and `packages/cli/src/commands/scan.ts`
- Source of truth to re-implement: `archive@8a55f4e:packages/cli/src/utils/exit.ts:1-37` (function `exitAfterFlush`: set `process.exitCode`, drain stdout and stderr with an empty write plus a 10 s unref'd timer, then `process.exit(code)`), and the two call sites `archive@8a55f4e:packages/cli/src/commands/scan.ts:370` (`return exitAfterFlush(exitCode)`) and `:993` (`await exitAfterFlush(exitCode)`), plus the import at `:27`.
- Write `exit.ts` fresh in the public tree (do not cherry-pick: histories differ; `git merge-base` between the two repos does not exist). Differences to respect: the archive `scan.ts` has `runScan(ctx)` and a `checkScanPath` split; the public `scan.ts` keeps the whole action inline. Therefore the two edits in public are `scan.ts:367` (`return process.exit(exitCode)` becomes `return exitAfterFlush(exitCode)`) and `scan.ts:989` (`process.exit(exitCode)` becomes `await exitAfterFlush(exitCode)`), plus one import line. Re-read both functions end to end before editing.
- Keep the catch in `drain()` logging at debug level (the archive version swallows with a comment only; the repo rule is "every catch logs"): `logger.debug('exit: stream already closed ...')`. The timeout fallback also logs a debug line.
- Out of scope, listed under RISKS: `src/cli.ts:190,206,210,214` and `src/handlers.ts:27,38,44` also call `process.exit` directly; they print short messages (no large payload), so they cannot truncate a scan JSON. Not changed.

### A6. Tests, docs and metadata
- Tests: section B. Existing tests to UPDATE (they pin today's silent behaviour): `tests/commands/scan-json-schema-freeze.test.ts` (schemaVersion `'6'`, `coverage` in the optional allow-list as required, `_skipped*` still must not leak), `tests/commands/scan-degraded-on-skip.test.ts` and `tests/commands/scan-bounds.test.ts` (binary-skip expectations), `tests/commands/schema-contract.test.ts` (new codes, version), `tests/utils/fs.test.ts` and `tests/utils/fs-bounds.test.ts` (ReadFilesResult shape; the removed extension ignores).
- `packages/cli/CHANGELOG.md`: add an "Unreleased" entry in the file's plain style (what changes for users: UTF-16 and NUL files scanned; scans that read nothing are no longer SAFE; JSON gains `coverage`, schemaVersion 6; `--strict --json` output no longer cut). NO version bump in `package.json`, NO tag (owner's call).
- `packages/cli/README.md`, `packages/cli/docs/llms.txt`, `packages/cli/docs/placement-kit.md`: grep for "binary", "skipped", "schemaVersion", "degraded" and update the lines that describe skipping. `packages/cli/scripts/gen-cli-facts.mjs` output must stay consistent (release-gate G2b).
- `docs/progress/scan-honest-coverage-20261102.md`: the progress entry, last commit (per the agent rules).

### A7. `scripts/release-gate.sh` G8 (shipped-tree self-scan, line ~198)
- No edit planned. Check only: the shipped tree must still scan `--strict` exit 0 (no NUL file, no unknown binary, no empty scan). If the packed tree contains any binary-looking file without magic or listed extension, G8 would now fail; fix the file or the list, not the gate.

### A8. What is NOT edited
- `packages/matcher-contract/**`: unchanged. See A9.
- `resolveExitCode`, `computeVerdict`, `applyVerdict`: unchanged.
- `packages/cli/package.json` version, any workflow, any tag.

### A9. Requirement 7: matcher-contract byte-identity
- Checked. In THIS repo `packages/matcher-contract/src/normalize.ts` is a normal source file; there is no copy-sync script or CI byte-compare. The only external copy is a packed tarball vendored by the platform repo: `agenticcli/agenticcli:apps/web/package.json:34` points at `vendor/agenticcli-matcher-contract-0.5.1.tgz`, and the platform imports only `selector` and `canonical` (`apps/web/convex/serving.ts:37`, `apps/web/lib/storedBundleVerify.ts:31`), never `normalize`. `public@2bf3a7d:packages/matcher-contract/package.json` is `0.5.1`.
- It already differs from the archive copy in comments only (`diff` of `normalize.ts` public vs archive `32b9962`: 5 comment lines), so byte-identity of `normalize.ts` is not an enforced property today.
- Decision: do NOT touch matcher-contract at all. All new logic is CLI-side (`classify.ts`); `detectBinary` and `decodeUtf8Strict` are called as they are. This keeps the 0.5.1 tarball, the `re2js-v1` freeze test and the conformance vectors untouched, and meets requirement 7 trivially. A test (B9) asserts `git diff --stat origin/main -- packages/matcher-contract` is empty on the branch.
- If a reviewer insists the contract's `detectBinary` should itself change: that is a contract version bump (0.5.2), a re-vendored tarball in the platform repo, and a conformance-vector update. Rejected for this branch.

---

## B. TEST PLAN (checks before merge)

Layout: Vitest under `packages/cli/tests/<domain>/`, existing conventions: unit tests in-process, e2e tests spawn `dist/cli.js` through `tests/helpers/spawn-cli.ts` with `vi.setConfig({ testTimeout: 30_000 })`. Each new test below is FAIL-BEFORE (run on the unmodified `origin/main` build, record the failure text) and PASS-AFTER. The agent running the plan records both runs in `docs/progress/scan-honest-coverage-20261102.md`. Telemetry is already forced off by `tests/setup/no-telemetry.ts`.

Fixture rule: planted secrets are the public example values already used in this suite (`AKIAIOSFODNN7EXAMPLE`, the `-----BEGIN RSA PRIVATE KEY-----` marker). No real secrets.

| # | File | What it proves | Fail-before (expected on `2bf3a7d`) |
|---|---|---|---|
| B1 | `tests/utils/classify.test.ts` (new, unit) | Table of buffers => result kind: empty; ASCII; UTF-8+BOM; UTF-16LE+BOM; UTF-16BE+BOM; BOM-less LE and BE ASCII text; BOM-less LE of random bytes (must NOT be text); UTF-32LE BOM => unknown-binary; one NUL in a 10 KB text; 2% NULs => unknown-binary; PNG/ZIP/ELF/WASM/PDF magic => binary; text content with `.png` name => text; PNG magic with `.js` name => binary; lone surrogate in UTF-16 => not text; odd length UTF-16 => not text; invalid UTF-8 => invalid-utf8. Also: NUL substitution keeps byte length, line count and column of a later match | Module missing: test file fails to import |
| B2 | `tests/commands/scan-nul-utf16-coverage.test.ts` (new, e2e) | Fixtures (BR B1, B2, B3): (a) key + one NUL byte; (b) UTF-16LE with BOM; (c) UTF-16BE with BOM; (d) UTF-16LE no BOM; (e) UTF-16BE no BOM. Each: the planted key is FOUND (>=1 finding with the right `file` and a line number equal to the line in the decoded text), `filesScanned` 1, `coverage.scanned` 1, `coverage.decoded.utf16` or `.nulSubstituted` 1, exit 0 without and with `--strict` per its findings (blocking finding => `--strict` exit 1) | `SAFE_TO_SHIP`, 0 findings, `filesScanned` 0 (BR B1-B3) |
| B3 | same file | UTF-16 non-ASCII BOM-less (CJK text) => skipped, `degraded:true`, code `UNSCANNED_UNKNOWN_BINARY`, `recommendation` `DO_NOT_SHIP`, `--strict` exit 1, no-strict exit 0 | `degraded:false`, SAFE |
| B4 | `tests/commands/scan-all-binary-tree.test.ts` (new, e2e) | BR B4: tree of 500 files each with a NUL and no magic and no known extension (unknown binary): 0 scanned, `degraded:true`, codes include `NO_FILES_SCANNED` and `UNSCANNED_UNKNOWN_BINARY`, never `SAFE_TO_SHIP`, `coverage.discovered` 500, `coverage.skipped.unknownBinary` 500, invariant holds, `--strict` exit 1 | 0 scanned, `SAFE_TO_SHIP`, `degraded:false` |
| B5 | same file | REAL-binary-only tree: fixtures with real magic bytes (a valid 1x1 PNG, a ZIP, a gzip stream, an ELF header, a WOFF2 header; all tiny, generated in the test from literal bytes), `package.json` NOT present (use `--all`): `coverage.skipped.binary` = N, `scanned` 0, `degraded:true` with ONLY `NO_FILES_SCANNED` (no unknown-binary code), `DO_NOT_SHIP`. Companion: the same tree plus one clean `.js` => `degraded` absent/false, `SAFE_TO_SHIP`, `skipped.binary` = N, `--strict` exit 0 (real binaries alone never degrade) | scanned 0, `SAFE_TO_SHIP` |
| B6 | same file | Empty directory with `--all` and a dir with only ignored files: `NO_FILES_SCANNED`, DO_NOT_SHIP. `--changed` in a git repo with zero changed files: `NO_FILES_SCANNED` too (see Q2). Exit code stays 0 without `--strict` | SAFE |
| B7 | `tests/commands/scan-coverage-json.test.ts` (new, e2e) | JSON always has `coverage` (also on a normal clean scan) with the invariant `discovered = scanned + sum(skipped) + notReached`; `schemaVersion` `'6'`; no `_skipped*`/`_truncated` keys; `coverage.files` names are sorted, capped at 50, project-relative; SARIF output has no `coverage`; human output prints the Coverage line on a clean scan and names each skip category; `--quiet` output unchanged apart from existing wording | `coverage` absent |
| B8 | `tests/utils/fs-bounds.test.ts` (extend) + `tests/commands/scan-bounds.test.ts` (extend) | Limit truncation: set low `limits.maxFiles` via policy (e.g. 10 with 25 files) => `degraded:true`, `OUTPUT_TRUNCATED`, `coverage.truncated = { by: 'maxFiles', notReached: 15 }`, detail names the cap; same for `maxTotalBytes`; exactly-at-cap (10 of 10) NOT truncated; `--changed` path has the same behaviour; a `maxFileSizeBytes` over-cap file => `FILE_TOO_LARGE` and `skipped.tooLarge` 1; 6000-file-style mixed tree scaled down (60 files, 20 NUL-unknown) proves binary does not use the file cap and is counted (BR L4) | no `coverage`, truncation detail without cap/count |
| B9 | `tests/commands/matcher-contract-untouched.test.ts` (new) | `git diff --name-only origin/main -- packages/matcher-contract` is empty (skipped outside a git checkout with `origin/main`), and `matcher-contract` `normalize` test file still passes | n/a (guard test; fails only if someone edits the contract) |
| B10 | `tests/commands/scan-default-ignore-coverage.test.ts` (new, e2e) | BR I1/I2/I4: tree with `x.min.js`, `debug.log`, root `vendor/a.js`, `package-lock.json`, `y.map` => `ignoredByDefault` lists each matching rule with counts, `node_modules` reported `present:true` and NOT walked (a 10,000-file `node_modules` fixture does not slow the scan: assert wall time < 5 s); not degraded. Media-extension change: a text file named `secret.png` containing the key => FOUND; a real PNG named `logo.png` => `skipped.binary` 1; a >512 KiB real-magic `big.png` => `skipped.binary`, NOT `FILE_TOO_LARGE`; a >512 KiB text file named `big.png` (no magic) => `FILE_TOO_LARGE` | all silently dropped; `secret.png` not found |
| B11 | `tests/utils/fs-special-files.test.ts` (new; skip on win32) | BR S4: a FIFO (`mkfifo` via `child_process`) => `skipped.special` 1, no hang (wall < 5 s), not degraded. S10 test-only: mock `readFile` to throw ENOENT for one file => `UNREADABLE_FILE`, `degraded:true` | FIFO silent: no count |
| B12 | `tests/commands/strict-json-pipe-truncation.test.ts` (new, e2e, Linux only: reads `/proc`) | BUG 2, fast lane. Re-implement the archive test's design (`archive@8a55f4e:packages/cli/tests/commands/strict-json-pipe-truncation.test.ts`): 25 files with the three example secrets so the JSON is above one pipe buffer (65,536 B); the child's stdout goes into a kernel pipe whose reader does not start until the child has reached its exit point (gate file + CPU-idle poll), so the reader cannot win the race. Asserts: `--strict` exit 1; stdout is valid JSON; same `findings.length` as the non-strict run; precondition: payload > 65,536 B | stdout cut (65,536 B class), `JSON.parse` throws |
| B13 | `tests/slow/strict-json-5mb.slow.test.ts` (new, slow lane, run with `VITEST_SLOW=1 pnpm --filter @agenticcli/shipguard test:slow`) | BUG 2 at scale (BR O1/O2): 3000 files x 2 findings => about 5.1 MB JSON (BR measured 5,157,758 B). Pipe-gated reader as in B12. Asserts stdout > 5,000,000 B, valid JSON, `findings.length` equals the non-strict run, exit 1. Also `--json --strict --quiet`-free variant and a `--sarif --strict` variant of the same fixture (SARIF goes through the same `console.log` then exit) | stdout cut at 65,536 or 69,632 B (BR O2, BUG 2 lab note), invalid JSON |
| B14 | `tests/utils/exit.test.ts` (new, unit) | `exitAfterFlush` sets `process.exitCode` before waiting, resolves after a stream's empty-write callback, does not hang on a destroyed stream (logs at debug), and gives up after the timeout (fake timers) | module missing |
| B15 | existing suites | `pnpm run build && pnpm run lint && pnpm test` (matcher-contract + cli) all green; `tests/slow` green; `scripts/release-gate.sh` in dry run (`RELEASE_GATE_DRY_RUN=1`) green incl. G8 | n/a |

Run discipline (from the repo rules): build `dist/` before any e2e test (`pnpm run build`), run the e2e files one at a time on this shared box, and keep aggregate CPU under the caps in the session rules. B13 is the heaviest (about 15 s per spawn in BR).

Fail-before protocol: on a clean checkout of `origin/main` build `dist`, run B2-B13 against it and keep the failing output in the progress entry. Then run on the branch. A test that cannot fail on the old code is rejected in code review.

A mutation check by the QA agent: revert one piece at a time (NUL substitution, BOM-less detection, `NO_FILES_SCANNED`, `exitAfterFlush`) and confirm exactly the matching tests go red.

## C. VERIFICATION PLAN (checks after release, on the built npm tarball)

Run only after the owner publishes. Nothing here publishes or tags anything.

1. Fetch the exact tarball from the registry: `npm pack @agenticcli/shipguard@<released version>` into a new empty temp dir (treat as untrusted data). Record the sha512 `integrity` from `npm view @agenticcli/shipguard@<version> dist.integrity` and confirm it equals the packed file; confirm provenance with `npm audit signatures` on the install. (Pre-release rehearsal: `pnpm --filter @agenticcli/shipguard build:publish && npm pack` in `packages/cli`, same steps against the local `.tgz`.)
2. Install into a second empty temp dir: `npm install --ignore-scripts ./shipguard-*.tgz`; run `npx shipguard --version` and compare to the tarball's `package.json`.
3. With `SHIPGUARD_TELEMETRY=0`, run the installed binary (not the repo build) against generated fixtures (reuse the generators in `agenticcli/agenticcli:tests/test-lab/boundary/lib` and `bin`, outputs to a new dir):
   - NUL + key; UTF-16LE+BOM; UTF-16BE+BOM; UTF-16LE no BOM (BR B1-B3): key found, not SAFE.
   - 500 NUL-unknown files (BR B4): `degraded:true`, `NO_FILES_SCANNED`, DO_NOT_SHIP.
   - Real-binary-only tree: DO_NOT_SHIP with `NO_FILES_SCANNED` only; the same plus one clean file: SAFE with `skipped.binary` > 0.
   - 5001 files and the 520 x 512 KiB total-bytes case is slow (BR: 20 min): run only 5001 files; assert `coverage.truncated.by === 'maxFiles'`, `notReached: 1`.
   - 3000 files x 2 findings: `scan --json --strict | wc -c` > 5,000,000 and `| node -e 'JSON.parse(...)'` succeeds, exit code via `PIPESTATUS`, repeated 5 times (the cut point moved between runs in the lab).
   - Each JSON has `schemaVersion` `'6'`, `coverage` with the invariant, and `cliVersion` equal to the installed version.
   - `shipguard schema --json` lists `NO_FILES_SCANNED` and `UNSCANNED_UNKNOWN_BINARY`.
4. Exit codes on the installed binary: no flag 0 for every degraded fixture; `--strict` 1 for the degraded ones and for a blocking-finding fixture; 0 for the clean + real-binary fixture; 2 for a missing path; 3 for the 10,000-deep tree (BR S7, unchanged).
5. Regression sweep: re-run the BR "works" rows (B6 BOM-8, B7 CRLF, B8 zero-byte, B9 UTF-8, S8 long path) and confirm results unchanged.
6. Hook check: `shipguard hook` installs the gate; on a temp git repo with one clean file the hook passes; on an all-binary repo it blocks (documented behaviour change).
7. Record command, output size and exit code for each (no secret values; the fixture keys are public examples). Failure of any check = tell the owner and recommend deprecating the version; no automatic action.

## D. Counterarguments and risks

- More degraded results for users. Cases that turn non-safe: empty or media-only repos (`NO_FILES_SCANNED`); NUL-heavy unknown files (`UNSCANNED_UNKNOWN_BINARY`). Installed hooks run `shipguard scan --json --strict` (`public@2bf3a7d:packages/cli/src/core/hook-templates.ts:30`), so a repo containing, say, a `.bin` blob not on the extension list would now be blocked at the merge boundary until the user excludes the path. This is the intended fail-closed behaviour, but it is user-visible: the CHANGELOG and the error text must say how to fix it (`ignore.paths`).
  - Mitigation: the known-extension list in D4 covers common cases; the detail text names the files.
- A repo with no text files at all (rare for code) gets DO_NOT_SHIP. Intended (brief item 5).
- JSON consumers see a new top-level `coverage` object and `schemaVersion` `'6'`. Strict-schema consumers or those pinning `'5'` can break; the freeze test and CHANGELOG state it. Alternative rejected: keep `'5'` and add the field (the bump is the repo's own documented evolution procedure, `scan-json-schema-freeze.test.ts` header).
- Two new `degradedReasons` codes; the contract says consumers must tolerate unknown codes, but a consumer that hard-fails on unknown codes will break.
- NUL substitution is a heuristic. Residual: a secret deliberately split by NUL bytes inside a file that passes the text-likeness test could be missed. Defence: the thresholds (1% NUL, 5% control) keep obfuscation-heavy files on the fail-closed path.
- BOM-less UTF-16 detection can misclassify; every guess is validated by strict decode, and failures fall to degraded, never silent.
- Removing media extensions from the default ignore list adds reads: a repo with many large images pays the 262-byte head read each; images over 512 KiB without a magic match now become `FILE_TOO_LARGE` instead of being ignored. Mitigated by magic-first.
- `ignoredByDefault` counting adds one more glob pass; bounded by excluding directory rules from the walk. B10 pins the cost.
- UTF-16 findings carry character offsets, and `treeDigest` for such a file hashes the decoded text (not raw bytes), so two byte-different encodings of the same text digest alike. Documented.
- The 5 MB pipe tests are slow (about 15 s per spawn in the lab); they live in the slow lane and the release gate, not the default CI run. The default CI run keeps B12 (above 64 KiB). Risk: a regression between 64 KiB and 5 MB is only caught by the slow lane; the release gate must run it (G8 area) and the QA agent runs it before merge.
- Graceful exit adds up to 10 s to a `--strict` run if the reader never reads (timer backstop). Accepted: a gate that hangs on a stuck reader is better than silently truncated JSON.
- Lab numbers (BR) were taken at archive `0f66db3` / cli 0.8.0; this tree is `2bf3a7d` / 0.8.1. Treated as hypotheses until the fail-before runs.
- Not in scope (tracked, not fixed): `.gitignore` not honoured (BR I5); no scan timeout (BR O3); nested ignore asymmetry (BR I3); `.shipguardignore` missing (BR I6); `src/cli.ts` and `src/handlers.ts` direct `process.exit` calls (short output only); `--pro` untested in the lab (BR O10).

## E. Open questions (not settled from the code)

- Q1. Should `*.log`, `*.min.js`, `vendor/`, `tmp/`, `out/` stay ignored (this plan: yes, counted)? Scanning them is a product and performance decision (min.js often exceeds the 512 KiB cap and would add `FILE_TOO_LARGE` degrades). Owner call.
- Q2. `--changed` with zero changed files: this plan applies the brief literally (`NO_FILES_SCANNED`, DO_NOT_SHIP, `--strict` exit 1). `--changed` is not used by the installed hook (`--json --strict` only), but a CI user running `--changed --strict` on an empty diff would be blocked. Alternative: exempt the git-confirmed zero-diff case. Needs a decision before build.
- Q3. Schema version bump to `'6'` vs additive-only `'5'`: this plan bumps (repo precedent). Confirm.
- Q4. Extension list in D4: confirm it, or accept it as a living list.

## Main-session decisions (2026-11-02; the owner delegated these calls)
- Q1: `*.log`, `*.min.js`, `vendor/`, `tmp/` and `out/` stay ignored by default. They are counted in `coverage` under an `ignored` reason, never silently. Reason: scanners commonly default-ignore these paths, and the counts make the ignore visible.
- Q2: `--changed` with a git-confirmed empty diff is EXEMPT from `NO_FILES_SCANNED` and is not degraded. Reason: commit hooks on doc-only or empty commits must not block. A non-empty diff where every path is skipped or binary still degrades. Add tests for both sides.
- Q3: bump schemaVersion 5 to 6. Reason: the verdict semantics change, even though the new fields are additive.
- Q4: the known-binary list is accepted as drafted, subject to the plan judge. It must be identified by magic bytes, never by extension alone.
