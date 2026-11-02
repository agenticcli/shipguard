# Plan: honest scan coverage (BUG 1) + strict JSON pipe fix (BUG 2)

- Branch: `scan-honest-coverage-20261102`, off `agenticcli/shipguard@2bf3a7d` (public repo, npm 0.8.1).
- Stakes: HIGH (a security control inside a release gate that ships to users). Route: plans judged (Opus, max 3 rounds) + one Codex review; build with code review; QA agent adds checks; an agent runs the test plan.
- Revision: ROUND 3, the last (after NO-GO in rounds 1 and 2 from the Opus judge and Codex). Section R maps round-2 decisions; section R3 maps every round-2 finding to where it now sits. Round-3 text overrides round-2 text where they differ.
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
- Where it sits in the classifier (see A1 for the full order): only reached for a file that `detectBinary` already flags, only AFTER a BOM check and the validated UTF-16 test of D3 have failed, and only AFTER the real-binary test of D4 has said "not a real binary".
- Choice: SCAN it, each NUL byte replaced by one space (U+0020). Count it under `coverage.decoded.nulSubstituted`. Not degraded when it passes the test below. Fails the test => skipped AND degraded with `UNSCANNED_UNKNOWN_BINARY`.
- Text-likeness test (all must hold): NUL bytes are at most 1% of the file; after substitution the bytes decode as strict UTF-8 (`decodeUtf8Strict`); control bytes other than TAB/LF/FF/CR are at most 5% of the first 32 KiB.
- Why UTF-16 is tried first (round-2 fix): a UTF-16LE file of 10,000 CJK characters followed by an AWS key has almost no NULs in the ASCII-parity pattern, yet its NUL share can pass the 1% test; substituting NULs would turn the key into letters separated by spaces and hide it. So any validated UTF-16 candidate is decoded as UTF-16 first (D3); NUL-to-space is only for what is left.
- Why scan and not "skip and degrade": the B1 attack is "plant one NUL byte next to a secret". Skip-and-degrade gives `--strict` an exit 1 but a human sees "DO_NOT_SHIP, 0 findings" and no key; scanning finds the key (BR B1 control: the same key in a plain file gives 2 findings). A single-byte substitution keeps every line number and column unchanged.
- Why not degrade the scanned file too: the file was read in full; no content is missing. Degrading every stray-NUL `.env` would train users to ignore the flag. It is reported (count plus capped file names), so it is not silent.
- Residual miss (documented, tested as test B17, see D): a secret split by an embedded NUL (`AKIA<NUL>IOSF...`) is not matched after substitution. That string is not a usable key for tooling that does not strip NULs; a tool that does strip them is the accepted residual.
- Files that fail the test are skipped AND degraded. This includes every NUL-heavy blob with no real-binary evidence (`creds.bin`, `dump.dat` with 2% NUL padding): file NAME and EXTENSION are never used to decide (see D4). The user clears a legitimate unknown blob by adding its path to `ignore.paths` (explicit and counted under `ignoredByUser`).

### D3. UTF-16 (LE and BE)
- Applies only to a file `detectBinary` flagged (it contains NULs or is control-dense). A file with no NUL and low control density never reaches this step: it goes straight to strict UTF-8 and a failed decode is degraded (`INVALID_UTF8`), exactly as today.
- BOM present (`FF FE` = LE, `FE FF` = BE): decode as UTF-16 and scan. `FF FE 00 00` (UTF-32LE) is not UTF-16; it continues to the later steps and ends as `UNSCANNED_UNKNOWN_BINARY`. A BOM-marked file whose decode FAILS (lone surrogate, or odd byte length) is NOT retried as anything else: it is skipped and degraded (`INVALID_UTF8`, detail says "UTF-16 with BOM, invalid").
- No BOM: a UTF-16 candidate (LE, and BE) is PLAUSIBLE only after a CONFIRMED strict decode of the WHOLE buffer (even length, no lone surrogates) AND a plausibility test on the decoded text (at most 1% U+0000, at most 5% other control characters, and at least 80% of code units inside a named list of text blocks: U+0009-000D, U+0020-007E, U+00A0-024F, U+0370-1FFF, U+2000-206F, U+3000-9FFF, U+AC00-D7AF, U+FF00-FFEF; uniformly random bytes land near 55% so they fail).
  - Endianness (round 3: no guessing, scan every plausible reading): each of LE and BE is tested independently with the plausibility test above (BE through `Buffer.swap16()` then the `utf-16le` decoder). The NUL-parity signature (one parity at least 40% NULs, the other at most 2%) is used only to REJECT the opposite endianness when it is clear-cut (ASCII text read the wrong way round becomes CJK-looking garbage that would otherwise pass).
  - Ambiguity rule (round 3, main decision 5): when MORE THAN ONE reading is plausible among {UTF-8 with NUL-to-space (D2), UTF-16LE, UTF-16BE}, the scanner scans EVERY plausible reading and UNIONS the findings, de-duplicated by rule id + file + line. Implementation: `classifyFile` returns a list of readings (`texts: Array<{ encoding, text, nulSubstituted }>`, length 1 in the normal case); the scanner builds one `FileInfo` per reading (same `relativePath`), runs all checks on each, and the existing final de-duplication (`collapseSameIssueFindings` plus a rule+file+line key) removes duplicates. `filesScanned` and `coverage.scanned` count the PATH once; `coverage.decoded.multiReading` counts such files; `treeDigest` includes each reading's digest line (sorted). A file with no plausible reading is `unknown-binary` (degraded).
  - Codex cases (test rows B1, B2, matrix): ASCII `a` x 1000 + `\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n` + one NUL (LE-plausible AND UTF-8-plausible; the UTF-8 reading finds the key); BOM-less BE `汉` x 10,000 + key (LE reading is junk, BE reading finds the key).
- Order guarantee superseded by the ambiguity rule above: no reading wins over another; all plausible readings are scanned (the round-2 order rule is kept only for the BOM case, where the BOM makes the reading certain). The 10,000 `汉` + key (UTF-16LE) case stays a test row in B2 and the matrix.
- The strict flag depends on ICU exactly as the existing `decodeUtf8Strict` already does (normalize.ts:116-133); no new platform assumption.
- Columns and offsets: findings in a UTF-16 file are reported in the DECODED text, counted in UTF-16 code units (JavaScript string indices; this is already how every file's columns are counted today). `treeDigest` hashes the decoded, normalized content as for every file (scanner.ts `computeTreeDigest`). NUL-bearing and UTF-16 files that used to be unread now enter the digest, so `treeDigest` for such trees changes between 0.8.1 and this version: stated in the CHANGELOG.

### D4. Real binaries (round 2: content only, never the extension)
- The rule: magic bytes count ONLY for a file that `detectBinary` already flags, and only when the file is also binary-dominant. A real binary is skipped, counted under `skipped.binary`, NOT degraded.
  - Gate 1: `detectBinary` true (a NUL anywhere, or more than 30% control bytes in the first 32 KiB). A file with no NULs and low control density NEVER consults magic: it goes to strict UTF-8; a failed decode is degraded. So a `.env` that begins `MZ=1\nAWS_ACCESS_KEY_ID=...` (PE magic) is scanned as text; a text file with `ustar` at offset 257 is scanned as text.
  - Gate 2: magic match on the head. List: PNG `89 50 4E 47`, JPEG `FF D8 FF`, GIF `47 49 46 38`, WEBP (`RIFF....WEBP`), ICO `00 00 01 00`, PDF `25 50 44 46`, ZIP/JAR/DOCX `50 4B 03 04`, GZIP `1F 8B`, BZIP2 `42 5A 68`, XZ `FD 37 7A 58 5A 00`, 7z `37 7A BC AF 27 1C`, TAR (`ustar` at offset 257), ELF `7F 45 4C 46`, Mach-O (`FE ED FA CE/CF`, `CE FA ED FE`, `CF FA ED FE`), PE `4D 5A`, WASM `00 61 73 6D`, SQLite `SQLite format 3`, WOFF `77 4F 46 46`, WOFF2 `77 4F 46 32`, TTF `00 01 00 00`, OTF `4F 54 54 4F`, MP4/MOV (`ftyp` at offset 4), Java class `CA FE BA BE`.
  - Gate 3 (binary-dominant): the printable share over the whole buffer is below 70%, where "printable" counts ASCII 0x20-0x7E, TAB/LF/FF/CR AND every complete, valid UTF-8 multibyte sequence (round 3: a CJK or accented text file is not binary just because its bytes are above 0x7F). Real compressed or machine-code data sits far below 70%. A PNG header followed by `KEY=` lines, or CJK UTF-8 text with an ASCII magic prefix, one NUL and a key, is mostly printable, fails this gate, and continues to the D3/D2 steps: it is scanned, or if its NUL share is above 1% it degrades. It is never silently skipped. Test rows: B1, B4 and the mutation table (spoof: CJK UTF-8 + ASCII magic + one NUL + a key).
- Extension is NEVER used. The old D4 step (3) "known extension => binary" is DELETED, together with the extension list. `creds.bin` or `dump.dat` with 2% NUL padding and no magic goes to `UNSCANNED_UNKNOWN_BINARY` (degraded); a text file named `secret.png` is read and scanned.
- Head-read shortcut (size-cap files only; round-3 rule): a file over `maxFileSizeBytes` is normally `FILE_TOO_LARGE` (degraded). The scanner may instead read the first 4,096 bytes and skip the full read ONLY when (a) the head matches a magic value AND (b) the head FAILS a strict UTF-8 decode (after dropping at most 3 trailing bytes that form an incomplete sequence cut by the 4,096 limit). A head of NULs and ASCII passes a strict UTF-8 decode, so the attack "PNG magic + NUL-heavy first 4 KiB + credential later" does NOT qualify and ends as `FILE_TOO_LARGE` (degraded). Genuine assets have invalid UTF-8 near the start (PNG `89`, JPEG `FF D8`, PDF binary-marker comment, MP4 box data). Such files count under `skipped.binary` and `coverage.skipped.binaryHeadOnly`. Files at or under the cap always get the full-buffer test (no shortcut). A head that fails either condition => `FILE_TOO_LARGE` as today. Real large assets are tested (B8, C0): a camera JPEG with EXIF/XMP, a PDF with early text objects, an MP4, each over 512 KiB: no false degrade. A PDF whose head is entirely valid UTF-8 degrades (visible, fixable with `ignore.paths`).
  - Residual (accepted, see D): a file over 512 KiB whose head has a real header plus invalid UTF-8 and hides text later is skipped as binary. Counted, not degraded.
- Order of the whole classifier is in A1. Counterargument: no extension fallback means an unusual blob degrades the scan. Answer: a false degrade (visible, fixable with `ignore.paths`) is preferred to a false SAFE in a release gate.

### D5. Default-ignored files (BR I1, I2, I4)
- Today `fs.ts:30-67` drops a fixed list with no signal: directories at the project root (`node_modules`, `dist`, `build`, `.next`, `coverage`, `.git`, `.cache`, `.turbo`, `.venv`, `venv`, `vendor`, `tmp`, `out`), lockfiles, and extensions (`*.log *.min.js *.map` plus media/binary extensions). `scanner.ts:34-42` carries a second, shorter list.
- Main decision on Q1: these stay ignored by default and are counted in `coverage.ignoredByDefault`.
- Choice:
  1. Remove the media/binary EXTENSIONS from the ignore list (`*.png *.jpg *.jpeg *.gif *.webp *.ico *.pdf *.zip *.gz *.tar *.mp4 *.mov *.wasm *.node`). They are now discovered and classified by content (D4), so a text file named `x.png` is scanned (closes an evasion the ignore list opened) and real images are counted under `skipped.binary`. Images over the size cap use the head-read shortcut of D4 (magic AND binary-looking head), so a 3 MB logo does not degrade the scan.
  2. KEEP ignoring the rest (dependency/build/VCS directories, lockfiles, `*.map`, `*.min.js`, `*.log`, `vendor tmp out .cache .venv venv`), but COUNT them: `coverage.ignoredByDefault` lists each rule that matched with a file count (rules that name a directory report `present:true` without enumerating it, so `node_modules` is never walked). Not degraded.
  3. Do NOT change which paths are scanned beyond item 1. Whether `*.log`, `*.min.js`, `vendor/`, `tmp/`, `out/` should be scanned is a product decision (owner item 12 class, and `*.min.js` over 512 KiB would add `FILE_TOO_LARGE` degrades). Decided by main (Q1): stay ignored, counted.
- Why not degrade: they are documented, deterministic exclusions the user can see in the counts; degrading them would make nearly every real project DO_NOT_SHIP (every repo has a lockfile).
- Counterargument: `*.log` and `vendor/` can hold real secrets or first-party source, so "counted" is weaker than "scanned". Accepted for this branch (main decision Q1); it moves silent to visible.

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
- `classifyFile(buffer: Uint8Array): ClassifyResult`, a pure function, no I/O, and NO file name argument (the name and extension must not influence the result). Result is a tagged union:
  - `{ kind: 'text', text: string, encoding: 'utf8' | 'utf16le' | 'utf16be', nulSubstituted: boolean }`
  - `{ kind: 'binary' }` (real binary, D4, not degraded)
  - `{ kind: 'unknown-binary' }` (degraded)
  - `{ kind: 'invalid-text', encoding: 'utf8' | 'utf16', reason: string }` (maps to the existing `INVALID_UTF8` code)
- The exact order (round-2 decision; every branch is a test row in B1):
  1. Empty => text.
  2. `detectBinary` false (no NUL, low control density) => strict UTF-8 decode (`decodeUtf8Strict`); failure => `invalid-text`. Magic is NEVER consulted here.
  3. `detectBinary` true, BOM `FF FE` (not followed by `00 00`) or `FE FF` => UTF-16 decode; failure => `invalid-text` (degraded). No other branch is tried.
  4. `detectBinary` true, no BOM: validated BOM-less UTF-16 candidate (D3) => text.
  5. Real binary (D4 gates 2 and 3: magic AND binary-dominant) => `binary`.
  6. NUL-to-space text-likeness test (D2) => text with `nulSubstituted`.
  7. Otherwise => `unknown-binary`.
- Constants for thresholds (30%, 70%, 1%, 5%, 40%/2%, 80%, 32 KiB, 4,096-byte head) are named and exported for tests.
- Reuses `detectBinary`, `decodeUtf8Strict`, `stripBom`, `normalizeNewlines` from `@agenticcli/matcher-contract`. It does NOT modify the matcher-contract (see A9).
- Result text for every `text` kind goes through `stripBom` then `normalizeNewlines`, as Gate 5 does now.

### A2. `packages/cli/src/utils/fs.ts` and `packages/cli/src/core/scanner.ts` - use the classifier in both read paths
- `fs.ts:323-343` (Gates 3-5 in `readFiles`) and `scanner.ts:294-312` (the `--changed` copy) are replaced by one call to `classifyFile`. Both paths then fill the same counters, so they cannot drift again.
- `ReadFilesResult` (fs.ts:~76-160) gains: `skippedUnknownBinary: string[]` (capped names plus a true count), `skippedSpecial` (count and capped names), `nulSubstitutedFiles` (count and capped names), `utf16Decoded` (count), `notReached` (number), `truncatedBy?: 'maxFiles' | 'maxTotalBytes'`, `discovered` (number), `ignoredByDefault: Array<{ pattern: string; files?: number; present?: boolean }>`, `ignoredByUser` (count).
- Head-read shortcut: only for files over `maxFileSizeBytes`, exactly as D4 defines (first 4,096 bytes, magic AND binary-looking head). Implemented once, called from both paths.
- ONE shared ignore helper (round-2 decision, new file `packages/cli/src/core/ignore.ts`): `buildIgnorePatterns(policy)` returns `[...DEFAULT_IGNORE (fs.ts), ...selfArtifactIgnorePatterns(policy), ...policy.ignore.paths]` and `classifyIgnored(relPath, patterns)` (uses `minimatch`, already a direct dependency of the CLI, with `{ dot: true }`; round 3: it tests the path AND every parent folder prefix against each pattern, so a bare `docs` or `secrets/` pattern ignores `docs/a/b.js` exactly as fast-glob's directory pruning does) returns `null`, `{ by: 'default', pattern }` or `{ by: 'user', pattern }`. The full path passes the same pattern list to fast-glob (replacing the list built at `public@2bf3a7d:packages/cli/src/core/scanner.ts:166-170`); the `--changed` filter (replacing the prefix/equality check at `scanner.ts:209-219`, which today ignores `policy.ignore.paths`) calls `classifyIgnored`. Result: `ignore.paths` works under `--changed`, so the remedy printed for `UNSCANNED_UNKNOWN_BINARY` works on both paths. Test B18 pins that the two matchers agree on a corpus of paths (root-only `*.log`, `dir/**`, nested `node_modules`, dotfiles, bare `docs`, `secrets/`, `docs/**`).
  - Disclosed behaviour change (round 3): the old `--changed` filter used the SHORT list in `scanner.ts:34-42`, so changed `*.log`, `*.min.js`, `vendor/`, `tmp/`, `out/` files WERE scanned under `--changed`. With the shared helper they follow the same default ignore list as the full scan and are counted in `ignoredByDefault`. Listed in D and the CHANGELOG; B18 has a row for it.
- `--changed` git output (rounds 2 and 3): `getChangedFiles` (`public@2bf3a7d:packages/cli/src/core/git.ts:100`) runs the three git commands with `-z` (`diff --name-only -z`, `diff --cached --name-only -z`, `ls-files --others --exclude-standard --full-name -z`) and the output is parsed AS A BUFFER (the shared `runGit` currently decodes with `encoding:'utf-8'`, `git.ts:49`; a Buffer variant is added). Split on NUL byte; every name is kept EXACTLY (no `trim()`); only empty entries are dropped.
  - Undecodable names (round 3): each name is decoded with the strict UTF-8 decoder (`decodeUtf8Strict`). A name that is not valid UTF-8 is NEVER replaced by U+FFFD (that would alias a different file) and is not scanned: it is recorded as skipped and DEGRADED with the existing code `UNREADABLE_FILE` (detail: "file name is not valid UTF-8, cannot be addressed safely"; counted in `coverage.skipped.unreadable`). Reuse is deliberate: the file exists but cannot be read by an exact path; a new code would add a consumer-visible value for a rare case. Test B19.
  - Nested scan root (round 3): git prints repository-root-relative paths for `diff` but cwd-relative paths for `ls-files` unless `--full-name` is given; the scanner then joins them to the scan directory. From `app/`, a changed `app/config.js` would resolve to `app/app/config.js` (a clean sibling) and the credential would stay unread. Fix: `getChangedFiles` asks git for `rev-parse --show-toplevel` and `rev-parse --show-prefix` (both run in the scan directory), takes all three outputs as repo-root-relative, keeps only paths that start with the prefix, and strips it. The result is relative to the scan directory and joins correctly. Paths outside the scan directory are counted in `coverage.changed.outsideScope` (not scanned, not degraded: they are outside what the user asked to scan). Test B22.
  - With `-z` git also stops quoting non-ASCII names (`core.quotePath` does not apply). A file named `secret.ts ` (trailing space) or a whitespace-only name is no longer aliased to a sibling or lost. Test B19.
- `--changed` empty diff (round-2 decision, REVERSES the earlier main decision): NO exemption. Zero scannable files gives `NO_FILES_SCANNED`, `degraded:true`, DO_NOT_SHIP, `--strict` exit 1. In non-JSON modes a stderr hint is printed: "`--changed` scans only files that differ from git; on a clean checkout it scans nothing. Run `shipguard scan` for the whole tree." (The hint goes to stderr so `--json` stdout stays pure; `json-stdout-purity` test is extended.) B6 asserts this.
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
    special: number,             // FIFO/socket/device (not degraded)
    binaryHeadOnly: number       // subset of `binary` decided from the head only (files over the size cap)
  },
  decoded: { utf16: number, nulSubstituted: number },
  truncated: false | { by: 'maxFiles' | 'maxTotalBytes', notReached: number },
  ignoredByDefault: Array<{ pattern: string, files?: number, present?: boolean }>,
  ignoredByUser: number,          // files matched by policy.ignore.paths (count)
  mode: 'full' | 'changed',
  changed?: { listed: number, outsideScope: number },   // --changed only: raw path count from git (-z), before ignore rules
  files: { binary: string[], tooLarge: string[], symlink: string[], unknownBinary: string[], special: string[], nulSubstituted: string[] }  // each capped at 50 names, sorted
}
```
- Why a nested object and not many top-level keys: one new top-level key (`coverage`) is the whole additive change for consumers; the freeze test allow-list (A6) gains one entry.
- `filesScanned` keeps today's meaning (accepted files).
- Coverage fields under `--changed` (round-2 decision): `mode:'changed'`; `changed.listed` = unique exact paths from git; `discovered` = `listed` minus the paths removed by the shared ignore helper (so the same invariant holds); `ignoredByDefault` and `ignoredByUser` are exact per-pattern file counts over the listed paths (full mode reports directory rules as `present:true`, changed mode can count exactly); a listed path that cannot be read or resolves outside the root counts under `skipped.unreadable`; `truncated` and `notReached` behave as in full mode. The two read paths call the same `classifyFile` and the same counter code, and test M (section B) asserts identical `coverage` and degrade codes for identical content.
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
  - `--check-regressions` (round 3, REVERSES round 2): behaviour UNCHANGED. The flag alone still exits 1 on a regression (`scan.ts:973-982`); that is documented in `--help` (`scan.ts:251`, `:263-265`) and `packages/cli/docs/llms.txt:16`, so changing it would break the documented contract. The only edit is the STALE doc comment at `scan.ts:62-64` ("This is the only condition that changes the exit code from the default 0"): reword it to say `--strict` blocking and `--check-regressions` are the two opt-in conditions. B20 becomes a guard asserting the flag alone exits 1. No CHANGELOG entry, not a risk.
  - Update the `Exit codes` help text in scan.ts (the `1  Blocked` bullet) and the doc comment at scan.ts:50-122 to list the new degraded cases.
  - `--sarif`: `toSarif(publicResult)` (scan.ts:~786) is unchanged; confirm in a test that `coverage` does not leak into SARIF.

### A5. BUG 2 port: `packages/cli/src/utils/exit.ts` (NEW) and `packages/cli/src/commands/scan.ts`
- Reference (not copied): `archive@8a55f4e:packages/cli/src/utils/exit.ts:1-37` waits for a write callback then forces `process.exit` after a 10 s timer; call sites `archive@8a55f4e:packages/cli/src/commands/scan.ts:370` and `:993`. Round 1 showed that design STILL truncates: when the reader is slower than 10 s the forced exit discards queued stdout (Codex reproduction: 182,720 of 5,000,012 bytes, invalid JSON, exit 1).
- EPIPE handlers (round 3): installed AT STARTUP in `packages/cli/src/cli.ts`, before `parseAsync`, for BOTH `process.stdout` and `process.stderr`: `stream.on('error', (err) => ...)`. For `EPIPE` (reader closed early, for example `| head -c 100`): log at debug and do nothing else, so the exit code stays whatever the scan computes (the handler never sets or changes `process.exitCode`). Any other stream error: log at warn, same. Why at startup and not in `setExitCode`: the JSON is written (`scan.ts:~788`) and then the code awaits telemetry (`scan.ts:~986`, up to 1.5 s) before it reaches the exit point; an EPIPE during that wait would hit `handlers.ts:27` (`process.exit(3)`). The handlers exist before the first output.
- New rule (round-2 decision): `process.exit` is NEVER called while stdout has queued data. The new `exit.ts` exports `setExitCode(code: number): void`:
  1. `process.exitCode = code`.
  2. Return. Node then exits on its own once stdout has drained and the event loop is empty. There is NO timer and NO forced exit.
- Call sites in public (`public@2bf3a7d:packages/cli/src/commands/scan.ts`): `exitWithError` (:352-367, `return process.exit(exitCode)`) and the final block (:988-990). Because `setExitCode` returns, every caller of `exitWithError` must stop executing: change the six call sites (:309, :327, :400, :553, :611, :658) to `return exitWithError(...)` (the code at :400-401 already has an unreachable-guard `return`), and the final block simply sets the code and falls off the end of the action. Re-read the whole action end to end before editing; existing tests that mock `process.exit` (for example `cli-exit-codes.test.ts`) are reviewed and updated to assert `process.exitCode`.
- Lingering handles: if a late handle (network keep-alive from telemetry or Pro fetch) keeps the process alive after the drain, the tarball rehearsal (C0) measures time-to-exit. The only permitted fallback is calling `process.exit(code)` from inside an empty-write callback on stdout AND stderr when `writableLength === 0` (nothing queued, so nothing can be lost). Never from a timer. If needed, this is added in the same file with its own test (B14).
- Out of scope, listed under RISKS: `src/cli.ts:190,206,210,214` and `src/handlers.ts:27,38,44` also call `process.exit` directly; they print short messages (no large payload).

### A6. Tests, docs and metadata
- Tests: section B. Existing tests to UPDATE (they pin today's silent behaviour): `tests/commands/scan-json-schema-freeze.test.ts` (schemaVersion `'6'`, `coverage` in the optional allow-list as required, `_skipped*` still must not leak), `tests/commands/scan-degraded-on-skip.test.ts` and `tests/commands/scan-bounds.test.ts` (binary-skip expectations), `tests/commands/schema-contract.test.ts` (new codes, version), `tests/utils/fs.test.ts` and `tests/utils/fs-bounds.test.ts` (ReadFilesResult shape; the removed extension ignores).
- `packages/cli/CHANGELOG.md`: add an "Unreleased" entry in the file's plain style. Fixed/Changed items: UTF-16 and NUL files are scanned; scans that read nothing are no longer SAFE (including `--changed` on a clean checkout); JSON gains `coverage`, schemaVersion 6; `treeDigest` changes for trees that contain NUL or UTF-16 files (they now enter the digest) and for `--changed` scans whose paths had odd whitespace; `--strict --json` output is no longer cut; `--changed` now honours `ignore.paths` and exact file names; `--changed` now follows the same default ignore list as the full scan, so changed `*.log`, `*.min.js`, `vendor/`, `tmp/`, `out/` files that it used to scan are now skipped (and counted); `--changed` from a sub-folder now reads the right file; a git file name that is not valid UTF-8 degrades the scan; a key split by an embedded NUL byte is still not matched (known limit). NO version bump in `package.json`, NO tag (owner's call).
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

Layout: Vitest under `packages/cli/tests/<domain>/`, existing conventions: unit tests in-process, e2e tests spawn the CLI through `tests/helpers/spawn-cli.ts` with `vi.setConfig({ testTimeout: 30_000 })`. The CLI path comes from one helper `cliPath()` (env `SHIPGUARD_CLI` if set, else `dist/cli.js`) so the same e2e files run against the packed tarball in C0. Telemetry is already forced off by `tests/setup/no-telemetry.ts`.

Fixture rule: planted secrets are the public example values already used in this suite (`AKIAIOSFODNN7EXAMPLE`, the `-----BEGIN RSA PRIVATE KEY-----` marker). No real secrets.

Test types (round-2 labelling): **R** = fail-before regression: it must FAIL on the unmodified `origin/main` build (`2bf3a7d`) and pass after; the failing output is recorded in the progress entry. **G** = guard: passes before and after, protects an invariant (it is never counted as proof of a fix). **D** = documentation test: pins a known limit.

### B.1 The test table

| # | Type | File | What it proves | Fail-before (expected on `2bf3a7d`) |
|---|---|---|---|---|
| B1 | R | `tests/utils/classify.test.ts` (new, unit) | One row per branch of the A1 order. Text: empty; ASCII; UTF-8+BOM; UTF-16LE+BOM; UTF-16BE+BOM; BOM-less LE ASCII; BOM-less BE ASCII; BOM-less LE CJK followed by a key (10,000 `汉` + `AKIAIOSFODNN7EXAMPLE`: decoded text CONTAINS the key); one NUL in 10 KB text => nul-substituted, same length, same line/column for a later match. Not text: BOM-less random even-length bytes; BOM-marked with a lone surrogate => invalid-text; BOM-marked odd length => invalid-text; UTF-32LE BOM => unknown-binary; 2% NULs and no magic => unknown-binary. Real binary (magic AND binary-dominant): PNG, ZIP, gzip, ELF, WASM, PDF, WOFF2. SPOOFS (must NOT be binary): `MZ=1\nAWS_ACCESS_KEY_ID=...` as a no-NUL `.env` => text (magic never consulted); a text file with `ustar` at offset 257 => text; a PNG header followed by `KEY=` lines => text or unknown-binary, never binary; `creds.bin`/`dump.dat` content (random text with 2% NUL padding, no magic) => unknown-binary. `classifyFile` takes no file name (a type test proves it) | module missing |
| B2 | R | `tests/commands/scan-coverage-matrix.test.ts` (new, e2e; see B.2) | Rows: NUL+key; UTF-16LE+BOM; UTF-16BE+BOM; BOM-less LE ASCII; BOM-less BE ASCII; CJK-then-key (Codex case). Each: key FOUND with the right `file` and line, `filesScanned` 1, `coverage.scanned` 1, `coverage.decoded.utf16` or `.nulSubstituted` 1, a blocking finding => `--strict` exit 1; on BOTH read paths | `SAFE_TO_SHIP`, 0 findings, scanned 0 (BR B1-B3) |
| B3 | R | same matrix | Degrading rows: BOM-marked UTF-16 with lone surrogate; BOM-marked odd length; BOM-less BE all-CJK; UTF-32LE: `degraded:true`, correct code (`INVALID_UTF8` for BOM-marked failures, `UNSCANNED_UNKNOWN_BINARY` for the rest), `DO_NOT_SHIP`, `--strict` exit 1, no-strict exit 0; both read paths | `degraded:false`, SAFE |
| B4 | R | same matrix + `tests/commands/scan-all-binary-tree.test.ts` (500-file tree) | BR B4: 500 NUL-heavy files with no magic: 0 scanned, `degraded:true`, codes `NO_FILES_SCANNED` + `UNSCANNED_UNKNOWN_BINARY`, never `SAFE_TO_SHIP`, `coverage.discovered` 500, invariant holds, `--strict` exit 1. Plus spoof rows (round 2): MZ-prefixed `.env` found, `ustar`-at-257 text found, PNG header + `KEY=` lines found-or-degraded, `creds.bin` and `dump.dat` (2% NUL padding) degraded; both read paths | scanned 0, SAFE (spoof rows: `.png`-named text never read) |
| B5 | R | same matrix | REAL-binary-only tree (valid 1x1 PNG, ZIP, gzip, ELF header, WOFF2 header, built from literal bytes; `--all`): `skipped.binary` = N, scanned 0, `degraded:true` with ONLY `NO_FILES_SCANNED` (no unknown-binary code), `DO_NOT_SHIP`. Companion: same tree plus one clean `.js` => not degraded, `SAFE_TO_SHIP`, `skipped.binary` = N, `--strict` exit 0. Both read paths | scanned 0, `SAFE_TO_SHIP` |
| B6 | R | same matrix | Empty directory with `--all`: `NO_FILES_SCANNED`. Dir with only ignored files: same. `--changed` in a git repo with an EMPTY diff: `NO_FILES_SCANNED`, `degraded:true`, DO_NOT_SHIP, `--strict` exit 1, exit 0 without `--strict`, and the stderr hint about clean checkouts is printed (human mode) and absent from `--json` stdout. No exemption | SAFE |
| B7 | R | `tests/commands/scan-coverage-json.test.ts` (new, e2e) | JSON always has `coverage` (also on a clean scan) with the invariant `discovered = scanned + sum(skipped except binaryHeadOnly) + notReached`; `schemaVersion` `'6'`; no `_skipped*`/`_truncated` keys; `coverage.files` sorted, capped at 50, project-relative; `--changed` has `mode:'changed'` and `changed.listed`; SARIF has no `coverage`; human output prints the Coverage line on a clean scan and names each skip category | `coverage` absent |
| B8 | R | `tests/utils/fs-bounds.test.ts` + `tests/commands/scan-bounds.test.ts` (extend) | Limit truncation: low `limits.maxFiles` via policy (10 of 25) => `degraded:true`, `OUTPUT_TRUNCATED`, `coverage.truncated = { by:'maxFiles', notReached:15 }`, detail names the cap; same for `maxTotalBytes`; exactly-at-cap NOT truncated; the same through `--changed`; over-size file => `FILE_TOO_LARGE`, `skipped.tooLarge` 1. Head shortcut (round 3): REAL-STYLE large assets, each over 512 KiB and built from literal structure in the test: a camera JPEG (SOI, EXIF APP1, XMP APP1 with text, then high-entropy scan data), a PDF with the binary-marker comment and early text objects, an MP4 (`ftyp`, `moov`, `mdat`) => `skipped.binary` + `binaryHeadOnly`, NOT degraded. Attack rows: over-cap PNG magic + NUL-heavy 4 KiB head + credential later => `FILE_TOO_LARGE`, degraded; over-cap text file with a PNG header and a text head => `FILE_TOO_LARGE`. Mixed tree (60 files, 20 unknown-binary) proves binary does not use the file cap and is counted (BR L4) | no `coverage`; truncation detail without cap/count |
| B9 | G | `tests/commands/matcher-contract-untouched.test.ts` (new) | `git diff --name-only origin/main -- packages/matcher-contract` is empty (skipped outside a checkout with `origin/main`) | passes before; fails only if someone edits the contract |
| B10 | R | `tests/commands/scan-default-ignore-coverage.test.ts` (new, e2e) | BR I1/I2/I4: `x.min.js`, `debug.log`, root `vendor/a.js`, `package-lock.json`, `y.map` => `ignoredByDefault` lists each rule with counts; `node_modules` reported `present:true` and NOT walked (a 10,000-file fixture, wall time < 5 s); not degraded. `ignore.paths` entries => `ignoredByUser` counts. Media extension change: text `secret.png` containing the key => FOUND; a real PNG `logo.png` => `skipped.binary` | silently dropped; `secret.png` not found |
| B11 | R (FIFO) / G (ENOENT) | `tests/utils/fs-special-files.test.ts` (new; skip on win32) | FIFO (`mkfifo`) => `skipped.special` 1, wall < 5 s, not degraded (R). Mock `readFile` throwing ENOENT => `UNREADABLE_FILE`, degraded (G: already true today) | FIFO: no count |
| B12 | R | `tests/commands/strict-json-pipe-truncation.test.ts` (new, e2e, Linux) | BUG 2, fast lane. Handshake design in B.3. 25 files => JSON above 65,536 B. `--strict`: exit 1; stdout valid JSON; same `findings.length` as the non-strict run; the probe reports `queuedBytes > 0` at the exit point (else the test is invalid and fails) | stdout cut at the pipe size, `JSON.parse` throws; MUST ALSO FAIL when `exit.ts` is reverted to a bare `process.exit` (mutation check, B.4) |
| B13 | R | `tests/slow/strict-json-5mb.slow.test.ts` (new, slow lane) | BUG 2 at scale: 3000 files x 2 findings => about 5.1 MB JSON. Same handshake. The reader is held back a further 12 s AFTER the handshake (so a 10 s forced-exit timer would fail), then released: stdout > 5,000,000 B, valid JSON, `findings.length` equal to the non-strict run, exit 1. Variants: `--sarif --strict`; `| head -c 100` (see B16) | cut at 65,536 / 69,632 / 182,720 B, invalid JSON |
| B14 | R | `tests/utils/exit.test.ts` (new, unit) | `setExitCode` sets `process.exitCode`, never calls `process.exit` (spy), has no timer (fake timers: nothing scheduled), installs the stdout error handler once | module missing |
| B15 | G | existing suites | `pnpm run build && pnpm run lint && pnpm test` (matcher-contract + cli) green; `tests/slow` green; `RELEASE_GATE_DRY_RUN=1 scripts/release-gate.sh` green incl. G8 | n/a |
| B16 | R | `tests/commands/strict-json-epipe.test.ts` (new, e2e) | `scan --json --strict <fixture> \| head -c 100` through bash: CLI exit code (via `PIPESTATUS[0]`) is 1, stderr has no unhandled `EPIPE` stack and no `Unexpected error`, no hang (< 10 s). Non-strict variant exits 0. VARIANT (round 3): the same run with telemetry ON (`SHIPGUARD_TELEMETRY` and `DO_NOT_TRACK` removed from the child env, because `tests/setup/no-telemetry.ts` forces them off in the parent) and `SHIPGUARD_TELEMETRY_URL` pointing at a local loopback server that answers after about 1 s: the reader closes early while the CLI waits for telemetry; the exit code must still be 1 (not 3). B16 proves EPIPE handling only; it does NOT prove the bare-`process.exit` mutation (that proof belongs to B12/B13) | uncaught EPIPE error / exit 3 or crash |
| B17 | D | `tests/utils/classify.test.ts` (row) | A key split by an embedded NUL (`AKIA\0IOSFODNN7EXAMPLE`) in an otherwise text file: classified text with `nulSubstituted`, NOT degraded, the key NOT found. Documents the residual in D2/D | n/a (documents the limit) |
| B18 | G/R | `tests/core/ignore.test.ts` (new, unit) + e2e rows | G: the shared helper's `classifyIgnored` agrees with fast-glob's `ignore` on a corpus (root-only `*.log`, `dir/**`, nested `node_modules`, dotfiles, `policy.ignore.paths` globs, bare `docs`, `secrets/`, a parent-folder row `docs/a/b.js` for pattern `docs`). R rows in plain words: (1) a changed file whose path is listed in `ignore.paths`: before this branch `--changed` still scanned it; after, it is skipped and counted in `ignoredByUser`. (2) a changed `debug.log` or `vendor/x.js`: before, `--changed` scanned them; after, they are skipped and counted in `ignoredByDefault` (the disclosed behaviour change) | before: the listed file and the `.log` file are scanned under `--changed`; after: both are skipped and counted |
| B19 | R | `tests/core/git.test.ts` (extend) | `getChangedFiles` with `-z` and Buffer parsing: file named `secret.ts ` (trailing space) AND a clean sibling `secret.ts`: both listed separately, exact; whitespace-only name kept; non-ASCII name unquoted; renamed/untracked/staged all present. Round 3: a file whose name contains the invalid byte `FF` AND a sibling containing a literal U+FFFD: the invalid one is NOT merged with the sibling; it is reported as skipped with `UNREADABLE_FILE` and `degraded:true` (e2e: DO_NOT_SHIP, `--strict` exit 1), never scanned as the sibling. Skipped on file systems that refuse such names | trim aliases `secret.ts ` to `secret.ts`; whitespace-only name dropped; `FF` name aliased to U+FFFD sibling |
| B20 | G | `tests/commands/check-regressions-exit.test.ts` (new, e2e) | Round 3 guard: with an injected regression, `--check-regressions` ALONE exits 1 (documented in `--help` and `llms.txt`); without a regression exits 0; `--strict` unaffected. Passes before and after: it protects the contract, it is not fix proof | n/a (guard) |
| B21 | G | `tests/helpers/exit-probe.test.ts` (new) | Probe self-test (round 3). Two tiny fixture scripts write 200 KB to a paused pipe: (a) bare `process.exit(1)` with data queued, (b) sets `process.exitCode = 1` and returns. The probe must emit exactly one `EXIT_POINT code=1 queued=<n>` line with n > 0 in BOTH cases, and the probe must not throw on Node 20, 22 and 24 (the CI matrix and the dev box). Proves the handshake works before B12/B13 rely on it | n/a (guard for the test harness) |
| B22 | R | `tests/core/git.test.ts` + matrix (extend) | Nested root (round 3): repo with `app/config.js` (changed, holds the key) and a clean `app/app/config.js`; scan from `app/` with `--changed`: the key IS found in `app/config.js` (reported as `config.js`), the clean sibling is not the file read; a changed file outside `app/` is counted in `coverage.changed.outsideScope` and not scanned. Same for a staged and for an untracked file | the clean `app/app/config.js` is resolved or nothing is read; SAFE |
| B23 | R | matrix + `tests/utils/classify.test.ts` | Ambiguity rows (round 3): `a` x 1000 + `\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n` + one NUL => key found, `decoded.multiReading` 1; BOM-less BE `汉` x 10,000 + key => key found; CJK UTF-8 + ASCII magic prefix + one NUL + key => key found (not binary); findings are de-duplicated by rule + file + line; both read paths | SAFE, 0 findings |

### B.2 Behavioural mutation matrix (both read paths)

- One parametrised file, `tests/commands/scan-coverage-matrix.test.ts`. A single fixtures table (id, files, expected coverage, expected degrade codes, expected findings). Each row runs TWICE: (full) `scan <dir>` and (changed) the same files created untracked inside a fresh git repo and scanned with `--changed`. The test asserts the expectations AND that `coverage` (apart from `mode`/`changed`) and `degradedReasons[].code` are IDENTICAL between the two runs. A reverted classifier in only one path therefore turns that path's rows red.
- Mutations the QA agent applies one at a time on the finished branch (each must turn exactly the named rows red; the table is stored in the progress entry):

| Mutation | Rows that must go red |
|---|---|
| fs.ts calls the old `detectBinary` gate (revert A2 in the full path only) | all full-path rows of B2, B3, B4 |
| scanner.ts `--changed` keeps the old gate (revert in the changed path only) | all changed-path rows of B2, B3, B4, B5 |
| magic consulted before `detectBinary` | MZ-prefixed `.env`, `ustar`-at-257 rows |
| extension used to decide binary | `secret.png` row, `creds.bin`/`dump.dat` rows |
| NUL-to-space before UTF-16 | CJK-then-key row |
| drop printable-share gate (Gate 3) | PNG-header-plus-`KEY=` row |
| remove `NO_FILES_SCANNED` | B4, B5, B6 rows |
| `trim()` back in git.ts | B19 |
| `policy.ignore.paths` removed from the changed filter | B18 e2e |
| `exit.ts` back to bare `process.exit` / timer | B12, B13 (NOT B16: a bare exit can still pass B16) |
| EPIPE handlers installed late (in `setExitCode` instead of `cli.ts` startup) | B16 telemetry-delay variant |
| printable-share counts ASCII only (no UTF-8 sequences) | B1/B4/B23 row: CJK UTF-8 + ASCII magic + one NUL + key |
| single reading instead of union of readings | B23 rows (`a` x 1000 + key + NUL; BE CJK + key) |
| head shortcut without the strict-UTF-8 failure test | B8 attack row (PNG magic + NUL-heavy head) |
| git paths not normalised to the repo root | B22 |
| git names decoded as lossy UTF-8 | B19 `FF` row |
| `classifyIgnored` without parent-folder test | B18 bare `docs` / `secrets/` rows |

### B.3 Pipe test handshake (B12, B13)

- Probe file (test-only, never shipped): `tests/helpers/exit-probe.mjs`, preloaded with `node --import <abs path> dist/cli.js ...`. `process.exitCode` is NON-CONFIGURABLE on Node 24 (defining a setter throws `TypeError: Cannot redefine property: exitCode`), so the probe does not touch it. It (a) wraps `process.exit` (the OLD code calls it), and (b) starts an `unref()`ed `setInterval` of about 5 ms that watches `process.exitCode` and `process.stdout.writableLength` (the NEW code only sets the code and returns). On whichever fires first, once, it writes ONE line with `fs.writeSync(2, ...)` (never queued): `EXIT_POINT code=<n> queued=<bytes>`. The interval is unref'd, so it never keeps the process alive. Self-test: B21.
- The test holds the read end of the stdout pipe PAUSED (not reading). It releases (resumes reading) only after it has read the `EXIT_POINT` line from stderr: an explicit handshake that the CLI has produced its whole output and decided its exit, with `queued > 0`. CPU idleness is NOT used anywhere.
- On the old code the CLI calls `process.exit` at that point and the data still queued is lost: the reader gets a cut payload, `JSON.parse` throws, the test fails. On the new code the CLI only sets `process.exitCode`; the reader then drains it all and the process exits by itself with the right code.
- The test asserts: `queued > 0` at the handshake, complete valid JSON, exit code, and (B13) that the process was still alive 12 s after the handshake (a timer-based forced exit would already have fired).

### B.4 Run discipline

Build `dist/` first (`pnpm run build`), run the e2e files one at a time on this shared box, keep aggregate CPU under the session caps. B13 is the heaviest (about 15 s per spawn in BR, plus the 12 s hold).

Fail-before protocol: on a clean checkout of `origin/main` build `dist`, run every R test against it and keep the failing output in the progress entry. A test that cannot fail on the old code is rejected in code review. G and D tests are labelled and not counted as fix proof.

## C. VERIFICATION PLAN

### C0. MANDATORY rehearsal before the owner publishes (on the `build:publish` tarball)

This is a gate for the release recommendation: if any step fails, the plan's report to the owner is "do not publish".

1. Build exactly as the release does: `pnpm run build` then `SHIPGUARD_PUBLISHED_BUILD=1 pnpm --filter @agenticcli/shipguard build:publish` (the `build:publish` script, `public@2bf3a7d:packages/cli/package.json:19`), then `npm pack` in `packages/cli` into a new empty directory. No publish, no tag.
2. Install the `.tgz` into a second empty temp dir with `npm install --ignore-scripts <tgz>`; confirm `shipguard --version` equals the packed `package.json` version.
3. Run these tests against the INSTALLED binary (set `SHIPGUARD_CLI=<temp>/node_modules/.bin/shipguard`; the e2e files use `cliPath()`): B2 (NUL, UTF-16 LE/BE with BOM, BOM-less, CJK-then-key), B4 (500-file tree, plus the four spoof cases and `creds.bin`/`dump.dat`), B12 (fast pipe test), B13 (5 MB pipe test with the 12 s hold), B16 (EPIPE), B6 (empty diff), and the real-binary-only tree of B5, the nested-root `--changed` row (B22) and the large-asset rows of B8 (camera-style JPEG, PDF, MP4 over 512 KiB, no false degrade; additionally run against two or three real large assets from the host's own image/PDF/video files, never committed). The pipe tests need the probe file; it is preloaded from the repo test directory, the CLI itself is the packed one.
4. Record command, output size and exit code per step in the progress entry (fixture keys are public examples).
5. Run the G8 shipped-tree self-scan on the packed tree: `--strict` exit 0.

### C1. After the owner publishes (on the registry tarball)

Run only after the owner publishes. Nothing here publishes or tags anything.

1. `npm pack @agenticcli/shipguard@<released version>` into a new empty temp dir (untrusted data). Record `npm view @agenticcli/shipguard@<version> dist.integrity` and confirm it equals the packed file; confirm provenance with `npm audit signatures` after install.
2. Install into another empty temp dir: `npm install --ignore-scripts ./shipguard-*.tgz`; `npx shipguard --version` equals the tarball's `package.json`.
3. With `SHIPGUARD_TELEMETRY=0`, repeat the C0 step-3 set against the installed registry binary, plus fixtures from `agenticcli/agenticcli:tests/test-lab/boundary/lib` and `bin` (outputs to a new dir):
   - 5001 files: `coverage.truncated.by === 'maxFiles'`, `notReached: 1`. (The 520 x 512 KiB total-bytes case takes about 20 min in BR; run once only if time allows.)
   - 3000 files x 2 findings: `scan --json --strict | wc -c` above 5,000,000 and the output parses; exit code via `PIPESTATUS`; repeated 5 times (the cut point moved between runs in the lab).
   - Every JSON has `schemaVersion` `'6'`, `coverage` with the invariant, and `cliVersion` equal to the installed version.
   - `shipguard schema --json` lists `NO_FILES_SCANNED` and `UNSCANNED_UNKNOWN_BINARY`.
4. Exit codes on the installed binary: no flag 0 for every degraded fixture; `--strict` 1 for degraded ones and for a blocking-finding fixture; 0 for the clean + real-binary fixture; 2 for a missing path; 3 for the 10,000-deep tree (BR S7, unchanged); `--check-regressions` alone 1 on a fixture with an injected regression (unchanged contract).
5. Regression sweep of the BR "works" rows (BOM-8, CRLF, zero-byte, UTF-8, long path): unchanged.
6. Hook check: `shipguard hook` installs the gate; on a temp git repo with one clean file it passes; on an all-binary repo it blocks (documented behaviour change).
7. Failure of any check = tell the owner and recommend deprecating the version; no automatic action.

## D. Counterarguments and risks

- More degraded results for users. Cases that turn non-safe: empty or media-only repos (`NO_FILES_SCANNED`); NUL-heavy unknown files (`UNSCANNED_UNKNOWN_BINARY`). Installed hooks run `shipguard scan --json --strict` (`public@2bf3a7d:packages/cli/src/core/hook-templates.ts:30`), so a repo containing, say, a `.bin` blob not on the extension list would now be blocked at the merge boundary until the user excludes the path. This is the intended fail-closed behaviour, but it is user-visible: the CHANGELOG and the error text must say how to fix it (`ignore.paths`).
  - Mitigation: there is no extension fallback (round 2), so an unusual blob degrades; the detail text names the files and says to add them to `ignore.paths`, which now works on both read paths.
- A repo with no text files at all (rare for code) gets DO_NOT_SHIP. Intended (brief item 5).
- JSON consumers see a new top-level `coverage` object and `schemaVersion` `'6'`. Strict-schema consumers or those pinning `'5'` can break; the freeze test and CHANGELOG state it. Alternative rejected: keep `'5'` and add the field (the bump is the repo's own documented evolution procedure, `scan-json-schema-freeze.test.ts` header).
- Two new `degradedReasons` codes; the contract says consumers must tolerate unknown codes, but a consumer that hard-fails on unknown codes will break.
- NUL substitution is a heuristic. Residual: a secret deliberately split by NUL bytes inside a file that passes the text-likeness test could be missed. Defence: the thresholds (1% NUL, 5% control) keep obfuscation-heavy files on the fail-closed path.
- BOM-less UTF-16 detection can misclassify; every guess is validated by strict decode, and failures fall to degraded, never silent.
- Removing media extensions from the default ignore list adds reads: images at or under 512 KiB are now read in full; images over 512 KiB use the 4 KiB head check, and a large file without real-binary evidence now becomes `FILE_TOO_LARGE` instead of being ignored.
- Binary-exclusion residual (ACCEPTED, round 3 main decision; Codex's "degrade every heuristic binary exclusion" is NOT adopted): a magic-verified binary is counted under `skipped.binary` or `skipped.binaryHeadOnly` and is not degraded. Reason: almost every web repo contains real images, fonts and PDFs; degrading them would make nearly every repo DO_NOT_SHIP and train users to ignore the flag. What is closed: magic alone never decides (it needs a flagged, mostly non-printable file, and for large files a head that fails strict UTF-8), no extension, so the cheap spoofs end as scanned or degraded. Main decision after code review: a magic-verified binary UNDER the size cap is also read for its printable strings (runs of 8+ ASCII characters, one per line, so line numbers are run indexes); it still counts as binary and `coverage.decoded.binaryStringsScanned` counts it. What remains: a file over 512 KiB whose head has a real header with invalid UTF-8 and hides text later (only its head is read), and text inside a below-cap binary that is not printable ASCII runs of 8+ (for example UTF-16 or compressed text inside it). The counts make the exclusion visible.
- `--changed` now skips default-ignored files that it used to scan (`*.log`, `*.min.js`, `vendor/`, `tmp/`, `out/`), because it shares the full scan's ignore list; they are counted in `ignoredByDefault`. Disclosed in the CHANGELOG; B18 row.
- Multi-reading scans: an ambiguous file is scanned up to three times (UTF-8 with NUL-to-space, UTF-16LE, UTF-16BE); cost is bounded by the file-size cap and only ambiguous flagged files pay it. Findings are de-duplicated by rule + file + line, so counts do not inflate.
- `--changed` with an empty diff is now degraded and `--strict` exits 1 (no exemption). A CI job that runs `--changed --strict` on commits touching only ignored/doc-less paths will be blocked; the stderr hint explains it.
- `--changed` now honours `policy.ignore.paths` (it did not before): files a user listed there stop being scanned under `--changed`. This is the documented meaning of the setting.
- A key split by an embedded NUL is not matched (B17 documents this).
- Bug 2: with no forced exit, a reader that never reads keeps the CLI alive (standard pipe back-pressure). Accepted; the alternative is truncated JSON. A late open handle could delay exit; C0 measures time-to-exit and the only allowed fallback is exit from inside an empty-write callback when nothing is queued.
- `ignoredByDefault` counting adds one more glob pass; bounded by excluding directory rules from the walk. B10 pins the cost.
- UTF-16 findings carry UTF-16 code-unit columns of the decoded text, and `treeDigest` for such a file hashes the decoded text (not raw bytes), so two byte-different encodings of the same text digest alike. Documented.
- The 5 MB pipe tests are slow (about 15 s per spawn in the lab); they live in the slow lane and the release gate, not the default CI run. The default CI run keeps B12 (above 64 KiB). Risk: a regression between 64 KiB and 5 MB is only caught by the slow lane; the release gate must run it (G8 area) and the QA agent runs it before merge.
- Lab numbers (BR) were taken at archive `0f66db3` / cli 0.8.0; this tree is `2bf3a7d` / 0.8.1. Treated as hypotheses until the fail-before runs.
- Not in scope (tracked, not fixed): `.gitignore` not honoured (BR I5); no scan timeout (BR O3); nested ignore asymmetry (BR I3); `.shipguardignore` missing (BR I6); `src/cli.ts` and `src/handlers.ts` direct `process.exit` calls (short output only); `--pro` untested in the lab (BR O10).

## E. Decisions from main and open questions

Main-session decisions (2026-11-02, round 2; they replace the round-1 "Main-session decisions" section):

- Q1: `*.log`, `*.min.js`, `vendor/`, `tmp/`, `out/` stay ignored by default and are counted in `coverage.ignoredByDefault` (never silently).
- Q2 (REVERSED, main was wrong in round 1): no empty-diff exemption. `--changed` with an empty diff is `NO_FILES_SCANNED`, degraded, DO_NOT_SHIP; B6 asserts it; a stderr hint explains it.
- Q3: `schemaVersion` 5 to 6.
- Q4 (changed): no extension list. Magic bytes count only for a file that `detectBinary` flags AND that is binary-dominant (D4).
- Open for the judges: none that block the build. Residual risks are in D.

## R. Round-2 map: where each decision now sits

1. Magic only when `detectBinary` is true; no-NUL files always strict UTF-8; head shortcut needs magic AND binary look; no extension; NUL-heavy no-magic => `UNSCANNED_UNKNOWN_BINARY`; spoof tests: D4, D2, A1 (order), A2 (shortcut), B1, B4, matrix mutations.
2. Q2 reversed, no exemption, stderr hint: E, A2 (last bullet), B6, D.
3. `-z` git output with no trim, shared ignore helper including `policy.ignore.paths`, `--changed` coverage fields: A2 (git and ignore bullets), A3 (coverage under `--changed`), B18, B19, B7.
4. UTF-16 before NUL-to-space, CJK-then-key, BOM-marked failure degraded, UTF-16 code-unit columns, BOM-less BE only with the parity signature: D3, D2, A1, B1, B2, B3.
5. Bug 2: no `process.exit` with queued data, `process.exitCode` and return, no 10 s timer, EPIPE handler, explicit handshake test that fails on reverted code: A5, B.3, B12, B13, B14, B16.
6. (round 2, REVERSED in round 3) `--check-regressions` behaviour is unchanged; see R3.
7. Mutation matrix over both read paths, R/G/D labels, NUL-split residual row, treeDigest CHANGELOG note: B.1 (types), B.2, B17, A6, D3.
8. Mandatory rehearsal on the `build:publish` tarball (B2, B4, B12, B13, spoofs): C0.
9. One field name pair, `ignoredByDefault` / `ignoredByUser`, used in D5, A2, A3, B7, B10, B18, E.

## R3. Round-3 map: every round-2 finding and main decision, and where it now sits

Round-2 findings (Judge and Codex, `out-r2.md`):
1. UTF-16 guessing hides intact secrets (`a` x 1000 + key + NUL; BOM-less BE CJK + key): scan every plausible reading and union the findings: D3 (ambiguity rule), A1, B23, mutation table. Decision 5.
2. Binary bypass remains (large file with PNG magic and NUL-heavy head; below-cap polyglot): head shortcut needs magic AND strict-UTF-8 failure, Gate 3 counts valid UTF-8 as printable; "degrade every heuristic exclusion" NOT adopted, recorded as an accepted residual with reasons: D4, D (binary-exclusion residual), B8 attack and real-asset rows, C0. Decisions 4 and 6.
3. EPIPE handler installed too late: handlers at startup in `cli.ts` for stdout and stderr, keep the computed exit code: A5, B16 telemetry-delay variant. Decision 2.
4. Nested-root `--changed` reads a clean sibling: rev-parse toplevel/prefix normalisation, `outsideScope` count: A2 (nested scan root), A3 (`changed` fields), B22. Decision 7.
5. Filename decoding aliases bytes: Buffer parsing, strict UTF-8 per name, undecodable name degraded with `UNREADABLE_FILE` (reuse justified in A2): A2, B19. Decision 8.
6. Pipe handshake cannot run (`process.exitCode` non-configurable on Node 24): wrap `process.exit` plus unref'd 5 ms interval, probe self-test: B.3, B21. Decision 3.
7. Mutation expectations overclaimed B16: bare-exit proof moved to B12/B13: mutation table, B16 text. Decision 2.
Main decision 1 (`--check-regressions`): round-2 change REVERSED, behaviour kept, only the stale comment at `scan.ts:62-64` is fixed; B20 is a guard; C1 step 4, D and CHANGELOG updated: A4, A6, B20, C1, D.
Main decision 9 (judge minors): `--changed` skipping default-ignored files disclosed in D and CHANGELOG, B18 row; `classifyIgnored` tests parent folders with rows; B18 fail-before cell rewritten in plain words: A2 (ignore helper), A6, B18, D.
