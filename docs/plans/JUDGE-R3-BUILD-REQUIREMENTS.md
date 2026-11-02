# Plan judge round 3: GO with conditions (2026-11-02, Opus high, plan head ef9dc5b6)
These are build requirements: each must be implemented, with the named test, before code review.

## MAJOR (must fix in the build)
1. D4:59 head shortcut. Run the strict-UTF-8 test on `head[magicLength..]` only, never on the magic bytes. Many magic values start with a non-UTF-8 byte (PNG 0x89, JPEG FF, GZIP 8B, Mach-O, Java class, 7z, XZ), so testing them always "fails" and the file is skipped. Keep the B8 attack row (PNG magic, then 4 KiB of NULs, then a key, file over 512 KiB, must give FILE_TOO_LARGE or degraded) and add JPEG and GZIP variants.
2. D3:47 / A1 mixed encodings. Add a byte-wise ASCII reading to the union for EVERY file classified as text, with or without a BOM. Each byte outside TAB/LF/CR/0x20-0x7E becomes a space, so line numbers are unchanged. Fixtures for the B23 matrix: (a) an ASCII .env with a key, then an appended UTF-16LE block (PowerShell 5.1 `>>`); (b) a BOM'd UTF-16LE file with ASCII and a key appended. Both must find the key.
3. A2:132 filename aliasing on the full-scan path. When any discovered path contains U+FFFD, re-list its folder with `readdirSync(dir, {encoding:'buffer'})`. Any name that is not valid UTF-8 becomes UNREADABLE_FILE (degraded). Add a full-path row to B19: `a\xFF.env` (with a key) next to `a�.env` (clean).
4. A2:133 nested root. Pass `-c diff.relative=false` (or `--no-relative`) to every git diff call. Add a B22 variant with `diff.relative=true` set in the repo's git config.

## Residual wording (required)
- Rewrite D and the CHANGELOG to name the formats that are counted but not scanned: SQLite (e.g. Prisma dev.db), uncompressed TAR, and string tables in ELF/PE/class/WASM. Drop the "needs a deliberate attacker" reasoning.
- Recommended, tracked rather than required: apply the MAJOR-2 ASCII reading to uncompressed formats under the size cap. Main decision: DO IT for SQLite and TAR under the cap, since it is cheap and closes the Prisma dev.db case.

## MINOR (fix in the build)
- A1:109-120: no early return at step 4. Every reading goes into `texts[]`. Update B1's type test.
- A3:161: add `coverage.decoded.multiReading`, and add it to the freeze test.
- D3:47: de-duplicate by rule + line only across the readings of ONE file. Keep `collapseSameIssueFindings` unchanged (collapse-findings.ts:128-140).
- Mutation row: magic prefix + UTF-16LE ASCII text + a key must be found. This guards against moving the real-binary step before the UTF-16 step.
- Track only, out of scope: under --changed a deleted file is counted UNREADABLE_FILE, which is a false degrade (consider `--diff-filter=d`).
