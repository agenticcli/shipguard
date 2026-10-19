// Input normalization functions — contract-side, pure, dependency-free.
// These functions define the canonical pre-processing that the CLI MUST apply
// to every file before passing it to a MatcherExecutor. CLI wiring (fs.ts /
// scanner.ts) is a separate later task (A-CLI-INT.1).
//
// DESIGN DECISIONS
// ================
// 1. decodeUtf8Strict: uses TextDecoder('utf-8', {fatal:true}) — the ONLY
//    valid decoding mode for this pipeline. The alternative (buffer.toString
//    'utf-8') silently replaces invalid byte sequences with U+FFFD (the
//    replacement character ''), which can destroy secrets that straddle an
//    invalid-UTF-8 boundary and cause a silent false-negative scan. We reject
//    loud: invalid UTF-8 → {ok:false, reason} → the CLI degrades loudly
//    (no silent failures).
//
// 2. UNICODE_NORMALIZATION_POLICY = "none": scanned content is NOT subjected
//    to NFC (or any other Unicode normalization form) before matching. Rationale:
//    secrets and sensitive tokens (API keys, passwords, connection strings) are
//    matched byte-accurately against user-authored source code. Applying NFC
//    normalization could transform the content into a form that no longer matches
//    the pattern (e.g. a combining character sequence appearing in a string
//    literal). The loss of byte-accuracy is a false-negative risk that outweighs
//    any benefit. If a rule author needs NFC-normalized matching they must express
//    it in the pattern itself. This is a DELIBERATE policy choice — not an
//    oversight.
//
// 3. normalizeNewlines: strips all \r before line slicing. This fixes the live
//    bug where CRLF line endings in Windows-authored files caused `line.split`
//    to produce lines ending with \r, breaking line-level anti-pattern matching
//    and suppression-key derivation. Bare \r (classic Mac line endings) is also
//    stripped — these do not form line breaks in the normalized content.
//    RATIONALE: normalizeNewlines is applied AFTER decoding and BOM stripping.
//    The resulting content uses only LF as a line separator, which is what all
//    offset/line/column computations in A.3 assume.
//
// 4. detectBinary: scans the ENTIRE buffer for NUL bytes (0x00) plus applies
//    a non-printable-byte-density heuristic over a configurable window.
//    The live bug was checking only the first 8192 bytes — a NUL at position
//    9000 in a file would be missed, causing garbage content (post-NUL binary
//    data decoded as replacement chars) to be pattern-matched. The fix:
//    NUL-anywhere (full-buffer scan) is the primary binary signal; the
//    density heuristic over a larger window is secondary.
//
// 5. hugeSingleLineCap: a single line exceeding this limit indicates a
//    minified file or binary-masquerading-as-text. The CLI should degrade
//    loudly (INCOMPLETE + non-safe) rather than attempt to match — matching a
//    very long line can cause catastrophic backtracking even in RE2 (linear
//    time per character, but a 100 MB line is expensive). The cap is generous
//    enough to never affect normal source code.
//
// PURE FUNCTIONS — no I/O, no side-effects.
// The CLI wires these into fs.ts / scanner.ts in Task A-CLI-INT.1.

// ---------------------------------------------------------------------------
// Unicode normalization policy (exported constant)
// ---------------------------------------------------------------------------

/**
 * The Unicode normalization policy applied to scanned file content.
 *
 * Value: `"none"` — no NFC (or any other) normalization is applied.
 *
 * Rationale: secrets are matched byte-accurately against user-authored source.
 * NFC normalization could alter combining character sequences appearing in
 * string literals, producing content that no longer matches the pattern — a
 * false-negative risk. Rule authors needing NFC-aware matching must express
 * it in the pattern itself.
 *
 * This is a deliberate, documented policy decision (Task A.5). Do NOT change
 * without updating this constant, the tests, and the pattern-authoring guide.
 */
export const UNICODE_NORMALIZATION_POLICY: string = 'none'

// ---------------------------------------------------------------------------
// hugeSingleLineCap
// ---------------------------------------------------------------------------

/**
 * Maximum length (in UTF-16 code units) of a single line in a file that the
 * scanner will attempt to match against.
 *
 * A line exceeding this length indicates a minified or binary-masquerading-
 * as-text file. The CLI MUST degrade loudly (INCOMPLETE + non-safe exit)
 * rather than pass such a line to a MatcherExecutor.
 *
 * The cap is deliberately generous (10 MiB in UTF-16 code units ≈ 10M chars)
 * to never affect normal source code, while providing a backstop against
 * pathological inputs.
 */
export const hugeSingleLineCap: number = 10 * 1024 * 1024 // 10 MiB in code units

// ---------------------------------------------------------------------------
// decodeUtf8Strict — reject invalid UTF-8, never produce replacement chars
// ---------------------------------------------------------------------------

/**
 * Decode a raw byte buffer as UTF-8 in strict (fatal) mode.
 *
 * Uses `TextDecoder('utf-8', {fatal: true})` which throws a TypeError on
 * any invalid byte sequence, including:
 * - Lone continuation bytes (0x80–0xBF without a leading byte)
 * - Overlong encodings (e.g. 0xC0 0x80 for U+0000)
 * - Truncated multi-byte sequences (leading byte without following continuation)
 * - Bytes that are never valid in UTF-8 (0xF5–0xFF, 0xC0, 0xC1)
 *
 * NEVER produces U+FFFD replacement characters (＂＂) on invalid input.
 * Replacement characters would silently destroy secrets straddling an
 * invalid-UTF-8 boundary, causing a false-negative scan — this is the live
 * bug documented in GROUND-TRUTH §1.
 *
 * @param buf - Raw file bytes (Uint8Array from fs.readFile or equivalent).
 * @returns `{ok: true, text}` on success, or `{ok: false, reason}` on failure.
 *   The caller MUST treat `{ok: false}` as a degrade signal: mark the scan
 *   result INCOMPLETE + non-safe and skip the file (do NOT scan with garbage).
 */
export function decodeUtf8Strict(
  buf: Uint8Array,
): { ok: true; text: string } | { ok: false; reason: string } {
  // TextDecoder is available in Node 16+ as a global (not a require).
  // In the contract package (used in tests via vitest/Node) and in the CLI
  // (tsup target node20) this is always available.
  try {
    const decoder = new TextDecoder('utf-8', { fatal: true })
    const text = decoder.decode(buf)
    return { ok: true, text }
  } catch (err: unknown) {
    const reason =
      err instanceof Error
        ? err.message
        : `Unknown UTF-8 decode error (${String(err)})`
    return { ok: false, reason }
  }
}

// ---------------------------------------------------------------------------
// stripBom — remove UTF-8 BOM (U+FEFF) from the start of decoded text
// ---------------------------------------------------------------------------

/**
 * Remove the UTF-8 BOM (U+FEFF, "ZERO WIDTH NO-BREAK SPACE") from the start
 * of a decoded string, if present.
 *
 * The UTF-8 BOM (byte sequence EF BB BF) is sometimes prepended to UTF-8
 * files on Windows. After UTF-8 decoding it appears as U+FEFF at position 0.
 * It must be stripped before pattern matching so that patterns anchored at
 * the start of a line are not broken.
 *
 * @param s - Decoded string (after decodeUtf8Strict).
 * @returns String with the leading BOM removed, or `s` unchanged if no BOM.
 */
export function stripBom(s: string): string {
  // U+FEFF = '﻿' (ZERO WIDTH NO-BREAK SPACE / BOM character)
  if (s.charCodeAt(0) === 0xfeff) {
    return s.slice(1)
  }
  return s
}

// ---------------------------------------------------------------------------
// normalizeNewlines — strip \r before line slicing (CRLF → LF, bare CR → "")
// ---------------------------------------------------------------------------

/**
 * Normalize line endings by stripping all carriage-return characters (`\r`).
 *
 * This is intentionally a GLOBAL strip (not `\r\n` → `\n` replacement):
 * - `\r\n` (Windows CRLF) becomes `\n` (LF) — the `\n` remains, preserving
 *   the line break.
 * - Bare `\r` (classic Mac line endings, CR-only) is removed — it does NOT
 *   become a line separator in the normalized representation. This is a
 *   simplification: CR-only files will have their lines concatenated. For
 *   the purposes of this scanner (modern source code), bare CR is treated as
 *   non-standard and normalized away rather than being preserved as a line
 *   separator.
 *
 * Must be applied AFTER `decodeUtf8Strict` and `stripBom`, and BEFORE any
 * line splitting, anti-pattern evaluation, or offset computation.
 *
 * @param s - Decoded, BOM-stripped string.
 * @returns String with all `\r` characters removed.
 */
export function normalizeNewlines(s: string): string {
  // Replace all \r globally. This handles both CRLF and bare CR in one pass.
  // Using replaceAll with a string is safe and avoids regex compilation cost.
  // eslint-disable-next-line no-control-regex -- literal CR is intentional here
  return s.replace(/\r/g, '')
}

// ---------------------------------------------------------------------------
// detectBinary — binary detection over a larger window + NUL-anywhere
// ---------------------------------------------------------------------------

/**
 * Heuristic binary-file detection.
 *
 * ## NUL-anywhere (primary signal)
 * A NUL byte (0x00) at ANY position in the buffer is an unambiguous binary
 * signal. Text files (UTF-8, ASCII) never contain NUL bytes. This fixes the
 * live bug where only the first 8192 bytes were checked — a NUL at position
 * 9000 would be missed, causing the scanner to attempt to match binary content
 * decoded as garbage/replacement characters.
 *
 * ## Non-printable-byte density (secondary signal)
 * If the first `BINARY_SCAN_WINDOW` bytes of the buffer contain more than
 * `BINARY_NON_PRINTABLE_THRESHOLD` of non-printable, non-whitespace bytes
 * (bytes in 0x01–0x08 and 0x0E–0x1F), the file is heuristically classified
 * as binary. This catches binary files that do not happen to contain NUL bytes
 * in the first window (rare in practice, but possible for some binary formats).
 *
 * ## Scan window
 * The NUL scan covers the ENTIRE buffer (no window — any NUL = binary).
 * The density heuristic scans up to `BINARY_SCAN_WINDOW` bytes (default 32 KiB).
 *
 * @param buf - Raw file bytes (before UTF-8 decoding).
 * @returns `true` if the buffer appears to be binary content.
 */
export function detectBinary(buf: Uint8Array): boolean {
  if (buf.length === 0) return false

  // --- NUL-anywhere scan (primary, full buffer) ---
  // The live bug only scanned the first 8192 bytes. We scan all bytes.
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0x00) return true
  }

  // --- Non-printable byte density heuristic (secondary, scan window) ---
  const BINARY_SCAN_WINDOW = 32 * 1024 // 32 KiB
  const BINARY_NON_PRINTABLE_THRESHOLD = 0.3 // 30% of the window

  const windowLen = Math.min(buf.length, BINARY_SCAN_WINDOW)
  let nonPrintableCount = 0

  for (let i = 0; i < windowLen; i++) {
    const b = buf[i]
    // Control characters excluding common whitespace (TAB=0x09, LF=0x0A, CR=0x0D, FF=0x0C)
    const isWhitespaceControl = b === 0x09 || b === 0x0a || b === 0x0c || b === 0x0d
    if (!isWhitespaceControl && b < 0x20) {
      nonPrintableCount++
    }
  }

  return nonPrintableCount / windowLen > BINARY_NON_PRINTABLE_THRESHOLD
}
