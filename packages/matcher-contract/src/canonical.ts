// RFC 8785 (JCS — JSON Canonicalization Scheme) implementation.
// Reference: https://www.rfc-editor.org/rfc/rfc8785
//
// DESIGN DECISIONS
// ================
// 1. Dependency-free: this module is bundled into the CLI via tsup noExternal;
//    no external libs allowed.
//
// 2. Key sorting: lexicographic by UTF-16 code unit (RFC 8785 §3.2.3).
//    Implemented via native JS string comparison (<, >) which operates on
//    UTF-16 code units by definition. localeCompare is explicitly NOT used.
//
// 3. Number serialization: RFC 8785 §3.2.2 defers to ES2019 Number::toString.
//    JS String(n) implements ES2019 ToString (ECMA-262 §7.1.12.1):
//      - -0 → "0" (RFC 8785 §3.2.2.3; handled explicitly via Object.is)
//      - NaN / ±Infinity: not valid JSON → TypeError (fail loud)
//      - Finite: shortest round-trip representation.
//        ECMA-262 §7.1.12.1 uses scientific notation only when the adjusted
//        exponent (n) satisfies n < -6 or n >= 21. Examples:
//          1.5e20   → "150000000000000000000" (exp=20, < 21 → decimal)
//          1.5e21   → "1.5e+21"               (exp=21 ≥ 21 → scientific)
//          1.5e-7   → "1.5e-7"                (exp=-7, < -6 → scientific)
//          1.5e-6   → "0.0000015"             (exp=-6 = -6, NOT < -6 → decimal)
//        This IS the correct RFC 8785 behaviour — test expectations must
//        match JS's actual String(n) output, not a human's mental model.
//    JUDGMENT CALL: RFC 8785 §3.2.2 says
//    "the serialization rules for Number values are identical to those
//    used in the ES2020 specification for JSON.stringify", which defers to
//    the abstract operation Number::toString. JS String(n) and
//    JSON.stringify(n) produce the same result for finite non-null numbers.
//    We use String(n) directly (equivalent to JSON.stringify for numbers).
//
// 4. parseStrictNoDup: pre-scan with a lightweight tokenizer before JSON.parse.
//    A reviver-based approach cannot reliably detect duplicates because the
//    reviver is called after the JS engine has already overwritten the
//    duplicate key on the holder object — only the final value remains visible.
//    The tokenizer approach scans the raw string character-by-character,
//    tracking per-object-scope Set<string> of seen keys, before delegating
//    actual parsing to JSON.parse.
//
// Phase C will import canonicalJson for crypto signing preimages.
// parseStrictNoDup is the gatekeeper before any canonicalization.

import type { CanonicalFinding } from './finding.js'

// ---------------------------------------------------------------------------
// Internal: RFC 8785 number serialization
// ---------------------------------------------------------------------------

function serializeNumber(n: number): string {
  if (Number.isNaN(n) || !Number.isFinite(n)) {
    throw new TypeError(
      `canonicalJson: NaN and Infinity are not valid JSON values (got ${n})`,
    )
  }
  // matcher spec §2: reject fractional and unsafe-integer numbers in
  // signed objects.  A non-safe-integer or fractional number in the preimage of a
  // cryptographically-signed object is a protocol violation — different JSON parsers
  // may represent the same IEEE 754 double with different decimal expansions, making
  // the canonical form ambiguous and enabling canonicalization-confusion attacks.
  // Safe integers are in the range [-(2^53-1), 2^53-1] with no fractional part.
  // RFC 8785 §3.2.2 defers to ES2019 Number::toString which is deterministic for
  // safe integers; for non-safe integers the shortest-decimal algorithm may diverge
  // across engines. We fail loudly rather than silently producing an unsafe preimage.
  if (!Number.isSafeInteger(n) && !Object.is(n, -0)) {
    throw new TypeError(
      `canonicalJson: number ${n} is not a safe integer — fractional or out-of-range ` +
      `numbers are rejected in signed objects (matcher spec §2). ` +
      `Only safe integers (−2^53+1 to 2^53−1) are permitted.`,
    )
  }
  // RFC 8785 §3.2.2.3: negative zero MUST be serialized as "0".
  if (Object.is(n, -0)) return '0'
  // ES2019 Number::toString() — JS String() implements this.
  // This produces the shortest round-trip decimal representation, switching
  // to scientific notation only for |exponent| meeting ECMA-262 §7.1.12.1 thresholds.
  return String(n)
}

// ---------------------------------------------------------------------------
// Internal: RFC 8785 string escaping
// ---------------------------------------------------------------------------

function serializeString(s: string): string {
  // RFC 8785 §3.2.1: strings use standard JSON escaping.
  // JSON.stringify on a string value (not an object) produces the correctly
  // escaped result including surrounding quotes.
  return JSON.stringify(s)
}

// ---------------------------------------------------------------------------
// Internal: recursive RFC 8785 serialization
// ---------------------------------------------------------------------------

function serializeValue(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') return serializeNumber(value)
  if (typeof value === 'string') return serializeString(value)

  if (Array.isArray(value)) {
    // RFC 8785 §3.2.4: arrays preserve element order (no sorting).
    const items = (value as unknown[]).map(serializeValue)
    return '[' + items.join(',') + ']'
  }

  if (typeof value === 'object') {
    // RFC 8785 §3.2.3: object members sorted by key using UTF-16 code-unit
    // comparison. Native JS string comparison (<, >) IS this algorithm.
    // localeCompare is explicitly NOT used (locale-dependent, platform-variable).
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort((a, b) => {
      if (a < b) return -1
      if (a > b) return 1
      return 0
    })
    const members = keys.map((k) => serializeString(k) + ':' + serializeValue(obj[k]))
    return '{' + members.join(',') + '}'
  }

  // undefined, function, symbol — not representable in JSON; throw loudly.
  throw new TypeError(
    `canonicalJson: value of type "${typeof value}" is not representable in JSON`,
  )
}

// ---------------------------------------------------------------------------
// Public API: canonicalJson
// ---------------------------------------------------------------------------

/**
 * Produce an RFC 8785 (JCS) canonical JSON string for `value`.
 *
 * Guarantees:
 * - Keys of every object are sorted lexicographically by UTF-16 code unit
 *   (§3.2.3). Locale-independent: native JS string comparison, NOT localeCompare.
 * - No insignificant whitespace (§3.2).
 * - Numbers: ES2019 Number::toString (§3.2.2); -0 → "0" (§3.2.2.3).
 * - Strings: standard JSON escaping (§3.2.1).
 * - Arrays: element order preserved (§3.2.4).
 * - NaN / ±Infinity: throws TypeError (not valid JSON).
 * - undefined / function / symbol: throws TypeError.
 *
 * This function is PURE and dependency-free. It is used as the canonical
 * preimage for Phase C cryptographic signatures.
 *
 * @param value - Any JSON-representable value.
 * @returns RFC 8785 canonical JSON string.
 * @throws TypeError if value contains NaN, ±Infinity, undefined, function, or symbol.
 */
export function canonicalJson(value: unknown): string {
  return serializeValue(value)
}

// ---------------------------------------------------------------------------
// Internal: lightweight tokenizer for duplicate-key detection
// ---------------------------------------------------------------------------

/**
 * Scan a JSON string for duplicate object member names at any nesting level.
 * Returns the first duplicate key found, or null if none.
 *
 * This is a minimal state-machine tokenizer — just enough to find string keys
 * inside objects. It is NOT a general-purpose JSON parser; JSON syntax
 * validity is delegated to JSON.parse (which runs after this scan).
 *
 * Runs BEFORE JSON.parse so duplicate keys are caught even when JSON.parse
 * silently last-wins.
 */
function findDuplicateKey(json: string): string | null {
  const len = json.length
  let i = 0
  let duplicateKey: string | null = null

  function skipWs(): void {
    while (i < len && (json[i] === ' ' || json[i] === '\t' || json[i] === '\n' || json[i] === '\r')) {
      i++
    }
  }

  // Consume a JSON string starting at i (which must point at `"`).
  // Returns the raw string content (escape sequences preserved as-is for key comparison).
  function consumeStr(): string {
    i++ // skip opening `"`
    let s = ''
    while (i < len) {
      const c = json[i]
      if (c === '\\') {
        i++
        const esc = json[i++]
        if (esc === 'u') {
          // \uXXXX — decode for accurate key comparison
          s += String.fromCharCode(parseInt(json.slice(i, i + 4), 16))
          i += 4
        } else {
          // Other escapes: append the escaped character directly (simplified).
          // Sufficient for key identity detection.
          s += esc
        }
      } else if (c === '"') {
        i++ // skip closing `"`
        break
      } else {
        s += c
        i++
      }
    }
    return s
  }

  // Recursively scan a JSON value, populating duplicateKey on first dup found.
  function scanValue(): void {
    skipWs()
    if (i >= len || duplicateKey) return
    const ch = json[i]

    if (ch === '"') {
      consumeStr()
    } else if (ch === '{') {
      i++ // skip `{`
      const scope = new Set<string>()
      skipWs()
      if (i < len && json[i] === '}') { i++; return } // empty object
      while (i < len) {
        if (duplicateKey) return
        skipWs()
        if (i >= len || json[i] !== '"') break // malformed JSON — JSON.parse will error
        const key = consumeStr()
        if (duplicateKey) return
        if (scope.has(key)) { duplicateKey = key; return }
        scope.add(key)
        skipWs()
        if (i < len && json[i] === ':') i++ // skip `:`
        scanValue()
        if (duplicateKey) return
        skipWs()
        if (i < len && json[i] === ',') { i++; continue }
        if (i < len && json[i] === '}') { i++; return }
        break
      }
    } else if (ch === '[') {
      i++ // skip `[`
      skipWs()
      if (i < len && json[i] === ']') { i++; return } // empty array
      while (i < len) {
        if (duplicateKey) return
        scanValue()
        skipWs()
        if (i < len && json[i] === ',') { i++; continue }
        if (i < len && json[i] === ']') { i++; return }
        break
      }
    } else {
      // Primitive (number, true, false, null): scan to next delimiter.
      while (
        i < len &&
        json[i] !== ',' && json[i] !== '}' && json[i] !== ']' &&
        json[i] !== ' ' && json[i] !== '\t' && json[i] !== '\n' && json[i] !== '\r'
      ) {
        i++
      }
    }
  }

  scanValue()
  return duplicateKey
}

// ---------------------------------------------------------------------------
// Public API: parseStrictNoDup
// ---------------------------------------------------------------------------

/**
 * Parse a JSON string, REJECTING any input that contains duplicate object
 * member names at any nesting level.
 *
 * ## Why this matters (RFC 8785 + threat model)
 * Standard JSON parsers (including JSON.parse) accept duplicate keys and
 * silently resolve them — typically last-wins. A duplicate-key payload could
 * be used to confuse a verifier: sign `{"a":1,"a":2}` and exploit the
 * receiver's parser resolving it differently than the signer's. RFC 8785
 * requires rejecting duplicates before canonicalization.
 *
 * ## Implementation
 * Pre-scan with a lightweight tokenizer (findDuplicateKey) that detects
 * duplicate keys at every nesting level BEFORE JSON.parse sees the input.
 * Note: a JSON.parse reviver approach cannot reliably detect duplicates
 * because the reviver is called AFTER the engine has already overwritten the
 * duplicate key — only the final value is visible.
 *
 * @param json - Raw JSON string.
 * @returns The parsed value (unknown — callers cast to their expected type).
 * @throws SyntaxError if json is not valid JSON.
 * @throws Error with "Duplicate JSON key" if any object has duplicate members.
 */
export function parseStrictNoDup(json: string): unknown {
  const dup = findDuplicateKey(json)
  if (dup !== null) {
    throw new Error(
      `Duplicate JSON key "${dup}" — duplicate object members are rejected (RFC 8785 / parseStrictNoDup)`,
    )
  }
  // JSON.parse handles all remaining validation (syntax errors, type coercion, etc.).
  return JSON.parse(json) as unknown
}

// ---------------------------------------------------------------------------
// Public API: canonicalizeFinding
// ---------------------------------------------------------------------------

/**
 * Produce a canonical plain-object representation of a CanonicalFinding
 * suitable for passing to canonicalJson.
 *
 * ## Excluded from canonical form
 * - Timestamps: CanonicalFinding carries no timestamp fields; any extra
 *   properties on the input are stripped by explicit field selection.
 * - Absolute paths: file must be root-relative (no leading `/`). This
 *   function preserves the file field as-is — callers are responsible for
 *   providing root-relative paths.
 *
 * ## Key ordering
 * The returned object has keys in insertion order. canonicalJson sorts them
 * by UTF-16 code unit — the insertion order here is irrelevant to output.
 *
 * ## Sort / dedup comparator
 * Compare findings by canonicalJson(canonicalizeFinding(f)) — this comparator
 * is locale-independent (pure UTF-16 code unit ordering from canonicalJson).
 *
 * @param f - A CanonicalFinding (only the 10 mandatory fields are included;
 *   extra properties are dropped).
 * @returns A plain object with exactly the 10 canonical fields.
 */
export function canonicalizeFinding(f: CanonicalFinding): Record<string, unknown> {
  // Explicit field selection strips timestamps and unknown properties.
  return {
    blocking: f.blocking,
    column: f.column,
    evidence: f.evidence,
    file: f.file,
    id: f.id,
    line: f.line,
    matcherType: f.matcherType,
    releaseId: f.releaseId,
    severity: f.severity,
    suppressionState: f.suppressionState,
  }
}
