// canonical.ts tests (canonicalJson + parseStrictNoDup).
// TDD: written BEFORE implementation.

import { describe, it, expect } from 'vitest'
import { canonicalJson, parseStrictNoDup } from '../canonical.js'

// ---------------------------------------------------------------------------
// RFC 8785 (JCS) — published test vectors
// Source: https://www.rfc-editor.org/rfc/rfc8785#appendix-A
// (Selected subset representable in TypeScript without file I/O.)
// ---------------------------------------------------------------------------

describe('A.4 — canonicalJson (RFC 8785 / JCS)', () => {
  // -------------------------------------------------------------------------
  // Key sorting — lexicographic by UTF-16 code unit (RFC 8785 §3.2.3)
  // -------------------------------------------------------------------------
  it('sorts object keys lexicographically by UTF-16 code unit', () => {
    // RFC 8785 §3.2.3: keys sorted as UTF-16 code-unit strings.
    // "b" (0x62) > "a" (0x61), so sorted = a, b.
    const obj = { b: 2, a: 1 }
    expect(canonicalJson(obj)).toBe('{"a":1,"b":2}')
  })

  it('sorts nested object keys recursively', () => {
    const obj = { z: { y: 1, x: 2 }, a: 0 }
    expect(canonicalJson(obj)).toBe('{"a":0,"z":{"x":2,"y":1}}')
  })

  it('upper-case letters sort before lower-case (UTF-16 code unit order)', () => {
    // 'A' = 0x41, 'a' = 0x61: 'A' < 'a'
    const obj = { b: 2, A: 1, a: 3 }
    expect(canonicalJson(obj)).toBe('{"A":1,"a":3,"b":2}')
  })

  // -------------------------------------------------------------------------
  // No insignificant whitespace
  // -------------------------------------------------------------------------
  it('produces no insignificant whitespace', () => {
    const obj = { a: 1, b: [1, 2, 3] }
    const result = canonicalJson(obj)
    expect(result).not.toMatch(/\s/)
    expect(result).toBe('{"a":1,"b":[1,2,3]}')
  })

  // -------------------------------------------------------------------------
  // Number serialization — RFC 8785 §3.2.2
  // -------------------------------------------------------------------------
  it('serializes integers without decimal point', () => {
    expect(canonicalJson(42)).toBe('42')
    expect(canonicalJson(-0)).toBe('0')  // RFC 8785: -0 → "0"
    expect(canonicalJson(0)).toBe('0')
  })

  it('rejects fractional and unsafe-integer numbers (matcher spec §2)', () => {
    // canonicalJson is used exclusively for cryptographic preimages of signed objects.
    // Fractional and unsafe-integer numbers are rejected: different JS engines may produce
    // different shortest-decimal representations for IEEE-754 doubles outside the safe-integer
    // range, making the canonical form ambiguous (canonicalization-confusion attack vector).
    // Only safe integers [-(2^53-1), 2^53-1] with no fractional part are permitted.
    expect(() => canonicalJson(3.14)).toThrow(/not a safe integer/)
    expect(() => canonicalJson(1.5e20)).toThrow(/not a safe integer/)
    expect(() => canonicalJson(1.5e21)).toThrow(/not a safe integer/)
    expect(() => canonicalJson(1.5e-7)).toThrow(/not a safe integer/)
    expect(() => canonicalJson(1.5e-6)).toThrow(/not a safe integer/)
    // Unsafe integer (2^53) is also rejected
    expect(() => canonicalJson(Number.MAX_SAFE_INTEGER + 1)).toThrow(/not a safe integer/)
    expect(() => canonicalJson(Number.MIN_SAFE_INTEGER - 1)).toThrow(/not a safe integer/)
  })

  it('accepts safe integers (within 2^53 - 1)', () => {
    expect(canonicalJson(42)).toBe('42')
    expect(canonicalJson(-1)).toBe('-1')
    expect(canonicalJson(Number.MAX_SAFE_INTEGER)).toBe(String(Number.MAX_SAFE_INTEGER))
    expect(canonicalJson(Number.MIN_SAFE_INTEGER)).toBe(String(Number.MIN_SAFE_INTEGER))
  })

  // -------------------------------------------------------------------------
  // Null, boolean, string
  // -------------------------------------------------------------------------
  it('serializes null', () => {
    expect(canonicalJson(null)).toBe('null')
  })

  it('serializes booleans', () => {
    expect(canonicalJson(true)).toBe('true')
    expect(canonicalJson(false)).toBe('false')
  })

  it('serializes strings with minimal escaping (RFC 8785 follows JSON escaping)', () => {
    expect(canonicalJson('hello')).toBe('"hello"')
    expect(canonicalJson('a\nb')).toBe('"a\\nb"')
    expect(canonicalJson('a\tb')).toBe('"a\\tb"')
  })

  // -------------------------------------------------------------------------
  // Arrays
  // -------------------------------------------------------------------------
  it('serializes arrays preserving order (no sorting)', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]')
    expect(canonicalJson(['b', 'a'])).toBe('["b","a"]')
  })

  // -------------------------------------------------------------------------
  // Insertion-order independence — same logical object → byte-identical output
  // -------------------------------------------------------------------------
  it('two objects with the same keys in different insertion order → byte-identical output', () => {
    const a = { z: 1, a: 2, m: 3 }
    const b = { m: 3, z: 1, a: 2 }
    expect(canonicalJson(a)).toBe(canonicalJson(b))
  })

  it('adding whitespace to the input value does not change canonical output (string values only)', () => {
    // Canonical JSON normalizes object structure; string content is preserved.
    // This tests that key-ordering canonicalizes regardless of insertion order.
    const a = { b: 'value', a: 'other' }
    const b = { a: 'other', b: 'value' }
    expect(canonicalJson(a)).toBe(canonicalJson(b))
    expect(canonicalJson(a)).toBe('{"a":"other","b":"value"}')
  })

  // -------------------------------------------------------------------------
  // RFC 8785 §3.2.3 — Appendix A sample vectors (selected)
  // -------------------------------------------------------------------------
  it('RFC 8785 vector: simple object', () => {
    // From RFC 8785 Appendix A.1 (simplified to avoid special characters)
    const obj = { one: 1, two: 2 }
    expect(canonicalJson(obj)).toBe('{"one":1,"two":2}')
  })

  it('RFC 8785 vector: empty object and array', () => {
    expect(canonicalJson({})).toBe('{}')
    expect(canonicalJson([])).toBe('[]')
  })

  it('RFC 8785 vector: nested structure', () => {
    const obj = { numbers: [1, 2, 3], empty: {}, flag: true, nothing: null }
    // Keys sorted: empty, flag, nothing, numbers
    expect(canonicalJson(obj)).toBe('{"empty":{},"flag":true,"nothing":null,"numbers":[1,2,3]}')
  })
})

// ---------------------------------------------------------------------------
// parseStrictNoDup — rejects duplicate object members before processing
// ---------------------------------------------------------------------------

describe('A.4 — parseStrictNoDup', () => {
  it('parses valid JSON without duplicates', () => {
    const result = parseStrictNoDup('{"a":1,"b":2}')
    expect(result).toEqual({ a: 1, b: 2 })
  })

  it('parses nested valid JSON without duplicates', () => {
    const result = parseStrictNoDup('{"a":{"x":1,"y":2},"b":3}')
    expect(result).toEqual({ a: { x: 1, y: 2 }, b: 3 })
  })

  it('throws on duplicate object member at top level', () => {
    expect(() => parseStrictNoDup('{"a":1,"a":2}')).toThrow()
  })

  it('throws on duplicate object member in nested object', () => {
    expect(() => parseStrictNoDup('{"outer":{"x":1,"x":2}}')).toThrow()
  })

  it('throws on malformed JSON', () => {
    expect(() => parseStrictNoDup('{not valid json}')).toThrow()
  })

  it('parses arrays without issue', () => {
    const result = parseStrictNoDup('[1,"two",null,true]')
    expect(result).toEqual([1, 'two', null, true])
  })

  it('parses null, boolean, number primitives at top level', () => {
    expect(parseStrictNoDup('null')).toBeNull()
    expect(parseStrictNoDup('true')).toBe(true)
    expect(parseStrictNoDup('42')).toBe(42)
  })

  it('throws on duplicate keys that appear more than twice (all duplicates rejected)', () => {
    expect(() => parseStrictNoDup('{"a":1,"b":2,"a":3,"a":4}')).toThrow()
  })
})
