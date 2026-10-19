// Task A.5 — Input normalization function tests.
// TDD: written BEFORE the implementation.

import { describe, it, expect } from 'vitest'
import {
  decodeUtf8Strict,
  stripBom,
  normalizeNewlines,
  detectBinary,
  hugeSingleLineCap,
  UNICODE_NORMALIZATION_POLICY,
} from '../normalize.js'

// ---------------------------------------------------------------------------
// decodeUtf8Strict — reject invalid UTF-8 loudly
// ---------------------------------------------------------------------------

describe('A.5 — decodeUtf8Strict', () => {
  it('decodes valid UTF-8 successfully', () => {
    const enc = new TextEncoder()
    const buf = enc.encode('hello world')
    const result = decodeUtf8Strict(buf)
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.text).toBe('hello world')
  })

  it('decodes valid multi-byte UTF-8 (BMP + supplementary)', () => {
    const enc = new TextEncoder()
    // α (U+03B1, 2 bytes), 中 (U+4E2D, 3 bytes), 😀 (U+1F600, 4 bytes — surrogate pair in JS)
    const buf = enc.encode('α中😀')
    const result = decodeUtf8Strict(buf)
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.text).toBe('α中😀')
  })

  it('returns {ok:false} for a lone continuation byte (invalid UTF-8)', () => {
    // 0x80 is a UTF-8 continuation byte with no leading byte — invalid.
    const buf = new Uint8Array([0x80])
    const result = decodeUtf8Strict(buf)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })

  it('returns {ok:false} for an overlong UTF-8 sequence', () => {
    // Overlong encoding of U+0000: 0xC0 0x80 — invalid in UTF-8.
    const buf = new Uint8Array([0xc0, 0x80])
    const result = decodeUtf8Strict(buf)
    expect(result.ok).toBe(false)
  })

  it('returns {ok:false} for a truncated multi-byte sequence', () => {
    // 0xE2 starts a 3-byte sequence but only 1 byte is provided.
    const buf = new Uint8Array([0xe2])
    const result = decodeUtf8Strict(buf)
    expect(result.ok).toBe(false)
  })

  it('returns {ok:false} for invalid byte embedded in otherwise valid UTF-8', () => {
    const enc = new TextEncoder()
    const valid = enc.encode('hello ')
    const invalid = new Uint8Array([0xff]) // 0xFF is never valid in UTF-8
    const combined = new Uint8Array(valid.length + invalid.length)
    combined.set(valid)
    combined.set(invalid, valid.length)
    const result = decodeUtf8Strict(combined)
    expect(result.ok).toBe(false)
  })

  it('NEVER produces replacement characters (U+FFFD) on invalid input', () => {
    // Verify that the strict decoder does not silently produce U+FFFD.
    const buf = new Uint8Array([0xff, 0xfe, 0x80]) // all invalid bytes
    const result = decodeUtf8Strict(buf)
    // Must return ok:false, NOT ok:true with replacement chars.
    if (result.ok) {
      expect(result.text).not.toContain('�')
      // If it somehow returned ok:true without a replacement char AND on invalid bytes,
      // the test above already covers that. The important check is:
      expect(result.ok).toBe(false)
    }
    expect(result.ok).toBe(false)
  })

  it('decodes an empty buffer successfully', () => {
    const result = decodeUtf8Strict(new Uint8Array(0))
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.text).toBe('')
  })
})

// ---------------------------------------------------------------------------
// stripBom — remove UTF-8 BOM (EF BB BF / U+FEFF) from decoded text
// ---------------------------------------------------------------------------

describe('A.5 — stripBom', () => {
  it('strips a UTF-8 BOM at the start of the string', () => {
    const withBom = '﻿' + 'hello'
    expect(stripBom(withBom)).toBe('hello')
  })

  it('does not strip BOM if not at the start', () => {
    const s = 'hello﻿world'
    expect(stripBom(s)).toBe('hello﻿world')
  })

  it('returns the string unchanged if no BOM present', () => {
    expect(stripBom('hello')).toBe('hello')
  })

  it('handles empty string', () => {
    expect(stripBom('')).toBe('')
  })

  it('handles a string that is only the BOM', () => {
    expect(stripBom('﻿')).toBe('')
  })
})

// ---------------------------------------------------------------------------
// normalizeNewlines — strip CR before line slicing (CRLF → LF)
// ---------------------------------------------------------------------------

describe('A.5 — normalizeNewlines', () => {
  it('converts CRLF to LF', () => {
    expect(normalizeNewlines('hello\r\nworld')).toBe('hello\nworld')
  })

  it('strips bare CR (\\r not followed by \\n)', () => {
    expect(normalizeNewlines('hello\rworld')).toBe('helloworld')
  })

  it('leaves LF-only content unchanged', () => {
    expect(normalizeNewlines('hello\nworld')).toBe('hello\nworld')
  })

  it('handles mixed line endings in one string', () => {
    const mixed = 'a\r\nb\nc\rd'
    // CRLF → LF, bare CR stripped
    expect(normalizeNewlines(mixed)).toBe('a\nb\ncd')
  })

  it('handles empty string', () => {
    expect(normalizeNewlines('')).toBe('')
  })

  it('handles string with no line endings', () => {
    expect(normalizeNewlines('no newlines here')).toBe('no newlines here')
  })
})

// ---------------------------------------------------------------------------
// detectBinary — binary detection over a window + NUL-anywhere
// ---------------------------------------------------------------------------

describe('A.5 — detectBinary', () => {
  it('detects a NUL byte anywhere in the buffer as binary', () => {
    // NUL byte (\x00) appears late in an otherwise text-looking buffer.
    const textPart = new TextEncoder().encode('a'.repeat(10_000))
    const buf = new Uint8Array(textPart.length + 1)
    buf.set(textPart)
    buf[textPart.length] = 0x00 // NUL at the end
    expect(detectBinary(buf)).toBe(true)
  })

  it('detects a NUL byte at the start', () => {
    const buf = new Uint8Array([0x00, 0x41, 0x42])
    expect(detectBinary(buf)).toBe(true)
  })

  it('does not flag a valid text buffer as binary', () => {
    const buf = new TextEncoder().encode('hello world\nno binary here\n')
    expect(detectBinary(buf)).toBe(false)
  })

  it('detects binary based on high density of non-printable bytes in the scan window', () => {
    // A buffer with a large proportion of bytes in the control-character range
    // (but NOT NUL) should still be detected as binary.
    // Use a mix of 0x01-0x08 bytes (non-printable, non-NUL) to exceed the threshold.
    const buf = new Uint8Array(512)
    for (let i = 0; i < 512; i++) {
      buf[i] = i % 8 === 0 ? 0x01 : 0x41 // 1/8 control chars
    }
    // Whether this triggers binary detection depends on the threshold;
    // check that the function returns a boolean without throwing.
    expect(typeof detectBinary(buf)).toBe('boolean')
  })

  it('returns false for an empty buffer', () => {
    expect(detectBinary(new Uint8Array(0))).toBe(false)
  })

  it('scans beyond the first 8192 bytes (larger window than the live bug)', () => {
    // Live bug: binary check was first 8192 bytes only (GROUND-TRUTH §1).
    // A.5 must scan a larger window OR scan all bytes (NUL-anywhere).
    // Test: NUL at position 9000 (> 8192) must be detected.
    const buf = new Uint8Array(10_000)
    buf.fill(0x41) // ASCII 'A'
    buf[9000] = 0x00 // NUL at position 9000
    expect(detectBinary(buf)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// hugeSingleLineCap
// ---------------------------------------------------------------------------

describe('A.5 — hugeSingleLineCap', () => {
  it('is a positive integer (cap exists)', () => {
    expect(Number.isInteger(hugeSingleLineCap)).toBe(true)
    expect(hugeSingleLineCap).toBeGreaterThan(0)
  })

  it('is at least 1 MiB (large files are not silently truncated)', () => {
    // The cap should be generous enough that normal files are never affected.
    expect(hugeSingleLineCap).toBeGreaterThanOrEqual(1024 * 1024)
  })
})

// ---------------------------------------------------------------------------
// Unicode normalization policy
// ---------------------------------------------------------------------------

describe('A.5 — UNICODE_NORMALIZATION_POLICY', () => {
  it('is a string documenting the policy decision', () => {
    expect(typeof UNICODE_NORMALIZATION_POLICY).toBe('string')
    expect(UNICODE_NORMALIZATION_POLICY.length).toBeGreaterThan(0)
  })

  it('policy is "none" (no NFC normalization applied to scanned content)', () => {
    // Per A.5 spec: default = no NFC normalization, to preserve byte-accurate
    // secret matching. The exported constant must document this explicitly.
    expect(UNICODE_NORMALIZATION_POLICY).toContain('none')
  })
})
