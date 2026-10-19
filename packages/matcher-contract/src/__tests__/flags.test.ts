// Flags strict enum tests.

import { describe, it, expect } from 'vitest'
import { parseFlags } from '../flags.js'
import type { Flag } from '../flags.js'

describe('A.6 — parseFlags strict enum', () => {
  // --- Accepted inputs ---

  it('accepts empty string (no flags)', () => {
    const result = parseFlags('')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.flags.size).toBe(0)
    }
  })

  it('accepts "i" alone', () => {
    const result = parseFlags('i')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.flags.has('i')).toBe(true)
    }
  })

  it('accepts "m" alone', () => {
    const result = parseFlags('m')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.flags.has('m')).toBe(true)
    }
  })

  it('accepts "s" alone', () => {
    const result = parseFlags('s')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.flags.has('s')).toBe(true)
    }
  })

  it('accepts "im" (two valid flags)', () => {
    const result = parseFlags('im')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.flags.has('i')).toBe(true)
      expect(result.flags.has('m')).toBe(true)
      expect(result.flags.size).toBe(2)
    }
  })

  it('accepts "ims" (all three valid flags)', () => {
    const result = parseFlags('ims')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.flags.size).toBe(3)
    }
  })

  it('accepts "si" (order does not matter)', () => {
    const result = parseFlags('si')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.flags.has('s')).toBe(true)
      expect(result.flags.has('i')).toBe(true)
    }
  })

  // --- Rejected inputs (unsupported JS/PCRE flags) ---

  it('rejects "g" with a reason', () => {
    const result = parseFlags('g')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBeTruthy()
      expect(result.reason).toMatch(/g/)
    }
  })

  it('rejects "y" with a reason', () => {
    const result = parseFlags('y')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBeTruthy()
    }
  })

  it('rejects "u" with a reason', () => {
    const result = parseFlags('u')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBeTruthy()
    }
  })

  it('rejects "x" with a reason', () => {
    const result = parseFlags('x')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBeTruthy()
    }
  })

  it('rejects "z" (unknown character) with a reason', () => {
    const result = parseFlags('z')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBeTruthy()
      expect(result.reason).toMatch(/z/)
    }
  })

  // --- Rejected inputs (duplicates) ---

  it('rejects "ii" (duplicate i) with a reason', () => {
    const result = parseFlags('ii')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/[Dd]uplicate/)
    }
  })

  it('rejects "ig" (valid + invalid combo) with a reason', () => {
    const result = parseFlags('ig')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      // The first bad char encountered produces a reason.
      expect(result.reason).toBeTruthy()
    }
  })

  // --- Return type shape ---

  it('ok=true result carries a Set<Flag> (type-compatible)', () => {
    const result = parseFlags('ms')
    expect(result.ok).toBe(true)
    if (result.ok) {
      // Type assertion confirms the Set element type is Flag
      const flags: Set<Flag> = result.flags
      expect(flags).toBeInstanceOf(Set)
    }
  })

  it('ok=false result carries a non-empty string reason', () => {
    const result = parseFlags('g')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(typeof result.reason).toBe('string')
      expect(result.reason.length).toBeGreaterThan(0)
    }
  })
})
