// TDD: Task A.8 — DegradedReason, ScanOutcome, resolveExitCode
// Failing tests first, then minimal impl, then commit.

import { describe, it, expect } from 'vitest'
import {
  DegradedReason,
  resolveExitCode,
  type ScanOutcome,
} from '../failure.js'

// ---------------------------------------------------------------------------
// DegradedReason enum values
// ---------------------------------------------------------------------------

describe('DegradedReason enum', () => {
  it('has all required canonical reason strings', () => {
    // Each value must be a non-empty string
    const expected = [
      'compile-failure',
      'bundle-or-manifest-mismatch',
      'missing-attestation',
      'engine-exception',
      'unreadable-file',
      'invalid-utf8',
      'cap-exceeded',
      'coderef-mismatch',
    ] as const

    for (const r of expected) {
      // TypeScript ensures these exist; the runtime check proves the enum is populated
      expect(typeof (DegradedReason as Record<string, string>)[r as string]).not.toBe('undefined')
      // Alternatively, just check the value is accessible
      expect(DegradedReason[r]).toBe(r)
    }
  })

  it('compile-failure reason has the right value', () => {
    expect(DegradedReason['compile-failure']).toBe('compile-failure')
  })

  it('cap-exceeded reason has the right value', () => {
    expect(DegradedReason['cap-exceeded']).toBe('cap-exceeded')
  })

  it('coderef-mismatch reason has the right value', () => {
    expect(DegradedReason['coderef-mismatch']).toBe('coderef-mismatch')
  })
})

// ---------------------------------------------------------------------------
// ScanOutcome + resolveExitCode — clean scan
// ---------------------------------------------------------------------------

describe('resolveExitCode — clean scan (no findings, not degraded)', () => {
  it('exit 0 for a clean scan with no blocking findings (non-strict)', () => {
    const outcome: ScanOutcome = {
      degraded: false,
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, false)).toBe(0)
  })

  it('exit 0 for a clean scan with no blocking findings (strict)', () => {
    const outcome: ScanOutcome = {
      degraded: false,
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, true)).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// resolveExitCode — blocking findings under --strict → exit 1
// ---------------------------------------------------------------------------

describe('resolveExitCode — blocking findings under --strict', () => {
  it('exit 1 when blocking findings present + --strict', () => {
    const outcome: ScanOutcome = {
      degraded: false,
      hasBlockingFindings: true,
    }
    expect(resolveExitCode(outcome, true)).toBe(1)
  })

  it('exit 0 when blocking findings present but NOT --strict (default: report only)', () => {
    const outcome: ScanOutcome = {
      degraded: false,
      hasBlockingFindings: true,
    }
    expect(resolveExitCode(outcome, false)).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// resolveExitCode — degraded scan → NEVER exit 0
// ---------------------------------------------------------------------------

describe('resolveExitCode — degraded scan never exits 0', () => {
  it('exit 2 for config-degraded (no blocking findings, non-strict)', () => {
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['compile-failure'],
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, false)).toBe(2)
  })

  it('exit 2 for config-degraded (no blocking findings, strict)', () => {
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['compile-failure'],
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, true)).toBe(2)
  })

  it('exit 3 for runtime-error reasons (engine-exception)', () => {
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['engine-exception'],
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, false)).toBe(3)
  })

  it('exit 3 for runtime-error reasons (unreadable-file)', () => {
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['unreadable-file'],
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, false)).toBe(3)
  })

  it('exit 3 for runtime-error reasons (invalid-utf8)', () => {
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['invalid-utf8'],
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, false)).toBe(3)
  })

  it('exit 3 for coderef-mismatch (runtime)', () => {
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['coderef-mismatch'],
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, false)).toBe(3)
  })

  it('exit 3 for missing-attestation (runtime)', () => {
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['missing-attestation'],
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, false)).toBe(3)
  })

  it('exit 3 for bundle-or-manifest-mismatch (runtime)', () => {
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['bundle-or-manifest-mismatch'],
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, false)).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// resolveExitCode — exit 1 wins over exit 2 under --strict + degraded
// ---------------------------------------------------------------------------

describe('resolveExitCode — exit 1 wins over exit 2 when blocking + --strict + config-degraded', () => {
  it('exit 1 when blocking + --strict + config-degraded (exit 1 wins over 2)', () => {
    // GROUND-TRUTH: constants.ts:9-14 / scan.ts:54-67 — exit 1 wins over 2
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['compile-failure'],
      hasBlockingFindings: true,
    }
    expect(resolveExitCode(outcome, true)).toBe(1)
  })

  it('exit 1 wins over 3 when blocking + --strict + runtime-error', () => {
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['engine-exception'],
      hasBlockingFindings: true,
    }
    expect(resolveExitCode(outcome, true)).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// resolveExitCode — cap-exceeded is config-degraded (exit 2)
// ---------------------------------------------------------------------------

describe('resolveExitCode — cap-exceeded maps to exit 2 (config-degraded)', () => {
  it('exit 2 for cap-exceeded without blocking findings', () => {
    const outcome: ScanOutcome = {
      degraded: true,
      degradedReason: DegradedReason['cap-exceeded'],
      hasBlockingFindings: false,
    }
    expect(resolveExitCode(outcome, false)).toBe(2)
  })
})
