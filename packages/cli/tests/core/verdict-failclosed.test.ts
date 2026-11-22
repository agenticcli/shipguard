/**
 * Fail-closed verdict.
 *
 * #1 verbatim: "`degraded: true` forces `recommendation: DO_NOT_SHIP` — verdict computed
 *               fail-closed, in one place, enum stays 2 values"
 * #2 verbatim: "Remove the duplicate `riskScore.recommendation` (mirror one minor version,
 *               then drop at next schemaVersion) — ships in the same change as #1"
 *
 * FAIL-BEFORE: before core/verdict.ts existed, `computeRiskScore` alone decided the verdict
 * from the score, so a truncated/unreadable scan with a low score printed SAFE_TO_SHIP right
 * next to its own `degraded: true` flag (the false-safe verdict).
 *
 * DISCIPLINE: unit-level, pure functions. The behavioral proof on the spawned
 * binary lives in tests/commands/scan-verdict-failclosed.test.ts.
 */
import { describe, it, expect } from 'vitest'
import type { ScanResult } from '@agenticcli/shared'
import { computeVerdict, applyVerdict, effectiveRecommendation } from '../../src/core/verdict.js'
import { computeRiskScore } from '../../src/core/risk-score.js'

function mkResult(score: number, degraded?: boolean): ScanResult {
  return {
    findings: [],
    riskScore: {
      score,
      recommendation: 'SAFE_TO_SHIP',
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      blockingCount: 0,
    },
    filesScanned: 1,
    timestamp: new Date().toISOString(),
    policyUsed: 'test',
    ...(degraded === undefined ? {} : { degraded }),
  }
}

const NONE = { blockingCount: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0 }

describe('#1 — degraded forces DO_NOT_SHIP, fail-closed', () => {
  it('a clean scan is DO_NOT_SHIP once it is degraded', () => {
    expect(computeVerdict({ riskScore: NONE, degraded: true })).toBe('DO_NOT_SHIP')
  })

  it('degradation beats every findings state', () => {
    for (const r of [NONE, { ...NONE, lowCount: 1 }, { ...NONE, highCount: 1, blockingCount: 1 }]) {
      expect(computeVerdict({ riskScore: r, degraded: true })).toBe('DO_NOT_SHIP')
    }
  })

  it('an undegraded scan follows spec 02 rows 4-6: blocking = DO_NOT_SHIP, other findings = REVIEW, none = SAFE', () => {
    expect(computeVerdict({ riskScore: NONE })).toBe('SAFE_TO_SHIP')
    expect(computeVerdict({ riskScore: { ...NONE, lowCount: 1 } })).toBe('REVIEW_BEFORE_SHIP')
    expect(computeVerdict({ riskScore: { ...NONE, infoCount: 1 } })).toBe('REVIEW_BEFORE_SHIP')
    expect(computeVerdict({ riskScore: { ...NONE, highCount: 1, blockingCount: 1 } })).toBe('DO_NOT_SHIP')
  })

  it('a high score with zero blocking findings is REVIEW_BEFORE_SHIP, never DO_NOT_SHIP (B-29)', () => {
    expect(computeVerdict({ riskScore: { ...NONE, mediumCount: 11 } })).toBe('REVIEW_BEFORE_SHIP')
  })

  it('degraded:false and degraded:undefined behave identically (no accidental fail-closed)', () => {
    expect(computeVerdict({ riskScore: NONE, degraded: false })).toBe('SAFE_TO_SHIP')
    expect(computeVerdict({ riskScore: NONE, degraded: undefined })).toBe('SAFE_TO_SHIP')
  })

  it('the enum is NOT extended — only the three published values can ever be returned', () => {
    const seen = new Set<string>()
    for (const degraded of [true, false]) {
      for (const r of [NONE, { ...NONE, lowCount: 1 }, { ...NONE, highCount: 1, blockingCount: 1 }]) {
        seen.add(computeVerdict({ riskScore: r, degraded }))
      }
    }
    expect([...seen].sort()).toEqual(['DO_NOT_SHIP', 'REVIEW_BEFORE_SHIP', 'SAFE_TO_SHIP'])
  })

  it('computeRiskScore routes its verdict through the same one place', () => {
    const rs = computeRiskScore([
      {
        id: 'x', title: 't', severity: 'info', category: 'secrets', file: 'a.js',
        explanation: 'e', recommendation: 'r', blocking: false,
      },
    ])
    expect(rs.recommendation).toBe('REVIEW_BEFORE_SHIP')
    expect(rs.recommendation).toBe(computeVerdict({ riskScore: rs }))
  })
})

describe('#2 — riskScore.recommendation is a written mirror, never a second computation', () => {
  it('applyVerdict writes both copies and they always agree', () => {
    const result = applyVerdict(mkResult(0, true))
    expect(result.recommendation).toBe('DO_NOT_SHIP')
    expect(result.riskScore.recommendation).toBe('DO_NOT_SHIP')
    expect(result.riskScore.recommendation).toBe(result.recommendation)
  })

  it('the mirror cannot go stale — a pre-set wrong value is overwritten', () => {
    const result = mkResult(0, true)
    result.riskScore.recommendation = 'SAFE_TO_SHIP'
    result.recommendation = 'SAFE_TO_SHIP'
    applyVerdict(result)
    expect(result.riskScore.recommendation).toBe('DO_NOT_SHIP')
    expect(result.recommendation).toBe('DO_NOT_SHIP')
  })

  it('applyVerdict is idempotent (scanner.ts applies it, scan.ts re-applies it)', () => {
    const once = applyVerdict(mkResult(60, true))
    const twice = applyVerdict(once)
    expect(twice.recommendation).toBe('DO_NOT_SHIP')
    expect(twice.riskScore.recommendation).toBe('DO_NOT_SHIP')
  })

  it('effectiveRecommendation prefers the top-level field over the deprecated mirror', () => {
    const result = mkResult(0, false)
    result.recommendation = 'DO_NOT_SHIP'
    result.riskScore.recommendation = 'SAFE_TO_SHIP'
    expect(effectiveRecommendation(result)).toBe('DO_NOT_SHIP')
  })

  it('effectiveRecommendation falls back to the mirror for legacy objects', () => {
    const result = mkResult(0, false)
    delete result.recommendation
    result.riskScore.recommendation = 'REVIEW_BEFORE_SHIP'
    expect(effectiveRecommendation(result)).toBe('REVIEW_BEFORE_SHIP')
  })
})
