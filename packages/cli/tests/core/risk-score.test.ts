import { describe, it, expect } from 'vitest'
import { computeRiskScore } from '../../src/core/risk-score.js'
import type { Finding } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function makeFindings(specs: Array<{ severity: Finding['severity']; blocking?: boolean }>): Finding[] {
  return specs.map((s, i) => ({
    id: `test-${i}`,
    title: `Test finding ${i}`,
    severity: s.severity,
    category: 'secrets' as const,
    file: 'test.ts',
    explanation: 'test',
    recommendation: 'test',
    blocking: s.blocking ?? false,
  }))
}

// ---------------------------------------------------------------------------
// Score and recommendation tests
// ---------------------------------------------------------------------------

describe('computeRiskScore', () => {
  it('0 findings → score 0, SAFE_TO_SHIP', () => {
    const result = computeRiskScore([])
    expect(result.score).toBe(0)
    expect(result.recommendation).toBe('SAFE_TO_SHIP')
    expect(result.totalFindings).toBe(0)
  })

  it('1 info finding → score 1, SAFE_TO_SHIP', () => {
    const findings = makeFindings([{ severity: 'info' }])
    const result = computeRiskScore(findings)
    expect(result.score).toBe(1)
    expect(result.recommendation).toBe('SAFE_TO_SHIP')
  })

  it('2 medium findings → score 30, REVIEW_BEFORE_SHIP', () => {
    const findings = makeFindings([{ severity: 'medium' }, { severity: 'medium' }])
    const result = computeRiskScore(findings)
    expect(result.score).toBe(30)
    expect(result.recommendation).toBe('REVIEW_BEFORE_SHIP')
  })

  it('1 critical + 1 high → score 80, DO_NOT_SHIP', () => {
    const findings = makeFindings([{ severity: 'critical' }, { severity: 'high' }])
    const result = computeRiskScore(findings)
    expect(result.score).toBe(80)
    expect(result.recommendation).toBe('DO_NOT_SHIP')
  })

  it('caps at 100 when many critical findings', () => {
    // 3 critical = 150 raw → capped at 100
    const findings = makeFindings([
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
    ])
    const result = computeRiskScore(findings)
    expect(result.score).toBe(100)
    expect(result.recommendation).toBe('DO_NOT_SHIP')
  })

  it('boundary: score 20 → SAFE_TO_SHIP', () => {
    // 4 low = 20
    const findings = makeFindings([
      { severity: 'low' },
      { severity: 'low' },
      { severity: 'low' },
      { severity: 'low' },
    ])
    const result = computeRiskScore(findings)
    expect(result.score).toBe(20)
    expect(result.recommendation).toBe('SAFE_TO_SHIP')
  })

  it('boundary: score 21 → REVIEW_BEFORE_SHIP', () => {
    // 4 low + 1 info = 21
    const findings = makeFindings([
      { severity: 'low' },
      { severity: 'low' },
      { severity: 'low' },
      { severity: 'low' },
      { severity: 'info' },
    ])
    const result = computeRiskScore(findings)
    expect(result.score).toBe(21)
    expect(result.recommendation).toBe('REVIEW_BEFORE_SHIP')
  })

  it('boundary: score 49 → REVIEW_BEFORE_SHIP', () => {
    // 1 high + 19 info = 49
    const findings = makeFindings([
      { severity: 'high' },
      ...Array(19).fill({ severity: 'info' }),
    ])
    const result = computeRiskScore(findings)
    expect(result.score).toBe(49)
    expect(result.recommendation).toBe('REVIEW_BEFORE_SHIP')
  })

  it('boundary: score 50 → DO_NOT_SHIP (one critical finding must block)', () => {
    // 1 critical = 50 — must block; threshold is >= 50
    const findings = makeFindings([{ severity: 'critical' }])
    const result = computeRiskScore(findings)
    expect(result.score).toBe(50)
    expect(result.recommendation).toBe('DO_NOT_SHIP')
  })

  it('boundary: score 51 → DO_NOT_SHIP', () => {
    // 1 high + 21 info = 51
    const findings = makeFindings([
      { severity: 'high' },
      ...Array(21).fill({ severity: 'info' }),
    ])
    const result = computeRiskScore(findings)
    expect(result.score).toBe(51)
    expect(result.recommendation).toBe('DO_NOT_SHIP')
  })

  it('correct counts per severity', () => {
    const findings = makeFindings([
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'high' },
      { severity: 'medium' },
      { severity: 'medium' },
      { severity: 'medium' },
      { severity: 'low' },
      { severity: 'info' },
      { severity: 'info' },
    ])
    const result = computeRiskScore(findings)
    expect(result.criticalCount).toBe(2)
    expect(result.highCount).toBe(1)
    expect(result.mediumCount).toBe(3)
    expect(result.lowCount).toBe(1)
    expect(result.infoCount).toBe(2)
    expect(result.totalFindings).toBe(9)
  })

  it('blocking count correct', () => {
    const findings = makeFindings([
      { severity: 'critical', blocking: true },
      { severity: 'high', blocking: true },
      { severity: 'medium', blocking: false },
      { severity: 'low', blocking: false },
    ])
    const result = computeRiskScore(findings)
    expect(result.blockingCount).toBe(2)
  })

  it('all non-blocking → blockingCount 0', () => {
    const findings = makeFindings([{ severity: 'high' }, { severity: 'medium' }])
    const result = computeRiskScore(findings)
    expect(result.blockingCount).toBe(0)
  })
})
