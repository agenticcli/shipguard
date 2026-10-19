import { describe, it, expect } from 'vitest'
import type { Finding } from '@agenticcli/shared'
import { computeRiskScore } from '../../src/core/risk-score.js'

const f = (over: Partial<Finding>): Finding => ({
  id: 'x', title: 't', severity: 'high', category: 'secrets', file: 'a.ts', line: 1,
  explanation: 'e', recommendation: 'r', blocking: false, ...over,
})

describe('suppressed findings do not count toward the risk score (design decision)', () => {
  it('contribute 0 to score and severity counts, but stay in totalFindings', () => {
    const r = computeRiskScore([f({ suppressed: true }), f({ suppressed: true, severity: 'critical' })])
    expect(r.score).toBe(0)
    expect(r.recommendation).toBe('SAFE_TO_SHIP')
    expect(r.highCount + r.criticalCount).toBe(0)
    expect(r.totalFindings).toBe(2)
  })

  it('a suppressed finding beside an active one changes nothing about the active score', () => {
    const active = computeRiskScore([f({})])
    const mixed = computeRiskScore([f({}), f({ suppressed: true }), f({ suppressed: true, severity: 'critical' })])
    expect(mixed.score).toBe(active.score)
    expect(mixed.highCount).toBe(1)
    expect(mixed.totalFindings).toBe(3)
  })

  it('antiPattern-suppressed (no user comment) is treated the same: contributes 0', () => {
    expect(computeRiskScore([f({ suppressed: true, suppressionState: 'suppressed' })]).score).toBe(0)
  })
})
