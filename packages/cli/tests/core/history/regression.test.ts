import { describe, it, expect } from 'vitest'
import { computeRegressionResult } from '../../../src/core/history/regression.js'
import type { ScanSnapshot } from '../../../src/core/history/regression.js'

/**
 * The ONE regression claim, tested as a pure
 * function — no DB involved. This is where the trust-critical false-positive guard lives:
 * a corpus/rule-version change must NEVER be reported as "you regressed."
 */

const SCOPE = 'fp-aaaa1111'

function snapshot(overrides: Partial<ScanSnapshot>): ScanSnapshot {
  return {
    scanId: 'scan-1',
    timestamp: '2026-07-15T00:00:00.000Z',
    scopeFingerprint: SCOPE,
    corpusVersion: 'free:0.4.1',
    stateStatus: 'complete',
    ruleOutcomes: [],
    ...overrides,
  }
}

describe('computeRegressionResult — skip conditions', () => {
  it('no baseline (first-ever scan for this repo+scope) → skipped, reason no-baseline', () => {
    const current = snapshot({})
    const result = computeRegressionResult(current, undefined)
    expect(result.regressionCheckSkipped).toBe(true)
    expect(result.regressionCheckSkippedReason).toBe('no-baseline')
    expect(result.regressions).toEqual([])
    expect(result.coverageChanged).toEqual([])
  })

  it('current stateStatus unavailable → skipped, reason state-unavailable (DB-unavailable never claims a regression)', () => {
    const baseline = snapshot({ scanId: 'scan-0' })
    const current = snapshot({ scanId: 'scan-1', stateStatus: 'unavailable' })
    const result = computeRegressionResult(current, baseline)
    expect(result.regressionCheckSkipped).toBe(true)
    expect(result.regressionCheckSkippedReason).toBe('state-unavailable')
  })

  it('baseline stateStatus corrupt → skipped, reason state-unavailable', () => {
    const baseline = snapshot({ scanId: 'scan-0', stateStatus: 'corrupt' })
    const current = snapshot({ scanId: 'scan-1' })
    const result = computeRegressionResult(current, baseline)
    expect(result.regressionCheckSkipped).toBe(true)
    expect(result.regressionCheckSkippedReason).toBe('state-unavailable')
  })

  it('scope fingerprint mismatch (defensive) → skipped, reason scope-mismatch', () => {
    const baseline = snapshot({ scanId: 'scan-0', scopeFingerprint: 'other-scope' })
    const current = snapshot({ scanId: 'scan-1', scopeFingerprint: SCOPE })
    const result = computeRegressionResult(current, baseline)
    expect(result.regressionCheckSkipped).toBe(true)
    expect(result.regressionCheckSkippedReason).toBe('scope-mismatch')
  })
})

describe('computeRegressionResult — the ONE regression claim', () => {
  it('a blocking rule that passed at baseline (0 findings) and now fails (>=1) under the SAME corpus/rule version → regression', () => {
    const baseline = snapshot({
      scanId: 'scan-0',
      timestamp: '2026-07-14T00:00:00.000Z',
      ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 0, ruleVersion: '1' }],
    })
    const current = snapshot({
      scanId: 'scan-1',
      ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 1, ruleVersion: '1' }],
    })

    const result = computeRegressionResult(current, baseline)

    expect(result.regressionCheckSkipped).toBe(false)
    expect(result.regressions).toHaveLength(1)
    expect(result.regressions[0]).toMatchObject({
      ruleId: 'hardcoded_secret',
      baselineScanId: 'scan-0',
      currentScanId: 'scan-1',
      scopeFingerprint: SCOPE,
    })
    expect(result.coverageChanged).toEqual([])
  })

  it('a rule that was already failing at baseline and still fails → NOT a regression (no new pass→fail flip)', () => {
    const baseline = snapshot({
      scanId: 'scan-0',
      ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 2, ruleVersion: '1' }],
    })
    const current = snapshot({
      scanId: 'scan-1',
      ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 1, ruleVersion: '1' }],
    })

    const result = computeRegressionResult(current, baseline)
    expect(result.regressions).toEqual([])
  })

  it('a rule that passed at baseline and still passes → no regression, no coverage change', () => {
    const baseline = snapshot({
      scanId: 'scan-0',
      ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 0, ruleVersion: '1' }],
    })
    const current = snapshot({
      scanId: 'scan-1',
      ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 0, ruleVersion: '1' }],
    })

    const result = computeRegressionResult(current, baseline)
    expect(result.regressions).toEqual([])
    expect(result.coverageChanged).toEqual([])
  })

  it('a warn/monitor (non-blocking) rule is never compared, even if it flips pass→fail', () => {
    const baseline = snapshot({
      scanId: 'scan-0',
      ruleOutcomes: [{ ruleId: 'missing_tests_for_changed_code', blocking: false, activeFindingCount: 0, ruleVersion: '1' }],
    })
    const current = snapshot({
      scanId: 'scan-1',
      ruleOutcomes: [{ ruleId: 'missing_tests_for_changed_code', blocking: false, activeFindingCount: 3, ruleVersion: '1' }],
    })

    const result = computeRegressionResult(current, baseline)
    expect(result.regressions).toEqual([])
    expect(result.coverageChanged).toEqual([])
  })
})

describe('computeRegressionResult — the false-positive guard: corpus/rule changes are "coverage changed", never regression', () => {
  it('rule VERSION changed between the two scans (a corpus update that touched this rule) → coverageChanged, NOT regression, even though it flipped pass→fail', () => {
    const baseline = snapshot({
      scanId: 'scan-0',
      corpusVersion: 'v5',
      ruleOutcomes: [{ ruleId: 'supabase.rls-missing', blocking: true, activeFindingCount: 0, ruleVersion: '1.0.0' }],
    })
    const current = snapshot({
      scanId: 'scan-1',
      corpusVersion: 'v6', // corpus release bumped
      ruleOutcomes: [{ ruleId: 'supabase.rls-missing', blocking: true, activeFindingCount: 1, ruleVersion: '1.1.0' }], // AND this rule's own version bumped
    })

    const result = computeRegressionResult(current, baseline)

    expect(result.regressionCheckSkipped).toBe(false)
    expect(result.regressions).toEqual([]) // the hard requirement: never a regression here
    expect(result.coverageChanged).toHaveLength(1)
    expect(result.coverageChanged[0]).toMatchObject({
      ruleId: 'supabase.rls-missing',
      reason: 'rule-version-changed',
      baselineRuleVersion: '1.0.0',
      currentRuleVersion: '1.1.0',
    })
  })

  it('corpus version bumped but THIS rule\'s own version did not change → still a real regression (unrelated corpus churn must not suppress a genuine signal)', () => {
    const baseline = snapshot({
      scanId: 'scan-0',
      corpusVersion: 'v5',
      ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 0, ruleVersion: '1.0.0' }],
    })
    const current = snapshot({
      scanId: 'scan-1',
      corpusVersion: 'v6',
      ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 1, ruleVersion: '1.0.0' }],
    })

    const result = computeRegressionResult(current, baseline)
    expect(result.regressions).toHaveLength(1)
    expect(result.regressions[0].ruleId).toBe('hardcoded_secret')
    expect(result.coverageChanged).toEqual([])
  })

  it('rule is NEW since baseline (did not exist in the baseline corpus at all) → coverageChanged "new-since-baseline", never regression', () => {
    const baseline = snapshot({
      scanId: 'scan-0',
      ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 0, ruleVersion: '1' }],
    })
    const current = snapshot({
      scanId: 'scan-1',
      ruleOutcomes: [
        { ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 0, ruleVersion: '1' },
        { ruleId: 'brand-new-rule', blocking: true, activeFindingCount: 1, ruleVersion: '1' },
      ],
    })

    const result = computeRegressionResult(current, baseline)
    expect(result.regressions).toEqual([])
    expect(result.coverageChanged).toEqual([{ ruleId: 'brand-new-rule', reason: 'new-since-baseline' }])
  })

  it('rule was WITHDRAWN since baseline (blocking at baseline, absent from current corpus) → coverageChanged "withdrawn-since-baseline", excluded from regression', () => {
    const baseline = snapshot({
      scanId: 'scan-0',
      ruleOutcomes: [
        { ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 0, ruleVersion: '1' },
        { ruleId: 'deprecated-rule', blocking: true, activeFindingCount: 0, ruleVersion: '1' },
      ],
    })
    const current = snapshot({
      scanId: 'scan-1',
      ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 0, ruleVersion: '1' }],
    })

    const result = computeRegressionResult(current, baseline)
    expect(result.regressions).toEqual([])
    expect(result.coverageChanged).toEqual([{ ruleId: 'deprecated-rule', reason: 'withdrawn-since-baseline' }])
  })

  it('a rule that was warn/monitor at baseline and is blocking now is coverage-changed, not a regression', () => {
    const baseline = snapshot({
      scanId: 'scan-0',
      ruleOutcomes: [{ ruleId: 'some-rule', blocking: false, activeFindingCount: 0, ruleVersion: '1' }],
    })
    const current = snapshot({
      scanId: 'scan-1',
      ruleOutcomes: [{ ruleId: 'some-rule', blocking: true, activeFindingCount: 1, ruleVersion: '1' }],
    })

    const result = computeRegressionResult(current, baseline)
    expect(result.regressions).toEqual([])
    expect(result.coverageChanged).toHaveLength(1)
    expect(result.coverageChanged[0].ruleId).toBe('some-rule')
  })

  it('multiple rules: only the genuinely regressed one is reported, coverage-changed ones are separate', () => {
    const baseline = snapshot({
      scanId: 'scan-0',
      ruleOutcomes: [
        { ruleId: 'rule-a', blocking: true, activeFindingCount: 0, ruleVersion: '1' }, // will regress
        { ruleId: 'rule-b', blocking: true, activeFindingCount: 0, ruleVersion: '1' }, // version changes, would-be regression suppressed
        { ruleId: 'rule-c', blocking: true, activeFindingCount: 3, ruleVersion: '1' }, // already failing, stays failing
      ],
    })
    const current = snapshot({
      scanId: 'scan-1',
      ruleOutcomes: [
        { ruleId: 'rule-a', blocking: true, activeFindingCount: 1, ruleVersion: '1' },
        { ruleId: 'rule-b', blocking: true, activeFindingCount: 1, ruleVersion: '2' },
        { ruleId: 'rule-c', blocking: true, activeFindingCount: 2, ruleVersion: '1' },
        { ruleId: 'rule-d', blocking: true, activeFindingCount: 0, ruleVersion: '1' }, // brand new, passing
      ],
    })

    const result = computeRegressionResult(current, baseline)
    expect(result.regressions).toEqual([
      expect.objectContaining({ ruleId: 'rule-a' }),
    ])
    expect(result.coverageChanged).toEqual([
      expect.objectContaining({ ruleId: 'rule-b', reason: 'rule-version-changed' }),
      expect.objectContaining({ ruleId: 'rule-d', reason: 'new-since-baseline' }),
    ])
  })
})
