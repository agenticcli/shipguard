// selectExpected + verifyExactSet
// Tests written BEFORE implementation per the TDD mandate.
//
// Spec source: matcher spec §4 (Selector + Exact-Set Completeness Algorithm)
// Implementation must faithfully reproduce the selection algorithm so that the
// CLI can independently recompute the expected rule-ID+hash MULTISET that
// Convex serves.

import { describe, it, expect } from 'vitest'
import {
  selectExpected,
  verifyExactSet,
  type ManifestRuleEntry,
  type FullManifest,
  type ScanRequest,
  type ExpectedSet,
} from '../selector.js'
import { DEFAULT_CAPS } from '../caps.js'

// ---------------------------------------------------------------------------
// Test-fixture helpers
// ---------------------------------------------------------------------------

function makeRule(overrides: Partial<ManifestRuleEntry>): ManifestRuleEntry {
  return {
    id: 'rule-1',
    executableHash: 'aabbccdd0011223344556677889900aabbccdd0011223344556677889900aa11',
    enabled: true,
    framework: 'generic',
    tier: 'free',
    severity: 'error',
    matcherType: 'pattern',
    title: 'Test Rule',
    flags: '',
    categories: [],
    ...overrides,
  }
}

function makeManifest(rules: ManifestRuleEntry[]): FullManifest {
  return {
    protocolVersion: '1',
    releaseId: 'test-release-1',
    releaseSequence: 1,
    corpusRuleCount: rules.length,
    rules,
    capProfile: {
      maxFileBytes: 10 * 1024 * 1024,
      maxFiles: DEFAULT_CAPS.maxFiles,
      maxFindings: DEFAULT_CAPS.maxFindings,
      maxPatternBytes: 1024,
      maxPatternsPerRule: DEFAULT_CAPS.maxPatternsPerRule,
      maxRules: DEFAULT_CAPS.maxRules,
    },
    matcherEngineVersion: 'v20.0.0',
    matcherEngineOptions: { LOOKBEHINDS: false },
    matcherRuntimeId: 'deadbeef',
    contractVersion: '0.1.0',
    gateBVersion: '1.0.0',
    gateCVersion: '1.0.0',
  }
}

// ---------------------------------------------------------------------------
// Step 1: basic selection — enabled-only filter
// ---------------------------------------------------------------------------

describe('A.11 selectExpected — step 1: enabled filter', () => {
  it('includes only enabled rules', () => {
    const rules = [
      makeRule({ id: 'enabled-1', enabled: true }),
      makeRule({ id: 'disabled-1', enabled: false }),
      makeRule({ id: 'enabled-2', enabled: true }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['generic'] }
    const result = selectExpected(manifest, request)
    const ids = result.map((r) => r.id)
    expect(ids).toContain('enabled-1')
    expect(ids).toContain('enabled-2')
    expect(ids).not.toContain('disabled-1')
  })
})

// ---------------------------------------------------------------------------
// Step 2: generic-rule merge
// ---------------------------------------------------------------------------

describe('A.11 selectExpected — step 2: generic-rule merge', () => {
  it('includes generic rules for all framework requests', () => {
    const rules = [
      makeRule({ id: 'generic-1', framework: 'generic' }),
      makeRule({ id: 'nextjs-1', framework: 'nextjs' }),
    ]
    const manifest = makeManifest(rules)
    // Request only 'react', not 'nextjs' — generic should still be included
    const request: ScanRequest = { frameworks: ['react'] }
    const result = selectExpected(manifest, request)
    const ids = result.map((r) => r.id)
    expect(ids).toContain('generic-1')
    expect(ids).not.toContain('nextjs-1')
  })

  it('includes framework-specific rules when framework is requested', () => {
    const rules = [
      makeRule({ id: 'generic-1', framework: 'generic' }),
      makeRule({ id: 'nextjs-1', framework: 'nextjs' }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['nextjs'] }
    const result = selectExpected(manifest, request)
    const ids = result.map((r) => r.id)
    expect(ids).toContain('generic-1')
    expect(ids).toContain('nextjs-1')
  })
})

// ---------------------------------------------------------------------------
// Step 3: framework deduplication — specific overrides generic
// ---------------------------------------------------------------------------

describe('A.11 selectExpected — step 3: framework dedup', () => {
  it('framework-specific rule wins over generic when IDs match', () => {
    const genericHash = 'generic' + '0'.repeat(58)
    const specificHash = 'specif' + '0'.repeat(58)
    const rules = [
      makeRule({ id: 'rule-x', framework: 'generic', executableHash: genericHash }),
      makeRule({ id: 'rule-x', framework: 'nextjs', executableHash: specificHash }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['nextjs'] }
    const result = selectExpected(manifest, request)
    // Only one entry for 'rule-x', using the nextjs-specific hash
    const ruleX = result.filter((r) => r.id === 'rule-x')
    expect(ruleX).toHaveLength(1)
    expect(ruleX[0].executableHash).toBe(specificHash)
  })

  it('generic rule is included when no framework-specific override exists', () => {
    const genericHash = 'generic' + '0'.repeat(58)
    const rules = [
      makeRule({ id: 'rule-y', framework: 'generic', executableHash: genericHash }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['nextjs'] }
    const result = selectExpected(manifest, request)
    const ruleY = result.filter((r) => r.id === 'rule-y')
    expect(ruleY).toHaveLength(1)
    expect(ruleY[0].executableHash).toBe(genericHash)
  })
})

// ---------------------------------------------------------------------------
// Step 4: category filter
// ---------------------------------------------------------------------------

describe('A.11 selectExpected — step 4: category filter', () => {
  it('includes all rules when no category filter is specified', () => {
    const rules = [
      makeRule({ id: 'r1', categories: ['security'] }),
      makeRule({ id: 'r2', categories: ['performance'] }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['generic'] }
    const result = selectExpected(manifest, request)
    expect(result.map((r) => r.id)).toContain('r1')
    expect(result.map((r) => r.id)).toContain('r2')
  })

  it('includes rules whose categories intersect the requested categories', () => {
    const rules = [
      makeRule({ id: 'sec-rule', categories: ['security'] }),
      makeRule({ id: 'perf-rule', categories: ['performance'] }),
      makeRule({ id: 'no-cat', categories: [] }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['generic'], categories: ['security'] }
    const result = selectExpected(manifest, request)
    const ids = result.map((r) => r.id)
    expect(ids).toContain('sec-rule')
    expect(ids).not.toContain('perf-rule')
    // Rule with no categories passes the category filter unconditionally (§4.1 step 4)
    expect(ids).toContain('no-cat')
  })

  it('a rule with no categories always passes the category filter', () => {
    const rules = [
      makeRule({ id: 'no-cat', categories: [] }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['generic'], categories: ['security'] }
    const result = selectExpected(manifest, request)
    expect(result.map((r) => r.id)).toContain('no-cat')
  })
})

// ---------------------------------------------------------------------------
// Step 6: tier filter
// ---------------------------------------------------------------------------

describe('A.11 selectExpected — step 6: tier filter', () => {
  it('non-pro request includes only free-tier rules', () => {
    const rules = [
      makeRule({ id: 'free-rule', tier: 'free' }),
      makeRule({ id: 'pro-rule', tier: 'pro' }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['generic'] }
    const result = selectExpected(manifest, request)
    const ids = result.map((r) => r.id)
    expect(ids).toContain('free-rule')
    expect(ids).not.toContain('pro-rule')
  })

  it('pro request includes both free and pro-tier rules', () => {
    const rules = [
      makeRule({ id: 'free-rule', tier: 'free' }),
      makeRule({ id: 'pro-rule', tier: 'pro' }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['generic'], isPro: true }
    const result = selectExpected(manifest, request)
    const ids = result.map((r) => r.id)
    expect(ids).toContain('free-rule')
    expect(ids).toContain('pro-rule')
  })

  it('no "local" tier appears in the manifest after aliasing (invariant)', () => {
    // "local" → "free" aliasing happens at publish time; the selector
    // treats "local" as an unknown tier (neither "free" nor "pro") for a
    // non-pro request — it would not be included.
    // This test verifies that aliasing has already been applied in any
    // properly-formed manifest (no "local" tier should appear at all).
    const rules = [
      makeRule({ id: 'local-rule', tier: 'local' as 'free' }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['generic'], isPro: false }
    const result = selectExpected(manifest, request)
    // "local" is not "free", so a non-pro request should exclude it —
    // verifying the consumer checks tier === "free" exactly.
    expect(result.map((r) => r.id)).not.toContain('local-rule')
  })
})

// ---------------------------------------------------------------------------
// Step 7: policy cap — maxRules exceeded
// ---------------------------------------------------------------------------

describe('A.11 selectExpected — step 7: maxRules cap', () => {
  it('throws with canonical INCOMPLETE reason when candidates exceed maxRules', () => {
    const rules = [
      makeRule({ id: 'r1' }),
      makeRule({ id: 'r2' }),
      makeRule({ id: 'r3' }),
    ]
    // Set maxRules = 2 so 3 candidates triggers the cap
    const manifest: FullManifest = {
      ...makeManifest(rules),
      capProfile: { ...makeManifest(rules).capProfile, maxRules: 2 },
    }
    const request: ScanRequest = { frameworks: ['generic'] }
    expect(() => selectExpected(manifest, request)).toThrowError(/rule-count-cap-exceeded/)
  })
})

// ---------------------------------------------------------------------------
// Step 8: deterministic output — sorted by id ascending
// ---------------------------------------------------------------------------

describe('A.11 selectExpected — step 8: deterministic output', () => {
  it('output is sorted by id ascending (deterministic)', () => {
    const rules = [
      makeRule({ id: 'zzz' }),
      makeRule({ id: 'aaa' }),
      makeRule({ id: 'mmm' }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['generic'] }
    const result = selectExpected(manifest, request)
    const ids = result.map((r) => r.id)
    expect(ids).toEqual([...ids].sort())
  })

  it('produces identical output on repeated calls (pure function)', () => {
    const rules = [
      makeRule({ id: 'b-rule' }),
      makeRule({ id: 'a-rule' }),
    ]
    const manifest = makeManifest(rules)
    const request: ScanRequest = { frameworks: ['generic'] }
    const first = selectExpected(manifest, request)
    const second = selectExpected(manifest, request)
    expect(first).toEqual(second)
  })
})

// ---------------------------------------------------------------------------
// verifyExactSet — EXACT multiset equality
// ---------------------------------------------------------------------------

describe('A.11 verifyExactSet — exact multiset equality', () => {
  const expectedSet: ExpectedSet = [
    { id: 'a', executableHash: 'aa'.padEnd(64, '0') },
    { id: 'b', executableHash: 'bb'.padEnd(64, '0') },
  ]

  it('returns ok=true when delivered matches expected exactly', () => {
    const delivered = [
      { id: 'a', executableHash: 'aa'.padEnd(64, '0') },
      { id: 'b', executableHash: 'bb'.padEnd(64, '0') },
    ]
    const result = verifyExactSet(delivered, expectedSet)
    expect(result.ok).toBe(true)
  })

  it('order of delivered does not matter (multiset equality)', () => {
    const delivered = [
      { id: 'b', executableHash: 'bb'.padEnd(64, '0') },
      { id: 'a', executableHash: 'aa'.padEnd(64, '0') },
    ]
    const result = verifyExactSet(delivered, expectedSet)
    expect(result.ok).toBe(true)
  })

  it('REJECT: missing rule in delivered set', () => {
    const delivered = [
      { id: 'a', executableHash: 'aa'.padEnd(64, '0') },
      // 'b' is missing
    ]
    const result = verifyExactSet(delivered, expectedSet)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.violations.some((v) => v.type === 'missing-rule')).toBe(true)
      expect(result.violations.some((v) => v.ruleId === 'b')).toBe(true)
    }
  })

  it('REJECT: extra rule in delivered set', () => {
    const delivered = [
      { id: 'a', executableHash: 'aa'.padEnd(64, '0') },
      { id: 'b', executableHash: 'bb'.padEnd(64, '0') },
      { id: 'c', executableHash: 'cc'.padEnd(64, '0') }, // unexpected
    ]
    const result = verifyExactSet(delivered, expectedSet)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.violations.some((v) => v.type === 'extra-rule')).toBe(true)
      expect(result.violations.some((v) => v.ruleId === 'c')).toBe(true)
    }
  })

  it('REJECT: hash mismatch for known rule', () => {
    const delivered = [
      { id: 'a', executableHash: 'aa'.padEnd(64, '0') },
      { id: 'b', executableHash: 'WRONG'.padEnd(64, '0') }, // wrong hash
    ]
    const result = verifyExactSet(delivered, expectedSet)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.violations.some((v) => v.type === 'hash-mismatch')).toBe(true)
      expect(result.violations.some((v) => v.ruleId === 'b')).toBe(true)
    }
  })

  it('REJECT: duplicate rule ID in delivered set', () => {
    const delivered = [
      { id: 'a', executableHash: 'aa'.padEnd(64, '0') },
      { id: 'a', executableHash: 'aa'.padEnd(64, '0') }, // duplicate
      { id: 'b', executableHash: 'bb'.padEnd(64, '0') },
    ]
    const result = verifyExactSet(delivered, expectedSet)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.violations.some((v) => v.type === 'duplicate-id')).toBe(true)
    }
  })

  it('REJECT: unknown rule (not in expected, not tracked as "extra" separately)', () => {
    // "unknown-rule" is not in expectedSet; this is the "extra-rule" violation
    const delivered = [
      { id: 'a', executableHash: 'aa'.padEnd(64, '0') },
      { id: 'b', executableHash: 'bb'.padEnd(64, '0') },
      { id: 'unknown-rule', executableHash: 'uu'.padEnd(64, '0') },
    ]
    const result = verifyExactSet(delivered, expectedSet)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.violations.some((v) => v.ruleId === 'unknown-rule')).toBe(true)
    }
  })

  it('REJECT: count mismatch (delivered has 1, expected has 2)', () => {
    const delivered = [
      { id: 'a', executableHash: 'aa'.padEnd(64, '0') },
    ]
    const result = verifyExactSet(delivered, expectedSet)
    expect(result.ok).toBe(false)
  })

  it('matches the highest-severity rule present — verified in the exact set', () => {
    // Verify that a correct expectedSet with a high-severity rule passes ok
    const highSeverityExpected: ExpectedSet = [
      { id: 'high-sev', executableHash: 'hs'.padEnd(64, '0') },
    ]
    const delivered = [
      { id: 'high-sev', executableHash: 'hs'.padEnd(64, '0') },
    ]
    expect(verifyExactSet(delivered, highSeverityExpected).ok).toBe(true)
  })

  it('REJECT when the highest-severity rule is missing from delivered set', () => {
    const highSeverityExpected: ExpectedSet = [
      { id: 'high-sev', executableHash: 'hs'.padEnd(64, '0') },
      { id: 'low-sev', executableHash: 'ls'.padEnd(64, '0') },
    ]
    // Only deliver the low-severity rule (missing high-severity)
    const delivered = [
      { id: 'low-sev', executableHash: 'ls'.padEnd(64, '0') },
    ]
    const result = verifyExactSet(delivered, highSeverityExpected)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.violations.some((v) => v.type === 'missing-rule' && v.ruleId === 'high-sev')).toBe(true)
    }
  })
})
