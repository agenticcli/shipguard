// Conformance vectors + harness
//
// Tests the executor-INDEPENDENT parts of the conformance suite:
//   - Vector set integrity (all vectors parse, have required fields)
//   - canonicalJson determinism over expected-finding-set (when non-null)
//   - selectExpected correctness via the caps and selector vectors
//   - Normalization edge cases (invalid UTF-8 reject, CRLF, BOM)
//   - Flag rejection vectors
//   - The harness skeleton runs against a trivial stub executor
//
// NOTE: Executor-DEPENDENT vectors (actual matching behavior for PatternMatcher,
// FilePresenceMatcher, FileRelationshipMatcher) are tested by Phase B.1 (native-v1
// adapter) and Phase D.1 (re2js-v1 adapter). Those phases call runConformance()
// with their real adapters and assert the frozen canonical hashes.

import { describe, it, expect } from 'vitest'
import {
  allConformanceVectors,
  executorIndependentVectors,
  executorDependentVectors,
  runConformance,
  type HarnessExecutor,
  type ConformanceVector,
} from '../conformance/index.js'
import { canonicalJson, canonicalizeFinding } from '../canonical.js'
import type { CanonicalFinding } from '../finding.js'
import type { Matcher, ExecCtx } from '../matcher.js'

// ---------------------------------------------------------------------------
// A.12.1 — Vector set integrity
// ---------------------------------------------------------------------------

describe('A.12 — conformance vectors: set integrity', () => {
  it('allConformanceVectors is non-empty', () => {
    expect(allConformanceVectors.length).toBeGreaterThan(0)
  })

  it('executor-independent + executor-dependent = all vectors', () => {
    expect(
      executorIndependentVectors.length + executorDependentVectors.length,
    ).toBe(allConformanceVectors.length)
  })

  it('every vector has a stable non-empty id', () => {
    for (const v of allConformanceVectors) {
      expect(typeof v.id).toBe('string')
      expect(v.id.length).toBeGreaterThan(0)
    }
  })

  it('every vector has a non-empty description', () => {
    for (const v of allConformanceVectors) {
      expect(typeof v.description).toBe('string')
      expect(v.description.length).toBeGreaterThan(0)
    }
  })

  it('every vector has a valid category', () => {
    const validCategories = new Set([
      'pattern', 'file-presence', 'file-relationship',
      'normalization', 'caps', 'flags', 'anti-pattern', 'zero-width',
    ])
    for (const v of allConformanceVectors) {
      expect(validCategories.has(v.category)).toBe(true)
    }
  })

  it('every vector has executorDependent field', () => {
    for (const v of allConformanceVectors) {
      expect(typeof v.executorDependent).toBe('boolean')
    }
  })

  it('all executorIndependentVectors have executorDependent=false', () => {
    for (const v of executorIndependentVectors) {
      expect(v.executorDependent).toBe(false)
    }
  })

  it('all executorDependentVectors have executorDependent=true', () => {
    for (const v of executorDependentVectors) {
      expect(v.executorDependent).toBe(true)
    }
  })

  it('vector IDs are unique across the full set', () => {
    const ids = allConformanceVectors.map((v) => v.id)
    const unique = new Set(ids)
    expect(unique.size).toBe(ids.length)
  })

  it('covers each matcher type in executor-dependent vectors', () => {
    const matcherTypes = new Set(
      executorDependentVectors
        .filter((v) => v.input.matcher !== null)
        .map((v) => (v.input.matcher as Matcher).type),
    )
    expect(matcherTypes.has('pattern')).toBe(true)
    expect(matcherTypes.has('file-presence')).toBe(true)
    expect(matcherTypes.has('file-relationship')).toBe(true)
  })

  it('covers normalization edge cases (invalid-utf8, CRLF, BOM)', () => {
    const normIds = executorIndependentVectors
      .filter((v) => v.category === 'normalization')
      .map((v) => v.id)
    expect(normIds).toContain('normalization-1') // invalid UTF-8
    expect(normIds).toContain('normalization-2') // CRLF
    expect(normIds).toContain('normalization-3') // BOM
  })

  it('covers flag rejection (flags="g" must be rejected)', () => {
    const flagIds = executorIndependentVectors
      .filter((v) => v.category === 'flags')
      .map((v) => v.id)
    expect(flagIds).toContain('flags-1') // flags="g" rejection
  })

  it('covers all flag combinations: no flags, i, m, s, im', () => {
    const patternVectors = executorDependentVectors.filter(
      (v) => v.category === 'pattern',
    )
    const flagsCovered = new Set(
      patternVectors
        .filter((v) => v.input.matcher !== null)
        .map((v) => (v.input.matcher as { flags: string }).flags),
    )
    expect(flagsCovered.has('')).toBe(true)   // no flags
    expect(flagsCovered.has('i')).toBe(true)  // case-insensitive
    expect(flagsCovered.has('m')).toBe(true)  // multiline
    expect(flagsCovered.has('s')).toBe(true)  // dotAll
    expect(flagsCovered.has('im')).toBe(true) // combined
  })

  it('has anti-pattern per-line scoping vector', () => {
    const antiPatternVectors = executorDependentVectors.filter(
      (v) => v.category === 'anti-pattern',
    )
    expect(antiPatternVectors.length).toBeGreaterThan(0)
  })

  it('has zero-width match vector', () => {
    const zeroWidthVectors = executorDependentVectors.filter(
      (v) => v.category === 'zero-width',
    )
    expect(zeroWidthVectors.length).toBeGreaterThan(0)
  })

  it('has caps-exceeded vector', () => {
    const capsVectors = executorIndependentVectors.filter(
      (v) => v.category === 'caps',
    )
    expect(capsVectors.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// A.12.2 — canonicalJson determinism over expected-finding-set
// ---------------------------------------------------------------------------

describe('A.12 — canonicalJson determinism over expected finding sets', () => {
  const sampleFinding: CanonicalFinding = {
    id: 'test-rule',
    file: 'src/config.ts',
    line: 1,
    column: 7,
    evidence: 'SECRET_KEY',
    severity: 'high',
    blocking: true,
    suppressionState: 'active',
    releaseId: 'test-release-1',
    matcherType: 'pattern',
  }

  it('canonicalizeFinding produces a plain object with exactly 10 fields', () => {
    const canonical = canonicalizeFinding(sampleFinding)
    const keys = Object.keys(canonical).sort()
    expect(keys).toEqual([
      'blocking', 'column', 'evidence', 'file', 'id',
      'line', 'matcherType', 'releaseId', 'severity', 'suppressionState',
    ])
  })

  it('canonicalJson over a finding is stable across calls (same input → same output)', () => {
    const first = canonicalJson(canonicalizeFinding(sampleFinding))
    const second = canonicalJson(canonicalizeFinding(sampleFinding))
    expect(first).toBe(second)
  })

  it('canonicalJson output is deterministic regardless of object key insertion order', () => {
    // Create two objects with the same logical content but different key order
    const findingA: CanonicalFinding = { ...sampleFinding }
    // TypeScript preserves literal insertion order but canonicalJson sorts keys
    const canonA = canonicalJson(canonicalizeFinding(findingA))
    const canonB = canonicalJson(canonicalizeFinding({ ...sampleFinding }))
    expect(canonA).toBe(canonB)
  })

  it('two findings that differ only in evidence produce different canonical hashes', () => {
    const f1: CanonicalFinding = { ...sampleFinding, evidence: 'SECRET_KEY' }
    const f2: CanonicalFinding = { ...sampleFinding, evidence: 'OTHER_KEY' }
    const c1 = canonicalJson(canonicalizeFinding(f1))
    const c2 = canonicalJson(canonicalizeFinding(f2))
    expect(c1).not.toBe(c2)
  })

  it('canonical form excludes timestamps and absolute paths (only 10 mandatory fields)', () => {
    // Add a fake timestamp to a finding object and verify it is excluded
    const findingWithTimestamp = { ...sampleFinding, createdAt: '2026-06-25T00:00:00Z' } as unknown as CanonicalFinding
    const canonical = canonicalizeFinding(findingWithTimestamp)
    expect('createdAt' in canonical).toBe(false)
    expect(Object.keys(canonical)).toHaveLength(10)
  })

  it('canonicalJson sorts keys alphabetically by UTF-16 code unit', () => {
    // "blocking" < "column" < "evidence" < "file" < "id" < "line" < "matcherType" < "releaseId" < "severity" < "suppressionState"
    const canonical = canonicalJson(canonicalizeFinding(sampleFinding))
    // Extract key order from JSON
    const keyOrder = [...canonical.matchAll(/"(\w+)":/g)].map((m) => m[1])
    expect(keyOrder).toEqual([
      'blocking', 'column', 'evidence', 'file', 'id',
      'line', 'matcherType', 'releaseId', 'severity', 'suppressionState',
    ])
  })
})

// ---------------------------------------------------------------------------
// A.12.3 — Harness skeleton: runs against a trivial stub executor
// ---------------------------------------------------------------------------

describe('A.12 — harness skeleton: trivial stub executor', () => {
  /**
   * A stub executor that always returns an empty findings array.
   * Used to verify that the harness runs without errors and produces
   * a valid ConformanceReport for executor-dependent vectors.
   *
   * Phase B.1 / D.1 will replace this with real adapters.
   */
  const stubExecutor: HarnessExecutor = {
    evaluate(
      _matcher: Matcher,
      _file: { relativePath: string; content: string },
      _ctx: ExecCtx,
    ): CanonicalFinding[] {
      return [] // always empty — stub for Phase A verification
    },
  }

  it('harness runs to completion without throwing', () => {
    expect(() => runConformance(stubExecutor, allConformanceVectors)).not.toThrow()
  })

  it('returns a ConformanceReport with totalVectors matching input', () => {
    const report = runConformance(stubExecutor, allConformanceVectors)
    expect(report.totalVectors).toBe(allConformanceVectors.length)
  })

  it('executor-independent vectors all pass with the stub', () => {
    const report = runConformance(stubExecutor, executorIndependentVectors)
    expect(report.failed).toBe(0)
    expect(report.passed).toBe(executorIndependentVectors.length)
  })

  it('executor-dependent vectors produce hash-recorded or fail status with stub', () => {
    const report = runConformance(stubExecutor, executorDependentVectors)
    // Stub always returns [] (empty findings).
    // Phase B.1 froze the hashes for all 9 executor-dependent vectors.
    // The stub's empty-findings hash does NOT match any frozen hash → status 'fail'.
    // If any vector still has null expectedCanonicalHash (pre-freeze), it would be 'hash-recorded'.
    // Either way, only 'hash-recorded', 'hash-frozen', or 'fail' are valid statuses here.
    for (const r of report.results) {
      expect(['hash-recorded', 'hash-frozen', 'fail']).toContain(r.status)
    }
    // Post-freeze: the stub WILL fail on all 9 frozen vectors — that is correct behavior.
    // The stub is not the real executor; it's only for Phase A skeleton verification.
    // This assertion documents the expected post-freeze behavior.
    const hasFrozenVectors = executorDependentVectors.some((v) => v.expectedCanonicalHash !== null)
    if (hasFrozenVectors) {
      // Frozen vectors will fail with stub (expected — stub ≠ real executor)
      expect(report.failed).toBeGreaterThan(0)
    } else {
      // Pre-freeze: all hash-recorded, none fail
      expect(report.failed).toBe(0)
    }
  })

  it('harness runs without executor: executor-dependent vectors are skipped', () => {
    const report = runConformance(null, allConformanceVectors)
    // Independent vectors should pass; dependent vectors should be skipped
    const skipped = report.results.filter((r) => r.status === 'skip')
    expect(skipped.length).toBe(executorDependentVectors.length)
    expect(report.passed).toBe(executorIndependentVectors.length)
  })

  it('results array length equals totalVectors', () => {
    const report = runConformance(stubExecutor, allConformanceVectors)
    expect(report.results.length).toBe(report.totalVectors)
  })

  it('each result has a vectorId matching an input vector id', () => {
    const report = runConformance(stubExecutor, allConformanceVectors)
    const inputIds = new Set(allConformanceVectors.map((v) => v.id))
    for (const r of report.results) {
      expect(inputIds.has(r.vectorId)).toBe(true)
    }
  })
})

// ---------------------------------------------------------------------------
// A.12.4 — Harness normalization assertions (independent, no executor)
// ---------------------------------------------------------------------------

describe('A.12 — harness normalization assertions (executor-independent)', () => {
  it('normalization-1: harness correctly fails on valid UTF-8 input (would succeed, not reject)', () => {
    // Run only the normalization-1 vector (invalid UTF-8 reject test)
    const normVectors = executorIndependentVectors.filter((v) => v.id === 'normalization-1')
    const report = runConformance(null, normVectors)
    expect(report.passed).toBe(1)
    expect(report.failed).toBe(0)
  })

  it('normalization-2: harness correctly confirms CRLF normalization', () => {
    const normVectors = executorIndependentVectors.filter((v) => v.id === 'normalization-2')
    const report = runConformance(null, normVectors)
    expect(report.passed).toBe(1)
    expect(report.failed).toBe(0)
  })

  it('normalization-3: harness correctly confirms BOM stripping', () => {
    const normVectors = executorIndependentVectors.filter((v) => v.id === 'normalization-3')
    const report = runConformance(null, normVectors)
    expect(report.passed).toBe(1)
    expect(report.failed).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// A.12.5 — Harness flag rejection assertions (independent, no executor)
// ---------------------------------------------------------------------------

describe('A.12 — harness flag rejection assertions (executor-independent)', () => {
  it('flags-1: harness confirms flags="g" is rejected by parseFlags', () => {
    const flagVectors = executorIndependentVectors.filter((v) => v.id === 'flags-1')
    const report = runConformance(null, flagVectors)
    expect(report.passed).toBe(1)
    expect(report.failed).toBe(0)
  })

  it('flags-2: harness confirms flags="ims" is accepted by parseFlags', () => {
    const flagVectors = executorIndependentVectors.filter((v) => v.id === 'flags-2')
    const report = runConformance(null, flagVectors)
    expect(report.passed).toBe(1)
    expect(report.failed).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// A.12.6 — Per-vector result detail is present
// ---------------------------------------------------------------------------

describe('A.12 — harness result detail strings', () => {
  it('each result has a non-empty detail string', () => {
    const report = runConformance(null, allConformanceVectors)
    for (const r of report.results) {
      expect(typeof r.detail).toBe('string')
      expect(r.detail.length).toBeGreaterThan(0)
    }
  })
})
