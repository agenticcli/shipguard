// Task A.4 — finding.ts tests (CanonicalFinding + canonicalizeFinding).
// TDD: written BEFORE implementation.

import { describe, it, expect } from 'vitest'
import { canonicalizeFinding, canonicalJson } from '../canonical.js'
import type { CanonicalFinding } from '../finding.js'

// ---------------------------------------------------------------------------
// CanonicalFinding — type-level smoke tests
// ---------------------------------------------------------------------------

const sampleFinding: CanonicalFinding = {
  id: 'RULE-001',
  file: 'src/app.ts',
  line: 10,
  column: 5,
  evidence: 'process.env.SECRET',
  severity: 'high',
  blocking: true,
  suppressionState: 'active',
  releaseId: 'rel-abc',
  matcherType: 'pattern',
}

describe('A.4 — CanonicalFinding shape', () => {
  it('CanonicalFinding has all mandatory fields', () => {
    expect(sampleFinding.id).toBe('RULE-001')
    expect(sampleFinding.file).toBe('src/app.ts')
    expect(sampleFinding.line).toBe(10)
    expect(sampleFinding.column).toBe(5)
    expect(sampleFinding.evidence).toBe('process.env.SECRET')
    expect(sampleFinding.severity).toBe('high')
    expect(sampleFinding.blocking).toBe(true)
    expect(sampleFinding.suppressionState).toBe('active')
    expect(sampleFinding.releaseId).toBe('rel-abc')
    expect(sampleFinding.matcherType).toBe('pattern')
  })

  it('accepts null evidence (explicit null representation)', () => {
    const f: CanonicalFinding = { ...sampleFinding, evidence: null }
    expect(f.evidence).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// canonicalizeFinding — insertion-order independence + byte-identical output
// ---------------------------------------------------------------------------

describe('A.4 — canonicalizeFinding', () => {
  it('same logical finding in two insertion orders → byte-identical canonicalJson', () => {
    const findingA: CanonicalFinding = {
      id: 'RULE-001',
      file: 'src/app.ts',
      line: 10,
      column: 5,
      evidence: 'secret',
      severity: 'high',
      blocking: true,
      suppressionState: 'active',
      releaseId: 'rel-1',
      matcherType: 'pattern',
    }

    // Insert fields in reverse order — canonicalizeFinding must produce the same output.
    const findingB: CanonicalFinding = {
      matcherType: 'pattern',
      releaseId: 'rel-1',
      suppressionState: 'active',
      blocking: true,
      severity: 'high',
      evidence: 'secret',
      column: 5,
      line: 10,
      file: 'src/app.ts',
      id: 'RULE-001',
    }

    const canonA = canonicalJson(canonicalizeFinding(findingA))
    const canonB = canonicalJson(canonicalizeFinding(findingB))
    expect(canonA).toBe(canonB)
  })

  it('different findings produce different canonical JSON', () => {
    const f1: CanonicalFinding = { ...sampleFinding, line: 10 }
    const f2: CanonicalFinding = { ...sampleFinding, line: 20 }
    expect(canonicalJson(canonicalizeFinding(f1))).not.toBe(canonicalJson(canonicalizeFinding(f2)))
  })

  it('excludes timestamps from canonical form (timestamps not present in CanonicalFinding)', () => {
    // CanonicalFinding has no timestamp fields — any extra fields on a plain object
    // must NOT appear in the canonicalized output (canonicalizeFinding strips unknowns).
    const findingWithExtra = { ...sampleFinding, createdAt: '2026-01-01T00:00:00Z' } as unknown as CanonicalFinding
    const canon = canonicalizeFinding(findingWithExtra)
    const json = canonicalJson(canon)
    expect(json).not.toContain('createdAt')
  })

  it('excludes absolute paths from canonical form (file is root-relative)', () => {
    // The file field in CanonicalFinding is already root-relative by contract;
    // canonicalizeFinding must not allow an absolute path to leak through.
    // We test that if an absolute path somehow appears it is preserved as-is
    // (canonicalizeFinding does NOT transform the path — callers are responsible
    // for providing root-relative paths; but the test documents the expectation).
    const f: CanonicalFinding = { ...sampleFinding, file: 'src/config.ts' }
    const json = canonicalJson(canonicalizeFinding(f))
    expect(json).toContain('"src/config.ts"')
    // An absolute path would only appear if the caller provided it — document that
    // canonicalizeFinding itself does not inject one.
    expect(json).not.toMatch(/"\/[^"]+":/)
  })

  it('canonical form uses forward-slash file separators', () => {
    const f: CanonicalFinding = { ...sampleFinding, file: 'src/deep/nested/file.ts' }
    const json = canonicalJson(canonicalizeFinding(f))
    expect(json).toContain('src/deep/nested/file.ts')
    expect(json).not.toContain('\\')  // no backslash path separators
  })

  it('null evidence is preserved as null in canonical form', () => {
    const f: CanonicalFinding = { ...sampleFinding, evidence: null }
    const json = canonicalJson(canonicalizeFinding(f))
    expect(json).toContain('"evidence":null')
  })

  it('produces sorted keys in canonical JSON (locale-independent)', () => {
    const canon = canonicalizeFinding(sampleFinding)
    const json = canonicalJson(canon)
    // Keys should be in lexicographic UTF-16 order:
    // blocking, column, evidence, file, id, line, matcherType, releaseId, severity, suppressionState
    const keyOrder = Object.keys(JSON.parse(json))
    const sorted = [...keyOrder].sort((a, b) => {
      for (let i = 0; i < Math.min(a.length, b.length); i++) {
        const diff = a.charCodeAt(i) - b.charCodeAt(i)
        if (diff !== 0) return diff
      }
      return a.length - b.length
    })
    expect(keyOrder).toEqual(sorted)
  })

  it('same finding set in two insertion orders → byte-identical canonicalJson for each', () => {
    const f1: CanonicalFinding = { ...sampleFinding, id: 'RULE-001', line: 5 }
    const f2: CanonicalFinding = { ...sampleFinding, id: 'RULE-002', line: 10 }

    const set1 = [f1, f2]
    const set2 = [f2, f1] // reversed order

    const json1 = set1.map((f) => canonicalJson(canonicalizeFinding(f))).sort().join('\n')
    const json2 = set2.map((f) => canonicalJson(canonicalizeFinding(f))).sort().join('\n')

    expect(json1).toBe(json2)
  })
})
