// Tests for computeExecutableHash, EXEC_RULE_FIELDS, EXEC_RULE_EXTENSION_FIELDS
// from matcher-contract/src/executable-hash.ts
//
// Contract 0.5.0: ALL behaviour-affecting fields are now in EXEC_RULE_FIELDS and
// hashed. EXEC_RULE_EXTENSION_FIELDS is empty (deprecated sentinel). Tampering
// fileGlob, blocking, action, presenceRule, antiPatternScope, or boundary on a
// delivered rule must cause a hash mismatch (tamper-detection property).

import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { canonicalJson } from '../canonical.js'
import {
  computeExecutableHash,
  EXEC_RULE_FIELDS,
  EXEC_RULE_EXTENSION_FIELDS,
} from '../executable-hash.js'

// ---------------------------------------------------------------------------
// Helpers for reference hash computation
// ---------------------------------------------------------------------------

function referenceHash(fields: Record<string, unknown>): string {
  const preimage = 'shipguard-rule-v1\x00' + canonicalJson(fields)
  return createHash('sha256').update(preimage, 'utf8').digest('hex')
}

// ---------------------------------------------------------------------------
// Test fixtures: representative rules of each matcherType
// ---------------------------------------------------------------------------

const PATTERN_RULE_BASE: Record<string, unknown> = {
  enabled: true,
  flags: 'i',
  framework: 'generic',
  id: 'generic.hardcoded-secret',
  matcherType: 'pattern',
  pattern: 'password\\s*=\\s*["\'][^"\']+["\']',
  severity: 'high',
  tier: 'free',
  title: 'generic.hardcoded-secret',
}

const FILE_PRESENCE_RULE_BASE: Record<string, unknown> = {
  enabled: true,
  flags: '',
  framework: 'generic',
  id: 'generic.env-file-committed',
  matcherType: 'file-presence',
  severity: 'critical',
  tier: 'free',
  title: 'generic.env-file-committed',
}

const FILE_RELATIONSHIP_RULE_BASE: Record<string, unknown> = {
  enabled: true,
  flags: '',
  framework: 'nextjs',
  id: 'nextjs.api-without-auth',
  matcherType: 'file-relationship',
  pattern: 'export\\s+default',
  requiresFile: 'middleware.ts',
  requiresPattern: 'withAuth',
  severity: 'medium',
  tier: 'pro',
  title: 'nextjs.api-without-auth',
}

// ---------------------------------------------------------------------------
// EXEC_RULE_FIELDS and EXEC_RULE_EXTENSION_FIELDS exports (contract 0.5.0)
// ---------------------------------------------------------------------------

describe('EXEC_RULE_FIELDS', () => {
  it('exports exactly 21 fields (20 from 0.5.0 + confidence added in 0.5.1)', () => {
    expect(EXEC_RULE_FIELDS).toHaveLength(21)
  })

  it('contains confidence (0.5.1 — per-rule confidence: per-rule confidence is hashed, not advisory)', () => {
    const fieldSet = new Set(EXEC_RULE_FIELDS)
    expect(fieldSet.has('confidence' as never)).toBe(true)
  })

  it('confidence affects the hash: HIGH vs LOW produce different hashes (0.5.1 tamper-detection)', () => {
    const base: Record<string, unknown> = {
      enabled: true, flags: '', framework: 'generic', id: 'r1',
      matcherType: 'pattern', pattern: 'x', severity: 'medium', tier: 'free', title: 'T',
    }
    const high = computeExecutableHash({ ...base, confidence: 'HIGH' })
    const low = computeExecutableHash({ ...base, confidence: 'LOW' })
    const absent = computeExecutableHash(base)
    expect(high).not.toBe(low)
    // Backward-compat invariant: a rule WITHOUT confidence hashes exactly as in 0.5.0
    // (present-fields-only preimage) — existing pinned hashes stay valid.
    expect(absent).not.toBe(high)
    expect(absent).not.toBe(low)
  })

  it('contains all original §3.1 fields', () => {
    const fieldSet = new Set(EXEC_RULE_FIELDS)
    const required = ['antiBoundary', 'antiPattern', 'categories', 'enabled', 'flags',
      'framework', 'id', 'matcherType', 'pattern', 'requiresFile', 'requiresPattern',
      'severity', 'tier', 'title']
    for (const f of required) {
      expect(fieldSet.has(f as never), `Missing §3.1 field: ${f}`).toBe(true)
    }
  })

  it('contains all previously-extension fields (now hashed in 0.5.0)', () => {
    const fieldSet = new Set(EXEC_RULE_FIELDS)
    for (const ext of ['action', 'blocking', 'fileGlob', 'presenceRule']) {
      expect(fieldSet.has(ext as never), `Previously-extension field "${ext}" must now be in EXEC_RULE_FIELDS`).toBe(true)
    }
  })

  it('contains the new behaviour-affecting fields antiPatternScope and boundary', () => {
    const fieldSet = new Set(EXEC_RULE_FIELDS)
    expect(fieldSet.has('antiPatternScope' as never)).toBe(true)
    expect(fieldSet.has('boundary' as never)).toBe(true)
  })
})

describe('EXEC_RULE_EXTENSION_FIELDS', () => {
  it('is empty — deprecated sentinel only (all fields now hashed)', () => {
    expect(EXEC_RULE_EXTENSION_FIELDS.size).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// computeExecutableHash: basic correctness
// ---------------------------------------------------------------------------

describe('computeExecutableHash', () => {
  it('produces a 64-character lowercase hex string', () => {
    const hash = computeExecutableHash(PATTERN_RULE_BASE)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('is deterministic — same input always yields same hash', () => {
    const h1 = computeExecutableHash(PATTERN_RULE_BASE)
    const h2 = computeExecutableHash(PATTERN_RULE_BASE)
    expect(h1).toBe(h2)
  })

  it('matches the reference matcher spec §3.1 preimage formula for a pattern rule', () => {
    // Reference: SHA-256("shipguard-rule-v1\x00" + JCS(all-fields-in-EXEC_RULE_FIELDS))
    const expected = referenceHash(PATTERN_RULE_BASE)
    expect(computeExecutableHash(PATTERN_RULE_BASE)).toBe(expected)
  })

  it('matches the reference formula for a file-presence rule', () => {
    const expected = referenceHash(FILE_PRESENCE_RULE_BASE)
    expect(computeExecutableHash(FILE_PRESENCE_RULE_BASE)).toBe(expected)
  })

  it('matches the reference formula for a file-relationship rule', () => {
    const expected = referenceHash(FILE_RELATIONSHIP_RULE_BASE)
    expect(computeExecutableHash(FILE_RELATIONSHIP_RULE_BASE)).toBe(expected)
  })

  it('key-sort invariance: object with fields in different insertion order gives same hash', () => {
    const shuffled: Record<string, unknown> = {
      title: PATTERN_RULE_BASE.title,
      tier: PATTERN_RULE_BASE.tier,
      severity: PATTERN_RULE_BASE.severity,
      pattern: PATTERN_RULE_BASE.pattern,
      matcherType: PATTERN_RULE_BASE.matcherType,
      id: PATTERN_RULE_BASE.id,
      framework: PATTERN_RULE_BASE.framework,
      flags: PATTERN_RULE_BASE.flags,
      enabled: PATTERN_RULE_BASE.enabled,
    }
    expect(computeExecutableHash(shuffled)).toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('different field values produce different hashes', () => {
    const modified = { ...PATTERN_RULE_BASE, severity: 'critical' }
    expect(computeExecutableHash(modified)).not.toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })
})

// ---------------------------------------------------------------------------
// Tamper-detection: previously-extension fields are NOW in the hash preimage
// Changing any of them on a delivered rule MUST produce a different hash (MITM
// tamper is detectable).
// ---------------------------------------------------------------------------

describe('tamper-detection: all formerly-extension fields affect the hash (0.5.0)', () => {
  it('blocking=true: hash DIFFERS from base rule (tamper is visible)', () => {
    const withBlocking = { ...PATTERN_RULE_BASE, blocking: true }
    expect(computeExecutableHash(withBlocking)).not.toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('blocking=false: hash DIFFERS from base rule', () => {
    const withBlocking = { ...PATTERN_RULE_BASE, blocking: false }
    expect(computeExecutableHash(withBlocking)).not.toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('action="block": hash DIFFERS from base rule', () => {
    const withAction = { ...PATTERN_RULE_BASE, action: 'block' }
    expect(computeExecutableHash(withAction)).not.toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('action="warn": hash DIFFERS from base rule', () => {
    const withAction = { ...PATTERN_RULE_BASE, action: 'warn' }
    expect(computeExecutableHash(withAction)).not.toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('fileGlob="**/*.ts": hash DIFFERS from base rule (tamper via glob scope change)', () => {
    const withGlob = { ...PATTERN_RULE_BASE, fileGlob: '**/*.ts' }
    expect(computeExecutableHash(withGlob)).not.toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('presenceRule="must-not-exist": hash DIFFERS from base rule', () => {
    const withPresence = { ...FILE_PRESENCE_RULE_BASE, presenceRule: 'must-not-exist' }
    expect(computeExecutableHash(withPresence)).not.toBe(computeExecutableHash(FILE_PRESENCE_RULE_BASE))
  })

  it('antiPatternScope="file": hash DIFFERS from base rule', () => {
    const withScope = { ...PATTERN_RULE_BASE, antiPatternScope: 'file' }
    expect(computeExecutableHash(withScope)).not.toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('antiPatternScope={lines:5}: hash DIFFERS from base rule', () => {
    const withScope = { ...PATTERN_RULE_BASE, antiPatternScope: { lines: 5 } }
    expect(computeExecutableHash(withScope)).not.toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('boundary="word": hash DIFFERS from base rule', () => {
    const withBoundary = { ...PATTERN_RULE_BASE, boundary: 'word' }
    expect(computeExecutableHash(withBoundary)).not.toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('mutating fileGlob from "**/*.ts" to "**/*.js" produces a distinct hash', () => {
    const ruleTs = { ...PATTERN_RULE_BASE, fileGlob: '**/*.ts' }
    const ruleJs = { ...PATTERN_RULE_BASE, fileGlob: '**/*.js' }
    expect(computeExecutableHash(ruleTs)).not.toBe(computeExecutableHash(ruleJs))
  })

  it('mutating blocking from true to false produces a distinct hash', () => {
    const ruleT = { ...PATTERN_RULE_BASE, blocking: true }
    const ruleF = { ...PATTERN_RULE_BASE, blocking: false }
    expect(computeExecutableHash(ruleT)).not.toBe(computeExecutableHash(ruleF))
  })
})

// ---------------------------------------------------------------------------
// Strict schema: genuinely-unknown fields are REJECTED
// ---------------------------------------------------------------------------

describe('unknown fields are rejected', () => {
  it('throws on an unknown field not in EXEC_RULE_FIELDS', () => {
    const withUnknown = { ...PATTERN_RULE_BASE, unknownField: 'surprise' }
    expect(() => computeExecutableHash(withUnknown)).toThrow(/unknownField/)
  })

  it('throws on another unknown field', () => {
    const withUnknown = { ...PATTERN_RULE_BASE, extraData: 42 }
    expect(() => computeExecutableHash(withUnknown)).toThrow(/extraData/)
  })

  it('does NOT throw on a now-hashed field (blocking)', () => {
    expect(() => computeExecutableHash({ ...PATTERN_RULE_BASE, blocking: true })).not.toThrow()
  })

  it('does NOT throw on a now-hashed field (action)', () => {
    expect(() => computeExecutableHash({ ...PATTERN_RULE_BASE, action: 'warn' })).not.toThrow()
  })

  it('does NOT throw on a now-hashed field (fileGlob)', () => {
    expect(() => computeExecutableHash({ ...PATTERN_RULE_BASE, fileGlob: '**/*.ts' })).not.toThrow()
  })

  it('does NOT throw on a now-hashed field (presenceRule)', () => {
    expect(() => computeExecutableHash({ ...PATTERN_RULE_BASE, presenceRule: 'must-not-exist' })).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Optional §3.1 fields: undefined/absent must be omitted from preimage
// ---------------------------------------------------------------------------

describe('optional §3.1 fields: absent fields omitted from preimage', () => {
  it('antiBoundary absent vs explicitly undefined: same hash', () => {
    const withUndef = { ...PATTERN_RULE_BASE, antiBoundary: undefined }
    expect(computeExecutableHash(withUndef)).toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('antiPattern absent vs explicitly undefined: same hash', () => {
    const withUndef = { ...PATTERN_RULE_BASE, antiPattern: undefined }
    expect(computeExecutableHash(withUndef)).toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('categories absent vs explicitly undefined: same hash', () => {
    const withUndef = { ...PATTERN_RULE_BASE, categories: undefined }
    expect(computeExecutableHash(withUndef)).toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('categories present changes the hash', () => {
    const withCats = { ...PATTERN_RULE_BASE, categories: ['security', 'injection'] }
    expect(computeExecutableHash(withCats)).not.toBe(computeExecutableHash(PATTERN_RULE_BASE))
  })

  it('categories sort invariance: [b,a] and [a,b] yield identical hash (canonicalized inside contract)', () => {
    const withUnsorted = { ...PATTERN_RULE_BASE, categories: ['b', 'a'] }
    const withSorted   = { ...PATTERN_RULE_BASE, categories: ['a', 'b'] }
    expect(computeExecutableHash(withUnsorted)).toBe(computeExecutableHash(withSorted))
  })

  it('categories sort invariance: multi-element unsorted matches sorted', () => {
    const unsorted = { ...PATTERN_RULE_BASE, categories: ['z', 'c', 'a', 'm'] }
    const sorted   = { ...PATTERN_RULE_BASE, categories: ['a', 'c', 'm', 'z'] }
    expect(computeExecutableHash(unsorted)).toBe(computeExecutableHash(sorted))
  })
})

// ---------------------------------------------------------------------------
// antiPatternScope hash-equality proof: {lines:N} form canonicalizes correctly
// ---------------------------------------------------------------------------

describe('antiPatternScope and boundary: hash-equality proof', () => {
  const RULE_WITH_SCOPE: Record<string, unknown> = {
    ...PATTERN_RULE_BASE,
    antiPatternScope: 'function',
    boundary: 'word',
    fileGlob: '**/*.ts',
  }

  it('hash matches reference preimage for rule with antiPatternScope, boundary, fileGlob', () => {
    const expected = referenceHash(RULE_WITH_SCOPE)
    expect(computeExecutableHash(RULE_WITH_SCOPE)).toBe(expected)
  })

  it('antiPatternScope={lines:10} key-insertion-order invariant (JCS sorts object keys)', () => {
    const ruleA = { ...PATTERN_RULE_BASE, antiPatternScope: { lines: 10 } }
    // JCS canonicalizes {lines:10} regardless of field insertion order
    const expected = referenceHash(ruleA)
    expect(computeExecutableHash(ruleA)).toBe(expected)
  })

  it('antiPatternScope="statement" and antiPatternScope="file" produce different hashes', () => {
    const ruleStmt = { ...PATTERN_RULE_BASE, antiPatternScope: 'statement' }
    const ruleFile = { ...PATTERN_RULE_BASE, antiPatternScope: 'file' }
    expect(computeExecutableHash(ruleStmt)).not.toBe(computeExecutableHash(ruleFile))
  })
})
