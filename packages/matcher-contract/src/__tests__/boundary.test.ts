// per-rule boundary mode type-shape tests
//
// PHASE B.4 commit 1: verify the TypeScript type shape of PatternMatcher.boundary.
//
// Behavioral tests (what the executor does with each mode) live in
// native-v1.test.ts (commit 2), since they require a real adapter.
//
// This file proves that:
//   1. `boundary` is an optional field on PatternMatcher.
//   2. The three literal values ('none' | 'word' | 'token') are accepted by tsc.
//   3. Omitting `boundary` compiles fine (it defaults to 'none' at runtime).
//   4. The discriminated union (Matcher) still type-checks with boundary present.

import { describe, it, expect } from 'vitest'
import type { PatternMatcher, Matcher } from '../matcher.js'

// ---------------------------------------------------------------------------
// B.4.1 — boundary field is optional: omitting it compiles
// ---------------------------------------------------------------------------

describe('B.4 — PatternMatcher.boundary: type shape', () => {
  it('PatternMatcher without boundary is valid (boundary is optional)', () => {
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: '',
      // boundary intentionally absent — must compile
    }
    expect(matcher.type).toBe('pattern')
    // boundary absent → undefined at runtime (default 'none' applied by executor)
    expect(matcher.boundary).toBeUndefined()
  })

  it("boundary: 'none' is accepted", () => {
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: '',
      boundary: 'none',
    }
    expect(matcher.boundary).toBe('none')
  })

  it("boundary: 'word' is accepted", () => {
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: '',
      boundary: 'word',
    }
    expect(matcher.boundary).toBe('word')
  })

  it("boundary: 'token' is accepted", () => {
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['sk-[A-Za-z0-9]{20}'],
      antiPatterns: [],
      flags: '',
      boundary: 'token',
    }
    expect(matcher.boundary).toBe('token')
  })
})

// ---------------------------------------------------------------------------
// B.4.2 — Matcher discriminated union still works with boundary field
// ---------------------------------------------------------------------------

describe('B.4 — Matcher union: boundary does not break discriminant narrowing', () => {
  function matcherTypeOf(m: Matcher): string {
    return m.type
  }

  it('PatternMatcher with boundary is assignable to Matcher', () => {
    const matcher: Matcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['SK'],
      antiPatterns: [],
      flags: 'i',
      boundary: 'token',
    }
    expect(matcherTypeOf(matcher)).toBe('pattern')
  })

  it('FilePresenceMatcher is still assignable to Matcher (boundary is pattern-only)', () => {
    const matcher: Matcher = {
      type: 'file-presence',
      fileGlob: '**/.env',
      presenceRule: 'must-not-exist',
    }
    expect(matcherTypeOf(matcher)).toBe('file-presence')
  })

  it('FileRelationshipMatcher is still assignable to Matcher (boundary is pattern-only)', () => {
    const matcher: Matcher = {
      type: 'file-relationship',
      fileGlob: '**/.env',
      context: { requiresFile: '**/.env.example' },
    }
    expect(matcherTypeOf(matcher)).toBe('file-relationship')
  })
})

// ---------------------------------------------------------------------------
// B.4.3 — Runtime note: behavioral tests for each mode
// ---------------------------------------------------------------------------

describe('B.4 — boundary mode behavioral note', () => {
  it('NOTE: behavioral tests (none/word/token executor behavior) are in native-v1.test.ts', () => {
    // This test is a placeholder documenting that the executor-level behavior
    // tests (did the occurrence get accepted or rejected per boundary mode)
    // live in packages/matcher-contract/src/__tests__/native-v1.test.ts.
    //
    // Specifically: native-v1.test.ts covers
    //   - boundary:'none'  → 21-char sequence matched (no boundary check)
    //   - boundary:'token' → 21-char sequence rejected (next char is alphanumeric)
    //   - boundary:'word'  → SECRET on SECRETS rejected; SECRET on "SECRET " accepted
    expect(true).toBe(true)
  })
})
