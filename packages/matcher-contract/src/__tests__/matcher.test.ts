// Task A.2 — Discriminated matcher-type union + executor interface tests.

import { describe, it, expect } from 'vitest'
import type {
  Matcher,
  PatternMatcher,
  FilePresenceMatcher,
  FileRelationshipMatcher,
  FileView,
  ExecCtx,
  MatchResult,
  MatcherExecutor,
} from '../matcher.js'

// ---------------------------------------------------------------------------
// Type-level tests (compile-time; if this file compiles, they pass)
// ---------------------------------------------------------------------------

// A PatternMatcher must be assignable to Matcher.
const _patternMatcher: Matcher = {
  type: 'pattern',
  fileGlob: '**/*.ts',
  patterns: ['process\\.env\\.SECRET'],
  antiPatterns: [],
  flags: 'i',
} satisfies PatternMatcher

// A FilePresenceMatcher must be assignable to Matcher.
const _filePres: Matcher = {
  type: 'file-presence',
  fileGlob: '.env',
  presenceRule: 'must-not-exist',
} satisfies FilePresenceMatcher

// A FileRelationshipMatcher must be assignable to Matcher.
const _fileRel: Matcher = {
  type: 'file-relationship',
  fileGlob: '**/*.tf',
  context: { requiresFile: '.terraform.lock.hcl' },
} satisfies FileRelationshipMatcher

// MatcherExecutor is parameterised on the Matcher variant.
// This compile-time check ensures the interface is well-formed.
const _executor: MatcherExecutor<PatternMatcher> = {
  evaluate(
    _matcher: PatternMatcher,
    _file: FileView,
    _ctx: ExecCtx,
  ): MatchResult[] {
    return []
  },
}

// Silence unused-variable lints without any runtime effect.
void _patternMatcher
void _filePres
void _fileRel
void _executor

// ---------------------------------------------------------------------------
// Runtime-discriminant tests
// ---------------------------------------------------------------------------

describe('A.2 — Matcher discriminated union', () => {
  it('discriminates PatternMatcher by type === "pattern"', () => {
    const m: Matcher = {
      type: 'pattern',
      fileGlob: '**/*.js',
      patterns: ['eval\\('],
      antiPatterns: [],
      flags: '',
    }
    expect(m.type).toBe('pattern')
  })

  it('discriminates FilePresenceMatcher by type === "file-presence"', () => {
    const m: Matcher = {
      type: 'file-presence',
      fileGlob: '.env',
      presenceRule: 'must-not-exist',
    }
    expect(m.type).toBe('file-presence')
  })

  it('discriminates FileRelationshipMatcher by type === "file-relationship"', () => {
    const m: Matcher = {
      type: 'file-relationship',
      fileGlob: 'docker-compose*.yml',
      context: { requiresFile: '.env.example', requiresPattern: 'DB_PASSWORD=' },
    }
    expect(m.type).toBe('file-relationship')
  })

  it('all three discriminants are mutually exclusive', () => {
    const matchers: Matcher[] = [
      { type: 'pattern', fileGlob: '*.ts', patterns: ['x'], antiPatterns: [], flags: '' },
      { type: 'file-presence', fileGlob: '.env', presenceRule: 'must-exist' },
      { type: 'file-relationship', fileGlob: '*.tf', context: {} },
    ]
    const types = matchers.map((m) => m.type)
    expect(new Set(types).size).toBe(3)
  })

  it('MatcherExecutor.evaluate returns MatchResult[] (runtime check with a stub impl)', () => {
    // A.3 full MatchResult shape — ruleId, file, releaseId, matcherType, occurrences[].
    const stubResult: MatchResult = {
      ruleId: 'test-rule',
      file: 'src/app.js',
      releaseId: 'rel-1',
      matcherType: 'pattern',
      occurrences: [
        {
          offset: 0,
          line: 1,
          column: 1,
          evidence: 'eval(',
          suppressionKey: 'src/app.js:1',
          suppressionState: 'active',
        },
      ],
    }
    const executor: MatcherExecutor<PatternMatcher> = {
      evaluate: () => [stubResult],
    }
    const file: FileView = { relativePath: 'src/app.js', content: 'eval()' }
    const ctx: ExecCtx = { allRelativePaths: ['src/app.js'], releaseId: 'rel-1' }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.js',
      patterns: ['eval\\('],
      antiPatterns: [],
      flags: '',
    }

    const results = executor.evaluate(matcher, file, ctx)
    expect(results).toHaveLength(1)
    expect(results[0].ruleId).toBe('test-rule')
    expect(results[0].occurrences[0].line).toBe(1)
    expect(results[0].occurrences[0].suppressionState).toBe('active')
  })
})
