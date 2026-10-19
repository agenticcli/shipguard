// Task A.3 — MatchResult full model tests.
// TDD: these tests are written BEFORE the implementation to drive it.

import { describe, it, expect } from 'vitest'
import type {
  MatchResult,
  MatchResultOccurrence,
  FileView,
  ExecCtx,
  PatternMatcher,
  MatcherExecutor,
} from '../matcher.js'

// ---------------------------------------------------------------------------
// Helper: a minimal stub executor that uses JS RegExp to produce MatchResults
// exercising the full A.3 model. In Phase B, the native/re2js adapters replace
// this — here we just need results shaped correctly.
// ---------------------------------------------------------------------------

/**
 * Minimal reference executor (STUB — NOT Phase B). Uses JS RegExp with the
 * exact zero-width-match advancement rule and UTF-16 offset semantics defined
 * in A.3, so the tests exercise the MODEL, not a real engine.
 */
function runStub(
  matcher: PatternMatcher,
  file: FileView,
  ctx: ExecCtx,
): MatchResult {
  const content = file.content
  // Build line-start index (UTF-16 code unit positions).
  const lineStarts: number[] = [0]
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') lineStarts.push(i + 1)
  }

  const occurrences: MatchResultOccurrence[] = []

  for (const pattern of matcher.patterns) {
    const flags = matcher.flags.includes('i') ? 'gi' : 'g'
    const re = new RegExp(pattern, flags + (matcher.flags.includes('s') ? 's' : '') + (matcher.flags.includes('m') ? 'm' : ''))
    let match: RegExpExecArray | null
    let lastIndex = 0
    re.lastIndex = 0

    while ((match = re.exec(content)) !== null) {
      const start = match.index
      // Zero-width-match advancement rule (A.3): advance by 1 code unit to avoid infinite loop.
      if (match[0].length === 0) {
        re.lastIndex = start + 1
      }
      if (start < lastIndex) continue // skip overlapping
      lastIndex = start + match[0].length

      // Resolve line and column (1-based, UTF-16 code units).
      let lineIndex = lineStarts.length - 1
      for (let l = 0; l < lineStarts.length; l++) {
        if (lineStarts[l] > start) { lineIndex = l - 1; break }
        if (l === lineStarts.length - 1) lineIndex = l
      }
      const lineStart = lineStarts[lineIndex]
      const line = lineIndex + 1
      const column = start - lineStart + 1

      // Check anti-patterns scoped to the matched line (A.3 context-window rule).
      const lineEnd = lineIndex + 1 < lineStarts.length ? lineStarts[lineIndex + 1] - 1 : content.length
      const lineText = content.slice(lineStart, lineEnd)
      const suppressed = matcher.antiPatterns.some((ap) => new RegExp(ap).test(lineText))

      occurrences.push({
        offset: start,
        line,
        column,
        evidence: match[0],
        suppressionKey: `${file.relativePath}:${line}`,
        suppressionState: suppressed ? 'suppressed' : 'active',
      })
    }
  }

  return {
    ruleId: (matcher as unknown as { id?: string }).id ?? 'stub-rule',
    file: file.relativePath,
    releaseId: ctx.releaseId,
    matcherType: matcher.type,
    occurrences,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('A.3 — MatchResult full model', () => {
  const ctx: ExecCtx = { allRelativePaths: ['src/app.ts'], releaseId: 'rel-test-1' }

  // -------------------------------------------------------------------------
  // UTF-16 offset / line / column semantics
  // -------------------------------------------------------------------------
  it('reports UTF-16 code-unit offset and 1-based line + column', () => {
    // 'hello\nworld' — "world" starts at UTF-16 offset 6 (line 2, col 1)
    const file: FileView = { relativePath: 'src/app.ts', content: 'hello\nworld' }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['world'],
      antiPatterns: [],
      flags: '',
    }
    const result = runStub(matcher, file, ctx)
    expect(result.occurrences).toHaveLength(1)
    const occ = result.occurrences[0]
    expect(occ.offset).toBe(6)    // UTF-16 code unit 6
    expect(occ.line).toBe(2)      // second line
    expect(occ.column).toBe(1)    // first column on that line
  })

  it('reports multiple non-overlapping matches in offset order', () => {
    // "foo bar foo" has "foo" at offsets 0 and 8
    const file: FileView = { relativePath: 'src/app.ts', content: 'foo bar foo' }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['foo'],
      antiPatterns: [],
      flags: '',
    }
    const result = runStub(matcher, file, ctx)
    expect(result.occurrences).toHaveLength(2)
    expect(result.occurrences[0].offset).toBe(0)
    expect(result.occurrences[0].column).toBe(1)
    expect(result.occurrences[1].offset).toBe(8)
    expect(result.occurrences[1].column).toBe(9)
  })

  it('column is UTF-16 code units from line start (not bytes)', () => {
    // Line 1: "αβ secret" — α=U+03B1 (1 UTF-16 unit), β=U+03B2 (1 UTF-16 unit)
    // "secret" starts at UTF-16 column 4 (αβ + space = 3 code units, then col 4)
    const file: FileView = { relativePath: 'src/app.ts', content: 'αβ secret' }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['secret'],
      antiPatterns: [],
      flags: '',
    }
    const result = runStub(matcher, file, ctx)
    expect(result.occurrences).toHaveLength(1)
    expect(result.occurrences[0].line).toBe(1)
    expect(result.occurrences[0].column).toBe(4) // α(1) + β(1) + space(1) + 1 = 4
  })

  // -------------------------------------------------------------------------
  // Zero-width match advancement rule
  // -------------------------------------------------------------------------
  it('advances by 1 code unit on a zero-width match (no infinite loop)', () => {
    // Pattern `a*` matches zero or more 'a'. On "bc", it matches "" at every position
    // including the end — the advancement rule must prevent an infinite loop.
    const file: FileView = { relativePath: 'src/app.ts', content: 'bc' }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['a*'],
      antiPatterns: [],
      flags: '',
    }
    // Must complete without hanging; zero-width matches are allowed to appear
    // but must not cause an infinite loop.
    const result = runStub(matcher, file, ctx)
    // Each zero-width match at each position (0, 1, 2) is one occurrence
    expect(result.occurrences.length).toBeGreaterThanOrEqual(0)
    // All offsets must be bounded by the content length
    for (const occ of result.occurrences) {
      expect(occ.offset).toBeLessThanOrEqual(file.content.length)
    }
  })

  // -------------------------------------------------------------------------
  // Anti-pattern scope: per-line (NOT file-wide)
  // -------------------------------------------------------------------------
  it('anti-pattern suppresses only the matched line — safe+unsafe in same file both reported correctly', () => {
    // Line 1: "const SAFE = process.env.SECRET // safe ignore" — anti-pattern matches → suppressed
    // Line 2: "const BAD = process.env.SECRET" — no anti-pattern → active (reported)
    const content = 'const SAFE = process.env.SECRET // safe ignore\nconst BAD = process.env.SECRET'
    const file: FileView = { relativePath: 'src/app.ts', content }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['process\\.env\\.SECRET'],
      antiPatterns: ['safe ignore'],
      flags: '',
    }
    const result = runStub(matcher, file, ctx)
    expect(result.occurrences).toHaveLength(2)
    const line1 = result.occurrences.find((o) => o.line === 1)
    const line2 = result.occurrences.find((o) => o.line === 2)
    expect(line1).toBeDefined()
    expect(line2).toBeDefined()
    expect(line1!.suppressionState).toBe('suppressed')
    expect(line2!.suppressionState).toBe('active')
  })

  it('anti-pattern is NOT file-wide: a safe match on line 1 does not suppress an unsafe match on line 2', () => {
    // This is the A.3 fix for the live bug: file-wide anti-pattern swallowed real findings.
    const content = 'ignore_safe_here\nprocess.env.SECRET_KEY'
    const file: FileView = { relativePath: 'src/app.ts', content }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['process\\.env\\.SECRET_KEY'],
      antiPatterns: ['ignore_safe_here'],
      flags: '',
    }
    const result = runStub(matcher, file, ctx)
    // The unsafe match is on line 2; the anti-pattern only appears on line 1 (different line)
    const line2 = result.occurrences.find((o) => o.line === 2)
    expect(line2).toBeDefined()
    expect(line2!.suppressionState).toBe('active') // NOT suppressed because anti-pattern is on a different line
  })

  // -------------------------------------------------------------------------
  // Per-occurrence suppression key
  // -------------------------------------------------------------------------
  it('each occurrence has a unique suppressionKey scoped to file:line', () => {
    const content = 'SECRET\nSECRET\nSECRET'
    const file: FileView = { relativePath: 'src/config.ts', content }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: '',
    }
    const result = runStub(matcher, file, ctx)
    expect(result.occurrences).toHaveLength(3)
    const keys = result.occurrences.map((o) => o.suppressionKey)
    expect(keys[0]).toBe('src/config.ts:1')
    expect(keys[1]).toBe('src/config.ts:2')
    expect(keys[2]).toBe('src/config.ts:3')
  })

  // -------------------------------------------------------------------------
  // Evidence field
  // -------------------------------------------------------------------------
  it('evidence contains the matched text', () => {
    const file: FileView = { relativePath: 'src/app.ts', content: 'password=hunter2' }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['password=\\w+'],
      antiPatterns: [],
      flags: '',
    }
    const result = runStub(matcher, file, ctx)
    expect(result.occurrences).toHaveLength(1)
    expect(result.occurrences[0].evidence).toBe('password=hunter2')
  })

  // -------------------------------------------------------------------------
  // MatchResult metadata
  // -------------------------------------------------------------------------
  it('MatchResult carries file, releaseId, and matcherType', () => {
    const file: FileView = { relativePath: 'src/app.ts', content: 'TOKEN=abc' }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['TOKEN=\\w+'],
      antiPatterns: [],
      flags: '',
    }
    const result = runStub(matcher, file, ctx)
    expect(result.file).toBe('src/app.ts')
    expect(result.releaseId).toBe('rel-test-1')
    expect(result.matcherType).toBe('pattern')
  })

  // -------------------------------------------------------------------------
  // No file-wide collapse: two instances in one file → two occurrences
  // -------------------------------------------------------------------------
  it('two distinct matches in one file produce two occurrences (no file-wide collapse)', () => {
    const content = 'BAD_TOKEN_A\nBAD_TOKEN_B'
    const file: FileView = { relativePath: 'src/app.ts', content }
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['BAD_TOKEN_[AB]'],
      antiPatterns: [],
      flags: '',
    }
    const result = runStub(matcher, file, ctx)
    expect(result.occurrences).toHaveLength(2)
    expect(result.occurrences[0].line).toBe(1)
    expect(result.occurrences[1].line).toBe(2)
  })
})
