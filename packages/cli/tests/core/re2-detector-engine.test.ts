/**
 * Unit tests for src/core/re2-detector-engine.ts
 *
 * Verifies:
 * 1. Safe patterns: helper results (match text, index, captures, multi-match)
 *    are IDENTICAL to native RegExp on the same inputs.
 * 2. The helper THROWS loudly on a lookahead pattern (never silently falls back
 *    to native, which would defeat ReDoS-immunity).
 * 3. Invalid flags are rejected with a clear error.
 */

import { describe, it, expect } from 'vitest'
import { compileDetectorRegex } from '../../src/core/re2-detector-engine.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Run native exec() and return a normalized result shape matching
 * DetectorExecResult so we can diff against the helper.
 */
function nativeExec(
  source: string,
  flags: string,
  input: string,
): { match: string; index: number; groups: (string | undefined)[] } | null {
  const re = new RegExp(source, flags)
  const m = re.exec(input)
  if (!m) return null
  // m[0] is full match; m[1..n] are capture groups.
  const groups: (string | undefined)[] = []
  for (let g = 1; g < m.length; g++) {
    groups.push(m[g])
  }
  return { match: m[0], index: m.index, groups }
}

/**
 * Run native matchAll() and return normalized results.
 */
function nativeMatchAll(
  source: string,
  flags: string,
  input: string,
): { match: string; index: number; groups: (string | undefined)[] }[] {
  const re = new RegExp(source, 'g' + flags.replace('g', ''))
  const results: { match: string; index: number; groups: (string | undefined)[] }[] = []
  for (const m of input.matchAll(re)) {
    const groups: (string | undefined)[] = []
    for (let g = 1; g < m.length; g++) {
      groups.push(m[g])
    }
    results.push({ match: m[0], index: m.index ?? 0, groups })
  }
  return results
}

// A battery of RE2-safe patterns with their flags and test inputs.
const SAFE_PATTERN_BATTERY = [
  {
    label: 'simple literal',
    source: 'hello',
    flags: '',
    inputs: ['hello world', 'say hello', 'no match here', ''],
  },
  {
    label: 'case-insensitive flag',
    source: 'openai',
    flags: 'i',
    inputs: ['OPENAI_KEY=x', 'openai_key=x', 'no key here'],
  },
  {
    label: 'multiline anchors',
    source: '^\\s*(//|#)',
    flags: 'm',
    inputs: ['// comment\ncode', '  # hash comment\ncode', 'not a comment'],
  },
  {
    label: 'single capturing group',
    source: `sk-proj-([a-zA-Z0-9_\\-]{4,})`,
    flags: '',
    inputs: [
      `const k = 'sk-proj-abc123XYZ'`,
      `key = "sk-proj-TestValue-99"`,
      'no secret here',
    ],
  },
  {
    label: 'two capturing groups',
    source: `(openai|stripe)_key\\s*=\\s*['"]([a-zA-Z0-9]{10,})['"]`,
    flags: 'i',
    inputs: [
      `openai_key = 'abcdefghij'`,
      `STRIPE_KEY = "1234567890x"`,
      'no key here',
    ],
  },
  {
    label: 'alternation',
    source: `ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{20,}`,
    flags: '',
    inputs: [
      `token = 'ghp_' + 'abc123def456abc123def456abc123def456xx'`,
      `pat = github_pat_abc123def456abc123def456x`,
      'nothing here',
    ],
  },
  {
    label: 'character class negation [^]',
    source: `jwt_secret\\s*=\\s*['"]([^'"]{8,})['"]`,
    flags: 'i',
    inputs: [
      `JWT_SECRET='mysupersecretkey'`,
      `jwt_secret = "anotheronethatlongone"`,
      'no match',
    ],
  },
  {
    label: 'dotall flag (. matches newline)',
    source: `BEGIN(.+?)END`,
    flags: 's',
    inputs: ['BEGIN\nsome content\nEND', 'BEGIN no newline END', 'no begin'],
  },
  {
    label: 'AWS Access Key ID format',
    source: `AKIA[0-9A-Z]{16}`,
    flags: 'm',
    inputs: [
      `const key = 'AKIAIOSFODNN7EXAMPLE'`,
      'not an aws key',
      `key1 = 'AKIAIOSFODNN7EXAM01'\nkey2 = 'AKIAIOSFODNN7EXAM02'`,
    ],
  },
  {
    label: 'database URL protocol alternation',
    source: `(postgres|mysql|mongodb)://[^'"]+:[^@'"]+@[^'"]+`,
    flags: 'i',
    inputs: [
      `const u = "postgres://user:pass@host/db"`,
      `uri = 'mongodb://admin:s3cr3t@host.com/mydb'`,
      'no db url',
    ],
  },
]

// ---------------------------------------------------------------------------
// Part 1: Safe patterns — helper == native RegExp
// ---------------------------------------------------------------------------

describe('re2-detector-engine — safe patterns match native RegExp', () => {
  for (const { label, source, flags, inputs } of SAFE_PATTERN_BATTERY) {
    describe(`pattern: ${label}`, () => {
      for (const input of inputs) {
        it(`test("${input.slice(0, 40)}") matches native`, () => {
          const helper = compileDetectorRegex(source, flags)
          const nativeRe = new RegExp(source, flags)
          expect(helper.test(input)).toBe(nativeRe.test(input))
        })

        it(`exec("${input.slice(0, 40)}") matches native`, () => {
          const helper = compileDetectorRegex(source, flags)
          const helperResult = helper.exec(input)
          const nativeResult = nativeExec(source, flags, input)

          if (nativeResult === null) {
            expect(helperResult).toBeNull()
          } else {
            expect(helperResult).not.toBeNull()
            expect(helperResult!.match).toBe(nativeResult.match)
            expect(helperResult!.index).toBe(nativeResult.index)
            expect(helperResult!.groups).toEqual(nativeResult.groups)
          }
        })

        it(`matchAll("${input.slice(0, 40)}") matches native`, () => {
          const helper = compileDetectorRegex(source, flags)
          const helperResults = helper.matchAll(input)
          const nativeResults = nativeMatchAll(source, flags, input)

          expect(helperResults.length).toBe(nativeResults.length)
          for (let i = 0; i < nativeResults.length; i++) {
            expect(helperResults[i].match).toBe(nativeResults[i].match)
            expect(helperResults[i].index).toBe(nativeResults[i].index)
            expect(helperResults[i].groups).toEqual(nativeResults[i].groups)
          }
        })
      }
    })
  }
})

// ---------------------------------------------------------------------------
// Part 2: Throws on lookahead (never silent fallback)
// ---------------------------------------------------------------------------

describe('re2-detector-engine — THROWS on unsupported constructs', () => {
  it('throws on positive lookahead (?=)', () => {
    expect(() => compileDetectorRegex('foo(?=bar)')).toThrow('[re2-detector-engine]')
  })

  it('throws on negative lookahead (?!)', () => {
    expect(() => compileDetectorRegex(`['"]secret['"](?!\\s*\\+)`)).toThrow('[re2-detector-engine]')
  })

  it('throws on positive lookbehind (?<=)', () => {
    expect(() => compileDetectorRegex('(?<=secret=)\\w+')).toThrow('[re2-detector-engine]')
  })

  it('throws on backreference \\1', () => {
    expect(() => compileDetectorRegex(`(['"])(.+)\\1`)).toThrow('[re2-detector-engine]')
  })

  it('throws on invalid flags (g flag)', () => {
    expect(() => compileDetectorRegex('foo', 'g')).toThrow('[re2-detector-engine]')
  })

  it('throws on invalid flags (unknown char)', () => {
    expect(() => compileDetectorRegex('foo', 'x')).toThrow('[re2-detector-engine]')
  })

  it('throws on duplicate flags', () => {
    expect(() => compileDetectorRegex('foo', 'ii')).toThrow('[re2-detector-engine]')
  })
})

// ---------------------------------------------------------------------------
// Part 3: Multi-match (matchAll) with multiple occurrences
// ---------------------------------------------------------------------------

describe('re2-detector-engine — matchAll finds all non-overlapping matches', () => {
  it('finds two AWS key IDs on separate lines', () => {
    const source = `AKIA[0-9A-Z]{16}`
    // AKIA + exactly 16 uppercase/digit chars = 20 total chars per key
    // KEY1: AKIA + IOSFODNN7EXAMPLE (16)  = 20 chars
    // KEY2: AKIA + IOSFODNN7EXAMPLA (16)  = 20 chars
    const input = `const key1 = 'AKIAIOSFODNN7EXAMPLE'\nconst key2 = 'AKIAIOSFODNN7EXAMPLA'`
    const helper = compileDetectorRegex(source, 'm')
    const results = helper.matchAll(input)
    expect(results.length).toBe(2)
    expect(results[0].match).toBe('AKIAIOSFODNN7EXAMPLE')
    expect(results[1].match).toBe('AKIAIOSFODNN7EXAMPLA')
    expect(results[0].index).not.toBe(results[1].index)
  })

  it('captures group text in each match', () => {
    const source = `(sk_live_|sk_test_)([a-zA-Z0-9]{10,})`
    const input = `a = 'sk_live_abcdefghij'\nb = 'sk_test_0123456789'`
    const helper = compileDetectorRegex(source, 'i')
    const results = helper.matchAll(input)
    expect(results.length).toBe(2)
    expect(results[0].groups[0]).toBe('sk_live_')
    expect(results[0].groups[1]).toBe('abcdefghij')
    expect(results[1].groups[0]).toBe('sk_test_')
    expect(results[1].groups[1]).toBe('0123456789')
  })
})

// ---------------------------------------------------------------------------
// Part 4: Edge cases for index / group correctness
// ---------------------------------------------------------------------------

describe('re2-detector-engine — exec() index and group correctness', () => {
  it('returns correct 0-based index for a mid-string match', () => {
    const source = 'SECRET'
    const input = '  const SECRET'
    const helper = compileDetectorRegex(source)
    const result = helper.exec(input)
    expect(result).not.toBeNull()
    expect(result!.index).toBe(8) // "  const " is 8 chars
  })

  it('returns undefined for unmatched optional group', () => {
    const source = `(A)?(B)`
    const input = 'B only'
    const helper = compileDetectorRegex(source)
    const result = helper.exec(input)
    expect(result).not.toBeNull()
    expect(result!.groups[0]).toBeUndefined() // group 1 (A) not matched
    expect(result!.groups[1]).toBe('B')       // group 2 (B) matched
  })

  it('test() returns false when no match', () => {
    const helper = compileDetectorRegex('sk-proj-[a-z]{20,}')
    expect(helper.test('no secrets here')).toBe(false)
  })

  it('test() returns true when match exists', () => {
    const helper = compileDetectorRegex('sk-proj-[a-z]{20,}')
    expect(helper.test(`key = 'sk-proj-abcdefghijklmnopqrst'`)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Part 5: replaceFirst() — D.4 extension for deployment.ts AS alias stripping
// ---------------------------------------------------------------------------

describe('re2-detector-engine — replaceFirst()', () => {
  it('replaces the FIRST occurrence only', () => {
    const re = compileDetectorRegex('foo')
    expect(re.replaceFirst('foo bar foo', 'baz')).toBe('baz bar foo')
  })

  it('returns the original string when no match', () => {
    const re = compileDetectorRegex('xyz')
    expect(re.replaceFirst('hello world', 'REPLACED')).toBe('hello world')
  })

  it('replaces at the start of the string', () => {
    const re = compileDetectorRegex('^hello', 'm')
    expect(re.replaceFirst('hello world', '')).toBe(' world')
  })

  it('replaces with an empty string (deletion)', () => {
    const re = compileDetectorRegex('\\s+AS\\s+\\w+', 'i')
    expect(re.replaceFirst('FROM node:18 AS builder', '').trim()).toBe('FROM node:18')
    expect(re.replaceFirst('FROM redis:7 as cache', '').trim()).toBe('FROM redis:7')
  })

  it('replaces with a non-empty string', () => {
    const re = compileDetectorRegex('world')
    expect(re.replaceFirst('hello world', 'JS')).toBe('hello JS')
  })

  it('handles zero-width replacement boundary correctly', () => {
    const re = compileDetectorRegex('a+')
    expect(re.replaceFirst('baaab', 'X')).toBe('bXb')
  })

  it('is equivalent to string.replace(nativeRe, "") for the AS alias case', () => {
    const nativeRe = /\s+AS\s+\w+/i
    const re2Re = compileDetectorRegex('\\s+AS\\s+\\w+', 'i')
    const cases = [
      'FROM node:18-alpine AS builder',
      'FROM redis:7 as cache',
      'FROM postgres AS db',
      'FROM node:latest',           // no alias — no change
      'FROM scratch AS intermediate',
    ]
    for (const s of cases) {
      const nativeResult = s.replace(nativeRe, '').trim()
      const re2Result = re2Re.replaceFirst(s, '').trim()
      expect(re2Result).toBe(nativeResult)
    }
  })
})

// ---------------------------------------------------------------------------
// Part 6: replace() — re2js-backed global replace, identical to native /g replace
// ---------------------------------------------------------------------------

/**
 * Helper: run native String.replace with a /g regex and compare to helper.replace().
 * 'g' is forced; additional flags merged in.
 */
function nativeReplaceAll(source: string, flags: string, input: string, replacement: string): string {
  const re = new RegExp(source, 'g' + flags.replace('g', ''))
  return input.replace(re, replacement)
}

// Battery of (source, flags, input, replacement) tuples for differential testing.
const REPLACE_BATTERY = [
  {
    label: 'SQL block comment strip (plain replacement)',
    source: '\\/\\*.*?\\*\\/',
    flags: 's',
    input: '/* DROP TABLE foo; */ SELECT 1; /* another comment */\nSELECT 2;',
    replacement: ' ',
  },
  {
    label: 'SQL line comment strip (replace with empty)',
    source: '--[^\n]*',
    flags: '',
    input: '-- drop this\nSELECT 1; -- inline comment\nSELECT 2;',
    replacement: '',
  },
  {
    label: 'global replace no matches (input unchanged)',
    source: 'DROP TABLE',
    flags: 'i',
    input: 'CREATE TABLE foo (id INT);',
    replacement: 'DELETED',
  },
  {
    label: 'global replace all occurrences',
    source: 'foo',
    flags: '',
    input: 'foo bar foo baz foo',
    replacement: 'qux',
  },
  {
    label: 'replacement with $& (full match)',
    source: '\\b\\d+\\b',
    flags: '',
    input: 'id=1 AND count=42',
    replacement: '[$&]',
  },
  {
    label: 'replacement with $1 (capture group)',
    source: '(DROP)\\s+(TABLE)',
    flags: 'i',
    input: 'DROP TABLE foo; drop table bar;',
    replacement: '/* $1 $2 */',
  },
  {
    label: 'replacement with $$ (literal dollar sign)',
    source: 'USD',
    flags: '',
    input: '100 USD and 200 USD',
    replacement: '$$',
  },
  {
    label: 'case-insensitive global replace',
    source: 'drop',
    flags: 'i',
    input: 'DROP drop Drop dRoP',
    replacement: 'NOOP',
  },
  {
    label: 'empty input — no matches',
    source: 'anything',
    flags: '',
    input: '',
    replacement: 'x',
  },
  {
    label: 'block comment spanning multiple lines',
    source: '\\/\\*.*?\\*\\/',
    flags: 's',
    input: '/* line1\nline2\nline3 */\nSELECT 1;',
    replacement: '',
  },
]

describe("re2-detector-engine — replace() is IDENTICAL to native String.replace(/re/g, ...) ", () => {
  for (const { label, source, flags, input, replacement } of REPLACE_BATTERY) {
    it(label, () => {
      const helper = compileDetectorRegex(source, flags)
      const helperResult = helper.replace(input, replacement)
      const nativeResult = nativeReplaceAll(source, flags, input, replacement)
      expect(helperResult).toBe(nativeResult)
    })
  }

  it('multiple calls on the same compiled instance are stateless (idempotent)', () => {
    const re = compileDetectorRegex('x', '')
    const a = re.replace('x x x', '_')
    const b = re.replace('x x x', '_')
    expect(a).toBe(b)
    expect(a).toBe('_ _ _')
  })

  it('replace does not affect subsequent test() / exec() calls on the same compiled instance', () => {
    const re = compileDetectorRegex('foo', 'i')
    re.replace('foo FOO foo', 'bar') // must not mutate compiled state
    expect(re.test('FOO')).toBe(true)
    const result = re.exec('FOO bar')
    expect(result).not.toBeNull()
    expect(result!.match).toBe('FOO')
  })
})
