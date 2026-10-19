/**
 * native-v1-fail-closed.test.ts — a rule that cannot compile must be loud, never silent.
 *
 * 
 *
 * The native fallback executor used to swallow an uncompilable pattern with a bare
 * `catch { continue }`. The consequence is the worst shape a scanner can have: the rule
 * produced ZERO findings, the scan completed normally, and the user got a clean result over
 * a rule that never ran. A skipped rule and a clean codebase look identical from outside.
 *
 * The anti-pattern case is worse still. Skipping a broken anti-pattern leaves the rule
 * FIRING but without the guard that keeps it off legitimate code — false positives with no
 * signal that the rule is running half-configured.
 *
 * The re2js executor (the active one) already fails closed here under its FIX 5 atomic-compile
 * contract. These tests pin the native fallback to the same behaviour, so which executor is
 * active can never decide whether a broken rule is loud or silent.
 *
 * The fallback is dormant today. That is exactly why it needed a test: nothing else would
 * have noticed when a future rule-corpus change armed it.
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
import { nativeV1Executor } from '@agenticcli/matcher-contract'
import type { PatternMatcher, ExecCtx } from '@agenticcli/matcher-contract'

const file = { relativePath: 'src/app.ts', content: "const key = 'AKIAIOSFODNN7EXAMPLE'\n" }
const ctx: ExecCtx = { allRelativePaths: ['src/app.ts'], releaseId: 'test' }

/** Valid RE2/re2js syntax, INVALID as a native JS RegExp — the realistic drift case. */
const UNCOMPILABLE = '(?P<name>AKIA[0-9A-Z]{16})'

afterEach(() => vi.restoreAllMocks())

describe('native-v1 — an uncompilable PATTERN fails closed', () => {
  it('throws instead of quietly reporting zero findings', () => {
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: [UNCOMPILABLE],
      antiPatterns: [],
      flags: '',
    }
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(() => nativeV1Executor.evaluate(matcher, file, ctx)).toThrow(/compile failure/i)
  })

  it('logs the reason before throwing — every catch logs', () => {
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: [UNCOMPILABLE],
      antiPatterns: [],
      flags: '',
    }
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(() => nativeV1Executor.evaluate(matcher, file, ctx)).toThrow()
    expect(spy).toHaveBeenCalled()
    expect(String(spy.mock.calls[0][0])).toMatch(/compile error for pattern/)
  })

  it('a broken pattern is not hidden by a valid sibling pattern in the same rule', () => {
    // The old `continue` meant the rule still returned the OTHER pattern's findings, so the
    // result looked plausible and the silent skip was invisible even on inspection.
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['AKIA[0-9A-Z]{16}', UNCOMPILABLE],
      antiPatterns: [],
      flags: '',
    }
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(() => nativeV1Executor.evaluate(matcher, file, ctx)).toThrow(/compile failure/i)
  })
})

describe('native-v1 — an uncompilable ANTI-PATTERN fails closed', () => {
  it('throws rather than running the rule without its guard', () => {
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['AKIA[0-9A-Z]{16}'],
      antiPatterns: [UNCOMPILABLE],
      flags: '',
      antiPatternScope: { lines: 2 },
    } as PatternMatcher
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(() => nativeV1Executor.evaluate(matcher, file, ctx)).toThrow(/anti-pattern compile failure/i)
  })
})

describe('native-v1 — the happy path is untouched', () => {
  it('still finds a real match when every pattern compiles', () => {
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['AKIA[0-9A-Z]{16}'],
      antiPatterns: [],
      flags: '',
    }
    const findings = nativeV1Executor.evaluate(matcher, file, ctx)
    expect(findings.length).toBe(1)
    expect(findings[0].line).toBe(1)
  })

  it('still suppresses via a VALID anti-pattern', () => {
    const matcher: PatternMatcher = {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['AKIA[0-9A-Z]{16}'],
      antiPatterns: ['EXAMPLE'],
      flags: '',
    }
    const findings = nativeV1Executor.evaluate(matcher, file, ctx)
    expect(findings.length).toBe(1)
    expect(findings[0].suppressionState).toBe('suppressed')
  })
})
