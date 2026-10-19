import { describe, it, expect } from 'vitest'
import { RE2JS } from 're2js'
import { installRe2jsCompileCache, re2jsCompileCacheSize } from '../../src/core/re2js-compile-cache.js'

describe('re2js compile cache (wrapper outside the frozen adapter)', () => {
  it('returns the same compiled object for the same pattern+flags', () => {
    installRe2jsCompileCache()
    const a = RE2JS.compile('abc+', 0)
    expect(RE2JS.compile('abc+', 0)).toBe(a)
    expect(RE2JS.compile('abc+', RE2JS.CASE_INSENSITIVE)).not.toBe(a)
  })
  it('is idempotent to install', () => {
    installRe2jsCompileCache()
    installRe2jsCompileCache()
    const n = re2jsCompileCacheSize()
    RE2JS.compile('zzz', 0)
    RE2JS.compile('zzz', 0)
    expect(re2jsCompileCacheSize()).toBe(n + 1)
  })
  it('never caches failures: invalid patterns throw on every call', () => {
    installRe2jsCompileCache()
    const n = re2jsCompileCacheSize()
    expect(() => RE2JS.compile('(?=x)', 0)).toThrow()
    expect(() => RE2JS.compile('(?=x)', 0)).toThrow()
    expect(re2jsCompileCacheSize()).toBe(n)
  })
})
