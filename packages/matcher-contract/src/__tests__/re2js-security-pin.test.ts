// Regression for GHSA-gg6h-894w-4m9c (CVE-2026-116795): quadratic-time DoS in re2js lookbehind
// matching, vulnerable range >= 2.2.0, < 2.8.7. The pin, both package.json files and the
// version actually installed must all be the same patched version. Reachability here is low
// (LOOKBEHINDS is false), but a public alert on a security tool is not acceptable, and the pin
// is hashed into RE2JS_V1_RUNTIME_ID, so the three places must never drift apart.

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { RE2JS_VERSION } from '../engine-meta.js'
import { re2jsTestPattern } from '../adapters/re2js-v1.js'

const here = dirname(fileURLToPath(import.meta.url))
const FIRST_PATCHED = [2, 8, 7] as const

function parts(v: string): number[] {
  return v.split('.').map(n => Number.parseInt(n, 10))
}

function atLeast(v: string, min: readonly number[]): boolean {
  const p = parts(v)
  for (let i = 0; i < 3; i++) {
    if (p[i] !== min[i]) return (p[i] ?? 0) > min[i]
  }
  return true
}

describe('re2js security pin (GHSA-gg6h-894w-4m9c)', () => {
  it('RE2JS_VERSION is at or above the first patched version 2.8.7', () => {
    expect(atLeast(RE2JS_VERSION, FIRST_PATCHED)).toBe(true)
  })

  it('matcher-contract package.json pins exactly RE2JS_VERSION', () => {
    const pkg = JSON.parse(readFileSync(resolve(here, '../../package.json'), 'utf8'))
    expect(pkg.dependencies.re2js).toBe(RE2JS_VERSION)
  })

  it('cli package.json pins exactly RE2JS_VERSION', () => {
    const pkg = JSON.parse(readFileSync(resolve(here, '../../../cli/package.json'), 'utf8'))
    expect(pkg.dependencies.re2js).toBe(RE2JS_VERSION)
  })

  it('the installed re2js is exactly RE2JS_VERSION', () => {
    const require = createRequire(import.meta.url)
    const entry = require.resolve('re2js')
    // walk up from the resolved entry to the package root
    let dir = dirname(entry)
    let pkgPath = resolve(dir, 'package.json')
    for (let i = 0; i < 4; i++) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))
        if (pkg.name === 're2js') {
          expect(pkg.version).toBe(RE2JS_VERSION)
          return
        }
      } catch { /* not here, go up */ }
      dir = dirname(dir)
      pkgPath = resolve(dir, 'package.json')
    }
    throw new Error('could not locate re2js package.json from ' + entry)
  })

  it('lookbehind stays disabled: a lookbehind pattern fails to compile instead of running', () => {
    // The advisory is only reachable with lookbehinds on. v1 keeps them off, so the adapter's
    // compile path (used by the Gate-C helper) must throw, never run the pattern.
    expect(() => re2jsTestPattern('(?<=a)b', 'ab')).toThrow()
  })
})
