/**
 * Regression tests for — CLI --version drift.
 *
 * Root cause: cli.ts called program.version('0.1.2') with a hardcoded literal
 * independent of package.json. Build shipped a stale string once (0.1.0),
 * burned npm 0.1.1.
 *
 * These tests are READ-ONLY (readFileSync on source text) — they do NOT import
 * cli.ts because cli.ts runs program.parseAsync(process.argv) at module load
 * and would execute against vitest's argv.
 *
 * Guard 1 (source guard): cli.ts must NOT contain program.version('X.Y.Z') —
 *   i.e., a version literal hardcoded directly in the program.version() call.
 *   This is the exact regression we are preventing.
 *
 * Guard 2 (build config guard): tsup.config.ts must read package.json and
 *   define __SHIPGUARD_VERSION__ — so the single-source-of-truth injection
 *   can never be accidentally removed without this test failing.
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { describe, it, expect } from 'vitest'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')

const cliSource = readFileSync(resolve(pkgRoot, 'src/cli.ts'), 'utf-8')
const tsupSource = readFileSync(resolve(pkgRoot, 'tsup.config.ts'), 'utf-8')
const pkgJson = JSON.parse(
  readFileSync(resolve(pkgRoot, 'package.json'), 'utf-8')
)

describe('Guard 1 — source-guard: no hardcoded version literal in cli.ts ', () => {
  it('cli.ts does NOT call program.version() with a hardcoded semver string', () => {
    // Matches: program.version('1.2.3') or program.version("1.2.3")
    // The exact pattern that caused.
    const hardcodedVersionPattern = /program\.version\(\s*['"][0-9]+\.[0-9]+\.[0-9]/

    expect(
      hardcodedVersionPattern.test(cliSource),
      'REGRESSION: cli.ts contains program.version() with a hardcoded semver literal. ' +
      'Replace with the __SHIPGUARD_VERSION__ injection (see tsup.config.ts). ' +
      'Incident d7285819.'
    ).toBe(false)
  })
})

describe('Guard 2 — build-config guard: tsup.config.ts injects version from package.json', () => {
  it('tsup.config.ts reads package.json to obtain the version', () => {
    expect(
      tsupSource,
      'tsup.config.ts must read package.json to derive the version for injection'
    ).toContain('package.json')
  })

  it('tsup.config.ts defines __SHIPGUARD_VERSION__ via tsup define', () => {
    expect(
      tsupSource,
      'tsup.config.ts must inject __SHIPGUARD_VERSION__ via the define option so the build binary always matches package.json'
    ).toContain('__SHIPGUARD_VERSION__')
  })

  it('cli.ts references __SHIPGUARD_VERSION__ for the program.version() call', () => {
    expect(
      cliSource,
      'cli.ts must use __SHIPGUARD_VERSION__ (injected from package.json) — not a hardcoded literal'
    ).toContain('__SHIPGUARD_VERSION__')
  })

  it('cli.ts has a typeof guard so tests/dev never crash when define is absent', () => {
    expect(
      cliSource,
      "cli.ts must use typeof __SHIPGUARD_VERSION__ !== 'undefined' guard for safe fallback in vitest"
    ).toContain("typeof __SHIPGUARD_VERSION__ !== 'undefined'")
  })

  it('package.json version is a valid semver string', () => {
    expect(pkgJson.version).toMatch(/^\d+\.\d+\.\d+/)
  })
})
