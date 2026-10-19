/**
 * gen-cli-facts-license.test.ts — regression: cli-facts.json must carry the license.
 *
 * Regression: gen-cli-facts.mjs read pkg.license into its `pkg` object but
 * never emitted it into the `facts` document, so the website's facts source of truth
 * (cli-facts.json, synced from this generator's output) had no license
 * field — which let a hardcoded "MIT" footer label ship live on /for-ai-agents for an
 * ELv2 product. The web app now derives its license label from cli-facts.json's
 * `licenseDisplay`, so this generator dropping the field again would re-open that
 * drift on the next facts sync.
 *
 * This test runs the REAL generator (no mocks) and asserts the emitted JSON carries:
 *   - `license` exactly equal to packages/cli/package.json's `license` field
 *     (the legal source of truth — currently "Elastic-2.0"), and
 *   - `licenseDisplay` mapped to the short UI label ("ELv2") the web footer renders.
 *
 * fail-before / pass-after: on the pre-fix generator the emitted JSON has neither
 * field (facts object literal never referenced pkg.license) — both assertions fail
 * with `undefined`. After the fix both pass.
 */

import { describe, it, expect, beforeAll } from 'vitest'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const cliDir = join(__dirname, '..', '..')
const generatorPath = join(cliDir, 'scripts', 'gen-cli-facts.mjs')
const emittedPath = join(cliDir, 'dist', 'cli-facts.json')
const pkgPath = join(cliDir, 'package.json')

describe('gen-cli-facts.mjs — license fields emitted', () => {
  let facts: Record<string, unknown>
  let pkg: { license?: string }

  beforeAll(() => {
    // Run the real generator; it creates dist/ itself if needed and exits non-zero
    // on any of its own fail-loud paths (including a missing/unmapped license).
    execFileSync('node', [generatorPath], { cwd: cliDir, stdio: 'pipe' })
    facts = JSON.parse(readFileSync(emittedPath, 'utf-8'))
    pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
  })

  it('emits `license` equal to package.json license (the legal source of truth)', () => {
    expect(pkg.license, 'package.json must declare a license').toBeTruthy()
    expect(facts.license).toBe(pkg.license)
  })

  it('emits `licenseDisplay` as the short UI label the web footer renders', () => {
    // If the license ever legitimately changes, update the generator's
    // LICENSE_DISPLAY map + this expectation together — never remove the field.
    expect(facts.licenseDisplay).toBe('ELv2')
  })

  it('generator source no longer silently drops pkg.license (structural lock)', () => {
    const src = readFileSync(generatorPath, 'utf-8')
    // The facts object literal must include both fields.
    expect(src).toMatch(/^\s*license,$/m)
    expect(src).toMatch(/^\s*licenseDisplay,$/m)
    // And the missing-license path must be fail-loud, not a silent omit.
    expect(src).toMatch(/no "license" field/)
  })
})
