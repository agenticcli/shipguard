/**
 * Hook templates must resolve the SCOPED package, never the unrelated unscoped npm `shipguard`,
 * and must never block a push without saying how to fix it.
 *
 * The behaviour of the shell itself (local bin first, PATH, npx, fail closed, the clock) is tested
 * against stub binaries in tests/gate/shim.test.ts; this file keeps the package-identity rules.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { GATE_MIN_VERSION, NPX_SPEC, claudeShimScript, gitHookScript } from '../../src/core/hook-templates.js'

describe('hook templates: scoped package + resolver', () => {
  it('never mentions the unscoped package or --no-install shipguard', () => {
    for (const t of [gitHookScript('pre-push'), gitHookScript('pre-merge-commit'), claudeShimScript()]) {
      expect(t).not.toMatch(/npx --no-install shipguard/)
      expect(t).not.toMatch(/npx (--yes )?shipguard\b/)
      expect(t).toContain('@agenticcli/shipguard@0.13')
    }
  })

  it('the pinned version is the first one with `shipguard gate` and never ahead of this package', () => {
    const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf-8')) as { version: string }
    const [major, minor] = pkg.version.split('.').map(Number)
    const [pinMajor, pinMinor] = GATE_MIN_VERSION.split('.').map(Number)
    expect(NPX_SPEC).toBe(`@agenticcli/shipguard@${GATE_MIN_VERSION}`)
    expect(pinMajor).toBe(major)
    // Before the 0.13 bump this package is 0.12.x: the pin names the release the hooks need.
    expect(pinMinor).toBeLessThanOrEqual(Math.max(minor, 13))
  })

  it('every cannot-start text names the install command, the reason and the manual removal', () => {
    for (const t of [gitHookScript('pre-push'), claudeShimScript()]) {
      expect(t).toContain('npm i -D @agenticcli/shipguard')
      expect(t).toContain('npm i -g @agenticcli/shipguard')
      expect(t).toContain('so nothing was scanned')
      expect(t).toContain('remove it by hand')
    }
  })
})
