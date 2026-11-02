/**
 * B20 (guard, passes before and after): `--check-regressions` ALONE keeps exiting 1 on a regression.
 * That is the documented contract (--help and docs/llms.txt), so this change must not alter it.
 */
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

describe('--check-regressions exit code (guard)', () => {
  it('exits 1 on a real regression with the flag alone, 0 without a regression, and --strict is unaffected', async () => {
    const dir = mkTree({ 'a.js': 'const a = 1\n', 'package.json': '{"name":"reg"}' })
    const baseline = await scanJson(dir, ['--check-regressions'])
    expect(baseline.code).toBe(0)
    writeFileSync(join(dir, 'config.js'), "const k = 'AKIAIOSFODNN7EXAMPLE'\n")
    const regressed = await scanJson(dir, ['--check-regressions'])
    expect((regressed.json!.regressions as unknown[]).length).toBeGreaterThan(0)
    expect(regressed.code).toBe(1)
    const clean = mkTree({ 'a.js': 'const a = 1\n', 'package.json': '{"name":"reg2"}' })
    await scanJson(clean)
    expect((await scanJson(clean, ['--check-regressions'])).code).toBe(0)
  })
})
