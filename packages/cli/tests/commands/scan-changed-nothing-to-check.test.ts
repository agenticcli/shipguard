/**
 * Bug (owner, 2026-11-06): `shipguard scan --changed` on a clean checkout scanned 0 files and
 * reported DO_NOT_SHIP (exit 0). An agent that runs `scan --changed` before every commit hit a
 * red verdict with no findings and nothing to fix.
 *
 * Fix: when git ran fine and the ONLY things changed are ShipGuard's own files (or nothing at all),
 * there is nothing to check. That is not a degraded scan: no NO_FILES_SCANNED, the normal verdict
 * (SAFE_TO_SHIP, risk 0), and `coverage.changed.nothingToCheck: true` so a consumer can tell it
 * apart from a scan that read files.
 *
 * What must NOT change (guards below): every other way of scanning zero files stays degraded and
 * DO_NOT_SHIP (empty folder, everything default-ignored, changed files that are all ignored or
 * outside the scan folder), and a changed file with a key is still found.
 */
import { execSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, degradeCodes, ENV_KEY_LINE, keyFoundIn, mkTree, runCli, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 180_000 })
afterAll(cleanupTrees)

function cleanRepo(): string {
  const dir = mkTree({ 'a.js': 'const a = 1\n' }, { git: true })
  execSync('git add . && git commit -q -m init', { cwd: dir })
  return dir
}

describe('--changed with nothing to check', () => {
  it('clean checkout: not degraded, SAFE_TO_SHIP, nothingToCheck, --strict exit 0', async () => {
    const dir = cleanRepo()
    const r = await scanJson(dir, ['--changed', '--strict'])
    expect(r.code).toBe(0)
    expect(r.json!.degraded).toBeFalsy()
    expect(degradeCodes(r.json)).toEqual([])
    expect(r.json!.recommendation).toBe('SAFE_TO_SHIP')
    expect(r.json!.filesScanned).toBe(0)
    expect(r.json!.coverage.scanned).toBe(0)
    expect(r.json!.coverage.mode).toBe('changed')
    expect(r.json!.coverage.changed.nothingToCheck).toBe(true)
  })

  it('second run (ShipGuard\'s own .shipguard files now show up as changed): still nothing to check', async () => {
    const dir = cleanRepo()
    await scanJson(dir, ['--changed'])
    const r = await scanJson(dir, ['--changed', '--strict'])
    expect(r.code).toBe(0)
    expect(degradeCodes(r.json)).toEqual([])
    expect(r.json!.recommendation).toBe('SAFE_TO_SHIP')
    expect(r.json!.coverage.changed.nothingToCheck).toBe(true)
  })

  it('human output says there is nothing to check and never calls it a failed scan', async () => {
    const dir = cleanRepo()
    const human = await runCli(['scan', dir, '--changed'])
    const all = human.stdout + human.stderr
    expect(all).toMatch(/nothing to check/i)
    expect(all).not.toMatch(/DO_NOT_SHIP, never safe/)
    expect(all).not.toMatch(/Nothing was scanned/)
    expect(all).not.toMatch(/No findings detected — clean scan/)
  })

  it('a changed file with a key is still found (control)', async () => {
    const dir = cleanRepo()
    writeFileSync(join(dir, 'cfg.txt'), ENV_KEY_LINE + 'pad=1\n')
    const r = await scanJson(dir, ['--changed'])
    expect(keyFoundIn(r.json, 'cfg.txt')).toBe(true)
    expect(r.json!.coverage.changed.nothingToCheck).toBeUndefined()
  })

  it('a changed file that is default-ignored: still NO_FILES_SCANNED, DO_NOT_SHIP (guard)', async () => {
    const dir = cleanRepo()
    writeFileSync(join(dir, 'app.log'), 'x\n')
    const r = await scanJson(dir, ['--changed', '--strict'])
    expect(degradeCodes(r.json)).toEqual(['NO_FILES_SCANNED'])
    expect(r.json!.recommendation).toBe('DO_NOT_SHIP')
    expect(r.code).toBe(1)
    expect(r.json!.coverage.changed.nothingToCheck).toBeUndefined()
  })

  it('full scan of a folder with nothing readable: still NO_FILES_SCANNED, DO_NOT_SHIP (guard)', async () => {
    const dir = mkTree({ 'node_modules/p/i.js': 'x' })
    const r = await scanJson(dir, ['--strict'])
    expect(degradeCodes(r.json)).toEqual(['NO_FILES_SCANNED'])
    expect(r.json!.recommendation).toBe('DO_NOT_SHIP')
    expect(r.code).toBe(1)
  })
})
