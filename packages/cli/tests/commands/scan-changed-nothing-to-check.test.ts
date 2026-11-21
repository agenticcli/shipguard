/**
 * Earlier bug: `shipguard scan --changed` on a clean checkout reported DO_NOT_SHIP with no
 * explanation. The next fix swung to the opposite, worse error: SAFE_TO_SHIP (risk 0) on a repo
 * that has a critical issue, because nothing was scanned.
 *
 * Contract now: when git ran fine and nothing but ShipGuard's own files changed, NOTHING WAS
 * SCANNED. That is never SAFE_TO_SHIP. The result is degraded NO_FILES_SCANNED (verdict DO_NOT_SHIP,
 * --strict exit 1 = "unfinished scan", exit 0 without --strict), with a detail that says why, plus
 * the additive `coverage.changed.nothingToCheck: true` so a consumer can tell "no changes" from
 * "everything unreadable". The human and --quiet lines say so too.
 *
 * What must NOT change (guards below): every other way of scanning zero files stays degraded and
 * DO_NOT_SHIP, and a changed file with a key is still found.
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
  it('clean checkout: never SAFE_TO_SHIP, degraded NO_FILES_SCANNED, nothingToCheck, --strict exit 1', async () => {
    const dir = cleanRepo()
    const r = await scanJson(dir, ['--changed', '--strict'])
    expect(r.code).toBe(1)
    expect(r.json!.degraded).toBe(true)
    expect(degradeCodes(r.json)).toEqual(['NO_FILES_SCANNED'])
    expect(r.json!.degradedReasons![0].detail).toMatch(/no changed files.*NOT a safe-to-ship/s)
    expect(r.json!.recommendation).toBe('DO_NOT_SHIP')
    expect(r.json!.recommendation).not.toBe('SAFE_TO_SHIP')
    expect(r.json!.filesScanned).toBe(0)
    expect(r.json!.coverage.scanned).toBe(0)
    expect(r.json!.coverage.mode).toBe('changed')
    expect(r.json!.coverage.changed.nothingToCheck).toBe(true)
    expect((await scanJson(dir, ['--changed'])).code).toBe(0) // passive by default
  })

  it('REGRESSION: repo with a committed critical issue, nothing changed: not SAFE_TO_SHIP in any mode', async () => {
    const dir = mkTree({ 'cfg.txt': ENV_KEY_LINE + 'pad=1\n' }, { git: true })
    execSync('git add . && git commit -q -m init', { cwd: dir })
    const full = await scanJson(dir)
    expect(full.json!.recommendation).not.toBe('SAFE_TO_SHIP')
    expect(keyFoundIn(full.json, 'cfg.txt')).toBe(true)
    for (const extra of [[], ['--strict']]) {
      const r = await scanJson(dir, ['--changed', ...extra])
      expect(r.json!.recommendation).not.toBe('SAFE_TO_SHIP')
      expect(r.json!.degraded).toBe(true)
    }
    const q = await runCli(['scan', dir, '--changed', '--quiet'])
    expect(q.stdout).not.toMatch(/SAFE_TO_SHIP/)
    expect(q.stdout).toMatch(/verdict=DO_NOT_SHIP .*incomplete=yes/)
  })

  it('second run (ShipGuard\'s own .shipguard files now show up as changed): same honest result', async () => {
    const dir = cleanRepo()
    await scanJson(dir, ['--changed'])
    const r = await scanJson(dir, ['--changed', '--strict'])
    expect(r.code).toBe(1)
    expect(degradeCodes(r.json)).toEqual(['NO_FILES_SCANNED'])
    expect(r.json!.recommendation).toBe('DO_NOT_SHIP')
    expect(r.json!.coverage.changed.nothingToCheck).toBe(true)
  })

  it('human output says nothing was scanned and that it is not safe, never "clean scan"', async () => {
    const dir = cleanRepo()
    const human = await runCli(['scan', dir, '--changed'])
    const all = human.stdout + human.stderr
    expect(all).toMatch(/Nothing was scanned: git reports no changed files\. This is not a safe-to-ship result\./)
    expect(all).not.toMatch(/No findings detected — clean scan/)
    expect(all).not.toMatch(/SAFE TO SHIP/)
  })

  it('empty folder: human, --quiet and --json agree (nothing scanned, never "clean scan")', async () => {
    const dir = mkTree({ 'node_modules/p/i.js': 'x' })
    const human = await runCli(['scan', dir])
    const all = human.stdout + human.stderr
    expect(all).toMatch(/cannot clear this repo: nothing was scanned \(no readable files were found\)/)
    expect(all).not.toMatch(/clean scan/)
    expect(all).toMatch(/DO NOT SHIP/)
    const quiet = await runCli(['scan', dir, '--quiet'])
    expect(quiet.stdout).toMatch(/verdict=DO_NOT_SHIP .*incomplete=yes/)
    const json = await scanJson(dir)
    expect(json.json!.recommendation).toBe('DO_NOT_SHIP')
    expect(degradeCodes(json.json)).toEqual(['NO_FILES_SCANNED'])
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
