/**
 * QA (2026-11-02, qa-final on ed3a6ae9): judge R3 MAJOR 3 for a FOLDER name, on both read paths.
 *
 * B19 covers a FILE named `a\xFF.env` next to `a�.env`. The same aliasing can happen one level
 * up: a folder `d\xFF/` (holding a key) is listed by fast-glob as `d�/...`, which addresses a
 * DIFFERENT folder (a clean sibling with a literal U+FFFD) or nothing. The file inside must never be
 * read as its sibling and never vanish: UNREADABLE_FILE, degraded, --strict exit 1.
 *
 * Found by QA on ed3a6ae9 (fails there): "full: d\xFF/x.env (key) alone". fast-glob cannot descend
 * into `d�` (that path does not exist), so it lists no file under it and the full scan never
 * calls the re-listing in utils/fs.ts resolveUndecodableNames (it only checks FILE paths). The
 * folder is not counted anywhere (coverage.discovered omits it) and the result is SAFE_TO_SHIP,
 * degraded:false, --strict exit 0 while a readable file holding a key was never read. The second
 * fast-glob pass (objectMode, onlyFiles:false) does return the `d�` directory entry.
 * The --changed path is correct (git lists the raw bytes, which fail strict UTF-8).
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, degradeCodes, ENV_KEY_LINE, keyFoundIn, mkTree, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 90_000 })
afterAll(cleanupTrees)

const rawPath = (dir: string, ...parts: Array<string | number[]>): Buffer =>
  Buffer.concat([Buffer.from(dir + '/'), ...parts.map((p) => (typeof p === 'string' ? Buffer.from(p) : Buffer.from(p)))])

function plantBadDir(dir: string): boolean {
  try {
    mkdirSync(rawPath(dir, 'd', [0xff]))
    writeFileSync(rawPath(dir, 'd', [0xff], '/x.env'), ENV_KEY_LINE)
    return true
  } catch {
    return false // a file system that refuses non-UTF-8 names cannot hold this case
  }
}

describe.skipIf(process.platform === 'win32' || process.platform === 'darwin')('QA: a folder name with an invalid UTF-8 byte is never aliased', () => {
  for (const mode of ['full', 'changed'] as const) {
    it(`${mode}: d\\xFF/x.env (key) next to d\\uFFFD/x.env (clean): UNREADABLE_FILE, degraded, sibling scanned`, async () => {
      const dir = mkTree({ 'd�/x.env': 'CLEAN=1\n', 'ok.js': 'const a = 1\n' }, { git: mode === 'changed' })
      if (!plantBadDir(dir)) return
      const run = await scanJson(dir, mode === 'changed' ? ['--strict', '--changed'] : ['--strict'])
      const json = run.json!
      expect(json, run.stderr.slice(0, 500)).toBeDefined()
      expect(degradeCodes(json)).toEqual(['UNREADABLE_FILE'])
      expect(json.coverage.skipped.unreadable).toBe(1)
      expect(json.coverage.scanned).toBe(2)
      expect(keyFoundIn(json, 'd�/x.env')).toBe(false)
      expect(json.recommendation).toBe('DO_NOT_SHIP')
      expect(run.code).toBe(1)
    })

    it(`${mode}: d\\xFF/x.env (key) alone: UNREADABLE_FILE, degraded (never a silent drop)`, async () => {
      const dir = mkTree({ 'ok.js': 'const a = 1\n' }, { git: mode === 'changed' })
      if (!plantBadDir(dir)) return
      const run = await scanJson(dir, mode === 'changed' ? ['--strict', '--changed'] : ['--strict'])
      const json = run.json!
      expect(json, run.stderr.slice(0, 500)).toBeDefined()
      expect(degradeCodes(json)).toEqual(['UNREADABLE_FILE'])
      expect(json.degraded).toBe(true)
      expect(run.code).toBe(1)
    })
  }
})
