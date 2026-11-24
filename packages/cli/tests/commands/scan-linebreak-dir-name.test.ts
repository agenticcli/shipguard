/**
 * QA (2026-11-02, qa-final re-check on b9c8bc39): a FOLDER whose name holds a line-break character
 * must never make its files vanish from the full scan.
 *
 * Found by the QA adversarial sweep on b9c8bc39 (fails there): a folder named `n\nl/` (LF), or with
 * CR, U+2028 or U+2029, holding a key. The full scan reports SAFE_TO_SHIP, degraded:false,
 * --strict exit 0, and coverage.discovered omits the file. The `--changed` path finds the key (git -z
 * lists the exact name), so the two read paths disagree.
 *
 * Cause: fast-glob 3.3.3 lists the folder's own directory entry in the objectMode probe pass
 * (utils/fs.ts readFiles, second fg call) but never descends into it: its `**` matcher is a regex
 * whose `.` does not match JS line terminators. The fix in 703d0093 re-lists only directory entries
 * whose name holds U+FFFD (utils/fs.ts, `dirNames` filter), so this folder is never looked at. A FILE
 * with the same characters in its name is listed and scanned (guard rows below).
 *
 * Same goal as scan-undecodable-dir-name.test.ts: a readable file holding a key is either read or the
 * scan is degraded; it never silently disappears behind SAFE_TO_SHIP.
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, ENV_KEY_LINE, keyFoundIn, mkTree, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

const BREAKS: Array<[string, string]> = [
  ['LF', '\n'],
  ['CR', '\r'],
  ['U+2028', ' '],
  ['U+2029', ' '],
]

/** Plant `rel` (holding the key) next to a clean ok.js. False when the file system refuses the name. */
function plant(dir: string, rel: string): boolean {
  try {
    mkdirSync(join(dir, rel, '..'), { recursive: true })
    writeFileSync(join(dir, rel), ENV_KEY_LINE)
    return true
  } catch {
    return false
  }
}

describe.skipIf(process.platform === 'win32')('QA: a folder name with a line-break character never hides its files', () => {
  for (const [label, br] of BREAKS) {
    for (const [shape, rel] of [
      ['root folder', `n${br}l/z.env`],
      ['nested folder', `src/n${br}l/z.env`],
    ] as const) {
      it(`full: ${shape} named with ${label} holding a key: key found or degraded, never SAFE_TO_SHIP, --strict exit 1`, async () => {
        const dir = mkTree({ 'ok.js': 'const a = 1\n' })
        if (!plant(dir, rel)) return
        const run = await scanJson(dir, ['--strict'])
        const json = run.json!
        expect(json, run.stderr.slice(0, 500)).toBeDefined()
        const ctx = JSON.stringify({ rec: json.recommendation, degraded: json.degraded, discovered: json.coverage?.discovered, scanned: json.coverage?.scanned })
        expect(keyFoundIn(json, rel) || json.degraded === true, ctx).toBe(true)
        expect(json.recommendation, ctx).not.toBe('SAFE_TO_SHIP')
        expect(run.code, ctx).toBe(1)
      })
    }
  }

  // Guards (green on b9c8bc39): the same names on --changed, and a FILE (not a folder) with LF in its name.
  it('changed (guard): root folder named with LF holding a key: key found', async () => {
    const rel = 'n\nl/z.env'
    const dir = mkTree({ 'ok.js': 'const a = 1\n' }, { git: true })
    if (!plant(dir, rel)) return
    const run = await scanJson(dir, ['--strict', '--changed'])
    expect(keyFoundIn(run.json, rel)).toBe(true)
    expect(run.code).toBe(1)
  })

  it('full (guard): a FILE named with LF holding a key: key found', async () => {
    const rel = 'src/a\nb.env'
    const dir = mkTree({ 'ok.js': 'const a = 1\n' })
    if (!plant(dir, rel)) return
    const run = await scanJson(dir, ['--strict'])
    expect(keyFoundIn(run.json, rel)).toBe(true)
    expect(run.code).toBe(1)
  })
})
