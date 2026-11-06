/**
 * QA (2026-11-02, qa-final on ed3a6ae9): plan D1 ("a scan that read nothing is never SAFE") must
 * hold on EVERY run, not only the first.
 *
 * Found by the QA tarball re-run (step 3d): the first
 * scan of an empty folder is NO_FILES_SCANNED / DO_NOT_SHIP / --strict exit 1, as designed. That
 * scan also writes `.gitignore` (the history store's courtesy line `.shipguard/`,
 * src/core/history/identity.ts ensureGitignoreEntry) into the scanned folder. The second scan then
 * reads that tool-written `.gitignore` as its one scanned file and reports SAFE_TO_SHIP, degraded
 * false, --strict exit 0. The same applies to a tree of real binaries only (B5): only the first run
 * is DO_NOT_SHIP. Every B4/B5/B6 test scans a fresh folder once, so none of them sees it.
 *
 * Content that ShipGuard itself wrote is not the user's content; a scan whose only "scanned" file is
 * the tool's own artifact has still read nothing of the project.
 */
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, degradeCodes, mkTree, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 180_000 })
afterAll(cleanupTrees)

const png1x1 = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
)

describe('QA: NO_FILES_SCANNED holds on a repeated scan of the same folder', () => {
  const cases: Array<[string, Record<string, Buffer | string>]> = [
    ['an empty folder', {}],
    ['a folder of real binaries only (B5 shape)', { 'logo.png': png1x1 }],
  ]
  for (const [name, files] of cases) {
    it(`${name}: run 1 and run 2 are both NO_FILES_SCANNED, DO_NOT_SHIP, --strict exit 1`, async () => {
      const dir = mkTree(files)
      for (const run of [1, 2]) {
        const r = await scanJson(dir, ['--strict'])
        const ctx = `run ${run}: ${JSON.stringify({ rec: r.json?.recommendation, codes: degradeCodes(r.json), scanned: r.json?.coverage?.scanned })}`
        expect(degradeCodes(r.json), ctx).toContain('NO_FILES_SCANNED')
        expect(r.json!.recommendation, ctx).toBe('DO_NOT_SHIP')
        expect(r.code, ctx).toBe(1)
      }
    })
  }
})
