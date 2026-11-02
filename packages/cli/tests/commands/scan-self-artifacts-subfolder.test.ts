/**
 * QA (2026-11-02, qa-final re-check on b9c8bc39): ShipGuard's own artifacts must never make a scan
 * look like it read the project, also when they sit in a SUBFOLDER.
 *
 * 703d0093 treats a ROOT `.gitignore` that holds only `.shipguard/` as a self-artifact
 * (coverage.selfArtifacts), and `.shipguard/**` is a default ignore. Both are ROOT-only. A scan of a
 * subfolder writes its artifacts into that subfolder (src/core/history/identity.ts ensureGitignored
 * and the `.shipguard/` history store, keyed to the scan root): `sub/.gitignore`, `sub/.shipguard/
 * repo-id`, `history.db`, `history.db.salt`, `reports/latest.{md,json}` and `reports/runs/*`.
 *
 * Found by the QA adversarial sweep on b9c8bc39 (fails there): a folder holding only a real PNG
 * (the B5 shape) and an empty `sub/`. `scan p/sub` is NO_FILES_SCANNED, as designed. The following
 * `scan p --strict` reads the 8 tool-written files as the project's scanned files and reports
 * SAFE_TO_SHIP, degraded:false, exit 0. With git (no commits) and --changed, `sub/.gitignore` alone
 * is enough (git hides sub/.shipguard/ through it): SAFE_TO_SHIP, exit 0. Plan D1: a scan that read
 * nothing of the project is never SAFE.
 */
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, degradeCodes, mkTree, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

const png1x1 = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
)

describe('QA: tool-written artifacts in a subfolder never count as the project being scanned', () => {
  for (const mode of ['full', 'changed'] as const) {
    it(`${mode}: scan p/sub first, then scan p (real PNG only): NO_FILES_SCANNED, DO_NOT_SHIP, --strict exit 1`, async () => {
      const p = mkTree({ 'logo.png': png1x1 }, { git: mode === 'changed' })
      mkdirSync(join(p, 'sub'))
      const first = await scanJson(join(p, 'sub'), ['--strict'])
      expect(degradeCodes(first.json), 'run on p/sub').toContain('NO_FILES_SCANNED')

      const r = await scanJson(p, mode === 'changed' ? ['--strict', '--changed'] : ['--strict'])
      const ctx = JSON.stringify({ rec: r.json?.recommendation, codes: degradeCodes(r.json), scanned: r.json?.coverage?.scanned, self: r.json?.coverage?.selfArtifacts })
      expect(degradeCodes(r.json), ctx).toContain('NO_FILES_SCANNED')
      expect(r.json!.recommendation, ctx).toBe('DO_NOT_SHIP')
      expect(r.code, ctx).toBe(1)
    })
  }
})
