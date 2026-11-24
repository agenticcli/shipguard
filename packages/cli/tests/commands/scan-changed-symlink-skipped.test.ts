/**
 * A symlink is never followed. The full scan reports SYMLINK_SKIPPED; `--changed` must report the
 * same code (it used to report UNREADABLE_FILE or follow the link inside the root).
 */
import { symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, degradeCodes, mkTree, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

describe.skipIf(process.platform === 'win32')('symlinks report SYMLINK_SKIPPED on both paths', () => {
  for (const mode of ['full', 'changed'] as const) {
    it(`${mode}: a symlink to an in-tree file is SYMLINK_SKIPPED, degraded, --strict exit 1`, async () => {
      const dir = mkTree({ 'real.js': 'const a = 1\n' }, { git: mode === 'changed' })
      symlinkSync('real.js', join(dir, 'link.js'))
      const r = await scanJson(dir, mode === 'changed' ? ['--strict', '--changed'] : ['--strict'])
      expect(degradeCodes(r.json)).toEqual(['SYMLINK_SKIPPED'])
      expect(r.json!.coverage.skipped.symlink).toBe(1)
      expect(r.code).toBe(1)
    })
  }
})
