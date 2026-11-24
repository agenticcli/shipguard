/**
 * B4 (500-file tree): BR "B4": 500 binary-looking files, 0 scanned, and the old scan said SAFE_TO_SHIP.
 * Now it must say DO_NOT_SHIP with a named reason, on BOTH read paths, and --strict must exit 1.
 */
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, degradeCodes, mkTree, noise, scanJson, type FileMap } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 90_000 })
afterAll(cleanupTrees)

function tree500(): FileMap {
  const files: FileMap = {}
  for (let i = 0; i < 500; i++) {
    // NUL-heavy, no magic: random bytes (NULs on both byte parities, never a known format).
    const b = noise(300, 1000 + i)
    b[0] = 0x41 // never start with a magic value
    b[1] = 0
    files[`blob/f${String(i).padStart(3, '0')}.dat`] = b
  }
  return files
}

describe('B4: 500 NUL-heavy files with no real-binary evidence', () => {
  for (const mode of ['full', 'changed'] as const) {
    it(`${mode} path: nothing scanned is DO_NOT_SHIP, never SAFE_TO_SHIP`, async () => {
      const dir = mkTree(tree500(), { git: mode === 'changed' })
      const run = await scanJson(dir, mode === 'changed' ? ['--strict', '--changed'] : ['--strict'])
      const json = run.json!
      expect(json.recommendation).toBe('DO_NOT_SHIP')
      expect(degradeCodes(json)).toEqual(['NO_FILES_SCANNED', 'UNSCANNED_UNKNOWN_BINARY'])
      expect(json.filesScanned).toBe(0)
      expect(json.coverage.discovered).toBe(500)
      expect(json.coverage.skipped.unknownBinary).toBe(500)
      expect(json.coverage.files.unknownBinary).toHaveLength(50)
      expect(run.code).toBe(1)
      const reason = json.degradedReasons.find((r: { code: string }) => r.code === 'UNSCANNED_UNKNOWN_BINARY')
      expect(reason.detail).toContain('ignore.paths')
    })
  }
})
