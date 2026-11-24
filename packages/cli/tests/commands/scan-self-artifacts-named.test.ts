/** Paths counted as selfArtifacts are also named in coverage.files.selfArtifacts (capped list), on both paths. */
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

describe('selfArtifacts are named', () => {
  for (const mode of ['full', 'changed'] as const) {
    it(`${mode}: sub/.shipguard/x.txt and sub/.gitignore (only .shipguard/) are counted and named`, async () => {
      const dir = mkTree(
        { 'ok.js': 'const a = 1\n', 'sub/.shipguard/x.txt': 'hello history\n', 'sub/.gitignore': '.shipguard/\n' },
        { git: mode === 'changed' },
      )
      const r = await scanJson(dir, mode === 'changed' ? ['--changed'] : [])
      expect(r.json!.coverage.selfArtifacts).toBeGreaterThanOrEqual(1)
      // Under --changed git already hides sub/.shipguard/ through sub/.gitignore, so it never lists it.
      if (mode === 'full') expect(r.json!.coverage.files.selfArtifacts).toContain('sub/.shipguard/x.txt')
      expect(r.json!.coverage.files.selfArtifacts).toContain('sub/.gitignore')
      expect(r.json!.coverage.files.selfArtifacts.length).toBe(r.json!.coverage.selfArtifacts)
    })
  }
})
