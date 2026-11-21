/** Slow lane (VITEST_SLOW=1): the 3k and 11k generated trees, same golden file as the 200-file test. */
import { describe, expect, it, vi } from 'vitest'
import { loadGolden, recordGolden, scanDigest } from '../helpers/golden-scan.js'

vi.setConfig({ testTimeout: 1_800_000 })

describe('golden (slow): findings are identical to the recorded baseline', () => {
  for (const size of [3000, 11000]) {
    it(`${size}-file generated tree`, async () => {
      const got = await scanDigest(size)
      if (process.env.GOLDEN_RECORD) {
        recordGolden(size, got)
        return
      }
      expect(got.findings).toBeGreaterThan(20)
      expect(got).toEqual(loadGolden()[String(size)])
    })
  }
})
