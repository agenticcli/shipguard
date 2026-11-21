/**
 * Golden equality for the scan speed work: the findings of a generated tree (rule id, file, line,
 * column, suppressed, blocking, evidence hash; order-normalized) must be IDENTICAL to what the code
 * produced before any speed change. The recorded digests in golden-baseline.json were written by the
 * unchanged scanner (`GOLDEN_RECORD=1`); a legitimate rule or check change regenerates them, a speed
 * change never may.
 *
 * The 3k and 11k sizes run in the slow lane: tests/slow/prefilter-golden-large.test.ts.
 */
import { describe, expect, it, vi } from 'vitest'
import { loadGolden, recordGolden, scanDigest } from '../helpers/golden-scan.js'

vi.setConfig({ testTimeout: 600_000 })

describe('golden: findings are identical to the recorded baseline', () => {
  it('200-file generated tree', async () => {
    const got = await scanDigest(200)
    if (process.env.GOLDEN_RECORD) {
      recordGolden(200, got)
      return
    }
    expect(got.findings).toBeGreaterThan(20) // the tree must actually produce findings
    expect(got).toEqual(loadGolden()['200'])
  })
})
