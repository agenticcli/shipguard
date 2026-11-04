/**
 * QA (2026-11-02, qa-final on ed3a6ae9): property guard for the branch goal.
 *
 * Goal (plan scan-honest-coverage-20261102, brief): no SAFE / degraded:false over readable text that
 * was not scanned. At the classifier level this is one property that must hold for EVERY file under
 * the size cap that contains a credential as contiguous ASCII bytes on its own line:
 *
 *   classifyFile(bytes) is either
 *     - 'text'   and at least one reading contains the credential line, or
 *     - 'binary' and its strings reading contains the credential line, or
 *     - 'unknown-binary' / 'invalid-text' (both DEGRADE the scan, so never SAFE).
 *
 * A 'text' or 'binary' result that hides the credential is a silent miss (the file counts as read or
 * as a normal binary, no degrade). The fixed-row tests in classify.test.ts pin chosen shapes; this
 * test throws thousands of seeded random mixes at the classifier so a future change that drops a
 * reading (the ASCII reading, the strings reading, the union of readings) is caught even for shapes
 * no fixed row names. Deterministic: same seeds, same inputs, every run.
 */
import { describe, expect, it } from 'vitest'
import { classifyFile, type ClassifyResult } from '../../src/utils/classify.js'
import { makeMixCase, MIX_KEY } from '../helpers/encoding-mix.js'

const LINE = `AWS_ACCESS_KEY_ID=${MIX_KEY}`
const hasLine = (t: string): boolean => t.split('\n').some((l) => l.includes(LINE))

function outcome(res: ClassifyResult): 'found' | 'degraded' | 'SILENT-MISS' {
  switch (res.kind) {
    case 'text':
      return res.texts.some((t) => hasLine(t.text)) ? 'found' : 'SILENT-MISS'
    case 'binary':
      return res.strings && hasLine(res.strings.text) ? 'found' : 'SILENT-MISS'
    case 'unknown-binary':
    case 'invalid-text':
      return 'degraded'
  }
}

describe('QA property: a credential in a file under the size cap is found or the scan degrades', () => {
  it('holds for 4,000 seeded random encodings and mixes (no silent miss)', () => {
    const misses: string[] = []
    const seen = { found: 0, degraded: 0, kinds: new Set<string>() }
    for (let seed = 1; seed <= 4000; seed++) {
      const { buf, recipe } = makeMixCase(seed)
      const res = classifyFile(new Uint8Array(buf))
      seen.kinds.add(res.kind)
      const o = outcome(res)
      if (o === 'SILENT-MISS') misses.push(`seed ${seed} (${res.kind}): ${recipe}`)
      else seen[o]++
    }
    expect(misses, misses.slice(0, 10).join('\n')).toEqual([])
    // The generator must actually reach every result kind, or the property proves little.
    expect([...seen.kinds].sort()).toEqual(['binary', 'invalid-text', 'text', 'unknown-binary'])
    expect(seen.found).toBeGreaterThan(1000)
    expect(seen.degraded).toBeGreaterThan(50)
  })
})
