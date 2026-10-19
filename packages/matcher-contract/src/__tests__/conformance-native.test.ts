// Phase B.1 — conformance harness wired to the native-v1 executor
//
// Asserts that ALL conformance vectors (executor-independent + executor-dependent)
// pass when run against the nativeV1Executor.
//
// HASH FREEZE PROTOCOL
// ====================
// On the first run (before hashes are frozen in vectors.ts), executor-dependent
// vectors have expectedCanonicalHash=null → they get status 'hash-recorded'.
// Phase B.1 freeze step:
//   1. Run this test with the "records hashes" test active → reads computed hashes.
//   2. Patch vectors.ts with the frozen hashes.
//   3. Re-run → all executor-dependent vectors become 'hash-frozen'.

import { describe, it, expect } from 'vitest'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { runConformance, allConformanceVectors } from '../conformance/index.js'
import { nativeV1Executor } from '../adapters/native-v1.js'

describe('A.12 conformance — native-v1 executor', () => {
  it('all vectors pass or record (zero failures)', () => {
    const report = runConformance(nativeV1Executor, allConformanceVectors)
    // Fail the test with helpful output if any vector fails
    if (report.failed > 0) {
      const failDetails = report.results
        .filter((r) => r.status === 'fail')
        .map((r) => `  ${r.vectorId}: ${r.detail}`)
        .join('\n')
      throw new Error(`${report.failed} conformance vector(s) failed:\n${failDetails}`)
    }
    expect(report.failed).toBe(0)
  })

  it('executor-dependent vectors are run (not skipped)', () => {
    const report = runConformance(nativeV1Executor, allConformanceVectors)
    expect(report.skipped).toBe(0)
  })

  it('re-running produces byte-identical hashes', () => {
    const r1 = runConformance(nativeV1Executor, allConformanceVectors)
    const r2 = runConformance(nativeV1Executor, allConformanceVectors)
    const hashes1 = r1.results.map((r) => r.computedHash ?? '').join(',')
    const hashes2 = r2.results.map((r) => r.computedHash ?? '').join(',')
    expect(hashes1).toBe(hashes2)
  })

  it('records hashes for freeze step (writes computed-hashes.json)', () => {
    const report = runConformance(nativeV1Executor, allConformanceVectors)
    const hashMap: Record<string, string> = {}
    for (const r of report.results) {
      if (r.computedHash !== null) {
        hashMap[r.vectorId] = r.computedHash
      }
    }
    // Write to a temp file so the freeze script can read it without re-running tests.
    const outPath = join(import.meta.dirname, '../../../../computed-hashes.json')
    writeFileSync(outPath, JSON.stringify(hashMap, null, 2))
    // The test itself always passes — it's a recording step, not an assertion.
    expect(Object.keys(hashMap).length).toBeGreaterThan(0)
  })
})
