// Phase D.1 — conformance harness wired to the re2js-v1 executor
//
// Tests:
// 1. All A.12 conformance vectors pass through both native-v1 and re2js-v1
//    and produce BYTE-IDENTICAL canonical findings (hash parity).
// 2. Catastrophic ReDoS pattern `(a+)+$` completes in < 100ms on re2js
//    for a non-matching input of length 20+ (native RegExp would hang).
// 3. RE2JS_V1_RUNTIME_ID is deterministic, frozen, and differs from
//    NATIVE_V1_RUNTIME_ID (two distinct adapters = two distinct IDs).
// 4. RE2-incompatible primary patterns (lookaheads) THROW fail-closed.
//    Gate B must prevent these from ever reaching the executor in production.
//
// NOTE on zero-width-1 vector (`(?=SECRET)` lookahead):
//   native-v1 records one zero-width occurrence; re2js-v1 THROWS fail-closed
//   (compile error — lookaheads are not RE2-compatible). This vector
//   is in the executor-dependent exclusion list and is not run against re2js-v1
//   in the shared conformance suite.

import { describe, it, expect } from 'vitest'
import { runConformance, allConformanceVectors, executorDependentVectors } from '../conformance/index.js'
import type { ConformanceVector } from '../conformance/vectors.js'
import { nativeV1Executor } from '../adapters/native-v1.js'
import { re2jsV1Executor, RE2JS_V1_RUNTIME_ID, RE2JS_V1_ADAPTER_IMPL_HASH } from '../adapters/re2js-v1.js'
import { NATIVE_V1_RUNTIME_ID, NATIVE_V1_ADAPTER_IMPL_HASH } from '../adapters/native-v1.js'
import type { ExecCtx } from '../matcher.js'

// Vectors that use RE2-incompatible syntax (lookaheads, backreferences) — these
// cannot produce the same hash as native-v1 because re2js refuses to compile them.
// Gate B rejects such patterns at authoring time, so they never appear in the live
// corpus. The divergence is documented and safe.
const RE2_INCOMPATIBLE_VECTOR_IDS = new Set(['zero-width-1'])

// Conformance vectors filtered to only those re2js-v1 can run with parity.
// The RE2-incompatible ones have their own separate test asserting graceful degrade.
const re2jsCompatibleVectors: ConformanceVector[] = allConformanceVectors.filter(
  (v) => !RE2_INCOMPATIBLE_VECTOR_IDS.has(v.id),
)

// ---------------------------------------------------------------------------
// 1. Full conformance suite — re2js-v1 passes all RE2-compatible vectors
// ---------------------------------------------------------------------------

describe('A.12 conformance — re2js-v1 executor', () => {
  it('all RE2-compatible vectors pass or record (zero failures)', () => {
    const report = runConformance(re2jsV1Executor, re2jsCompatibleVectors)
    if (report.failed > 0) {
      const failDetails = report.results
        .filter((r) => r.status === 'fail')
        .map((r) => `  ${r.vectorId}: ${r.detail}`)
        .join('\n')
      throw new Error(`${report.failed} conformance vector(s) failed:\n${failDetails}`)
    }
    expect(report.failed).toBe(0)
  })

  it('RE2-incompatible vectors (lookahead etc.) fail-closed — THROW, not silent zero', () => {
    // RE2-incompatible primary patterns now throw fail-closed instead of
    // silently producing 0 findings.  Gate B prevents these from reaching the
    // executor in production; if they do, it is a bundle integrity violation.
    for (const vectorId of RE2_INCOMPATIBLE_VECTOR_IDS) {
      const v = allConformanceVectors.find((vec) => vec.id === vectorId)
      if (!v || !v.input.matcher) continue
      const ctx: ExecCtx = {
        allRelativePaths: v.input.allRelativePaths ?? [v.input.relativePath],
        releaseId: v.input.releaseId,
      }
      const file = { relativePath: v.input.relativePath, content: v.input.content ?? '' }
      expect(() => {
        re2jsV1Executor.evaluate(v.input.matcher!, file, ctx)
      }).toThrow(/primary pattern compile failure/)
    }
  })

  it('executor-dependent vectors are run (not skipped)', () => {
    const report = runConformance(re2jsV1Executor, re2jsCompatibleVectors)
    expect(report.skipped).toBe(0)
  })

  it('re-running produces byte-identical hashes (deterministic)', () => {
    const r1 = runConformance(re2jsV1Executor, re2jsCompatibleVectors)
    const r2 = runConformance(re2jsV1Executor, re2jsCompatibleVectors)
    const hashes1 = r1.results.map((r) => r.computedHash ?? '').join(',')
    const hashes2 = r2.results.map((r) => r.computedHash ?? '').join(',')
    expect(hashes1).toBe(hashes2)
  })
})

// ---------------------------------------------------------------------------
// 2. Native-v1 vs re2js-v1 parity — byte-identical canonical hashes
//
// For every executor-dependent vector, both executors must produce the
// same canonical hash. The only expected divergence is the zero-width-1
// vector (`(?=SECRET)` lookahead) which re2js cannot compile.
// ---------------------------------------------------------------------------

describe('conformance parity — native-v1 vs re2js-v1 byte-identical hashes', () => {
  // Vectors that are EXPECTED to diverge between native-v1 and re2js-v1.
  // Reason: these patterns use lookaheads or other constructs unsupported by RE2.
  // Gate B rejects such patterns at authoring time; they should not appear in
  // the live corpus. The divergence is safe and documented.
  const KNOWN_DIVERGENCES: Record<string, string> = {
    'zero-width-1':
      'Lookahead (?=SECRET) is unsupported by RE2 — re2js THROWS fail-closed. ' +
      'Gate B rejects lookahead patterns; divergence is safe and expected.',
  }

  for (const vector of executorDependentVectors) {
    if (KNOWN_DIVERGENCES[vector.id]) {
      it(`[KNOWN DIVERGENCE] ${vector.id}: ${KNOWN_DIVERGENCES[vector.id]}`, () => {
        // Document the divergence but do NOT assert parity.
        // native-v1 succeeds; re2js-v1 throws fail-closed (no silent skip).
        expect(() => {
          nativeV1Executor.evaluate(
            vector.input.matcher!,
            { relativePath: vector.input.relativePath, content: vector.input.content ?? '' },
            { allRelativePaths: vector.input.allRelativePaths ?? [vector.input.relativePath], releaseId: vector.input.releaseId },
          )
        }).not.toThrow()
        expect(() => {
          re2jsV1Executor.evaluate(
            vector.input.matcher!,
            { relativePath: vector.input.relativePath, content: vector.input.content ?? '' },
            { allRelativePaths: vector.input.allRelativePaths ?? [vector.input.relativePath], releaseId: vector.input.releaseId },
          )
        }).toThrow(/primary pattern compile failure/)
      })
    } else {
      it(`parity: ${vector.id} — byte-identical canonical hash between native-v1 and re2js-v1`, () => {
        if (!vector.input.matcher) {
          // Executor-independent vector — no parity check needed.
          return
        }
        const ctx: ExecCtx = {
          allRelativePaths: vector.input.allRelativePaths ?? [vector.input.relativePath],
          releaseId: vector.input.releaseId,
        }
        const file = {
          relativePath: vector.input.relativePath,
          content: vector.input.content ?? '',
        }
        const nativeFindings = nativeV1Executor.evaluate(vector.input.matcher, file, ctx)
        const re2jsFindings = re2jsV1Executor.evaluate(vector.input.matcher, file, ctx)

        // Sort both arrays by evidence+line+column for stable comparison
        const sort = (arr: typeof nativeFindings) =>
          [...arr].sort((a, b) => {
            const ea = `${a.line}:${a.column}:${a.evidence ?? ''}`
            const eb = `${b.line}:${b.column}:${b.evidence ?? ''}`
            return ea.localeCompare(eb)
          })

        const sortedNative = sort(nativeFindings)
        const sortedRe2js = sort(re2jsFindings)

        // Length must match
        expect(sortedRe2js).toHaveLength(sortedNative.length)

        // Each finding must be field-identical
        for (let i = 0; i < sortedNative.length; i++) {
          const n = sortedNative[i]
          const r = sortedRe2js[i]
          expect(r.line).toBe(n.line)
          expect(r.column).toBe(n.column)
          expect(r.evidence).toBe(n.evidence)
          expect(r.suppressionState).toBe(n.suppressionState)
          expect(r.matcherType).toBe(n.matcherType)
        }
      })
    }
  }
})

// ---------------------------------------------------------------------------
// 3. ReDoS proof: `(a+)+$` on re2js completes in < 100ms for input length 20+
// ---------------------------------------------------------------------------

describe('ReDoS immunity — re2js linear-time guarantee', () => {
  it('catastrophic backtracking pattern (a+)+$ on 20-char non-matching input completes < 100ms', () => {
    // This pattern causes exponential backtracking in native RegExp.
    // A non-matching input of length 20 would take astronomically long with
    // native RegExp but completes in linear time with re2js.
    const REDOS_PATTERN = '(a+)+$'
    // Non-matching input: 'aaaaaaaaaaaaaaaaaaaab' — 20 a's + 'b' (no $ match)
    const NON_MATCHING_INPUT = 'a'.repeat(20) + 'b'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: [REDOS_PATTERN],
      antiPatterns: [],
      flags: '',
    }
    const file = { relativePath: 'src/test.ts', content: NON_MATCHING_INPUT }
    const ctx: ExecCtx = { allRelativePaths: ['src/test.ts'], releaseId: 'test-release' }

    const start = Date.now()
    const findings = re2jsV1Executor.evaluate(matcher, file, ctx)
    const elapsed = Date.now() - start

    // Must complete in < 100ms (re2js linear time)
    expect(elapsed).toBeLessThan(100)
    // Must return zero findings (the pattern does not match a+b ending)
    expect(findings).toHaveLength(0)
  })

  it('catastrophic pattern with even longer input (30 chars) still < 100ms', () => {
    const REDOS_PATTERN = '(a+)+$'
    const NON_MATCHING_INPUT = 'a'.repeat(30) + 'b'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: [REDOS_PATTERN],
      antiPatterns: [],
      flags: '',
    }
    const file = { relativePath: 'src/test.ts', content: NON_MATCHING_INPUT }
    const ctx: ExecCtx = { allRelativePaths: ['src/test.ts'], releaseId: 'test-release' }

    const start = Date.now()
    re2jsV1Executor.evaluate(matcher, file, ctx)
    const elapsed = Date.now() - start

    expect(elapsed).toBeLessThan(100)
  })
})

// ---------------------------------------------------------------------------
// 4. RE2JS_V1_RUNTIME_ID — frozen, deterministic, distinct from native-v1
// ---------------------------------------------------------------------------

describe('RE2JS_V1_RUNTIME_ID — frozen identity', () => {
  it('RE2JS_V1_RUNTIME_ID is a 64-character lowercase hex string', () => {
    expect(RE2JS_V1_RUNTIME_ID).toMatch(/^[0-9a-f]{64}$/)
  })

  it('RE2JS_V1_RUNTIME_ID differs from NATIVE_V1_RUNTIME_ID (distinct adapters = distinct IDs)', () => {
    expect(RE2JS_V1_RUNTIME_ID).not.toBe(NATIVE_V1_RUNTIME_ID)
  })

  it('RE2JS_V1_ADAPTER_IMPL_HASH is a 64-character lowercase hex string', () => {
    expect(RE2JS_V1_ADAPTER_IMPL_HASH).toMatch(/^[0-9a-f]{64}$/)
  })

  it('RE2JS_V1_ADAPTER_IMPL_HASH differs from NATIVE_V1_ADAPTER_IMPL_HASH', () => {
    expect(RE2JS_V1_ADAPTER_IMPL_HASH).not.toBe(NATIVE_V1_ADAPTER_IMPL_HASH)
  })

  it('RE2JS_V1_RUNTIME_ID matches the expected frozen constant (0.5.0 freeze)', () => {
    // Updated at 0.5.0 freeze (contractVersion 0.5.0, buildLock re2js-v1-build-2026-06-25-v0.5.0).
    // The re2js-v1-freeze.test.ts regression test re-derives this value from current bytes.
    // If THIS test fails, the constant was changed without a proper freeze update.
    expect(RE2JS_V1_RUNTIME_ID).toBe(
      '971fab9b230f60a1b663c7f9a888769e9a2d6ace58fa150e8ee574a3fc3c91d7',
    )
  })
})

// ---------------------------------------------------------------------------
// 5. Fail-closed on RE2-incompatible patterns (was: graceful degrade)
//
// 0.5.0: RE2-incompatible primary patterns now THROW (fail-closed)
// instead of silently skipping to zero findings. Gate B MUST reject such
// patterns before they reach the executor — if they reach it, it is a bundle
// integrity violation and we must hard-fail rather than silently suppress.
// ---------------------------------------------------------------------------

describe('re2js-v1: fail-closed on RE2-incompatible primary patterns', () => {
  it('lookahead (?=x) THROWS a bundle-degraded error (fail-closed)', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['(?=SECRET)'],
      antiPatterns: [],
      flags: '',
    }
    const file = { relativePath: 'src/test.ts', content: 'const SECRET = 1\n' }
    const ctx: ExecCtx = { allRelativePaths: ['src/test.ts'], releaseId: 'test-release' }

    // Must THROW — fail-closed. Gate B prevents this in the live corpus;
    // if it reaches the executor, the whole evaluation is aborted.
    expect(() => {
      re2jsV1Executor.evaluate(matcher, file, ctx)
    }).toThrow(/primary pattern compile failure.*bundle degraded.*fail-closed/)
  })

  it('mixed patterns: RE2-incompatible + RE2-compatible → THROWS on the incompatible one', () => {
    // even if a later pattern is valid, the first invalid pattern must fail-closed.
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['(?=SECRET)', 'SECRET_KEY'],
      antiPatterns: [],
      flags: '',
    }
    const file = { relativePath: 'src/test.ts', content: 'const SECRET_KEY = 1\n' }
    const ctx: ExecCtx = { allRelativePaths: ['src/test.ts'], releaseId: 'test-release' }

    // Throws on the lookahead — does NOT produce partial findings for the valid pattern.
    expect(() => {
      re2jsV1Executor.evaluate(matcher, file, ctx)
    }).toThrow(/primary pattern compile failure/)
  })
})
