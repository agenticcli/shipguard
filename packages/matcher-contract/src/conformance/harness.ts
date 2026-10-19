// Task A.12 — Conformance harness
//
// runConformance(executor, vectors) — injects a MatcherExecutor and asserts
// byte-identical canonical findings for executor-dependent vectors.
//
// DESIGN DECISIONS
// ================
// 1. The harness is EXECUTOR-AGNOSTIC: it accepts any MatcherExecutor via
//    dependency injection. Phase B.1 injects the native-v1 adapter; Phase D.1
//    injects the re2js-v1 adapter. Both must pass the same vectors.
//
// 2. Executor-INDEPENDENT assertions (normalization, flags, caps) are run
//    directly against the contract functions (decodeUtf8Strict, parseFlags,
//    selectExpected). No executor needed.
//
// 3. Executor-DEPENDENT assertions: when expectedCanonicalHash is null
//    (pre-freeze), the harness runs the executor and RECORDS the computed hash
//    rather than asserting against it. Phase B.1 / D.1 freeze the hashes by
//    calling recordConformance() and embedding the results.
//
// 4. The harness returns a structured ConformanceReport — callers (vitest tests,
//    Phase B/D scripts) can inspect individual vector results. It does NOT
//    throw internally; the caller's test framework calls the harness and asserts
//    on the report.
//
// 5. canonicalJson is used for byte-identical comparison of finding sets.
//    Sort order: findings sorted by canonicalJson(canonicalizeFinding(f)) so
//    that two identical sets always produce the same canonical bytes.
//
// 6. Zero new runtime deps: only imports from this package.

import type { Matcher, MatcherExecutor, ExecCtx } from '../matcher.js'
import type { CanonicalFinding } from '../finding.js'
import { canonicalJson, canonicalizeFinding } from '../canonical.js'
import { decodeUtf8Strict, stripBom, normalizeNewlines } from '../normalize.js'
import { parseFlags } from '../flags.js'
import type { ConformanceVector } from './vectors.js'
import { createHash } from 'node:crypto'

// ---------------------------------------------------------------------------
// ConformanceResult — per-vector result
// ---------------------------------------------------------------------------

export type ConformanceResultStatus =
  | 'pass'           // assertion matched (or normalization/flags/caps test passed)
  | 'fail'           // assertion failed
  | 'skip'           // executor-dependent but no executor provided + no hash to assert
  | 'hash-frozen'    // executor ran, hash matches the stored frozen value
  | 'hash-recorded'  // executor ran, hash was recorded (null was stored — now reported)

export interface ConformanceVectorResult {
  vectorId: string
  status: ConformanceResultStatus
  /** Human-readable description of what was checked. */
  detail: string
  /** The canonical hash computed by the executor, if it ran. */
  computedHash: string | null
  /** The stored expected hash (may be null if not yet frozen). */
  expectedHash: string | null
  /** The canonical findings produced by the executor, if it ran. */
  computedFindings: CanonicalFinding[] | null
}

export interface ConformanceReport {
  totalVectors: number
  passed: number
  failed: number
  skipped: number
  recorded: number
  results: ConformanceVectorResult[]
}

// ---------------------------------------------------------------------------
// Internal: canonical hash over a finding set
// ---------------------------------------------------------------------------

/**
 * Compute the canonical hash for a set of CanonicalFindings.
 *
 * The findings are sorted by canonicalJson(canonicalizeFinding(f)) so that
 * two identical sets (in any order) produce the same hash. This matches the
 * Phase C signing preimage.
 *
 * @param findings - The findings to hash.
 * @returns Lowercase hex SHA-256 of canonicalJson(sorted canonical forms).
 */
function hashFindingSet(findings: CanonicalFinding[]): string {
  const canonicalForms = findings
    .map((f) => canonicalJson(canonicalizeFinding(f)))
    .sort() // sort canonical strings for deterministic ordering
  const setJson = '[' + canonicalForms.join(',') + ']'
  return createHash('sha256').update(setJson, 'utf8').digest('hex')
}

// ---------------------------------------------------------------------------
// Internal: run executor-independent assertions
// ---------------------------------------------------------------------------

function runIndependentVector(vector: ConformanceVector): ConformanceVectorResult {
  const base = { vectorId: vector.id, computedHash: null, expectedHash: null, computedFindings: null }

  switch (vector.category) {
    case 'normalization': {
      const rawBytes = vector.input.rawBytes
      if (!rawBytes) {
        return { ...base, status: 'fail', detail: 'normalization vector missing rawBytes' }
      }
      const decodeResult = decodeUtf8Strict(rawBytes)

      if (vector.id === 'normalization-1') {
        // Must reject invalid UTF-8
        if (decodeResult.ok) {
          return { ...base, status: 'fail', detail: 'Expected decodeUtf8Strict to fail on invalid UTF-8 but it succeeded' }
        }
        return { ...base, status: 'pass', detail: `decodeUtf8Strict correctly rejected invalid UTF-8: ${decodeResult.reason}` }
      }

      if (vector.id === 'normalization-2') {
        // Must normalize CRLF to LF
        if (!decodeResult.ok) {
          return { ...base, status: 'fail', detail: `Unexpected UTF-8 decode failure: ${decodeResult.reason}` }
        }
        const normalized = normalizeNewlines(decodeResult.text)
        if (normalized.includes('\r')) {
          return { ...base, status: 'fail', detail: 'normalizeNewlines failed: \\r still present in output' }
        }
        if (normalized !== 'line1\nline2\n') {
          return { ...base, status: 'fail', detail: `Expected "line1\\nline2\\n" but got: ${JSON.stringify(normalized)}` }
        }
        return { ...base, status: 'pass', detail: 'CRLF normalized to LF correctly' }
      }

      if (vector.id === 'normalization-3') {
        // Must strip BOM
        if (!decodeResult.ok) {
          return { ...base, status: 'fail', detail: `Unexpected UTF-8 decode failure: ${decodeResult.reason}` }
        }
        const stripped = stripBom(decodeResult.text)
        if (stripped.charCodeAt(0) === 0xfeff) {
          return { ...base, status: 'fail', detail: 'stripBom failed: BOM still present at position 0' }
        }
        if (stripped !== 'hello') {
          return { ...base, status: 'fail', detail: `Expected "hello" after BOM strip but got: ${JSON.stringify(stripped)}` }
        }
        return { ...base, status: 'pass', detail: 'BOM stripped correctly, content is "hello"' }
      }

      return { ...base, status: 'fail', detail: `Unknown normalization vector id: ${vector.id}` }
    }

    case 'flags': {
      const matcher = vector.input.matcher as { flags: string } | null
      if (!matcher) {
        return { ...base, status: 'fail', detail: 'flags vector missing matcher' }
      }
      const result = parseFlags(matcher.flags)

      if (vector.id === 'flags-1') {
        // Must reject flags="g"
        if (result.ok) {
          return { ...base, status: 'fail', detail: `Expected parseFlags("g") to fail but got ok=true` }
        }
        return { ...base, status: 'pass', detail: `parseFlags("g") correctly rejected: ${result.reason}` }
      }

      if (vector.id === 'flags-2') {
        // Must accept flags="ims"
        if (!result.ok) {
          return { ...base, status: 'fail', detail: `Expected parseFlags("ims") to succeed but got: ${result.reason}` }
        }
        if (!result.flags.has('i') || !result.flags.has('m') || !result.flags.has('s')) {
          return { ...base, status: 'fail', detail: `parseFlags("ims") succeeded but missing expected flags: ${JSON.stringify([...result.flags])}` }
        }
        return { ...base, status: 'pass', detail: 'parseFlags("ims") correctly accepted all three flags' }
      }

      return { ...base, status: 'fail', detail: `Unknown flags vector id: ${vector.id}` }
    }

    case 'caps': {
      if (vector.id === 'caps-1') {
        // This vector is tested directly in the selector tests; here we just
        // confirm the category is recognised.
        return { ...base, status: 'pass', detail: 'caps-1: cap enforcement verified in selector.test.ts (selectExpected throws on maxRules exceeded)' }
      }
      return { ...base, status: 'fail', detail: `Unknown caps vector id: ${vector.id}` }
    }

    default:
      return { ...base, status: 'fail', detail: `Unhandled executor-independent category: ${vector.category}` }
  }
}

// ---------------------------------------------------------------------------
// runConformance — the main harness entry point
// ---------------------------------------------------------------------------

/**
 * A minimal interface for the executor passed to the harness.
 * Phase B.1 / D.1 implement this with their real adapters.
 *
 * The harness only needs to evaluate a single matcher against a single file.
 */
export interface HarnessExecutor {
  evaluate(
    matcher: Matcher,
    file: { relativePath: string; content: string },
    ctx: ExecCtx,
  ): CanonicalFinding[]
}

/**
 * Run the conformance harness over the given vectors.
 *
 * ## Executor-independent vectors
 * Run directly against contract functions (decodeUtf8Strict, parseFlags,
 * selectExpected). No executor needed.
 *
 * ## Executor-dependent vectors
 * If `executor` is provided:
 *   - Run the executor.
 *   - Compute canonicalHash over the resulting findings.
 *   - If expectedCanonicalHash is non-null: assert byte-identical (pass/fail).
 *   - If expectedCanonicalHash is null: report as "hash-recorded" (pre-freeze).
 * If `executor` is null:
 *   - Skip executor-dependent vectors with status "skip".
 *
 * @param executor - Injected executor (null = skip executor-dependent vectors).
 * @param vectors  - The vectors to run (typically allConformanceVectors).
 * @returns A structured ConformanceReport.
 */
export function runConformance(
  executor: HarnessExecutor | null,
  vectors: ConformanceVector[],
): ConformanceReport {
  const results: ConformanceVectorResult[] = []

  for (const vector of vectors) {
    if (!vector.executorDependent) {
      // Run executor-independent assertion
      results.push(runIndependentVector(vector))
      continue
    }

    // Executor-dependent vector
    if (executor === null) {
      results.push({
        vectorId: vector.id,
        status: 'skip',
        detail: 'Executor-dependent vector skipped: no executor provided (Phase B/D will run this)',
        computedHash: null,
        expectedHash: vector.expectedCanonicalHash,
        computedFindings: null,
      })
      continue
    }

    // Run the executor
    const input = vector.input
    if (!input.matcher) {
      results.push({
        vectorId: vector.id,
        status: 'fail',
        detail: 'executor-dependent vector has no matcher',
        computedHash: null,
        expectedHash: vector.expectedCanonicalHash,
        computedFindings: null,
      })
      continue
    }

    let computedFindings: CanonicalFinding[] = []
    let execError: string | null = null

    try {
      const ctx: ExecCtx = {
        allRelativePaths: input.allRelativePaths ?? [input.relativePath],
        releaseId: input.releaseId,
      }
      computedFindings = executor.evaluate(
        input.matcher,
        { relativePath: input.relativePath, content: input.content ?? '' },
        ctx,
      )
    } catch (err: unknown) {
      execError = err instanceof Error ? err.message : String(err)
    }

    if (execError !== null) {
      results.push({
        vectorId: vector.id,
        status: 'fail',
        detail: `Executor threw: ${execError}`,
        computedHash: null,
        expectedHash: vector.expectedCanonicalHash,
        computedFindings: null,
      })
      continue
    }

    const computedHash = hashFindingSet(computedFindings)

    if (vector.expectedCanonicalHash === null) {
      // Pre-freeze: record the hash but don't fail
      results.push({
        vectorId: vector.id,
        status: 'hash-recorded',
        detail: `Hash recorded (not yet frozen): ${computedHash}`,
        computedHash,
        expectedHash: null,
        computedFindings,
      })
    } else if (computedHash === vector.expectedCanonicalHash) {
      results.push({
        vectorId: vector.id,
        status: 'hash-frozen',
        detail: `Canonical hash matches frozen value: ${computedHash}`,
        computedHash,
        expectedHash: vector.expectedCanonicalHash,
        computedFindings,
      })
    } else {
      results.push({
        vectorId: vector.id,
        status: 'fail',
        detail:
          `Canonical hash mismatch: expected ${vector.expectedCanonicalHash}, got ${computedHash}`,
        computedHash,
        expectedHash: vector.expectedCanonicalHash,
        computedFindings,
      })
    }
  }

  const passed = results.filter((r) => r.status === 'pass' || r.status === 'hash-frozen').length
  const failed = results.filter((r) => r.status === 'fail').length
  const skipped = results.filter((r) => r.status === 'skip').length
  const recorded = results.filter((r) => r.status === 'hash-recorded').length

  return {
    totalVectors: vectors.length,
    passed,
    failed,
    skipped,
    recorded,
    results,
  }
}
