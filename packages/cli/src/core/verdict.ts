import type { Recommendation, RiskScore, ScanResult } from '@agenticcli/shared'

/**
 * THE single place the ship / don't-ship verdict is computed.
 *
 * Design rule:
 *
 *   "`degraded: true` forces `recommendation: DO_NOT_SHIP` — verdict computed
 *    fail-closed, in one place, enum stays 2 values"
 *
 * WHY (the false-safe verdict): a scan that could not read every file it was
 * asked to read has not checked the thing it is being asked about. Printing
 * "SAFE_TO_SHIP" beside its own `degraded: true` flag is the single worst output a
 * release gate can produce — it is a truthful field and a false headline in the same
 * document, and every consumer that keys on the headline is misled.
 *
 * WHAT THIS DOES NOT DO — the load-bearing distinction:
 * this changes what the report SAYS, never what the process DOES. ShipGuard stays
 * PASSIVE BY DEFAULT: a degraded scan still exits 0 while saying
 * DO_NOT_SHIP. Only `--strict` — the designated opt-in hard stop
 * turns that truthful verdict into exit 1. See resolveExitCode() in commands/scan.ts.
 *
 * ENUM: the `Recommendation` union is NOT extended here. Reviewers independently
 * killed `SAFE_TO_SHIP_INCOMPLETE` / `INDETERMINATE` as a fail-open trap for the very
 * common `recommendation !== 'DO_NOT_SHIP'` parser. A degraded scan reuses
 * the existing DO_NOT_SHIP value; the WHY lives in `degraded` + `degradedReasons`.
 */
export function computeVerdict(input: {
  /** Only `score` is read — the thresholds live here and nowhere else. */
  riskScore: Pick<RiskScore, 'score'>
  /** true when ANY part of the scan did not run to completion. Fail-closed. */
  degraded?: boolean
}): Recommendation {
  // Fail-closed FIRST — an incomplete scan can never be reported as safe, whatever
  // the findings it did manage to collect happen to score.
  if (input.degraded === true) return 'DO_NOT_SHIP'

  const score = input.riskScore.score
  if (score <= 20) return 'SAFE_TO_SHIP'
  if (score < 50) return 'REVIEW_BEFORE_SHIP'
  return 'DO_NOT_SHIP'
}

/**
 * Stamp the computed verdict onto a scan result — BOTH copies, always together.
 *
 * Note: `riskScore.recommendation` duplicates the top-level
 * `recommendation`. Two copies of one verdict desynchronize the moment either is
 * patched, and a consumer that picked the other field silently gets the stale answer.
 * Until the next schemaVersion drops it (see the deprecation note on
 * `RiskScore.recommendation` in packages/shared/src/types.ts), the duplicate is kept
 * as a MIRROR that is written here and only here — never computed independently.
 *
 * Idempotent by construction: applying it twice yields the same values, so it is safe
 * to call once in scanner.ts (so a direct `scan()` caller is already correct) and again
 * in commands/scan.ts after the pro-fetch degradation is OR-merged in (the only point
 * at which the FINAL `degraded` value is known).
 */
export function applyVerdict<T extends ScanResult>(result: T): T {
  const verdict = computeVerdict({
    riskScore: result.riskScore,
    degraded: result.degraded,
  })
  result.recommendation = verdict
  // Deprecated mirror — see the doc comment above. Never compute this separately.
  result.riskScore.recommendation = verdict
  return result
}

/**
 * Read the authoritative verdict off a result.
 *
 * Prefers the top-level `recommendation` (the field the schema documents as the
 * verdict) and falls back to the deprecated mirror only for objects built by older
 * code paths / test fixtures that never went through `applyVerdict`.
 */
export function effectiveRecommendation(result: ScanResult): Recommendation {
  return result.recommendation ?? result.riskScore.recommendation
}
