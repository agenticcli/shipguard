import type {
  CoverageChangedEntry,
  RegressionCheckSkippedReason,
  RegressionEntry,
  StateStatus,
} from '@agenticcli/shared'

/** Per-rule outcome for one scan — everything the regression comparison needs (§4). */
export interface RuleOutcome {
  ruleId: string
  /** Whether this rule was blocking in THIS scan's active corpus (free policy.block, or pro action==='block'). */
  blocking: boolean
  /** Count of active (non-suppressed) findings for this rule in this scan. 0 = the rule passed. */
  activeFindingCount: number
  /** The rule's own version — free-tier rules use the CLI build version as their version axis. */
  ruleVersion: string
}

/** Everything the regression comparison needs about one scan — DB-shape-agnostic (pure). */
export interface ScanSnapshot {
  scanId: string
  timestamp: string
  scopeFingerprint: string
  corpusVersion: string
  stateStatus: StateStatus
  ruleOutcomes: RuleOutcome[]
}

export interface RegressionResult {
  regressionCheckSkipped: boolean
  regressionCheckSkippedReason?: RegressionCheckSkippedReason
  regressions: RegressionEntry[]
  coverageChanged: CoverageChangedEntry[]
}

/**
 * The ONE regression claim (§4): "a previously-passing blocking rule now fails, under the
 * same scope fingerprint, within the same corpus release family."
 *
 * `baseline` is already the most recent PRIOR `stateStatus: complete` scan for the SAME
 * repoId + scopeFingerprint (the caller does that lookup) — this function only decides,
 * given the two snapshots, what can safely be claimed as a regression vs. reported as a
 * coverage change vs. skipped entirely. Pure and DB-free so it is exhaustively unit-testable.
 */
export function computeRegressionResult(
  current: ScanSnapshot,
  baseline: ScanSnapshot | undefined,
): RegressionResult {
  const skip = (reason: RegressionCheckSkippedReason): RegressionResult => ({
    regressionCheckSkipped: true,
    regressionCheckSkippedReason: reason,
    regressions: [],
    coverageChanged: [],
  })

  if (!baseline) return skip('no-baseline')

  // The hard rule (§1.6): a regression verdict can only ever be claimed when stateStatus is
  // `complete` for BOTH the current and the compared-against run.
  if (current.stateStatus !== 'complete' || baseline.stateStatus !== 'complete') {
    return skip('state-unavailable')
  }

  // Defensive — the caller's baseline lookup already filters by fingerprint, but a mismatch
  // here would be exactly the "scope drift misread as code drift" failure this schema exists
  // to prevent, so it is checked again at the point of decision, not trusted from upstream.
  if (current.scopeFingerprint !== baseline.scopeFingerprint) {
    return skip('scope-mismatch')
  }

  const regressions: RegressionEntry[] = []
  const coverageChanged: CoverageChangedEntry[] = []
  const baselineByRule = new Map(baseline.ruleOutcomes.map((r) => [r.ruleId, r]))
  const currentRuleIds = new Set(current.ruleOutcomes.map((r) => r.ruleId))

  for (const cur of current.ruleOutcomes) {
    if (!cur.blocking) continue // the ONE claim is scoped to blocking rules only (§4 step 4)

    const base = baselineByRule.get(cur.ruleId)
    if (!base) {
      // Rule didn't exist (or wasn't blocking) in the baseline's active corpus at all —
      // a "pass" here would be a lie (it never ran), so this is coverage, not regression.
      coverageChanged.push({ ruleId: cur.ruleId, reason: 'new-since-baseline' })
      continue
    }

    if (base.ruleVersion !== cur.ruleVersion) {
      // The rule's own logic changed between the two scans (a corpus/CLI update that
      // touched THIS rule) — a new failure here may be the updated detection logic, not
      // the user's code getting worse. Report as coverage-changed, never regression
      // (the false-positive guard this schema exists to enforce, §3/§4).
      coverageChanged.push({
        ruleId: cur.ruleId,
        reason: 'rule-version-changed',
        baselineRuleVersion: base.ruleVersion,
        currentRuleVersion: cur.ruleVersion,
      })
      continue
    }

    if (!base.blocking) {
      // Rule existed but was warn/monitor in the baseline — not comparable as a
      // pass↔fail blocking flip; its blocking status itself changed (coverage, not code).
      coverageChanged.push({ ruleId: cur.ruleId, reason: 'rule-version-changed' })
      continue
    }

    if (base.activeFindingCount === 0 && cur.activeFindingCount > 0) {
      regressions.push({
        ruleId: cur.ruleId,
        baselineScanId: baseline.scanId,
        baselineTimestamp: baseline.timestamp,
        currentScanId: current.scanId,
        corpusVersion: { baseline: baseline.corpusVersion, current: current.corpusVersion },
        scopeFingerprint: current.scopeFingerprint,
      })
    }
  }

  // Rules that were blocking in the baseline's corpus but are absent from the current
  // scan's rule set entirely — withdrawn/deprecated between the two scans (§4 step 3).
  for (const base of baseline.ruleOutcomes) {
    if (base.blocking && !currentRuleIds.has(base.ruleId)) {
      coverageChanged.push({ ruleId: base.ruleId, reason: 'withdrawn-since-baseline' })
    }
  }

  return { regressionCheckSkipped: false, regressions, coverageChanged }
}
