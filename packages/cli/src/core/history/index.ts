import type {
  CoverageChangedEntry,
  Finding,
  Policy,
  QualityGateRule,
  RegressionCheckSkippedReason,
  RegressionEntry,
  ScanResult,
  StateStatus,
} from '@agenticcli/shared'
import { UNVERSIONED } from './schema.js'
import { resolveHistoryPath } from './path.js'
import { resolveRepoIdentity } from './identity.js'
import { computeScopeFingerprint } from './fingerprint.js'
import { HistoryStore } from './store.js'
import { computeRegressionResult } from './regression.js'
import type { RuleOutcome, ScanSnapshot } from './regression.js'
import { deriveBlocking } from '../pro-scanner.js'
import { getFindingKey } from '../redact.js'
import { logger } from '../../utils/logger.js'

export interface RecordScanHistoryInput {
  cwd: string
  scanId: string
  cliVersion: string
  policy: Policy
  changedOnly: boolean
  categories: string[]
  proRules: QualityGateRule[] | undefined
  /** Pro rules were ACTUALLY applied this scan (not merely requested — see fingerprint.ts). */
  proApplied: boolean
  rulesVersion: string | undefined
  result: ScanResult
}

export interface HistoryOutcome {
  stateStatus: StateStatus
  regressionCheckSkipped: boolean
  regressionCheckSkippedReason?: RegressionCheckSkippedReason
  regressions: RegressionEntry[]
  coverageChanged: CoverageChangedEntry[]
}

function isActive(finding: Finding): boolean {
  if (finding.suppressionState) return finding.suppressionState === 'active'
  return !finding.suppressed
}

/**
 * The full set of rule outcomes for THIS scan's active corpus — free-tier ids come from the
 * policy's own block/warn lists (the only enumerable source of "which free rule ids exist",
 * since free checks are fixed modules, not a registry); pro-tier ids come from the fetched
 * QualityGateRule[] actually applied. `blocking` mirrors the exact derivation the scanner
 * itself uses (deriveBlocking, pro-scanner.ts) so history never disagrees with the verdict.
 */
function buildRuleOutcomes(
  policy: Policy,
  proRules: QualityGateRule[] | undefined,
  proApplied: boolean,
  cliVersion: string,
  corpusVersion: string,
  result: ScanResult,
): RuleOutcome[] {
  const outcomes: RuleOutcome[] = []
  const countActive = (ruleId: string): number =>
    result.findings.filter((f) => f.id === ruleId && isActive(f)).length

  for (const ruleId of policy.block) {
    outcomes.push({ ruleId, blocking: true, activeFindingCount: countActive(ruleId), ruleVersion: cliVersion })
  }
  for (const ruleId of policy.warn) {
    outcomes.push({ ruleId, blocking: false, activeFindingCount: countActive(ruleId), ruleVersion: cliVersion })
  }

  if (proApplied && proRules) {
    for (const rule of proRules) {
      outcomes.push({
        ruleId: rule.id,
        blocking: deriveBlocking(rule),
        activeFindingCount: countActive(rule.id),
        ruleVersion: rule.version ?? corpusVersion,
      })
    }
  }

  return outcomes
}

/**
 * The E5 write-point + the ONE regression claim, wired together. Called once per scan from
 * commands/scan.ts, AFTER the scan itself has produced its findings/verdict. Side-effect-free
 * to that verdict and exit code by construction: every failure mode here (unsupported Node
 * runtime, disk full, corrupt file, migration failure, lock timeout) resolves to a typed
 * `stateStatus` + `regressionCheckSkipped: true` — it never throws, and the caller never
 * awaits anything that can change the scan's own outcome.
 */
export async function recordScanHistory(input: RecordScanHistoryInput): Promise<HistoryOutcome> {
  const { cwd, scanId, cliVersion, policy, changedOnly, categories, proRules, proApplied, rulesVersion, result } = input

  const scopeFingerprint = computeScopeFingerprint({
    changedOnly,
    categories,
    ignorePaths: policy.ignore.paths,
    proApplied,
  })
  const identity = resolveRepoIdentity(cwd)
  // Free-tier rules are versioned by the CLI build (the only thing that ever changes their
  // logic); pro-tier rules are versioned by the fetched corpus release label.
  const corpusVersion = proApplied ? (rulesVersion ?? UNVERSIONED) : `free:${cliVersion}`
  const proReleaseId = proApplied ? result.findings.find((f) => f.releaseId)?.releaseId : undefined
  const releaseId = proReleaseId ?? UNVERSIONED

  const historyPath = resolveHistoryPath(cwd, policy)
  const openResult = await HistoryStore.open(historyPath, cliVersion)

  if (!openResult.ok) {
    // Loud, not silent (loud errors) — but never fatal to the scan.
    logger.warn(`ShipGuard history ${openResult.status}: ${openResult.reason}`)
    return {
      stateStatus: openResult.status,
      regressionCheckSkipped: true,
      regressionCheckSkippedReason: 'state-unavailable',
      regressions: [],
      coverageChanged: [],
    }
  }

  const store = openResult.store
  try {
    const ruleOutcomes = buildRuleOutcomes(policy, proRules, proApplied, cliVersion, corpusVersion, result)
    const baseline = store.getBaseline(identity.repoId, scopeFingerprint)

    const ruleVersionById = new Map(ruleOutcomes.map((ro) => [ro.ruleId, ro.ruleVersion]))
    const findingRows = result.findings.map((f) => ({
      ruleId: f.id,
      findingKey: getFindingKey(f),
      filePath: f.file,
      severity: f.severity,
      blocking: Boolean(f.blocking),
      active: isActive(f),
      ruleVersion: ruleVersionById.get(f.id) ?? corpusVersion,
      corpusVersion,
      releaseId: f.releaseId ?? releaseId,
    }))

    const writeResult = store.writeScan({
      scanId,
      repoId: identity.repoId,
      repoIdKind: identity.repoIdKind,
      remoteLabel: identity.remoteLabel,
      scopeFingerprint,
      corpusVersion,
      releaseId,
      cliVersion,
      timestamp: result.timestamp,
      recommendation: result.recommendation,
      blockingCount: result.riskScore.blockingCount,
      criticalCount: result.riskScore.criticalCount,
      highCount: result.riskScore.highCount,
      mediumCount: result.riskScore.mediumCount,
      lowCount: result.riskScore.lowCount,
      infoCount: result.riskScore.infoCount,
      ruleOutcomes,
      findings: findingRows,
    })

    const stateStatus: StateStatus = writeResult.ok ? 'complete' : 'unavailable'
    if (!writeResult.ok) {
      logger.warn(`ShipGuard history write failed — this scan's findings/verdict are unaffected: ${writeResult.reason}`)
    }

    const retentionDays = policy.history?.retention_days
    if (writeResult.ok && retentionDays && retentionDays > 0) {
      const pruneResult = store.prune(identity.repoId, retentionDays)
      if (!pruneResult.ok) {
        logger.warn(`ShipGuard history retention pruning failed (non-fatal): ${pruneResult.reason}`)
      } else if (pruneResult.deleted > 0) {
        logger.info(`ShipGuard history: pruned ${pruneResult.deleted} scan(s) older than ${retentionDays} day(s)`)
      }
    }

    const currentSnapshot: ScanSnapshot = {
      scanId,
      timestamp: result.timestamp,
      scopeFingerprint,
      corpusVersion,
      stateStatus,
      ruleOutcomes,
    }

    const regressionResult = computeRegressionResult(currentSnapshot, baseline)
    return { stateStatus, ...regressionResult }
  } catch (err) {
    logger.warn(
      `ShipGuard history recording failed unexpectedly — this scan's findings/verdict are unaffected: ${err instanceof Error ? err.message : err}`,
    )
    return {
      stateStatus: 'unavailable',
      regressionCheckSkipped: true,
      regressionCheckSkippedReason: 'state-unavailable',
      regressions: [],
      coverageChanged: [],
    }
  } finally {
    store.close()
  }
}

export { resolveHistoryPath } from './path.js'
export { resolveRepoIdentity, resolveContentIdentity } from './identity.js'
export { computeScopeFingerprint } from './fingerprint.js'
export { HistoryStore } from './store.js'
export { computeRegressionResult } from './regression.js'
export type { RuleOutcome, ScanSnapshot, RegressionResult } from './regression.js'
// ScanId reuse — scanId retry-idempotency across whole-process retries.
export { resolveScanId, computeScanIdReuseKey, resolveScanIdReuseWindowMs } from './scan-id.js'
export type { ResolveScanIdInput, ResolveScanIdResult, ScanIdReuseKeyInput } from './scan-id.js'
