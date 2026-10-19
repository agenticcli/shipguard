import { createHash, randomUUID } from 'node:crypto'
import { relative } from 'node:path'
import type { Policy } from '@agenticcli/shared'
import { DEFAULT_SCAN_ID_REUSE_WINDOW_MINUTES, SCAN_ID_REUSE_WINDOW_ENV_VAR } from '@agenticcli/shared'
import { resolveHistoryPath } from './path.js'
import { resolveRepoIdentity, resolveContentIdentity } from './identity.js'
import { HistoryStore } from './store.js'
import { logger } from '../../utils/logger.js'

/**
 * ScanId reuse — closes the last gap in retry idempotency.
 *
 * Background: scanId idempotency already makes the CLI send its scanId to the API (as the request
 * body field AND the `Idempotency-Key` header — pro-scanner.ts, scan.ts) so the server can
 * dedupe a dropped-response retry WITHIN one process. But before this fix, that scanId was
 * `randomUUID()`'d fresh every time `scanCommand()`'s action ran (scan.ts, pre-fix) — so a
 * WHOLE-PROCESS retry (an agent re-running `shipguard scan --pro` after the process died or
 * the response never arrived) minted a brand-new scanId, and the server's (userId, scanId)
 * dedup could never fire. That is the double-charge gap this file closes.
 *
 * Design: reuse the local SQLite history store (history/store.ts) rather than a second
 * persistence layer. A NEW sibling table, `scan_id_reservations` (schema.ts migration 2),
 * keyed by (repo_id, reuse_key) — NOT the same as `scans.scope_fingerprint`, which needs
 * `proApplied` (an outcome only known AFTER the pro-fetch attempt, and only written once the
 * whole scan has completed — see history/index.ts). The reuse key here is computed from what
 * is REQUESTED, before anything runs, so it is available in time to matter: before the
 * pro-fetch call that actually needs the reused scanId to make the server-side dedup work.
 *
 * Reuse-key composition (all REQUEST metadata, never source bytes): requested scope
 * (changed-files mode + normalized `--category` filter + policy `ignore.paths`), whether
 * `--pro` was requested, the DETECTED FRAMEWORK SET (which selects the paid bundle — a change
 * here MUST mint a fresh scanId, or a retry would re-deliver the already-paid stale bundle and
 * a newly-added framework's rules would never run), and a local-only working-tree content
 * identity. Frameworks are detected in scan.ts BEFORE this runs and passed in — they cannot be
 * inferred from the content identity alone (a second edit to an already-dirty tracked file
 * leaves the porcelain listing byte-identical; see ScanIdReuseKeyInput.frameworks).
 */

export interface ScanIdReuseKeyInput {
  /** true = changed-files-only mode, false = full-project scan (mirrors fingerprint.ts). */
  changedOnly: boolean
  /** Normalized category filter for pro rules. Empty = no filter. */
  categories: string[]
  /** Effective ignore-paths list (policy `ignore.paths`, normalized). */
  ignorePaths: string[]
  /** Whether `--pro` was REQUESTED this run (not whether it ends up applying — that is an
   * outcome unknown at reuse-key-computation time, unlike fingerprint.ts's `proApplied`). */
  proRequested: boolean
  /**
   * Detected framework names for this scan (e.g. `['nextjs','prisma']`) — request metadata,
   * NOT source bytes (no privacy impact). These select WHICH Pro rule bundle the server builds
   * and charges for, so a change in the detected set MUST mint a fresh scanId: otherwise a
   * retry would reuse the prior scanId and the server would re-deliver the already-paid STALE
   * bundle built for the old framework set, and the newly-added framework's Pro rules would
   * never run — a false-green on the paid gate. This cannot be inferred from `contentIdentity`
   * alone: a second edit to an already-modified tracked file (e.g. package.json edited twice
   * with no intervening commit) leaves the porcelain record byte-identical, so the framework
   * set is the only signal that catches it.
   */
  frameworks: string[]
  /** Local-only working-tree content identity (identity.ts `resolveContentIdentity`). */
  contentIdentity: string
}

/**
 * Compute the pre-scan scanId reuse key. Deliberately a SEPARATE function from
 * `computeScopeFingerprint` (fingerprint.ts) even though the inputs overlap — that one is an
 * outcome-based fingerprint written once per completed scan for regression comparison; this
 * one is a request-based fingerprint computed before the scan runs, for a different purpose
 * (retry idempotency, not regression tracking). Collapsing them would force a chicken-and-egg
 * dependency on `proApplied` before it can possibly be known.
 */
export function computeScanIdReuseKey(input: ScanIdReuseKeyInput): string {
  const normalized = {
    mode: input.changedOnly ? 'changed' : 'full',
    categories: [...input.categories].map((c) => c.trim().toLowerCase()).filter(Boolean).sort(),
    ignorePaths: [...input.ignorePaths].map((p) => p.trim()).filter(Boolean).sort(),
    proRequested: input.proRequested,
    // Sorted so listing order never affects the key; a changed framework set → fresh scanId.
    frameworks: [...input.frameworks].map((f) => f.trim().toLowerCase()).filter(Boolean).sort(),
    content: input.contentIdentity,
  }
  const json = JSON.stringify(normalized)
  return createHash('sha256').update(json).digest('hex').slice(0, 16)
}

export interface ResolveScanIdInput {
  cwd: string
  policy: Policy
  cliVersion: string
  changedOnly: boolean
  categories: string[]
  proRequested: boolean
  /** Detected framework names (see ScanIdReuseKeyInput.frameworks — selects the paid bundle). */
  frameworks: string[]
}

export interface ResolveScanIdResult {
  scanId: string
  /** true when this scanId was reused from a prior local reservation, not freshly minted. */
  scanIdReused: boolean
}

/** Env wins over policy wins over default — same precedence pattern as `resolveHistoryPath`. */
export function resolveScanIdReuseWindowMs(policy: Pick<Policy, 'history'>): number {
  const envMinutes = process.env[SCAN_ID_REUSE_WINDOW_ENV_VAR]
  if (envMinutes && envMinutes.trim().length > 0) {
    const parsed = Number(envMinutes)
    if (Number.isFinite(parsed) && parsed > 0) return parsed * 60 * 1000
  }
  const policyMinutes = policy.history?.scan_id_reuse_window_minutes
  if (typeof policyMinutes === 'number' && policyMinutes > 0) {
    return policyMinutes * 60 * 1000
  }
  return DEFAULT_SCAN_ID_REUSE_WINDOW_MINUTES * 60 * 1000
}

/**
 * Resolve THIS scan's scanId — reusing a prior reservation when one exists for the identical
 * (repo, requested-scope, content) key within the reuse window, else minting + persisting a
 * fresh one. Called once, early in `runScan` (commands/scan.ts), AFTER policy load but BEFORE
 * the `--pro` rules fetch — the whole point is for the reused id to be available in time to
 * ride the Idempotency-Key header on that fetch.
 *
 * NEVER throws, NEVER blocks the scan (matches the history store's `stateStatus` degrade contract):
 * any failure — Node <22.5 (no `node:sqlite`), unreadable/corrupt store, lock timeout, no
 * resolvable git HEAD — falls back to exactly today's behavior, `randomUUID()` with
 * `scanIdReused: false`. With the store absent entirely, behavior is strictly identical to
 * before this feature existed.
 */
export async function resolveScanId(input: ResolveScanIdInput): Promise<ResolveScanIdResult> {
  const { cwd, policy, cliVersion, changedOnly, categories, proRequested, frameworks } = input

  try {
    const historyPath = resolveHistoryPath(cwd, policy)
    // Exclude ShipGuard's OWN artifacts from the working-tree content identity — otherwise the
    // history db this very call is about to create would flip the identity on the next retry
    // and defeat reuse (see identity.ts resolveContentIdentity). `.shipguard/` covers the
    // default db path, the fallback repo-id file, and report output; the resolved history path
    // covers a custom `history.path` pointed elsewhere in the tree.
    const historyRelPath = relative(cwd, historyPath).replace(/\\/g, '/')
    const excludePrefixes = ['.shipguard/', historyRelPath]

    // No resolvable git HEAD → no safe content identity → do not attempt reuse at all.
    const contentIdentity = resolveContentIdentity(cwd, excludePrefixes)
    if (!contentIdentity) {
      return { scanId: randomUUID(), scanIdReused: false }
    }

    const identity = resolveRepoIdentity(cwd)
    const reuseKey = computeScanIdReuseKey({
      changedOnly,
      categories,
      ignorePaths: policy.ignore.paths,
      proRequested,
      frameworks,
      contentIdentity,
    })
    const reuseWindowMs = resolveScanIdReuseWindowMs(policy)
    const openResult = await HistoryStore.open(historyPath, cliVersion)

    if (!openResult.ok) {
      logger.warn(`ShipGuard scanId persistence unavailable (${openResult.status}) — minting a fresh scanId: ${openResult.reason}`)
      return { scanId: randomUUID(), scanIdReused: false }
    }

    const store = openResult.store
    try {
      const result = store.reserveScanId(identity.repoId, reuseKey, reuseWindowMs)
      if (!result.ok) {
        logger.warn(`ShipGuard scanId persistence failed — minting a fresh scanId: ${result.reason}`)
        return { scanId: randomUUID(), scanIdReused: false }
      }
      return { scanId: result.scanId, scanIdReused: result.reused }
    } finally {
      store.close()
    }
  } catch (err) {
    logger.warn(
      `ShipGuard scanId persistence failed unexpectedly — minting a fresh scanId: ${err instanceof Error ? err.message : err}`,
    )
    return { scanId: randomUUID(), scanIdReused: false }
  }
}
