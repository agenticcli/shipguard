import { createHash, randomUUID } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { lstatSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path'
import type { Policy } from '@agenticcli/shared'
import { DEFAULT_SCAN_ID_REUSE_WINDOW_MINUTES, SCAN_ID_REUSE_WINDOW_ENV_VAR } from '@agenticcli/shared'
import { resolveHistoryPath } from './path.js'
import { resolveRepoIdentity, resolveContentIdentity, resolveListingIdentity } from './identity.js'
import { openHistoryStore } from './store.js'
import { logger } from '../../utils/logger.js'
import { pathEscapeReason } from '../../utils/paths.js'

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
  /** Whether the full rulebook was REQUESTED this run (an explicit `--pro`, or the signed-in default
   * that asks for it; not whether it ends up applying — that is an outcome unknown at reuse-key-
   * computation time, unlike fingerprint.ts's `proApplied`). */
  rulebookRequested: boolean
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
    rulebookRequested: input.rulebookRequested,
    // Sorted so listing order never affects the key; a changed framework set → fresh scanId.
    frameworks: [...input.frameworks].map((f) => f.trim().toLowerCase()).filter(Boolean).sort(),
    content: input.contentIdentity,
  }
  const json = JSON.stringify(normalized)
  return createHash('sha256').update(json).digest('hex').slice(0, 16)
}

/**
 * The gate scans a fresh temp extraction every run, so the extraction path and its mtimes can never identify the
 * work. The gate hands its child the REAL repo folder and the commit it extracted through a private file it creates
 * next to the extraction (`<tmp>/shipguard-gate-XXXX/gate-handover.json`, mode 0600, in a 0700 folder it owns), never
 * through the environment: a user-set variable must not be able to claim "this is the gate" on a plain scan (that
 * would fake scan-id reuse and write history into any folder). The reservation is then keyed by repo + commit (+ the
 * usual request fields) and lives in the real repo's history store, so a gate rerun on the same commit reuses the
 * scan id and a Pro gate rerun is not counted twice.
 */
export const GATE_HANDOVER_FILE = 'gate-handover.json'
const EXTRACTION_PREFIX = 'shipguard-gate-'
const EXTRACTION_SUBDIR = 'tree'

export interface GateReuse {
  /** Absolute folder of the real repository the gate runs for. */
  dir: string
  /** The commit the gate extracted (hex object id). */
  commit: string
}

const COMMIT_RE = /^[0-9a-f]{40}([0-9a-f]{24})?$/

/** Gate side: write the hand-over next to the extraction (`extraction` = `<root>/tree`). Throws when it cannot be written. */
export function writeGateHandover(extraction: string, reuse: GateReuse): void {
  writeFileSync(join(dirname(extraction), GATE_HANDOVER_FILE), JSON.stringify(reuse), { encoding: 'utf-8', mode: 0o600, flag: 'wx' })
}

function gitOut(dir: string, args: string[]): string | null {
  try {
    return execFileSync('git', ['-C', dir, ...args], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch {
    return null
  }
}

/**
 * Child side: the gate's hand-over, or undefined. Honoured only when ALL hold: the scan runs as a gate/hook child
 * (SHIPGUARD_GATE_KIND names a known host); the folder scanned is `<os tmpdir>/shipguard-gate-*\/tree`, a 0700 folder
 * of this user; the hand-over file next to it is a regular file of this user with mode 0600; its folder is a git
 * top level that holds the commit. Anything else is a plain scan: no reuse, no history outside the scanned folder.
 */
export function gateReuseFor(cwd: string, env: NodeJS.ProcessEnv = process.env, tmp: string = tmpdir()): GateReuse | undefined {
  const kind = env.SHIPGUARD_GATE_KIND
  if (kind !== 'claude' && kind !== 'git' && kind !== 'ci') return undefined
  try {
    const tree = realpathSync(cwd)
    const root = dirname(tree)
    if (basename(tree) !== EXTRACTION_SUBDIR || !basename(root).startsWith(EXTRACTION_PREFIX)) return undefined
    if (dirname(root) !== realpathSync(tmp)) return undefined
    const uid = typeof process.getuid === 'function' ? process.getuid() : null
    const rootStat = lstatSync(root)
    const file = join(root, GATE_HANDOVER_FILE)
    const st = lstatSync(file)
    if (!rootStat.isDirectory() || !st.isFile()) return undefined
    if (uid !== null && (rootStat.uid !== uid || st.uid !== uid)) return undefined
    if (process.platform !== 'win32' && ((rootStat.mode & 0o077) !== 0 || (st.mode & 0o077) !== 0)) return undefined
    const parsed = JSON.parse(readFileSync(file, 'utf-8')) as Partial<GateReuse>
    if (typeof parsed.dir !== 'string' || !isAbsolute(parsed.dir) || typeof parsed.commit !== 'string' || !COMMIT_RE.test(parsed.commit)) return undefined
    const top = gitOut(parsed.dir, ['rev-parse', '--show-toplevel'])
    if (top === null || realpathSync(top) !== realpathSync(parsed.dir)) return undefined
    if (gitOut(parsed.dir, ['cat-file', '-e', `${parsed.commit}^{commit}`]) === null) return undefined
    return { dir: parsed.dir, commit: parsed.commit }
  } catch (err) {
    logger.debug(`scan-id: no gate hand-over here (${err instanceof Error ? err.message : String(err)}); treated as a plain scan`)
    return undefined
  }
}

export interface ResolveScanIdInput {
  cwd: string
  policy: Policy
  cliVersion: string
  changedOnly: boolean
  categories: string[]
  /** The full rulebook was requested this run (see ScanIdReuseKeyInput.rulebookRequested). */
  rulebookRequested: boolean
  /** Detected framework names (see ScanIdReuseKeyInput.frameworks — selects the paid bundle). */
  frameworks: string[]
  /** Set by the gate's child scan (gateReuseFor): key the reservation by repo + commit, store it in the real repo. */
  gate?: GateReuse
}

export interface ResolveScanIdResult {
  scanId: string
  /** true when this scanId was reused from a prior local reservation, not freshly minted. */
  scanIdReused: boolean
}

/** Where the reservations live when the SQLite history store cannot open (Node older than 22.5, corrupt or locked db). */
export const SCAN_ID_FALLBACK_FILE = '.shipguard/scan-id-reuse.json'
const FALLBACK_MAX_ENTRIES = 200
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Same reuse rule as `HistoryStore.reserveScanId`, kept in one small JSON file for Node < 22.5 (no `node:sqlite`): without
 * it a Pro re-scan after a dropped response would mint a new scan id there and be charged twice. Entries are
 * request metadata only (repo key, reuse key hash, scan id, time). A file that is not ours (not a symlink-free path in
 * the project, wrong shape, a scan id that is not a UUID) is ignored, never trusted. Returns null when the file cannot be
 * used, and the caller mints a fresh id like today.
 */
function reserveScanIdFile(root: string, repoId: string, reuseKey: string, reuseWindowMs: number): ResolveScanIdResult | null {
  try {
    if (pathEscapeReason(root, SCAN_ID_FALLBACK_FILE) !== null) return null
    const file = join(root, SCAN_ID_FALLBACK_FILE)
    const now = Date.now()
    let entries: Record<string, { scanId: string; createdAt: number }> = {}
    try {
      const parsed: unknown = JSON.parse(readFileSync(file, 'utf-8'))
      const raw = typeof parsed === 'object' && parsed !== null ? (parsed as { entries?: unknown }).entries : undefined
      if (typeof raw === 'object' && raw !== null) {
        for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
          const e = v as { scanId?: unknown; createdAt?: unknown } | null
          if (e && typeof e.scanId === 'string' && UUID_RE.test(e.scanId) && typeof e.createdAt === 'number' && now - e.createdAt <= reuseWindowMs && e.createdAt <= now) {
            entries[k] = { scanId: e.scanId, createdAt: e.createdAt }
          }
        }
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') logger.debug(`scan-id: fallback file ignored: ${err instanceof Error ? err.message : String(err)}`)
      entries = {}
    }
    const key = createHash('sha256').update(`${repoId}\0${reuseKey}`).digest('hex')
    const hit = entries[key]
    if (hit) return { scanId: hit.scanId, scanIdReused: true }
    const scanId = randomUUID()
    entries[key] = { scanId, createdAt: now }
    const newest = Object.entries(entries).sort((a, b) => b[1].createdAt - a[1].createdAt).slice(0, FALLBACK_MAX_ENTRIES)
    mkdirSync(dirname(file), { recursive: true })
    const tmp = `${file}.${process.pid}.tmp`
    writeFileSync(tmp, JSON.stringify({ version: 1, entries: Object.fromEntries(newest) }) + '\n', 'utf-8')
    renameSync(tmp, file)
    return { scanId, scanIdReused: false }
  } catch (err) {
    logger.debug(`scan-id: fallback file unusable: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
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
  const { cwd, policy, cliVersion, changedOnly, categories, rulebookRequested, frameworks, gate } = input

  try {
    const historyPath = resolveHistoryPath(gate ? gate.dir : cwd, policy)
    // Exclude ShipGuard's OWN artifacts from the working-tree content identity — otherwise the
    // history db this very call is about to create would flip the identity on the next retry
    // and defeat reuse (see identity.ts resolveContentIdentity). `.shipguard/` covers the
    // default db path, the fallback repo-id file, and report output; the resolved history path
    // covers a custom `history.path` pointed elsewhere in the tree.
    const historyRelPath = relative(gate ? gate.dir : cwd, historyPath).replace(/\\/g, '/')
    const excludePrefixes = ['.shipguard/', historyRelPath]

    // Git identity first (HEAD + dirty paths). With no resolvable git HEAD (not a git repo, no commits yet)
    // fall back to a local folder-listing identity (paths, sizes, mtimes; never file contents) so a re-run in
    // a non-git folder still reuses its scan id and a gate re-run is never counted twice. Neither available
    // (folder too big to list) → do not attempt reuse at all.
    const gitIdentity = gate ? undefined : resolveContentIdentity(cwd, excludePrefixes)
    // Gate child: the extracted commit IS the content (a tracked-tree extraction, no working-tree changes to read).
    const contentIdentity = gate ? `gate-commit:${gate.commit}` : (gitIdentity ?? resolveListingIdentity(cwd, excludePrefixes))
    if (!contentIdentity) {
      return { scanId: randomUUID(), scanIdReused: false }
    }

    // Non-git folder: key the reservation by the folder path. resolveRepoIdentity would write `.gitignore` and
    // `.shipguard/repo-id` BEFORE the scan, which would show up as a scanned/changed file of the scan itself.
    const identity = gitIdentity
      ? resolveRepoIdentity(cwd)
      : { repoId: `path:${createHash('sha256').update(resolve(gate ? gate.dir : cwd)).digest('hex').slice(0, 32)}` }
    const reuseKey = computeScanIdReuseKey({
      changedOnly,
      categories,
      ignorePaths: policy.ignore.paths,
      rulebookRequested,
      frameworks,
      contentIdentity,
    })
    const reuseWindowMs = resolveScanIdReuseWindowMs(policy)
    const openResult = await openHistoryStore(gate ? gate.dir : cwd, policy, cliVersion)

    if (!openResult.ok) {
      // No history store (Node < 22.5, corrupt, locked): keep the reuse rule in a small file so a re-scan is not counted twice.
      const viaFile = reserveScanIdFile(gate ? gate.dir : cwd, identity.repoId, reuseKey, reuseWindowMs)
      if (viaFile !== null) {
        logger.debug(`scan-id: history store unavailable (${openResult.status}); reservation kept in ${SCAN_ID_FALLBACK_FILE}`)
        return viaFile
      }
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
