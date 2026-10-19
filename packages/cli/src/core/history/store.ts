import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import type { StateStatus } from '@agenticcli/shared'
import { CURRENT_SCHEMA_VERSION, MIGRATIONS } from './schema.js'
import { keyFindingIdentity, loadOrCreateSalt } from './finding-key.js'
import { logger } from '../../utils/logger.js'
import type { RuleOutcome, ScanSnapshot } from './regression.js'

// ---------------------------------------------------------------------------
// node:sqlite lazy loader
//
// Deliberate implementation choice (deviation the design doc left open — it specifies
// the STORE CONTRACT, not a library): built-in `node:sqlite` (DatabaseSync), not
// better-sqlite3. Zero added dependencies (matches this CLI's "minimal deps, no install
// scripts" npm-packaging posture) at the cost of requiring Node >=22.5 for the history
// feature specifically. Below that (or if the module is ever removed/renamed), the
// history layer degrades to `stateStatus: unavailable` — the scan itself is NEVER
// affected, matching §1.6's hard rule (memory is a side-channel, the gate is free).
// ---------------------------------------------------------------------------

type SqliteModule = typeof import('node:sqlite')
type DatabaseSyncInstance = InstanceType<SqliteModule['DatabaseSync']>

let sqliteModulePromise: Promise<SqliteModule | undefined> | undefined
let warningFilterInstalled = false

/**
 * Node still tags `node:sqlite` as experimental as of the version this was built against
 * and emits an ExperimentalWarning the first time it's imported. That is expected and
 * intentional here (not something the user needs to see on every single scan), so it is
 * filtered out specifically — every OTHER process warning still passes through unchanged,
 * either to whatever listener was already registered or Node's own default stderr print.
 */
function installSqliteWarningFilter(): void {
  if (warningFilterInstalled) return
  warningFilterInstalled = true
  const existingListeners = [...process.listeners('warning')] as Array<(w: Error) => void>
  process.removeAllListeners('warning')
  process.on('warning', (warning: Error) => {
    if (warning.name === 'ExperimentalWarning' && /SQLite/i.test(warning.message)) return
    if (existingListeners.length > 0) {
      for (const listener of existingListeners) listener(warning)
    } else {
      console.error(`${warning.name}: ${warning.message}`)
    }
  })
}

// esbuild/tsup bundling quirk (verified against the built dist/cli.js): a STATIC string
// literal `import('node:sqlite')` gets its `node:` prefix silently stripped to a bare
// `import("sqlite")` at bundle time (esbuild's node-target externalization rewrites
// `node:x` → `x` for specifiers it treats as legacy-compatible, which does not exist for
// a Node-22.5+-only built-in like sqlite — the rewritten specifier then fails to resolve
// at runtime and the module always reports "unavailable", never actually loading). Building
// the specifier from a non-literal expression defeats esbuild's static import-string
// analysis, so it leaves the `import()` call untouched and Node resolves it correctly at
// runtime. This is NOT a workaround for a Node behavior — it is a bundler behavior, and the
// regression test (tests/commands/history-e2e.test.ts) asserts against the BUILT binary
// specifically because an in-process unit test would never have caught it.
const NODE_SQLITE_SPECIFIER = ['node', 'sqlite'].join(':')

/**
 * Why history is off when `node:sqlite` cannot be imported. Names the running Node, the minimum
 * and the fix so the warning is actionable (and greppable: tests assert on it).
 */
export function sqliteUnavailableReason(nodeVersion: string = process.versions.node): string {
  return (
    `node:sqlite is not available on Node.js ${nodeVersion} (scan history requires Node >=22.5). ` +
    `Upgrade Node to enable history; until then history is not recorded and regression checks are skipped. ` +
    `The scan's own findings/verdict are unaffected.`
  )
}

async function loadSqliteModule(): Promise<SqliteModule | undefined> {
  if (!sqliteModulePromise) {
    installSqliteWarningFilter()
    sqliteModulePromise = import(NODE_SQLITE_SPECIFIER).catch(() => undefined)
  }
  return sqliteModulePromise
}

function isBusyOrLockedError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err)
  return /SQLITE_BUSY|database is locked|SQLITE_LOCKED/i.test(message)
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ScanRecordInput {
  scanId: string
  repoId: string
  repoIdKind: string
  remoteLabel?: string
  scopeFingerprint: string
  corpusVersion: string
  releaseId: string
  cliVersion: string
  timestamp: string
  recommendation?: string
  blockingCount: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  infoCount: number
  ruleOutcomes: RuleOutcome[]
  findings: Array<{
    ruleId: string
    /**
     * Identity digest of the finding (see computeFindingKey in redact.ts). It is only ever an
     * INPUT: the store persists HMAC(salt, digest), never this value.
     */
    findingKey: string
    filePath?: string
    severity?: string
    blocking: boolean
    active: boolean
    ruleVersion: string
    corpusVersion: string
    releaseId: string
  }>
}

export type OpenResult =
  | { ok: true; store: HistoryStore }
  | { ok: false; status: Extract<StateStatus, 'unavailable' | 'corrupt'>; reason: string }

export type WriteResult = { ok: true } | { ok: false; reason: string }
export type PruneResult = { ok: true; deleted: number } | { ok: false; reason: string }
export type ReserveScanIdResult =
  | { ok: true; scanId: string; reused: boolean }
  | { ok: false; reason: string }

// ---------------------------------------------------------------------------
// HistoryStore
// ---------------------------------------------------------------------------

export class HistoryStore {
  private constructor(
    private readonly db: DatabaseSyncInstance,
    public readonly path: string,
    private readonly salt: Buffer,
  ) {}

  /**
   * Open (creating if absent) + forward-only-migrate + integrity-check the history store.
   * NEVER throws — every failure mode returns a typed `{ ok: false, status, reason }` so
   * the caller can set `stateStatus` and keep the scan itself going (§1.6).
   */
  static async open(dbPath: string, cliVersion: string): Promise<OpenResult> {
    const sqlite = await loadSqliteModule()
    if (!sqlite) {
      return {
        ok: false,
        status: 'unavailable',
        reason: sqliteUnavailableReason(),
      }
    }

    const preExisted = existsSync(dbPath)

    try {
      mkdirSync(dirname(dbPath), { recursive: true })
    } catch (err) {
      return {
        ok: false,
        status: 'unavailable',
        reason: `Could not create the history directory: ${err instanceof Error ? err.message : err}`,
      }
    }

    // The key salt must exist before anything is opened or migrated, so a failure here leaves the
    // history file untouched. Without a salt, history stays off: finding identities are never
    // written unkeyed.
    const saltResult = loadOrCreateSalt(dbPath)
    if (!saltResult.ok) {
      return { ok: false, status: 'unavailable', reason: saltResult.reason }
    }
    const salt = saltResult.salt

    let db: DatabaseSyncInstance
    try {
      db = new sqlite.DatabaseSync(dbPath)
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err)
      return {
        ok: false,
        status: isBusyOrLockedError(err) ? 'unavailable' : preExisted ? 'corrupt' : 'unavailable',
        reason: `Could not open history store at ${dbPath}: ${reason}`,
      }
    }

    try {
      // busy_timeout first: switching to WAL needs a lock, and a second process opening the same
      // file at that moment must wait for it instead of failing at once.
      db.exec('PRAGMA busy_timeout = 5000')
      db.exec('PRAGMA journal_mode = WAL')
      db.exec('PRAGMA foreign_keys = ON')
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err)
      try { db.close() } catch { /* ignore close failure on an already-failing path */ }
      return {
        ok: false,
        status: isBusyOrLockedError(err) ? 'unavailable' : 'corrupt',
        reason: `Could not configure history store at ${dbPath}: ${reason}`,
      }
    }

    // Corruption detection (§1.6) — cheap, run once on open.
    try {
      const row = db.prepare('PRAGMA integrity_check').get() as { integrity_check?: string } | undefined
      if (row?.integrity_check && row.integrity_check !== 'ok') {
        db.close()
        return {
          ok: false,
          status: 'corrupt',
          reason: `History store failed integrity check (${row.integrity_check}). File: ${dbPath} — back it up or delete it to start fresh.`,
        }
      }
    } catch (err) {
      try { db.close() } catch { /* ignore */ }
      const reason = err instanceof Error ? err.message : String(err)
      return {
        ok: false,
        status: isBusyOrLockedError(err) ? 'unavailable' : preExisted ? 'corrupt' : 'unavailable',
        reason: `History store integrity check failed: ${reason}`,
      }
    }

    // schema_meta + forward-only migration, each migration in its own transaction (§1.3).
    try {
      db.exec(
        'CREATE TABLE IF NOT EXISTS schema_meta (schema_version INTEGER NOT NULL, created_at TEXT NOT NULL, cli_version_created_with TEXT NOT NULL)',
      )
      const metaRow = db
        .prepare('SELECT schema_version FROM schema_meta ORDER BY schema_version DESC LIMIT 1')
        .get() as { schema_version?: number } | undefined
      const existingVersion = metaRow?.schema_version ?? 0

      if (existingVersion > CURRENT_SCHEMA_VERSION) {
        db.close()
        return {
          ok: false,
          status: 'unavailable',
          reason:
            `History file was created by a newer ShipGuard (schema v${existingVersion}) — ` +
            `this CLI only knows schema v${CURRENT_SCHEMA_VERSION}. Upgrade ShipGuard to keep ` +
            `recording history. File: ${dbPath}`,
        }
      }

      const insertMeta = db.prepare(
        'INSERT INTO schema_meta (schema_version, created_at, cli_version_created_with) VALUES (?, ?, ?)',
      )

      // Rows re-keyed by a migration must not leave the old values behind in freed pages.
      const mayNeedScrub = existingVersion > 0 && existingVersion < 3
      if (mayNeedScrub) db.exec('PRAGMA secure_delete = ON')
      let rekeyedHere = false

      for (const migration of MIGRATIONS) {
        if (migration.version <= existingVersion) continue
        try {
          db.exec('BEGIN IMMEDIATE')
          // Re-read the version now that this process holds the write lock: another process may
          // have applied this migration since the read above. Migration 3 re-keys rows and must
          // never run twice.
          const lockedRow = db
            .prepare('SELECT MAX(schema_version) AS v FROM schema_meta')
            .get() as { v?: number | null } | undefined
          if (migration.version <= (lockedRow?.v ?? 0)) {
            db.exec('COMMIT')
            continue
          }
          db.exec(migration.sql)
          migration.run?.(db, salt)
          if (migration.version === 3 && mayNeedScrub) rekeyedHere = true
          insertMeta.run(migration.version, new Date().toISOString(), cliVersion)
          db.exec('COMMIT')
        } catch (err) {
          try { db.exec('ROLLBACK') } catch { /* ignore */ }
          db.close()
          const reason = err instanceof Error ? err.message : String(err)
          return {
            ok: false,
            status: 'corrupt',
            reason:
              `Migration to schema v${migration.version} failed partway (the original file is ` +
              `left untouched, never partially applied): ${reason}. File: ${dbPath} — back it up ` +
              `or delete it to start fresh.`,
          }
        }
      }
      if (rekeyedHere) {
        // Fold the write-ahead log into the main file, then rebuild the file so no page still
        // holds a pre-migration (unkeyed) finding key.
        try {
          db.exec('PRAGMA wal_checkpoint(TRUNCATE)')
          db.exec('VACUUM')
          db.exec('PRAGMA wal_checkpoint(TRUNCATE)')
        } catch (err) {
          logger.warn(
            `ShipGuard history: the upgrade re-keyed your finding identities, but cleaning the old values out of ${dbPath} failed ` +
              `(${err instanceof Error ? err.message : err}). Delete the file if you need them gone.`,
          )
        }
      }
    } catch (err) {
      try { db.close() } catch { /* ignore */ }
      const reason = err instanceof Error ? err.message : String(err)
      return { ok: false, status: 'corrupt', reason: `History store migration bookkeeping failed: ${reason}` }
    }

    return { ok: true, store: new HistoryStore(db, dbPath, salt) }
  }

  /**
   * One transaction per scan record (§1.4): begin → insert scan row + rule-outcome rows +
   * finding rows → commit. Never throws — a write failure rolls back and returns
   * `{ ok: false }` so the caller sets `stateStatus: 'unavailable'` and keeps going.
   */
  writeScan(input: ScanRecordInput): WriteResult {
    try {
      this.db.exec('BEGIN IMMEDIATE')

      // INSERT OR REPLACE (not plain INSERT) so re-recording the SAME scan_id is idempotent
      // rather than a hard PK-conflict failure. This is the retry case scanId reuse introduces: a
      // retried scan reuses its prior scanId (history/scan-id.ts), so its history write lands
      // on the same primary key. REPLACE deletes the prior row — cascading (FK ON DELETE
      // CASCADE, set at open) to its rule_outcomes/findings — then inserts the fresh row, and
      // the child inserts below repopulate them; net result is one clean, current row per
      // logical scan, never duplicated children. Before scanId reuse every scanId was unique, so this
      // behaves identically to a plain INSERT for all pre-existing callers.
      this.db
        .prepare(
          `INSERT OR REPLACE INTO scans (
            scan_id, repo_id, repo_id_kind, repo_remote_label, scope_fingerprint,
            corpus_version, release_id, cli_version, timestamp, recommendation,
            blocking_count, critical_count, high_count, medium_count, low_count, info_count,
            state_status
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        )
        .run(
          input.scanId,
          input.repoId,
          input.repoIdKind,
          input.remoteLabel ?? null,
          input.scopeFingerprint,
          input.corpusVersion,
          input.releaseId,
          input.cliVersion,
          input.timestamp,
          input.recommendation ?? null,
          input.blockingCount,
          input.criticalCount,
          input.highCount,
          input.mediumCount,
          input.lowCount,
          input.infoCount,
          'complete',
        )

      const insertRuleOutcome = this.db.prepare(
        'INSERT INTO rule_outcomes (scan_id, rule_id, blocking, active_finding_count, rule_version) VALUES (?,?,?,?,?)',
      )
      for (const ro of input.ruleOutcomes) {
        insertRuleOutcome.run(input.scanId, ro.ruleId, ro.blocking ? 1 : 0, ro.activeFindingCount, ro.ruleVersion)
      }

      const insertFinding = this.db.prepare(
        `INSERT INTO findings (
          scan_id, rule_id, finding_key, file_path, severity, blocking, active,
          rule_version, corpus_version, release_id
        ) VALUES (?,?,?,?,?,?,?,?,?,?)`,
      )
      for (const f of input.findings) {
        insertFinding.run(
          input.scanId,
          f.ruleId,
          keyFindingIdentity(this.salt, f.findingKey),
          f.filePath ?? null,
          f.severity ?? null,
          f.blocking ? 1 : 0,
          f.active ? 1 : 0,
          f.ruleVersion,
          f.corpusVersion,
          f.releaseId,
        )
      }

      this.db.exec('COMMIT')
      return { ok: true }
    } catch (err) {
      try { this.db.exec('ROLLBACK') } catch { /* ignore — nothing to roll back if BEGIN itself failed */ }
      return { ok: false, reason: err instanceof Error ? err.message : String(err) }
    }
  }

  /**
   * Most recent PRIOR scan for the same repo + scope fingerprint with `state_status = 'complete'`
   * (§4 step 2). Returns undefined when there is no such scan (first-ever scan for this
   * repo+scope — regressionCheckSkipped: 'no-baseline', not an error).
   */
  getBaseline(repoId: string, scopeFingerprint: string): ScanSnapshot | undefined {
    const scanRow = this.db
      .prepare(
        `SELECT scan_id, timestamp, corpus_version FROM scans
         WHERE repo_id = ? AND scope_fingerprint = ? AND state_status = 'complete'
         ORDER BY timestamp DESC LIMIT 1`,
      )
      .get(repoId, scopeFingerprint) as { scan_id: string; timestamp: string; corpus_version: string } | undefined

    if (!scanRow) return undefined

    const ruleRows = this.db
      .prepare('SELECT rule_id, blocking, active_finding_count, rule_version FROM rule_outcomes WHERE scan_id = ?')
      .all(scanRow.scan_id) as Array<{
      rule_id: string
      blocking: number
      active_finding_count: number
      rule_version: string
    }>

    return {
      scanId: scanRow.scan_id,
      timestamp: scanRow.timestamp,
      scopeFingerprint,
      corpusVersion: scanRow.corpus_version,
      stateStatus: 'complete',
      ruleOutcomes: ruleRows.map((r) => ({
        ruleId: r.rule_id,
        blocking: r.blocking === 1,
        activeFindingCount: r.active_finding_count,
        ruleVersion: r.rule_version,
      })),
    }
  }

  /**
   * ScanId reuse — look up or mint the scanId for a PRE-scan reuse key
   * (repo_id + reuse_key, see history/scan-id.ts). Never throws — every failure (lock
   * timeout, disk full, etc.) returns `{ ok: false, reason }` so the caller falls back to a
   * fresh in-memory `randomUUID()` exactly like today (graceful degrade, §1.6's pattern).
   *
   * A row within `reuseWindowMs` of its `created_at` is reused verbatim (`reused: true`);
   * otherwise (no row, or the row aged out) a fresh UUID is minted and UPSERTed — replacing
   * any stale row for the same (repo_id, reuse_key) rather than accumulating one, so a
   * legitimately new scan of unchanged-looking content never keeps resurrecting an
   * arbitrarily old scanId once the window has passed.
   */
  reserveScanId(repoId: string, reuseKey: string, reuseWindowMs: number): ReserveScanIdResult {
    try {
      const row = this.db
        .prepare('SELECT scan_id, created_at FROM scan_id_reservations WHERE repo_id = ? AND reuse_key = ?')
        .get(repoId, reuseKey) as { scan_id: string; created_at: string } | undefined

      if (row) {
        const ageMs = Date.now() - new Date(row.created_at).getTime()
        if (ageMs >= 0 && ageMs <= reuseWindowMs) {
          return { ok: true, scanId: row.scan_id, reused: true }
        }
      }

      const scanId = randomUUID()
      this.db
        .prepare(
          `INSERT INTO scan_id_reservations (repo_id, reuse_key, scan_id, created_at) VALUES (?, ?, ?, ?)
           ON CONFLICT(repo_id, reuse_key) DO UPDATE SET scan_id = excluded.scan_id, created_at = excluded.created_at`,
        )
        .run(repoId, reuseKey, scanId, new Date().toISOString())

      return { ok: true, scanId, reused: false }
    } catch (err) {
      return { ok: false, reason: err instanceof Error ? err.message : String(err) }
    }
  }

  /** Read-only recent-scans listing for `shipguard history` — most recent first. */
  listRecentScans(repoId: string, limit: number): Array<{
    scanId: string
    timestamp: string
    scopeFingerprint: string
    corpusVersion: string
    recommendation: string | null
    blockingCount: number
    stateStatus: string
  }> {
    const rows = this.db
      .prepare(
        `SELECT scan_id, timestamp, scope_fingerprint, corpus_version, recommendation, blocking_count, state_status
         FROM scans WHERE repo_id = ? ORDER BY timestamp DESC LIMIT ?`,
      )
      .all(repoId, limit) as Array<{
      scan_id: string
      timestamp: string
      scope_fingerprint: string
      corpus_version: string
      recommendation: string | null
      blocking_count: number
      state_status: string
    }>
    return rows.map((r) => ({
      scanId: r.scan_id,
      timestamp: r.timestamp,
      scopeFingerprint: r.scope_fingerprint,
      corpusVersion: r.corpus_version,
      recommendation: r.recommendation,
      blockingCount: r.blocking_count,
      stateStatus: r.state_status,
    }))
  }

  /**
   * User-controlled pruning only (§1.7) — default is keep-everything (retentionDays unset).
   * Never removes the most recent scan per (repo, scope fingerprint), even if it's past the
   * window, so a regression baseline can never be pruned out from under a future comparison.
   * Scoped to ONE repoId so an opt-in shared history file never lets one project's retention
   * policy delete another project's rows.
   */
  prune(repoId: string, retentionDays: number): PruneResult {
    try {
      this.db.exec('BEGIN IMMEDIATE')
      const info = this.db
        .prepare(
          `DELETE FROM scans
           WHERE repo_id = ?
             AND (julianday('now') - julianday(timestamp)) > ?
             AND scan_id NOT IN (
               SELECT s2.scan_id FROM (
                 SELECT scope_fingerprint, MAX(timestamp) AS max_ts FROM scans WHERE repo_id = ? GROUP BY scope_fingerprint
               ) latest
               JOIN scans s2 ON s2.repo_id = ? AND s2.scope_fingerprint = latest.scope_fingerprint AND s2.timestamp = latest.max_ts
             )`,
        )
        .run(repoId, retentionDays, repoId, repoId) as { changes?: number }
      this.db.exec('COMMIT')
      return { ok: true, deleted: info.changes ?? 0 }
    } catch (err) {
      try { this.db.exec('ROLLBACK') } catch { /* ignore */ }
      return { ok: false, reason: err instanceof Error ? err.message : String(err) }
    }
  }

  close(): void {
    try {
      this.db.close()
    } catch {
      // Nothing meaningful to do — the process is exiting anyway; never throw from close().
    }
  }
}
