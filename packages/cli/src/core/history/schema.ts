/**
 * observability/audit-trail store — versioned schema + forward-only migrations.
 *
 * Each migration is a numbered, idempotent SQL step applied inside the single open
 * transaction store.ts wraps around migrate(). Forward-only: there is no down-migration.
 * If an older CLI opens a file stamped with a NEWER schema_version, store.ts refuses to
 * write (stateStatus: 'unavailable') rather than guess at an unknown shape.
 */

import { keyFindingIdentity } from './finding-key.js'

export const CURRENT_SCHEMA_VERSION = 3

export interface Migration {
  version: number
  sql: string
  /**
   * Optional code step run right after `sql`, inside the same transaction. `salt` is the
   * history database's key salt (see finding-key.ts).
   */
  run?: (db: { prepare(sql: string): { all(): unknown[]; run(...params: unknown[]): unknown } }, salt: Buffer) => void
}

/**
 * Migration 1 — initial schema.
 *
 * scans           — one row per scan; the unit the regression comparison keys off.
 * findings        — one row per active/suppressed finding on a scan, joined to scans.
 * schema_meta     — single-row table recording the schema version this file was created/
 *                    migrated to, and the CLI version that did it (§1.3).
 *
 * Design decisions baked into the DDL:
 * - `scans.scan_id` is the CLI's own UUID (already minted per-scan for idempotency
 *   elsewhere in the codebase) — reused here as the natural primary key.
 * - `state_status` lives on the scan row: it describes whether writing/reading THIS
 *   scan's history succeeded, independent of the scan's own findings/verdict (§1.6).
 * - `finding_key` (ruleId + file + normalized-match-hash, §2.3) is stored now even
 *   though the V1 regression query only needs rule-level pass/fail counts — so
 *   longitudinal same-finding tracking is additive later, never a schema redo (§3).
 * - Indexes support the exact regression lookup (§4 step 2): most recent prior
 *   COMPLETE scan for the same repo + scope fingerprint.
 */
const MIGRATION_1_INIT = `
CREATE TABLE IF NOT EXISTS schema_meta (
  schema_version INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  cli_version_created_with TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY,
  repo_id TEXT NOT NULL,
  repo_id_kind TEXT NOT NULL,
  repo_remote_label TEXT,
  scope_fingerprint TEXT NOT NULL,
  corpus_version TEXT NOT NULL,
  release_id TEXT NOT NULL,
  cli_version TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  recommendation TEXT,
  blocking_count INTEGER NOT NULL DEFAULT 0,
  critical_count INTEGER NOT NULL DEFAULT 0,
  high_count INTEGER NOT NULL DEFAULT 0,
  medium_count INTEGER NOT NULL DEFAULT 0,
  low_count INTEGER NOT NULL DEFAULT 0,
  info_count INTEGER NOT NULL DEFAULT 0,
  state_status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_repo_scope_ts
  ON scans (repo_id, scope_fingerprint, timestamp DESC);

CREATE TABLE IF NOT EXISTS rule_outcomes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL,
  blocking INTEGER NOT NULL,
  active_finding_count INTEGER NOT NULL DEFAULT 0,
  rule_version TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rule_outcomes_scan ON rule_outcomes (scan_id);
CREATE INDEX IF NOT EXISTS idx_rule_outcomes_rule ON rule_outcomes (rule_id);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL,
  finding_key TEXT NOT NULL,
  file_path TEXT,
  severity TEXT,
  blocking INTEGER NOT NULL,
  active INTEGER NOT NULL,
  rule_version TEXT NOT NULL,
  corpus_version TEXT NOT NULL,
  release_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule_key ON findings (rule_id, finding_key);
`

/**
 * Migration 2 — scanId retry-idempotency reservations (scanId reuse).
 *
 * Sibling table, additive, forward-only — does NOT touch the `scans` table's own
 * `scan_id` primary key or any existing column (the schema design's
 * "additive later, never a schema redo" promise from migration 1's own design note).
 *
 * `scan_id_reservations` is keyed by (repo_id, reuse_key) as a COMPOSITE PRIMARY KEY —
 * `reuse_key` is a pre-scan fingerprint (requested scope + whether `--pro` was requested +
 * working-tree content identity; see history/scan-id.ts) computed BEFORE the scan runs, so
 * it can be looked up before the pro-rules fetch call — unlike `scans.scope_fingerprint`,
 * which needs `proApplied` (an OUTCOME only known after the fetch attempt) and is written
 * only once the scan has fully completed.
 *
 * A fresh mint REPLACEs the row for that (repo_id, reuse_key) rather than inserting a new
 * one (`ON CONFLICT ... DO UPDATE` in store.ts), so the table stays bounded to "one live
 * reservation per distinct scope+content combination ever scanned" — the same bound the
 * `scans` table gets from user-controlled retention pruning, but automatic here since a
 * reservation's whole purpose expires with its reuse window.
 */
const MIGRATION_2_SCAN_ID_RESERVATIONS = `
CREATE TABLE IF NOT EXISTS scan_id_reservations (
  repo_id TEXT NOT NULL,
  reuse_key TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (repo_id, reuse_key)
);

CREATE INDEX IF NOT EXISTS idx_scan_id_reservations_created
  ON scan_id_reservations (created_at);
`

/**
 * Migration 3 — `findings.finding_key` becomes a keyed digest.
 *
 * Schema 1-2 stored a plain truncated SHA-256 of the matched text, which anyone holding the file
 * could test guesses against. Every existing key is replaced in place by HMAC(salt, old key), the
 * same function new scans use, so a finding keeps its identity across the upgrade. No table or
 * column changes, hence the no-op SQL; the work is the `run` step (see store.ts, which also
 * clears the old values out of freed pages and the write-ahead log after this commits).
 */
const MIGRATION_3_KEYED_FINDING_KEYS = `SELECT 1;`

export const MIGRATIONS: Migration[] = [
  { version: 1, sql: MIGRATION_1_INIT },
  { version: 2, sql: MIGRATION_2_SCAN_ID_RESERVATIONS },
  {
    version: 3,
    sql: MIGRATION_3_KEYED_FINDING_KEYS,
    run: (db, salt) => {
      const rows = db.prepare('SELECT id, finding_key FROM findings').all() as Array<{ id: number; finding_key: string }>
      const update = db.prepare('UPDATE findings SET finding_key = ? WHERE id = ?')
      for (const row of rows) update.run(keyFindingIdentity(salt, row.finding_key), row.id)
    },
  },
]

/** Sentinel used whenever a real corpus/release/rule version genuinely isn't available (§3). */
export const UNVERSIONED = 'unversioned'
