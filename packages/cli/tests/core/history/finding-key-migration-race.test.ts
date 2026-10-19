/**
 * Two processes opening the same old history file at the same time must migrate it ONCE.
 *
 * Regression: schema_version used to be read before the migration transaction began, so a second
 * process that read "v2" while the first was still migrating then ran migration 3 again after the
 * first committed. Migration 3 re-keys every finding_key (HMAC), which is not idempotent, so the
 * rows were keyed twice and finding identities silently stopped matching.
 *
 * This test starts several real node processes on the same v2 file at the same instant and checks
 * every key was keyed exactly once. Tests written first (fail-before / pass-after).
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { build } from 'tsup'
import { MIGRATIONS } from '../../../src/core/history/schema.js'
import { keyFindingIdentity, loadOrCreateSalt } from '../../../src/core/history/finding-key.js'
import { spawnNode } from '../../helpers/spawn-cli.js'

const CLI_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const tempDirs: string[] = []
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

const digest = (n: number): string => createHash('sha256').update(`FAKE_TEST_SECRET_${n}`).digest('hex').slice(0, 16)

/** A history file exactly as the previous CLI wrote it (schema v2, plain keys), with many rows. */
async function legacyDb(dbPath: string, rows: number): Promise<string[]> {
  mkdirSync(dirname(dbPath), { recursive: true })
  const { DatabaseSync } = await import('node:sqlite')
  const db = new DatabaseSync(dbPath)
  db.exec('PRAGMA journal_mode = WAL')
  db.exec('PRAGMA foreign_keys = ON')
  db.exec('CREATE TABLE schema_meta (schema_version INTEGER NOT NULL, created_at TEXT NOT NULL, cli_version_created_with TEXT NOT NULL)')
  for (const m of MIGRATIONS.filter((x) => x.version <= 2)) {
    db.exec(m.sql)
    db.prepare('INSERT INTO schema_meta VALUES (?,?,?)').run(m.version, new Date().toISOString(), '0.7.1')
  }
  db.prepare(
    `INSERT INTO scans (scan_id, repo_id, repo_id_kind, repo_remote_label, scope_fingerprint, corpus_version, release_id, cli_version, timestamp, recommendation, blocking_count, critical_count, high_count, medium_count, low_count, info_count, state_status)
     VALUES ('old-scan','repo-abc','root-commit',NULL,'fp-1','free:0.7.1','unversioned','0.7.1','2026-10-01T00:00:00.000Z','DO_NOT_SHIP',1,1,0,0,0,0,'complete')`,
  ).run()
  const ins = db.prepare(
    `INSERT INTO findings (scan_id, rule_id, finding_key, file_path, severity, blocking, active, rule_version, corpus_version, release_id)
     VALUES ('old-scan','hardcoded_secret',?,'src/a.ts','critical',1,1,'0.7.1','free:0.7.1','unversioned')`,
  )
  const olds: string[] = []
  db.exec('BEGIN')
  for (let i = 0; i < rows; i++) {
    const d = digest(i)
    olds.push(d)
    ins.run(d)
  }
  db.exec('COMMIT')
  db.close()
  return olds
}

describe('schema v3 migration under concurrent opens', () => {
  it('N processes opening the same v2 file at once key every row exactly once', async () => {
    const work = mkdtempSync(join(tmpdir(), 'shipguard-migration-race-'))
    tempDirs.push(work)

    // Bundle the real store into a standalone module the child processes can import. It is built
    // inside node_modules/.cache so its dependencies resolve exactly like the real CLI's.
    const outDir = join(CLI_DIR, 'node_modules', '.cache', 'history-race')
    await build({
      entry: { store: join(CLI_DIR, 'src/core/history/store.ts') },
      outDir,
      format: ['esm'],
      platform: 'node',
      target: 'node20',
      dts: false,
      clean: true,
      silent: true,
      config: false,
      splitting: false,
      sourcemap: false,
    })
    const child = join(outDir, 'open-child.mjs')
    writeFileSync(
      child,
      [
        "import { HistoryStore } from './store.js'",
        'const [dbPath, startAt] = process.argv.slice(2)',
        'while (Date.now() < Number(startAt)) { /* spin until the shared start time */ }',
        "const r = await HistoryStore.open(dbPath, '0.8.0')",
        'if (r.ok) r.store.close()',
        'console.log(JSON.stringify({ ok: r.ok, reason: r.ok ? undefined : r.reason }))',
      ].join('\n'),
    )

    const dbPath = join(work, '.shipguard', 'history.db')
    const olds = await legacyDb(dbPath, 5_000)

    const PROCESSES = 6
    const startAt = Date.now() + 2500
    const results = await Promise.all(
      Array.from({ length: PROCESSES }, () => spawnNode(child, [dbPath, String(startAt)], { cwd: work })),
    )
    for (const r of results) {
      expect(r.code, r.stderr).toBe(0)
      expect(JSON.parse(r.stdout.trim().split('\n').pop() as string).ok, r.stdout).toBe(true)
    }

    const salt = loadOrCreateSalt(dbPath)
    if (!salt.ok) throw new Error(salt.reason)
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(dbPath)
    const keys = (db.prepare('SELECT finding_key FROM findings ORDER BY id').all() as Array<{ finding_key: string }>).map((r) => r.finding_key)
    const versions = (db.prepare('SELECT schema_version FROM schema_meta ORDER BY schema_version').all() as Array<{ schema_version: number }>).map((r) => r.schema_version)
    db.close()

    expect(versions).toEqual([1, 2, 3]) // migration 3 recorded once, not once per process
    const expected = olds.map((o) => keyFindingIdentity(salt.salt, o))
    const wrong = keys.filter((k, i) => k !== expected[i]).length
    expect(wrong, `${wrong} of ${keys.length} rows were keyed more than once`).toBe(0)
  }, 120_000)
})
