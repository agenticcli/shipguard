/**
 * History `finding_key` must not be a plain hash of the raw secret.
 *
 * Before: finding_key = sha256(raw evidence) truncated to 16 hex, unsalted. For a low-entropy
 * secret (a weak database password) anyone holding .shipguard/history.db could test guesses
 * offline. After: finding_key = HMAC-SHA256(per-history random salt, identity digest), where the
 * salt lives in a separate mode-600 file next to the database, and existing rows are re-keyed
 * in place by a forward-only migration (schema v3) that leaves no old value behind in the file.
 *
 * Tests written first (fail-before / pass-after).
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createHash, createHmac } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { HistoryStore } from '../../../src/core/history/store.js'
import type { ScanRecordInput } from '../../../src/core/history/store.js'
import { MIGRATIONS, CURRENT_SCHEMA_VERSION } from '../../../src/core/history/schema.js'
import { keyFindingIdentity, loadOrCreateSalt, saltPathFor } from '../../../src/core/history/finding-key.js'

const tempDirs: string[] = []
function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-finding-key-'))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      chmodSync(dir, 0o700)
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
})

// A weak, guessable "secret" is the realistic threat: the digest of it is what an attacker tests.
const WEAK_SECRET = 'hunter2-FAKE_TEST_SECRET'
const identityDigest = (raw: string): string => createHash('sha256').update(raw).digest('hex').slice(0, 16)

function record(findingKey: string): ScanRecordInput {
  return {
    scanId: 'scan-1',
    repoId: 'repo-abc',
    repoIdKind: 'root-commit',
    scopeFingerprint: 'fp-1',
    corpusVersion: 'free:0.8.0',
    releaseId: 'unversioned',
    cliVersion: '0.8.0',
    timestamp: new Date().toISOString(),
    recommendation: 'DO_NOT_SHIP',
    blockingCount: 1,
    criticalCount: 1,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
    ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 1, ruleVersion: '0.8.0' }],
    findings: [
      {
        ruleId: 'hardcoded_secret',
        findingKey,
        filePath: 'src/a.ts',
        severity: 'critical',
        blocking: true,
        active: true,
        ruleVersion: '0.8.0',
        corpusVersion: 'free:0.8.0',
        releaseId: 'unversioned',
      },
    ],
  }
}

/** Every byte of the database and its WAL/SHM side files. */
function allBytes(dbPath: string): Buffer {
  const dir = join(dbPath, '..')
  const base = dbPath.split('/').pop() as string
  return Buffer.concat(
    readdirSync(dir)
      .filter((n) => n === base || n === `${base}-wal` || n === `${base}-shm`)
      .map((n) => readFileSync(join(dir, n))),
  )
}

describe('keyFindingIdentity', () => {
  it('is a 16-hex keyed digest: deterministic per salt, different per salt, never the plain digest', () => {
    const saltA = Buffer.alloc(32, 1)
    const saltB = Buffer.alloc(32, 2)
    const d = identityDigest(WEAK_SECRET)
    const a1 = keyFindingIdentity(saltA, d)
    expect(a1).toMatch(/^[0-9a-f]{16}$/)
    expect(keyFindingIdentity(saltA, d)).toBe(a1)
    expect(keyFindingIdentity(saltB, d)).not.toBe(a1)
    expect(a1).not.toBe(d)
    expect(a1).toBe(createHmac('sha256', saltA).update(d).digest('hex').slice(0, 16))
  })
})

describe('loadOrCreateSalt', () => {
  it('creates a random 32-byte salt file next to the database, readable by the owner only', () => {
    const dir = mkTemp()
    const dbPath = join(dir, '.shipguard', 'history.db')
    mkdirSync(join(dir, '.shipguard'), { recursive: true })
    const r = loadOrCreateSalt(dbPath)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.salt).toHaveLength(32)
    const p = saltPathFor(dbPath)
    expect(p).not.toBe(dbPath)
    expect(existsSync(p)).toBe(true)
    if (process.platform !== 'win32') expect(statSync(p).mode & 0o077).toBe(0)
    expect(readFileSync(p, 'utf-8').trim()).toMatch(/^[0-9a-f]{64}$/)
  })

  it('returns the SAME salt on every later call, and tightens loose permissions', () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    const first = loadOrCreateSalt(dbPath)
    const second = loadOrCreateSalt(dbPath)
    expect(first.ok && second.ok).toBe(true)
    if (!first.ok || !second.ok) return
    expect(second.salt.equals(first.salt)).toBe(true)
    if (process.platform !== 'win32') {
      chmodSync(saltPathFor(dbPath), 0o644)
      expect(loadOrCreateSalt(dbPath).ok).toBe(true)
      expect(statSync(saltPathFor(dbPath)).mode & 0o077).toBe(0)
    }
  })

  it('two different databases get two different salts', () => {
    const dir = mkTemp()
    const a = loadOrCreateSalt(join(dir, 'a.db'))
    const b = loadOrCreateSalt(join(dir, 'b.db'))
    expect(a.ok && b.ok).toBe(true)
    if (a.ok && b.ok) expect(a.salt.equals(b.salt)).toBe(false)
  })

  it('refuses (loudly, with a reason) when the salt file is not a valid salt', () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    writeFileSync(saltPathFor(dbPath), 'not-a-salt', { mode: 0o600 })
    const r = loadOrCreateSalt(dbPath)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toMatch(/salt/i)
  })
})

describe('HistoryStore stores the keyed identity, never the plain digest', () => {
  it('writeScan persists HMAC(salt, digest); the plain digest is not in the file', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, '.shipguard', 'history.db')
    const open = await HistoryStore.open(dbPath, '0.8.0')
    expect(open.ok).toBe(true)
    if (!open.ok) return
    const d = identityDigest(WEAK_SECRET)
    expect(open.store.writeScan(record(d)).ok).toBe(true)
    open.store.close()

    const salt = loadOrCreateSalt(dbPath)
    expect(salt.ok).toBe(true)
    if (!salt.ok) return
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(dbPath)
    const rows = db.prepare('SELECT finding_key FROM findings').all() as Array<{ finding_key: string }>
    db.close()
    expect(rows.map((r) => r.finding_key)).toEqual([keyFindingIdentity(salt.salt, d)])
    expect(allBytes(dbPath).includes(Buffer.from(d))).toBe(false)
  })

  it('the same finding keeps the same key across scans (identity survives), a different one differs', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    const keys: string[] = []
    for (const [scanId, raw] of [['s1', WEAK_SECRET], ['s2', WEAK_SECRET], ['s3', 'another-FAKE_TEST_SECRET']]) {
      const open = await HistoryStore.open(dbPath, '0.8.0')
      if (!open.ok) throw new Error(open.reason)
      expect(open.store.writeScan({ ...record(identityDigest(raw)), scanId }).ok).toBe(true)
      open.store.close()
    }
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(dbPath)
    for (const r of db.prepare('SELECT finding_key FROM findings ORDER BY rowid').all() as Array<{ finding_key: string }>) keys.push(r.finding_key)
    db.close()
    expect(keys[0]).toBe(keys[1])
    expect(keys[2]).not.toBe(keys[0])
  })

  it('history is unavailable (loud reason, scan unaffected) when no salt can be created: never falls back to plain digests', async () => {
    if (process.platform === 'win32') return
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    // A directory squatting on the salt path makes it impossible to create or read the salt.
    mkdirSync(saltPathFor(dbPath))
    const open = await HistoryStore.open(dbPath, '0.8.0')
    expect(open.ok).toBe(false)
    if (!open.ok) {
      expect(open.status).toBe('unavailable')
      expect(open.reason).toMatch(/salt/i)
    }
  })
})

describe('migration to schema v3 re-keys existing rows and leaves no old value in the file', () => {
  /** A history file exactly as the previous CLI wrote it (schema v2, unsalted keys). */
  async function legacyDb(dbPath: string, digests: string[]): Promise<void> {
    mkdirSync(join(dbPath, '..'), { recursive: true })
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
    for (const d of digests) ins.run(d)
    db.close()
  }

  it('current schema is v3 and the migration list ends with a v3 step', () => {
    expect(CURRENT_SCHEMA_VERSION).toBe(3)
    expect(MIGRATIONS.map((m) => m.version)).toEqual([1, 2, 3])
  })

  it('every old key becomes HMAC(salt, old key); the old plain digests are gone from the file', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, '.shipguard', 'history.db')
    const olds = [identityDigest(WEAK_SECRET), identityDigest('second-FAKE_TEST_SECRET')]
    await legacyDb(dbPath, olds)
    expect(allBytes(dbPath).includes(Buffer.from(olds[0]))).toBe(true) // sanity: the weakness is real

    const open = await HistoryStore.open(dbPath, '0.8.0')
    expect(open.ok).toBe(true)
    if (!open.ok) return
    open.store.close()

    const salt = loadOrCreateSalt(dbPath)
    expect(salt.ok).toBe(true)
    if (!salt.ok) return
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(dbPath)
    const keys = (db.prepare('SELECT finding_key FROM findings ORDER BY rowid').all() as Array<{ finding_key: string }>).map((r) => r.finding_key)
    const version = (db.prepare('SELECT MAX(schema_version) AS v FROM schema_meta').get() as { v: number }).v
    db.close()
    expect(version).toBe(3)
    expect(keys).toEqual(olds.map((o) => keyFindingIdentity(salt.salt, o)))
    for (const o of olds) expect(allBytes(dbPath).includes(Buffer.from(o)), `old key ${o} still in file`).toBe(false)
  })

  it('a new scan of the same secret after migration matches the migrated row (identity continuity)', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    const d = identityDigest(WEAK_SECRET)
    await legacyDb(dbPath, [d])
    const open = await HistoryStore.open(dbPath, '0.8.0')
    if (!open.ok) throw new Error(open.reason)
    expect(open.store.writeScan({ ...record(d), scanId: 'new-scan' }).ok).toBe(true)
    open.store.close()
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(dbPath)
    const keys = (db.prepare('SELECT finding_key FROM findings ORDER BY rowid').all() as Array<{ finding_key: string }>).map((r) => r.finding_key)
    db.close()
    expect(keys).toHaveLength(2)
    expect(keys[0]).toBe(keys[1])
  })

  it('opening twice does not re-key twice (idempotent)', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    const d = identityDigest(WEAK_SECRET)
    await legacyDb(dbPath, [d])
    for (let i = 0; i < 2; i++) {
      const open = await HistoryStore.open(dbPath, '0.8.0')
      if (!open.ok) throw new Error(open.reason)
      open.store.close()
    }
    const salt = loadOrCreateSalt(dbPath)
    if (!salt.ok) throw new Error(salt.reason)
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(dbPath)
    const keys = (db.prepare('SELECT finding_key FROM findings').all() as Array<{ finding_key: string }>).map((r) => r.finding_key)
    db.close()
    expect(keys).toEqual([keyFindingIdentity(salt.salt, d)])
  })

  it('if the salt cannot be created the old file is left untouched (no partial migration)', async () => {
    if (process.platform === 'win32') return
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    const d = identityDigest(WEAK_SECRET)
    await legacyDb(dbPath, [d])
    mkdirSync(saltPathFor(dbPath))
    const open = await HistoryStore.open(dbPath, '0.8.0')
    expect(open.ok).toBe(false)
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(dbPath)
    const row = db.prepare('SELECT finding_key AS k FROM findings').get() as { k: string }
    const version = (db.prepare('SELECT MAX(schema_version) AS v FROM schema_meta').get() as { v: number }).v
    db.close()
    expect(row.k).toBe(d)
    expect(version).toBe(2)
  })
})
