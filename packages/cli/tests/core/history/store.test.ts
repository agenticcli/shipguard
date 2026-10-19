import { describe, it, expect, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { HistoryStore } from '../../../src/core/history/store.js'
import type { ScanRecordInput } from '../../../src/core/history/store.js'

const tempDirs: string[] = []
function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-history-store-'))
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
})

function baseRecord(overrides: Partial<ScanRecordInput> = {}): ScanRecordInput {
  return {
    scanId: 'scan-1',
    repoId: 'repo-abc',
    repoIdKind: 'root-commit',
    remoteLabel: undefined,
    scopeFingerprint: 'fp-1',
    corpusVersion: 'free:0.4.1',
    releaseId: 'unversioned',
    cliVersion: '0.4.1',
    timestamp: new Date().toISOString(),
    recommendation: 'SAFE_TO_SHIP',
    blockingCount: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
    ruleOutcomes: [{ ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 0, ruleVersion: '0.4.1' }],
    findings: [],
    ...overrides,
  }
}

describe('HistoryStore.open — lifecycle', () => {
  it('creates a fresh store, integrity-checks clean, no prior file (fresh-file is normal, not "unavailable")', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, '.shipguard', 'history.db')
    const result = await HistoryStore.open(dbPath, '0.4.1')
    expect(result.ok).toBe(true)
    if (result.ok) result.store.close()
  })

  it('write then getBaseline round-trips the exact scan + rule outcomes', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    const opened = await HistoryStore.open(dbPath, '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    const store = opened.store

    const write = store.writeScan(baseRecord())
    expect(write.ok).toBe(true)

    const baseline = store.getBaseline('repo-abc', 'fp-1')
    expect(baseline).toBeDefined()
    expect(baseline?.scanId).toBe('scan-1')
    expect(baseline?.ruleOutcomes).toEqual([
      { ruleId: 'hardcoded_secret', blocking: true, activeFindingCount: 0, ruleVersion: '0.4.1' },
    ])
    store.close()
  })

  it('getBaseline returns undefined for a repo/scope with no prior scans', async () => {
    const dir = mkTemp()
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    expect(opened.store.getBaseline('nonexistent-repo', 'fp-x')).toBeUndefined()
    opened.store.close()
  })

  it('getBaseline only returns the most recent PRIOR scan for the SAME repo+scope', async () => {
    const dir = mkTemp()
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    const store = opened.store

    store.writeScan(baseRecord({ scanId: 'scan-1', timestamp: '2026-07-01T00:00:00.000Z' }))
    store.writeScan(baseRecord({ scanId: 'scan-2', timestamp: '2026-07-02T00:00:00.000Z' }))
    store.writeScan(baseRecord({ scanId: 'scan-3', timestamp: '2026-07-03T00:00:00.000Z' }))

    const baseline = store.getBaseline('repo-abc', 'fp-1')
    expect(baseline?.scanId).toBe('scan-3')
    store.close()
  })

  it('a DIFFERENT scope fingerprint is never returned as a baseline for another scope', async () => {
    const dir = mkTemp()
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    const store = opened.store

    store.writeScan(baseRecord({ scanId: 'scan-1', scopeFingerprint: 'fp-full' }))
    const baseline = store.getBaseline('repo-abc', 'fp-changed-only')
    expect(baseline).toBeUndefined()
    store.close()
  })

  it('a re-open of the same file preserves prior data (schema_meta / migration is idempotent)', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    const first = await HistoryStore.open(dbPath, '0.4.1')
    expect(first.ok).toBe(true)
    if (!first.ok) return
    first.store.writeScan(baseRecord())
    first.store.close()

    const second = await HistoryStore.open(dbPath, '0.4.2')
    expect(second.ok).toBe(true)
    if (!second.ok) return
    expect(second.store.getBaseline('repo-abc', 'fp-1')?.scanId).toBe('scan-1')
    second.store.close()
  })
})

describe('HistoryStore.open — corruption + unavailability (§1.6)', () => {
  it('a file that is not a valid SQLite database at all → status corrupt, never throws', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    // Pre-existing garbage — not a SQLite file at all (bad header).
    writeFileSync(dbPath, 'this is definitely not a sqlite database file\0\0\0garbage', 'utf-8')

    const result = await HistoryStore.open(dbPath, '0.4.1')
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.status).toBe('corrupt')
    expect(result.reason.length).toBeGreaterThan(0)
  })

  it('an unwritable parent directory (a FILE where the directory should be) → status unavailable, never throws', async () => {
    const dir = mkTemp()
    const blockerPath = join(dir, 'blocker')
    writeFileSync(blockerPath, 'i am a file, not a directory', 'utf-8')
    // Ask the store to live INSIDE the file path — mkdir must fail.
    const dbPath = join(blockerPath, 'nested', 'history.db')

    const result = await HistoryStore.open(dbPath, '0.4.1')
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.status).toBe('unavailable')
  })

  it('a newer schema_version than this CLI knows → status unavailable, refuses to write (forward-only, §1.3)', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    const opened = await HistoryStore.open(dbPath, '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    opened.store.close()

    // Simulate "a future CLI already migrated this file" by hand-bumping schema_meta.
    const sqlite = await import('node:sqlite')
    const db = new sqlite.DatabaseSync(dbPath)
    db.exec(
      "INSERT INTO schema_meta (schema_version, created_at, cli_version_created_with) VALUES (999, '2099-01-01T00:00:00.000Z', '9.9.9')",
    )
    db.close()

    const reopened = await HistoryStore.open(dbPath, '0.4.1')
    expect(reopened.ok).toBe(false)
    if (reopened.ok) return
    expect(reopened.status).toBe('unavailable')
    expect(reopened.reason).toMatch(/newer ShipGuard/i)
  })
})

describe('HistoryStore — concurrent writers on one file (§1.5, WAL mode)', () => {
  it('two separate store handles on the SAME file both write successfully; no corruption; both rows land', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')

    const openedA = await HistoryStore.open(dbPath, '0.4.1')
    const openedB = await HistoryStore.open(dbPath, '0.4.1')
    expect(openedA.ok).toBe(true)
    expect(openedB.ok).toBe(true)
    if (!openedA.ok || !openedB.ok) return

    // Interleave writes from two independent connections to the same file — the scenario
    // two parallel worktree scans sharing an opt-in history.path would hit.
    // Explicit, strictly increasing timestamps: getBaseline orders by `timestamp` only, and four
    // writes in the same millisecond (a fast CI runner, 2026-10-18) tie, so "most recent" would be
    // whichever row SQLite returns first. The ordering under test must not depend on the wall clock.
    const t = (i: number) => new Date(Date.UTC(2026, 9, 18, 16, 0, 0, i)).toISOString()
    const writeA1 = openedA.store.writeScan(baseRecord({ scanId: 'scan-a1', scopeFingerprint: 'fp-a', timestamp: t(1) }))
    const writeB1 = openedB.store.writeScan(baseRecord({ scanId: 'scan-b1', scopeFingerprint: 'fp-b', timestamp: t(2) }))
    const writeA2 = openedA.store.writeScan(baseRecord({ scanId: 'scan-a2', scopeFingerprint: 'fp-a', timestamp: t(3) }))
    const writeB2 = openedB.store.writeScan(baseRecord({ scanId: 'scan-b2', scopeFingerprint: 'fp-b', timestamp: t(4) }))

    expect(writeA1.ok).toBe(true)
    expect(writeB1.ok).toBe(true)
    expect(writeA2.ok).toBe(true)
    expect(writeB2.ok).toBe(true)

    // Both connections can see everything — no lost writes, no corruption.
    expect(openedA.store.getBaseline('repo-abc', 'fp-a')?.scanId).toBe('scan-a2')
    expect(openedB.store.getBaseline('repo-abc', 'fp-b')?.scanId).toBe('scan-b2')

    openedA.store.close()
    openedB.store.close()

    // A fresh open + integrity_check afterward proves the file wasn't corrupted by the
    // interleaved writers.
    const verify = await HistoryStore.open(dbPath, '0.4.1')
    expect(verify.ok).toBe(true)
    if (verify.ok) verify.store.close()
  })
})

describe('HistoryStore.reserveScanId — scanId reuse reservation table', () => {
  it('first call for a (repoId, reuseKey) mints a fresh scanId, reused:false', async () => {
    const dir = mkTemp()
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return

    const result = opened.store.reserveScanId('repo-abc', 'key-1', 60_000)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.reused).toBe(false)
    expect(result.scanId).toMatch(/^[0-9a-f-]{36}$/)
    opened.store.close()
  })

  it('a second call within the window for the SAME (repoId, reuseKey) reuses the SAME scanId', async () => {
    const dir = mkTemp()
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return

    const first = opened.store.reserveScanId('repo-abc', 'key-1', 60_000)
    const second = opened.store.reserveScanId('repo-abc', 'key-1', 60_000)
    expect(first.ok && second.ok).toBe(true)
    if (!first.ok || !second.ok) return
    expect(second.reused).toBe(true)
    expect(second.scanId).toBe(first.scanId)
    opened.store.close()
  })

  it('a DIFFERENT reuseKey (even same repoId) mints its OWN scanId — no cross-scope collision', async () => {
    const dir = mkTemp()
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return

    const a = opened.store.reserveScanId('repo-abc', 'key-a', 60_000)
    const b = opened.store.reserveScanId('repo-abc', 'key-b', 60_000)
    expect(a.ok && b.ok).toBe(true)
    if (!a.ok || !b.ok) return
    expect(a.scanId).not.toBe(b.scanId)
    opened.store.close()
  })

  it('a DIFFERENT repoId (even same reuseKey) mints its OWN scanId — never leaks across repos', async () => {
    const dir = mkTemp()
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return

    const a = opened.store.reserveScanId('repo-a', 'key-1', 60_000)
    const b = opened.store.reserveScanId('repo-b', 'key-1', 60_000)
    expect(a.ok && b.ok).toBe(true)
    if (!a.ok || !b.ok) return
    expect(a.scanId).not.toBe(b.scanId)
    opened.store.close()
  })

  it('a reservation past the reuse window is REPLACED (not reused) on the next call', async () => {
    const dir = mkTemp()
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return

    // Deterministic clock: the store compares Date.now() with the row's created_at, so two calls
    // in the SAME millisecond are inside a 0 ms window (ageMs === 0) and would be reused. The
    // wall clock cannot be relied on to tick between two synchronous calls on a fast runner (it
    // did not on CI, 2026-10-18), so freeze it and advance it past the window explicitly.
    vi.useFakeTimers({ now: new Date('2026-10-18T16:00:00.000Z'), toFake: ['Date'] })
    let first: ReturnType<typeof opened.store.reserveScanId>
    let second: ReturnType<typeof opened.store.reserveScanId>
    try {
      first = opened.store.reserveScanId('repo-abc', 'key-1', 0)
      vi.advanceTimersByTime(1) // 1 ms later: ageMs = 1 > reuseWindowMs = 0 -> must be replaced
      second = opened.store.reserveScanId('repo-abc', 'key-1', 0)
    } finally {
      vi.useRealTimers()
    }
    expect(first.ok && second.ok).toBe(true)
    if (!first.ok || !second.ok) return
    expect(second.reused).toBe(false)

    // Replacement, not accumulation — only one row should exist for this (repo, key) pair.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const db = (opened.store as any).db
    const rows = db.prepare('SELECT COUNT(*) AS n FROM scan_id_reservations WHERE repo_id = ? AND reuse_key = ?').get('repo-abc', 'key-1')
    expect(rows.n).toBe(1)
    opened.store.close()
  })

  it('reserveScanId never throws even against a closed/invalid db handle — returns { ok: false }', async () => {
    const dir = mkTemp()
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    opened.store.close() // close the underlying sqlite handle first

    let threw = false
    let result: ReturnType<typeof opened.store.reserveScanId> | undefined
    try {
      result = opened.store.reserveScanId('repo-abc', 'key-1', 60_000)
    } catch {
      threw = true
    }
    expect(threw).toBe(false)
    expect(result?.ok).toBe(false)
  })
})

describe('HistoryStore.prune — retention (§1.7)', () => {
  it('deletes rows past the retention window but keeps the most-recent-per-scope even if it is old (never breaks a future baseline lookup)', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    const opened = await HistoryStore.open(dbPath, '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    const store = opened.store

    const veryOld = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString()
    const old = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString()
    store.writeScan(baseRecord({ scanId: 'scan-old-1', timestamp: veryOld }))
    store.writeScan(baseRecord({ scanId: 'scan-old-2', timestamp: old })) // most recent — must survive pruning

    const prune = store.prune('repo-abc', 30)
    expect(prune.ok).toBe(true)

    const baseline = store.getBaseline('repo-abc', 'fp-1')
    expect(baseline?.scanId).toBe('scan-old-2')
    store.close()
  })

  it('is scoped to ONE repoId — never deletes another repo\'s rows sharing the same file', async () => {
    const dir = mkTemp()
    const dbPath = join(dir, 'history.db')
    const opened = await HistoryStore.open(dbPath, '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    const store = opened.store

    const veryOld = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString()
    store.writeScan(baseRecord({ scanId: 'repo-a-old', repoId: 'repo-a', timestamp: veryOld }))
    store.writeScan(baseRecord({ scanId: 'repo-b-old', repoId: 'repo-b', timestamp: veryOld }))
    // Give repo-a a MORE RECENT scan so its old one is eligible for deletion.
    store.writeScan(baseRecord({ scanId: 'repo-a-new', repoId: 'repo-a' }))

    store.prune('repo-a', 30)

    // repo-b's old (and only) scan must survive — prune() was scoped to repo-a.
    const repoBRows = store.listRecentScans('repo-b', 10)
    expect(repoBRows.map((r) => r.scanId)).toContain('repo-b-old')
    store.close()
  })
})
