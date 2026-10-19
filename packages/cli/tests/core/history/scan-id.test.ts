/**
 * ScanId reuse — scanId retry idempotency.
 *
 * REPRO (fail-before): `packages/cli/src/commands/scan.ts:207` (pre-fix) minted
 * `randomUUID` fresh on every `scanCommand` invocation, in-memory only. ScanId idempotency already
 * makes the CLI forward that scanId to `fetchProRules` (as the request body field AND the
 * `Idempotency-Key` header) so the server's `(userId, scanId)` reservation can dedupe a
 * dropped-response retry WITHIN one process — but a WHOLE-PROCESS retry (an agent re-running
 * `shipguard scan --pro` after the process died, or the response never arrived at all) got a
 * brand-new scanId every time, so the server-side dedup could never fire: a legitimate retry
 * looked like a brand-new scan and could double-charge Pro credits.
 *
 * RCA: no persistence layer existed for the per-scan scanId across process boundaries.
 *
 * FIX: `resolveScanId` (history/scan-id.ts) computes a PRE-scan reuse key (requested scope +
 * whether `--pro` was requested + a local-only working-tree content identity — see
 * identity.ts's `resolveContentIdentity`) and looks it up in a new sibling SQLite table,
 * `scan_id_reservations` (schema.ts migration 2), reusing the history store rather than a
 * second persistence layer. A hit within the reuse window reuses the prior scanId; a miss (or
 * an expired hit) mints + persists a fresh one. Every failure mode (Node <22.5, corrupt/locked
 * store, no resolvable git HEAD) falls back to today's exact behavior: a fresh in-memory
 * `randomUUID()`, never blocking the scan.
 *
 * This file covers the function-level contract with a REAL git repo + REAL SQLite store (not
 * mocks). The command-level end-to-end proof (that `fetchProRules` receives the SAME scanId
 * across two full `scanCommand()` invocations) lives in
 * tests/commands/scan-retry-scanid-persistence.test.ts.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { Policy } from '@agenticcli/shared'
import { computeScanIdReuseKey, resolveScanId, resolveScanIdReuseWindowMs } from '../../../src/core/history/scan-id.js'
import { HistoryStore } from '../../../src/core/history/store.js'
import { resolveRepoIdentity } from '../../../src/core/history/identity.js'

const tempDirs: string[] = []
function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-scanid-'))
  tempDirs.push(dir)
  return dir
}
function mkRepo(): string {
  const dir = mkTemp()
  execSync('git init -q', { cwd: dir })
  execSync('git config user.email test@example.com', { cwd: dir })
  execSync('git config user.name test', { cwd: dir })
  writeFileSync(join(dir, 'a.txt'), 'hello', 'utf-8')
  execSync('git add a.txt', { cwd: dir })
  execSync('git commit -q -m "first"', { cwd: dir })
  return dir
}

const savedEnv = process.env.SHIPGUARD_SCAN_ID_REUSE_WINDOW_MINUTES
afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
  if (savedEnv === undefined) delete process.env.SHIPGUARD_SCAN_ID_REUSE_WINDOW_MINUTES
  else process.env.SHIPGUARD_SCAN_ID_REUSE_WINDOW_MINUTES = savedEnv
})

function makePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    version: 1,
    project: { name: 'test', framework: 'auto', risk_profile: 'standard' },
    scan: { changed_files_only: false, generate_report: false },
    block: [],
    warn: [],
    ignore: { paths: [] },
    report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
    ...overrides,
  }
}

describe('computeScanIdReuseKey — pure function contract', () => {
  const base = {
    changedOnly: false,
    categories: ['secrets', 'auth'],
    ignorePaths: ['dist/**'],
    proRequested: true,
    frameworks: ['nextjs', 'prisma'],
    contentIdentity: 'abc123',
  }

  it('is deterministic for identical input', () => {
    expect(computeScanIdReuseKey(base)).toBe(computeScanIdReuseKey({ ...base }))
  })

  it('is order-insensitive for categories/ignorePaths/frameworks (normalized + sorted, matches fingerprint.ts convention)', () => {
    const reordered = { ...base, categories: ['auth', 'secrets'], ignorePaths: ['dist/**'], frameworks: ['prisma', 'nextjs'] }
    expect(computeScanIdReuseKey(base)).toBe(computeScanIdReuseKey(reordered))
  })

  it('differs when changedOnly differs', () => {
    expect(computeScanIdReuseKey(base)).not.toBe(computeScanIdReuseKey({ ...base, changedOnly: true }))
  })

  it('differs when proRequested differs', () => {
    expect(computeScanIdReuseKey(base)).not.toBe(computeScanIdReuseKey({ ...base, proRequested: false }))
  })

  it('differs when contentIdentity differs (different working-tree state)', () => {
    expect(computeScanIdReuseKey(base)).not.toBe(computeScanIdReuseKey({ ...base, contentIdentity: 'xyz789' }))
  })

  it('differs when categories differ', () => {
    expect(computeScanIdReuseKey(base)).not.toBe(computeScanIdReuseKey({ ...base, categories: ['payments'] }))
  })

  it('differs when the detected framework set differs (selects the paid bundle — over-dedup guard)', () => {
    // Same content identity + same scope, but a newly-detected framework → the key MUST change
    // so the retry mints a fresh scanId and the server builds the new bundle .
    expect(computeScanIdReuseKey(base)).not.toBe(
      computeScanIdReuseKey({ ...base, frameworks: ['nextjs', 'prisma', 'supabase'] }),
    )
  })
})

describe('resolveScanIdReuseWindowMs — precedence (env wins over policy wins over default)', () => {
  it('defaults to 30 minutes with no override', () => {
    delete process.env.SHIPGUARD_SCAN_ID_REUSE_WINDOW_MINUTES
    expect(resolveScanIdReuseWindowMs(makePolicy())).toBe(30 * 60 * 1000)
  })

  it('policy override wins over the default', () => {
    delete process.env.SHIPGUARD_SCAN_ID_REUSE_WINDOW_MINUTES
    const policy = makePolicy({ history: { scan_id_reuse_window_minutes: 5 } })
    expect(resolveScanIdReuseWindowMs(policy)).toBe(5 * 60 * 1000)
  })

  it('env var wins over the policy override', () => {
    process.env.SHIPGUARD_SCAN_ID_REUSE_WINDOW_MINUTES = '2'
    const policy = makePolicy({ history: { scan_id_reuse_window_minutes: 5 } })
    expect(resolveScanIdReuseWindowMs(policy)).toBe(2 * 60 * 1000)
  })
})

describe('resolveScanId — end-to-end over a real git repo + real SQLite store', () => {
  it('PASS-AFTER: two successive resolutions with the SAME fingerprint reuse ONE scanId', async () => {
    const dir = mkRepo()
    const policy = makePolicy({ history: { path: join(dir, 'history.db') } })

    const first = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: [],
    })
    const second = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: [],
    })

    expect(first.scanIdReused).toBe(false)
    expect(second.scanIdReused).toBe(true)
    expect(second.scanId).toBe(first.scanId)
  })

  it('two DIFFERENT fingerprints (different requested categories) get DIFFERENT scanIds — no over-dedup', async () => {
    const dir = mkRepo()
    const policy = makePolicy({ history: { path: join(dir, 'history.db') } })

    const secretsOnly = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: ['secrets'], proRequested: true,
      frameworks: [],
    })
    const authOnly = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: ['auth'], proRequested: true,
      frameworks: [],
    })

    expect(authOnly.scanId).not.toBe(secretsOnly.scanId)
    expect(authOnly.scanIdReused).toBe(false)
  })

  it('OVER-DEDUP GUARD: same repo + IDENTICAL content identity but a DIFFERENT detected framework set → DIFFERENT scanId (fresh, never reused)', async () => {
    // The defect: a second edit to an already-dirty tracked file keeps the
    // porcelain record byte-identical, so contentIdentity does NOT change — but the detected
    // frameworks (and thus the paid bundle) DO. If frameworks were absent from the reuse key,
    // this would REUSE the prior scanId → server re-delivers the stale bundle → new framework's
    // Pro rules never run → false-green. With frameworks in the key it mints a fresh scanId.
    const dir = mkRepo()
    const policy = makePolicy({ history: { path: join(dir, 'history.db') } })

    const firstFrameworks = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: ['nextjs'],
    })
    // Same cwd → identical git HEAD + identical porcelain → identical contentIdentity. Only the
    // framework set differs (a newly-detected dep), simulating the re-edit-an-already-dirty-file case.
    const secondFrameworks = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: ['nextjs', 'express'],
    })

    expect(firstFrameworks.scanIdReused).toBe(false)
    expect(secondFrameworks.scanIdReused).toBe(false) // fresh mint on the framework change
    expect(secondFrameworks.scanId).not.toBe(firstFrameworks.scanId)
  })

  it('SAME-FRAMEWORKS retry still dedups: identical scope + content + framework set → ONE scanId reused', async () => {
    const dir = mkRepo()
    const policy = makePolicy({ history: { path: join(dir, 'history.db') } })

    const first = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: ['nextjs', 'prisma'],
    })
    const second = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: ['prisma', 'nextjs'], // reordered — must still hash equal, still reuse
    })

    expect(first.scanIdReused).toBe(false)
    expect(second.scanIdReused).toBe(true)
    expect(second.scanId).toBe(first.scanId)
  })

  it('a NEW commit between two scans (genuinely different content) gets a DIFFERENT scanId — no stale reuse', async () => {
    const dir = mkRepo()
    const policy = makePolicy({ history: { path: join(dir, 'history.db') } })

    const beforeCommit = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: false,
      frameworks: [],
    })

    writeFileSync(join(dir, 'b.txt'), 'world', 'utf-8')
    execSync('git add b.txt', { cwd: dir })
    execSync('git commit -q -m "second"', { cwd: dir })

    const afterCommit = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: false,
      frameworks: [],
    })

    expect(afterCommit.scanId).not.toBe(beforeCommit.scanId)
    expect(afterCommit.scanIdReused).toBe(false)
  })

  it('FAIL-BEFORE regression guard: a non-git directory (no content identity) never reuses — always a fresh scanId, never throws', async () => {
    const dir = mkTemp() // no git init at all
    const policy = makePolicy({ history: { path: join(dir, 'history.db') } })

    const first = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: [],
    })
    const second = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: [],
    })

    expect(first.scanIdReused).toBe(false)
    expect(second.scanIdReused).toBe(false)
    expect(second.scanId).not.toBe(first.scanId)
  })

  it('store-unavailable path (unwritable history directory) falls back to a fresh per-process scanId and never throws', async () => {
    const dir = mkRepo()
    const blocker = join(dir, 'blocker-file')
    writeFileSync(blocker, 'i am a file', 'utf-8')
    // Ask the store to live INSIDE a file path — mkdir must fail, HistoryStore.open returns { ok: false }.
    const policy = makePolicy({ history: { path: join(blocker, 'nested', 'history.db') } })

    await expect(
      resolveScanId({ cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true, frameworks: [] }),
    ).resolves.not.toThrow()

    const first = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: [],
    })
    const second = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: [],
    })

    // No persistence possible → every call mints fresh, never reused.
    expect(first.scanIdReused).toBe(false)
    expect(second.scanIdReused).toBe(false)
    expect(second.scanId).not.toBe(first.scanId)
  })

  it('reuse-window expiry: an expired prior scanId is NOT reused', async () => {
    const dir = mkRepo()
    const policy = makePolicy({ history: { path: join(dir, 'history.db'), scan_id_reuse_window_minutes: 30 } })

    const first = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: [],
    })
    expect(first.scanIdReused).toBe(false)

    // Simulate "reservation made 2 hours ago" by hand-backdating created_at in the real store —
    // well past the 30-minute reuse window configured above.
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    const identity = resolveRepoIdentity(dir)
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
    // Reach into the sqlite handle directly (test-only) to backdate the one row this repo has.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const db = (opened.store as any).db
    db.prepare('UPDATE scan_id_reservations SET created_at = ? WHERE repo_id = ?').run(twoHoursAgo, identity.repoId)
    opened.store.close()

    const second = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: [],
    })

    expect(second.scanIdReused).toBe(false)
    expect(second.scanId).not.toBe(first.scanId)
  })

  it('a reservation still WITHIN the reuse window is reused even when close to the boundary', async () => {
    const dir = mkRepo()
    const policy = makePolicy({ history: { path: join(dir, 'history.db'), scan_id_reuse_window_minutes: 30 } })

    const first = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: [],
    })

    // Backdate to 29 minutes ago — still inside the 30-minute window.
    const opened = await HistoryStore.open(join(dir, 'history.db'), '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    const identity = resolveRepoIdentity(dir)
    const twentyNineMinAgo = new Date(Date.now() - 29 * 60 * 1000).toISOString()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const db = (opened.store as any).db
    db.prepare('UPDATE scan_id_reservations SET created_at = ? WHERE repo_id = ?').run(twentyNineMinAgo, identity.repoId)
    opened.store.close()

    const second = await resolveScanId({
      cwd: dir, policy, cliVersion: '0.4.1', changedOnly: false, categories: [], proRequested: true,
      frameworks: [],
    })

    expect(second.scanIdReused).toBe(true)
    expect(second.scanId).toBe(first.scanId)
  })
})

describe('HistoryStore migration — scan_id_reservations table is additive (scanId reuse)', () => {
  it('a v1-schema file created by an older CLI build still opens cleanly and gains the new table on next open', async () => {
    const dir = mkTemp()
    mkdirSync(dir, { recursive: true })
    const dbPath = join(dir, 'history.db')

    // Open + write once with today's (v2) build — establishes the file.
    const opened = await HistoryStore.open(dbPath, '0.4.1')
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    opened.store.close()

    // Re-opening must not throw and must have the new table available.
    const reopened = await HistoryStore.open(dbPath, '0.4.1')
    expect(reopened.ok).toBe(true)
    if (!reopened.ok) return
    const result = reopened.store.reserveScanId('repo-x', 'key-x', 60_000)
    expect(result.ok).toBe(true)
    reopened.store.close()
  })
})
