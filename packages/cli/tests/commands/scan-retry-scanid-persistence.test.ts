/**
 * scan-retry-scanid-persistence.test.ts — scanId reuse, command-layer
 * end-to-end proof.
 *
 * Companion to tests/commands/scan-pro-scanid.test.ts (scanId idempotency): that test proved the
 * command forwards ITS OWN scanId into fetchProRules. This test proves the scanId itself now
 * SURVIVES a whole-process retry — the actual gap scanId reuse closes. Before this fix,
 * `scanCommand()`'s action minted `randomUUID()` fresh on every invocation (scan.ts, in-memory
 * only) — so two separate `shipguard scan --pro` process runs against the identical repo
 * state (the realistic "agent retries after a dropped response" scenario) sent TWO DIFFERENT
 * scanIds to `fetchProRules`, defeating the server's `(userId, scanId)` idempotency reservation
 * and risking a double credit charge on a legitimate retry.
 *
 * Uses a REAL git repo (temp dir) + the REAL SQLite history store (not mocked) — only
 * scanner.js/pro-scanner.js/framework.js/config-generator.js/telemetry.js are mocked, exactly
 * like scan-pro-scanid.test.ts, so this exercises the genuine resolveScanId → reserveScanId →
 * fetchProRules wiring end to end.
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
import { execSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { ScanResult, Policy } from '@agenticcli/shared'

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    findings: [],
    riskScore: {
      score: 0,
      recommendation: 'SAFE_TO_SHIP',
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      blockingCount: 0,
    },
    filesScanned: 0,
    timestamp: new Date().toISOString(),
    policyUsed: 'test-app',
    degraded: false,
    ...overrides,
  }
}

// A single mutable object (never reassigned) so the mocked loadPolicy's closure below always
// sees the CURRENT test's history-path override — mutate its `history` field per test instead
// of reassigning the binding, to sidestep any doubt about closure-over-`let` staleness.
const stubPolicy: Policy = {
  version: 1,
  project: { name: 'test-app', framework: 'auto', risk_profile: 'standard' },
  scan: { changed_files_only: false, generate_report: false },
  block: [],
  warn: [],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}

vi.mock('../../src/core/scanner.js', () => ({
  scan: vi.fn().mockImplementation(async () => makeScanResult()),
}))

vi.mock('../../src/core/policy.js', () => ({
  loadPolicy: vi.fn().mockImplementation(async () => stubPolicy),
  DEFAULT_POLICY: stubPolicy,
}))

vi.mock('../../src/core/git.js', () => ({
  isGitRepo: vi.fn(() => true),
  getChangedFiles: vi.fn(() => []),
}))

vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    success: vi.fn(),
    finding: vi.fn(),
    score: vi.fn(),
    divider: vi.fn(),
  },
}))

vi.mock('../../src/core/framework.js', () => ({
  detectFrameworks: vi.fn(() => ({ frameworks: [{ name: 'generic' }] })),
}))

vi.mock('../../src/core/config-generator.js', () => ({
  hasConfig: vi.fn(() => true),
  generateConfig: vi.fn(() => '.shipguard.yml'),
}))

vi.mock('../../src/core/pro-scanner.js', () => ({
  fetchProRules: vi.fn().mockImplementation(async () => ({
    rules: [],
    creditsRemaining: 42,
    rulesVersion: 'test-release-1',
  })),
}))

vi.mock('../../src/core/telemetry.js', () => ({
  sendTelemetry: vi.fn(),
}))

// Load AFTER vi.mock hoisting.
const { fetchProRules: mockFetchProRules } = await import('../../src/core/pro-scanner.js')
const { scanCommand } = await import('../../src/commands/scan.js')

const tempDirs: string[] = []
let repoCounter = 0
function mkRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-retry-scanid-'))
  tempDirs.push(dir)
  execSync('git init -q', { cwd: dir })
  execSync('git config user.email test@example.com', { cwd: dir })
  execSync('git config user.name test', { cwd: dir })
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  // Unique marker → a distinct root-commit hash per repo. Without this, two repos created in
  // the same second with identical content + author can collide on their root-commit hash
  // (which resolveRepoIdentity uses as repoId), making the cross-repo test flaky.
  writeFileSync(join(dir, 'repo-marker.txt'), `repo-${repoCounter++}-${Math.random()}`, 'utf-8')
  execSync('git add -A', { cwd: dir })
  execSync('git commit -q -m "init"', { cwd: dir })
  return dir
}

const realFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = realFetch
  vi.clearAllMocks()
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
})

describe('scanId reuse — a whole-process retry reuses the SAME scanId (closes the last idempotency gap)', () => {
  it('PASS-AFTER: two separate scanCommand() invocations against the SAME unchanged repo send the SAME scanId to fetchProRules', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('offline')) as unknown as typeof fetch
    const dir = mkRepo()
    stubPolicy.history = { path: join(dir, 'history.db') }

    await scanCommand().parseAsync(['node', 'scan', dir, '--json', '--pro'])
    await scanCommand().parseAsync(['node', 'scan', dir, '--json', '--pro'])

    expect(mockFetchProRules).toHaveBeenCalledTimes(2)
    const call1 = vi.mocked(mockFetchProRules).mock.calls[0]
    const call2 = vi.mocked(mockFetchProRules).mock.calls[1]

    // FAIL-BEFORE (pre-fix): call1[3] !== call2[3] — a fresh randomUUID() every invocation.
    expect(call2[3]).toBeDefined()
    expect(call2[3]).toBe(call1[3])
  })

  it('a DIFFERENT repo (different git identity) gets its OWN scanId — no cross-repo collision', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('offline')) as unknown as typeof fetch
    const dirA = mkRepo()
    const dirB = mkRepo()
    const sharedHistoryDb = join(dirA, 'shared-history.db')
    stubPolicy.history = { path: sharedHistoryDb }

    await scanCommand().parseAsync(['node', 'scan', dirA, '--json', '--pro'])
    await scanCommand().parseAsync(['node', 'scan', dirB, '--json', '--pro'])

    const call1 = vi.mocked(mockFetchProRules).mock.calls[0]
    const call2 = vi.mocked(mockFetchProRules).mock.calls[1]
    expect(call2[3]).not.toBe(call1[3])
  })

  it('a scan with a DIFFERENT requested scope (--category) on the SAME unchanged repo gets a DIFFERENT scanId — no over-dedup', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('offline')) as unknown as typeof fetch
    const dir = mkRepo()
    stubPolicy.history = { path: join(dir, 'history.db') }

    await scanCommand().parseAsync(['node', 'scan', dir, '--json', '--pro', '--category', 'secrets'])
    await scanCommand().parseAsync(['node', 'scan', dir, '--json', '--pro', '--category', 'auth'])

    const call1 = vi.mocked(mockFetchProRules).mock.calls[0]
    const call2 = vi.mocked(mockFetchProRules).mock.calls[1]
    expect(call2[3]).not.toBe(call1[3])
  })

  it('store-unavailable (unwritable history path) never blocks the scan and never throws — falls back to a fresh scanId each run', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('offline')) as unknown as typeof fetch
    const dir = mkRepo()
    const blocker = join(dir, 'blocker-file')
    writeFileSync(blocker, 'i am a file', 'utf-8')
    stubPolicy.history = { path: join(blocker, 'nested', 'history.db') }

    await expect(scanCommand().parseAsync(['node', 'scan', dir, '--json', '--pro'])).resolves.not.toThrow()
    await expect(scanCommand().parseAsync(['node', 'scan', dir, '--json', '--pro'])).resolves.not.toThrow()

    expect(mockFetchProRules).toHaveBeenCalledTimes(2)
    const call1 = vi.mocked(mockFetchProRules).mock.calls[0]
    const call2 = vi.mocked(mockFetchProRules).mock.calls[1]
    expect(call1[3]).toBeDefined()
    expect(call2[3]).toBeDefined()
    // No persistence possible → never reused.
    expect(call2[3]).not.toBe(call1[3])
  })
})
