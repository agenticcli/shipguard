/**
 * scan-retry-framework-change.test.ts — scanId reuse over-dedup regression .
 *
 * THE HOLE (fail-before): the scanId reuse key must include the DETECTED FRAMEWORK SET,
 * because the framework set selects WHICH paid Pro-rule bundle the server builds and charges
 * for. It cannot be inferred from the working-tree content identity alone: a SECOND edit to an
 * already-modified tracked file (here, `package.json` edited twice with NO intervening commit)
 * leaves `git status --porcelain` byte-identical (` M package.json` stays ` M package.json`,
 * HEAD unchanged) → identical content identity. If frameworks were absent from the key, the
 * second `--pro` scan would REUSE the first scan's scanId, the server would re-deliver the
 * already-paid STALE bundle built for the OLD framework set, and the newly-added framework's
 * Pro rules would never run — a false-green on the PAID gate.
 *
 * PASS-AFTER: with the framework set in the reuse key, the two scans get DIFFERENT scanIds, so
 * the retry re-fetches the correct (new) bundle. A same-frameworks retry still dedups (proven
 * both here and in scan-retry-scanid-persistence.test.ts).
 *
 * This file deliberately does NOT mock `framework.js` — it exercises the REAL `detectFrameworks`
 * against a real (edited) package.json, which is the whole point of the regression. Real git
 * repo + real SQLite store; only scanner/policy/pro-scanner/config-generator/telemetry/logger
 * are mocked so no network/scan work runs.
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

// Single mutable policy object; mutate .history per test (see scan-retry-scanid-persistence.test.ts).
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

// NOTE: framework.js is intentionally NOT mocked — real detection is what this test proves.

// hasConfig=true so no .shipguard.yml is written (a new untracked file would itself change the
// porcelain listing between runs and mask the framework variable we are isolating).
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

const { fetchProRules: mockFetchProRules } = await import('../../src/core/pro-scanner.js')
const { scanCommand } = await import('../../src/commands/scan.js')

const tempDirs: string[] = []
function mkRepoWithPackageJson(deps: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-fwchange-'))
  tempDirs.push(dir)
  execSync('git init -q', { cwd: dir })
  execSync('git config user.email test@example.com', { cwd: dir })
  execSync('git config user.name test', { cwd: dir })
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'fixture', dependencies: deps }), 'utf-8')
  execSync('git add -A', { cwd: dir })
  execSync('git commit -q -m init', { cwd: dir })
  // history db lives under .shipguard/ (excluded from content identity) — set explicitly.
  stubPolicy.history = { path: join(dir, '.shipguard', 'history.db') }
  return dir
}
/** Overwrite package.json deps WITHOUT committing — the file stays a modified-tracked file, so
 *  `git status --porcelain` reports the identical ` M package.json` record before and after. */
function editDeps(dir: string, deps: Record<string, string>): void {
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'fixture', dependencies: deps }), 'utf-8')
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

describe('scanId reuse over-dedup guard — a framework change on an already-dirty tree mints a fresh scanId', () => {
  it('FAIL-BEFORE/PASS-AFTER: package.json edited twice (porcelain identical, HEAD unchanged) with a DIFFERENT framework set → DIFFERENT scanIds', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('offline')) as unknown as typeof fetch
    // Committed with an already-dirty next dep, so the working tree is dirty from run 1 onward.
    const dir = mkRepoWithPackageJson({ next: '^15.0.0' })

    // Run 1: edit package.json (now dirty) → detects nextjs. porcelain: ` M package.json`.
    editDeps(dir, { next: '^15.0.0', 'react': '^19.0.0' })
    await scanCommand().parseAsync(['node', 'scan', dir, '--json', '--pro'])

    // Run 2: edit package.json AGAIN (still dirty, porcelain STILL ` M package.json`, HEAD
    // unchanged → identical content identity) but ADD express → framework set changes.
    editDeps(dir, { next: '^15.0.0', 'react': '^19.0.0', express: '^4.19.0' })
    await scanCommand().parseAsync(['node', 'scan', dir, '--json', '--pro'])

    expect(mockFetchProRules).toHaveBeenCalledTimes(2)
    const call1 = vi.mocked(mockFetchProRules).mock.calls[0]
    const call2 = vi.mocked(mockFetchProRules).mock.calls[1]

    // Sanity: the two runs genuinely detected DIFFERENT framework sets (arg 0 = framework names).
    expect(call1[0]).toEqual(['nextjs'])
    expect(call2[0]).toEqual(expect.arrayContaining(['nextjs', 'express']))

    // FAIL-BEFORE (frameworks NOT in the key): identical contentIdentity + same scope → call2[3]
    // would EQUAL call1[3] (reused stale scanId). PASS-AFTER: they DIFFER (fresh on fw change).
    expect(call1[3]).toBeDefined()
    expect(call2[3]).toBeDefined()
    expect(call2[3]).not.toBe(call1[3])
  })

  it('SAME framework set across an identical retry still dedups → the SAME scanId (real detection)', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('offline')) as unknown as typeof fetch
    const dir = mkRepoWithPackageJson({ next: '^15.0.0' })

    // Two back-to-back scans, package.json NOT touched between them → same frameworks, same
    // content, same scope → the retry must reuse ONE scanId.
    await scanCommand().parseAsync(['node', 'scan', dir, '--json', '--pro'])
    await scanCommand().parseAsync(['node', 'scan', dir, '--json', '--pro'])

    const call1 = vi.mocked(mockFetchProRules).mock.calls[0]
    const call2 = vi.mocked(mockFetchProRules).mock.calls[1]
    expect(call1[0]).toEqual(['nextjs'])
    expect(call2[0]).toEqual(['nextjs'])
    expect(call2[3]).toBe(call1[3]) // dedup preserved for a genuine same-frameworks retry
  })
})
