import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { Policy, ScanResult, QualityGateRule, Finding } from '@agenticcli/shared'
import { recordScanHistory } from '../../../src/core/history/index.js'

/**
 * Integration coverage for the exact function commands/scan.ts calls at the write point
 * (see scan.ts's `recordScanHistory({...})` call, right before the public --json result is
 * built). Uses a REAL temp SQLite file via the real HistoryStore — the only thing mocked is
 * the ScanResult/policy/proRules shapes, which mirror production data exactly.
 */

const tempDirs: string[] = []
function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-record-history-'))
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

function makePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    version: 1,
    project: { name: 'test', framework: 'auto', risk_profile: 'standard' },
    scan: { changed_files_only: false, generate_report: false },
    block: ['hardcoded_secret'],
    warn: [],
    ignore: { paths: [] },
    report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
    ...overrides,
  }
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'hardcoded_secret',
    title: 'Hardcoded secret',
    severity: 'high',
    category: 'secrets',
    file: 'src/index.ts',
    evidence: '...abc123***...',
    explanation: 'x',
    recommendation: 'x',
    blocking: true,
    ...overrides,
  }
}

function makeResult(findings: Finding[], timestamp = new Date().toISOString()): ScanResult {
  const blockingCount = findings.filter((f) => f.blocking && !f.suppressed).length
  return {
    findings,
    riskScore: {
      score: blockingCount > 0 ? 60 : 0,
      recommendation: blockingCount > 0 ? 'DO_NOT_SHIP' : 'SAFE_TO_SHIP',
      totalFindings: findings.length,
      criticalCount: 0,
      highCount: blockingCount,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      blockingCount,
    },
    filesScanned: 1,
    timestamp,
    policyUsed: 'shipguard.policy.yml',
  }
}

describe('recordScanHistory — the ONE regression claim, end-to-end over a real store', () => {
  it('run 1 (first scan) → regressionCheckSkipped (no baseline); run 2 (still passing) → no regression; run 3 (now fails, same scope+corpus) → regression=true', async () => {
    const cwd = mkTemp()
    const policy = makePolicy({ history: { path: join(cwd, 'history.db') } })

    // Run 1 — rule passes (no findings).
    const run1 = await recordScanHistory({
      cwd,
      scanId: 'scan-1',
      cliVersion: '0.4.1',
      policy,
      changedOnly: false,
      categories: [],
      proRules: undefined,
      proApplied: false,
      rulesVersion: undefined,
      result: makeResult([], '2026-07-13T00:00:00.000Z'),
    })
    expect(run1.stateStatus).toBe('complete')
    expect(run1.regressionCheckSkipped).toBe(true)
    expect(run1.regressionCheckSkippedReason).toBe('no-baseline')

    // Run 2 — still passes.
    const run2 = await recordScanHistory({
      cwd,
      scanId: 'scan-2',
      cliVersion: '0.4.1',
      policy,
      changedOnly: false,
      categories: [],
      proRules: undefined,
      proApplied: false,
      rulesVersion: undefined,
      result: makeResult([], '2026-07-14T00:00:00.000Z'),
    })
    expect(run2.stateStatus).toBe('complete')
    expect(run2.regressionCheckSkipped).toBe(false)
    expect(run2.regressions).toEqual([])

    // Run 3 — the SAME rule now fails, same scope fingerprint, same (free) corpus version.
    const run3 = await recordScanHistory({
      cwd,
      scanId: 'scan-3',
      cliVersion: '0.4.1',
      policy,
      changedOnly: false,
      categories: [],
      proRules: undefined,
      proApplied: false,
      rulesVersion: undefined,
      result: makeResult([makeFinding()], '2026-07-15T00:00:00.000Z'),
    })
    expect(run3.stateStatus).toBe('complete')
    expect(run3.regressionCheckSkipped).toBe(false)
    expect(run3.regressions).toHaveLength(1)
    expect(run3.regressions[0]).toMatchObject({ ruleId: 'hardcoded_secret', baselineScanId: 'scan-2', currentScanId: 'scan-3' })
    expect(run3.coverageChanged).toEqual([])
  })

  it('a CLI-version bump between two free-tier scans (rule logic tied to CLI build) → coverageChanged, never a regression', async () => {
    const cwd = mkTemp()
    const policy = makePolicy({ history: { path: join(cwd, 'history.db') } })

    await recordScanHistory({
      cwd, scanId: 'scan-1', cliVersion: '0.4.1', policy,
      changedOnly: false, categories: [], proRules: undefined, proApplied: false, rulesVersion: undefined,
      result: makeResult([], '2026-07-13T00:00:00.000Z'),
    })

    // Same rule now fires, but the CLI itself was upgraded (0.4.1 → 0.4.2) between scans —
    // free-tier ruleVersion is tied to the CLI build, so this must read as coverage-changed.
    const run2 = await recordScanHistory({
      cwd, scanId: 'scan-2', cliVersion: '0.4.2', policy,
      changedOnly: false, categories: [], proRules: undefined, proApplied: false, rulesVersion: undefined,
      result: makeResult([makeFinding()], '2026-07-14T00:00:00.000Z'),
    })

    expect(run2.regressionCheckSkipped).toBe(false)
    expect(run2.regressions).toEqual([])
    expect(run2.coverageChanged).toHaveLength(1)
    expect(run2.coverageChanged[0]).toMatchObject({ ruleId: 'hardcoded_secret', reason: 'rule-version-changed' })
  })

  it('a pro corpus release bump that ALSO bumps the specific rule\'s own version → coverageChanged, never regression (the false-positive guard, end-to-end)', async () => {
    const cwd = mkTemp()
    const policy = makePolicy({ block: [], history: { path: join(cwd, 'history.db') } })
    const ruleId = 'supabase.rls-missing'

    const ruleV1: QualityGateRule = {
      id: ruleId,
      framework: ['supabase'],
      category: 'database',
      tier: 'pro',
      severity: 'high',
      action: 'block',
      version: '1.0.0',
      matcher: { type: 'pattern', fileGlob: '**/*.ts', patterns: [], antiPatterns: [] },
      explanation: 'x',
      recommendation: 'x',
    }
    const ruleV2: QualityGateRule = { ...ruleV1, version: '1.1.0' }

    await recordScanHistory({
      cwd, scanId: 'scan-1', cliVersion: '0.4.1', policy,
      changedOnly: false, categories: [], proRules: [ruleV1], proApplied: true, rulesVersion: 'release-5',
      result: makeResult([], '2026-07-13T00:00:00.000Z'),
    })

    const run2 = await recordScanHistory({
      cwd, scanId: 'scan-2', cliVersion: '0.4.1', policy,
      changedOnly: false, categories: [], proRules: [ruleV2], proApplied: true, rulesVersion: 'release-6',
      result: makeResult([makeFinding({ id: ruleId, category: 'database' })], '2026-07-14T00:00:00.000Z'),
    })

    expect(run2.regressionCheckSkipped).toBe(false)
    expect(run2.regressions).toEqual([])
    expect(run2.coverageChanged.some((c) => c.ruleId === ruleId && c.reason === 'rule-version-changed')).toBe(true)
  })

  it('a DIFFERENT scope fingerprint (changed-files-only vs full scan) is never compared', async () => {
    const cwd = mkTemp()
    const policy = makePolicy({ history: { path: join(cwd, 'history.db') } })

    await recordScanHistory({
      cwd, scanId: 'scan-1', cliVersion: '0.4.1', policy,
      changedOnly: false, categories: [], proRules: undefined, proApplied: false, rulesVersion: undefined,
      result: makeResult([], '2026-07-13T00:00:00.000Z'),
    })

    // Second scan is --changed (different scope) and the rule fires — must NOT be read as a
    // regression against the full-scan baseline; it has no baseline of its own yet.
    const run2 = await recordScanHistory({
      cwd, scanId: 'scan-2', cliVersion: '0.4.1', policy,
      changedOnly: true, categories: [], proRules: undefined, proApplied: false, rulesVersion: undefined,
      result: makeResult([makeFinding()], '2026-07-14T00:00:00.000Z'),
    })

    expect(run2.regressionCheckSkipped).toBe(true)
    expect(run2.regressionCheckSkippedReason).toBe('no-baseline')
  })
})

describe('recordScanHistory — DB-unavailable never blocks or changes the scan (§1.6)', () => {
  it('an unwritable history path → stateStatus unavailable, regressionCheckSkipped true, resolves without throwing', async () => {
    const cwd = mkTemp()
    const blocker = join(cwd, 'blocker-file')
    writeFileSync(blocker, 'i am a file', 'utf-8')
    const policy = makePolicy({ history: { path: join(blocker, 'nested', 'history.db') } })

    const outcome = await recordScanHistory({
      cwd, scanId: 'scan-1', cliVersion: '0.4.1', policy,
      changedOnly: false, categories: [], proRules: undefined, proApplied: false, rulesVersion: undefined,
      result: makeResult([makeFinding()]),
    })

    expect(outcome.stateStatus).toBe('unavailable')
    expect(outcome.regressionCheckSkipped).toBe(true)
    expect(outcome.regressionCheckSkippedReason).toBe('state-unavailable')
    expect(outcome.regressions).toEqual([])
  })

  it('a corrupt pre-existing history file → stateStatus corrupt, scan-unaffected outcome shape still returned', async () => {
    const cwd = mkTemp()
    mkdirSync(join(cwd, '.shipguard'), { recursive: true })
    const dbPath = join(cwd, '.shipguard', 'history.db')
    writeFileSync(dbPath, 'not a sqlite database, just bytes', 'utf-8')
    const policy = makePolicy({ history: { path: dbPath } })

    const outcome = await recordScanHistory({
      cwd, scanId: 'scan-1', cliVersion: '0.4.1', policy,
      changedOnly: false, categories: [], proRules: undefined, proApplied: false, rulesVersion: undefined,
      result: makeResult([]),
    })

    expect(outcome.stateStatus).toBe('corrupt')
    expect(outcome.regressionCheckSkipped).toBe(true)
  })
})
