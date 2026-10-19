/**
 * WS-2 Core Orchestration QA Tests
 *
 * Tests the "Core Orchestration" workstream: scanner, pro-scanner (incl.
 * runProRulesWithDispatch), coderef-dispatch, policy, sarif mapper, report,
 * exit codes.
 *
 * Convention: Tests assert ACTUAL behaviour of the code.
 * Where actual behaviour differs from desired, the test is marked
 * it.fails() and the discrepancy is documented in docs/qa-results-WS2.md.
 * A PASS in this suite means code is correct. A it.fails() with the outer
 * wrapper PASSING means the bug is confirmed + encoded.
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const POLICY_STUB = { maxHighFindings: 0 } as unknown as import('@agenticcli/shared').Policy

function makeFile(relativePath: string, content: string): import('@agenticcli/shared').FileInfo {
  return { path: `/project/${relativePath}`, content, relativePath }
}

// ---------------------------------------------------------------------------
// Import under test
// ---------------------------------------------------------------------------

import {
  runProRules,
  runProRulesWithDispatch,
  type ProRulesDispatchResult,
} from '../../src/core/pro-scanner.js'
import {
  runCoderefRules,
  DEFAULT_DISPATCH_TABLE,
  semverLt,
  type CodeRef,
  type ChecksumManifest,
} from '../../src/core/coderef-dispatch.js'
import { toSarif, type SarifLog, type SarifResultEntry } from '../../src/core/sarif.js'
import { generateReport } from '../../src/core/report.js'
import { computeRiskScore } from '../../src/core/risk-score.js'
import { loadPolicy, DEFAULT_POLICY } from '../../src/core/policy.js'
import { resolveExitCode } from '../../src/commands/scan.js'
import { EXIT_CODES } from '@agenticcli/shared'
import type { QualityGateRule, FileInfo, Finding, ScanResult, CheckModule } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// ============================================================
// SECTION 1 — scanner basics (TC-SC-01 to TC-SC-06)
// ============================================================
// ---------------------------------------------------------------------------

vi.mock('../../src/core/git.js', () => ({
  isGitRepo: vi.fn(() => false),
  getChangedFiles: vi.fn(() => []),
}))

const { scan } = await import('../../src/core/scanner.js')
const gitModule = await import('../../src/core/git.js')
const mockIsGitRepo = vi.mocked(gitModule.isGitRepo)
const mockGetChangedFiles = vi.mocked(gitModule.getChangedFiles)

const tempDirs: string[] = []

function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'ws2-test-'))
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  vi.restoreAllMocks()
  mockIsGitRepo.mockReturnValue(false)
  mockGetChangedFiles.mockReturnValue([])
  for (const dir of tempDirs.splice(0)) {
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  }
})

// ---------------------------------------------------------------------------

describe('TC-SC-01 — scanner returns valid ScanResult shape', () => {
  it('result has all required fields', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'index.ts'), 'export const x = 1\n', 'utf-8')
    const orig = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(result).toHaveProperty('findings')
      expect(result).toHaveProperty('riskScore')
      expect(result).toHaveProperty('filesScanned')
      expect(result).toHaveProperty('timestamp')
      expect(result).toHaveProperty('policyUsed')
      expect(Array.isArray(result.findings)).toBe(true)
      expect(typeof result.filesScanned).toBe('number')
      expect(typeof result.riskScore.score).toBe('number')
    } finally { process.chdir(orig) }
  })
})

describe('TC-SC-02 — scanner detects blocking finding in known-bad file', () => {
  it('secrets check fires on hardcoded key', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'config.ts'), 'const key = "sk_live_abcdefghijklmnopqrstuvwx"\n', 'utf-8')
    const orig = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      const secrets = result.findings.filter(f => f.category === 'secrets')
      expect(secrets.length).toBeGreaterThan(0)
    } finally { process.chdir(orig) }
  })
})

describe('TC-SC-03 — scanner propagates coderef degraded flag', () => {
  it('degraded flag is false when no proRules given', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'index.ts'), 'const x = 1\n', 'utf-8')
    const orig = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      // No pro rules → coderefDegraded must be falsy
      expect(result.degraded).toBeFalsy()
    } finally { process.chdir(orig) }
  })

  it('degraded flag is true when a coderef rule is version-skipped', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'index.ts'), 'const x = 1\n', 'utf-8')
    const orig = process.cwd()
    process.chdir(dir)
    try {
      // Craft a coderef rule that will be skipped due to version mismatch
      const proRule: QualityGateRule & { implType: string; codeRef: CodeRef } = {
        id: 'test-coderef-version',
        framework: ['generic'],
        category: 'secrets',
        tier: 'pro',
        severity: 'high',
        matcher: { type: 'pattern', fileGlob: '**/*.ts', patterns: ['x'], antiPatterns: [] },
        explanation: 'Test',
        recommendation: 'Fix',
        implType: 'coderef',
        codeRef: { moduleId: 'stub', exportName: 'stubCheck', minCliVersion: '999.0.0' },
      }
      const result = await scan(
        { changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' },
        [proRule],
      )
      // coderef version skip → degraded must propagate back
      expect(result.degraded).toBe(true)
    } finally { process.chdir(orig) }
  })
})

describe('TC-SC-04 — scanner changedOnly uses mock git', () => {
  it('only scans changed file when in git repo', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'changed.ts'), 'const a = 1\n', 'utf-8')
    writeFileSync(join(dir, 'other.ts'), 'const b = 2\n', 'utf-8')
    mockIsGitRepo.mockReturnValue(true)
    mockGetChangedFiles.mockReturnValue(['changed.ts'])
    const orig = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: true, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(result.filesScanned).toBe(1)
    } finally { process.chdir(orig) }
  })
})

describe('TC-SC-05 — scanner riskScore in valid range', () => {
  it('score is 0–100 and recommendation is valid enum', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'clean.ts'), 'export const hello = "world"\n', 'utf-8')
    const orig = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(result.riskScore.score).toBeGreaterThanOrEqual(0)
      expect(result.riskScore.score).toBeLessThanOrEqual(100)
      expect(['SAFE_TO_SHIP', 'REVIEW_BEFORE_SHIP', 'DO_NOT_SHIP']).toContain(result.riskScore.recommendation)
    } finally { process.chdir(orig) }
  })
})

describe('TC-SC-06 — scanner timestamp is ISO 8601', () => {
  it('timestamp is a valid ISO string', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'a.ts'), 'const x = 1\n', 'utf-8')
    const orig = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(() => new Date(result.timestamp)).not.toThrow()
      expect(new Date(result.timestamp).toISOString()).toBe(result.timestamp)
    } finally { process.chdir(orig) }
  })
})

// ---------------------------------------------------------------------------
// ============================================================
// SECTION 2 — pro-scanner: legacy/fallback tamper path
// TC-PS-01: tampered bundle must NOT silently pass through fallback
// ============================================================
// ---------------------------------------------------------------------------

/**
 * The legacy AES-GCM encrypted bundle path is PERMANENTLY DISABLED.
 * verifyAndDecryptBundle always throws 'legacy-bundle-rejected: attestation required'.
 * The discriminated-catch approach is superseded — the function is a tombstone.
 *
 * TC-PS-01 retains tests for:
 *   (a) verifyAndDecryptBundle tombstone (always throws legacy-bundle-rejected)
 *   (b) fetchProRules hard rejection when server returns a legacy signedBundle
 *       without fullManifest (legacy guard at pro-scanner.ts bottom)
 */
describe('TC-PS-01 — legacy bundle paths permanently disabled', () => {
  it('verifyAndDecryptBundle is tombstoned — throws legacy-bundle-rejected for any input', async () => {
    // function is permanently disabled regardless of input content.
    const { verifyAndDecryptBundle } = await import('../../src/core/crypto.js')

    const fakePayload = {
      ciphertext: Buffer.from('fake').toString('base64'),
      iv: Buffer.from('fake-iv-12-bytes').toString('base64'),
      salt: Buffer.from('fake-salt-32-bytes-x-xxxxxxxxxx').toString('base64'),
      watermark: { userId: 'u1', scanId: 's1', issuedAt: Date.now() },
      expiresAt: Date.now() + 60000,
    }
    const bundle = Buffer.from(JSON.stringify({
      signature: Buffer.from('invalidsig').toString('base64'),
      payload: fakePayload,
    })).toString('base64')

    await expect(verifyAndDecryptBundle(bundle, 'any-token'))
      .rejects.toThrow('legacy-bundle-rejected')
  })

  /**
   * legacy guard at pro-scanner.ts bottom: if the server returns a response that
   * does not have 'fullManifest' at the top level, fetchProRules throws
   * 'legacy-bundle-rejected: attestation required — server response lacks fullManifest'.
   *
   * This replaces the discriminated-catch approach: there is no longer a fallback path
   * of any kind — legacy bundles are categorically refused.
   *
   * Mock isolation: fetchProRules is statically imported at the top of this file
   * and is cached before the test runs. We must resetModules + doMock + dynamic
   * import inside the test to get a fresh module instance that sees the auth mock.
   */
  it('fetchProRules rejects legacy signedBundle (no fullManifest) with legacy-bundle-rejected', async () => {
    vi.resetModules()
    vi.doMock('../../src/core/auth.js', () => ({
      getAuthToken: vi.fn(() => Promise.resolve('fake-token')),
    }))

    const fakePayload = {
      ciphertext: Buffer.from('fake').toString('base64'),
      iv: Buffer.from('fake-iv-12-bytes').toString('base64'),
      salt: Buffer.from('fake-salt-32-bytes-x-xxxxxxxxxx').toString('base64'),
      watermark: { userId: 'u1', scanId: 's1', issuedAt: Date.now() },
      expiresAt: Date.now() + 60000,
    }
    const legacyB64 = Buffer.from(JSON.stringify({
      signature: Buffer.from('invalidsig').toString('base64'),
      payload: fakePayload,
    })).toString('base64')

    // Mock fetch to return a legacy signedBundle (no fullManifest at top level).
    // text() is required by the Finding-8 fix (res.text() + parseStrictNoDup).
    const legacyBody = JSON.stringify({ signedBundle: legacyB64 })
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: true,
      status: 200,
      headers: new Headers({ 'X-Credits-Remaining': '10', 'X-Rules-Version': '1' }),
      text: () => Promise.resolve(legacyBody),
      json: () => Promise.resolve({ signedBundle: legacyB64 }),
    })))

    // Fresh import after resetModules so the auth mock takes effect
    const { fetchProRules: fetchProRulesFresh } = await import('../../src/core/pro-scanner.js')

    // response lacks fullManifest → legacy-bundle-rejected hard refusal.
    // Use a trusted hostname (localhost) so domain-pinning passes.
    await expect(fetchProRulesFresh(['generic'], undefined, 'http://localhost'))
      .rejects.toThrow('legacy-bundle-rejected')

    vi.unstubAllGlobals()
    vi.doUnmock('../../src/core/auth.js')
  })
})

// ---------------------------------------------------------------------------
// ============================================================
// SECTION 3 — exit code precedence
// TC-EXIT-01: A1 exit-code contract — verdict-neutral by default (2026-07-13)
// ============================================================
// ---------------------------------------------------------------------------

/**
 * SUPERSEDES the pre-A1 "degraded → exit 2" contract that lived here
 * (an earlier case where exit 2 masked exit 1 — still true under A1: a
 * blocked+degraded scan under --strict is still exit 1, never softened).
 *
 * A1: the CLI is triggered by an agent that reads
 * `--json`; ShipGuard *informs*, the caller chooses soft vs hard gating.
 *
 * RCA of the bug this replaces: the OLD resolveExitCode() returned exit 0
 * for a DEFAULT (non-strict) scan with critical blocking findings — but the
 * written contract (README, help text) claimed "0=safe", which is a lie for
 * a scan that found a hardcoded secret. `--quiet` printed "DO NOT SHIP" and
 * still exited 0 with no caveat. Separately, exit 2 was OVERLOADED as both
 * "config error" (bad policy/flags) and "degraded scan" (pro rules
 * unavailable, oversized file skipped) — an agent piping `--json` could not
 * tell "your policy.yml is broken" from "we couldn't check everything" from
 * the exit code alone.
 *
 * Fix: exit code is now VERDICT-NEUTRAL. resolveExitCode() takes only
 * {strict, blockingCount} — `degraded` is REMOVED from its signature entirely,
 * because degradation NEVER changes the exit code under A1; it is surfaced
 * exclusively via the JSON `degraded`/`degradedReasons` fields (already part
 * of the frozen ScanResult schema — see packages/shared/src/types.ts).
 *
 * New contract:
 *   0 — scan completed. Verdict is in the JSON `recommendation` field, EVEN
 *       IF findings are blocking, EVEN IF the scan is degraded/partial.
 *   1 — blocked. ONLY --strict + blockingCount > 0 (opt-in hard gate).
 *   2 — config error, STRICTLY (bad policy file, bad flags, non-project dir).
 *       Never reused for a degraded-but-completed scan.
 *   3 — runtime error / scan could not meaningfully run at all (resolved
 *       elsewhere in scan.ts — e.g. NO_RULES_APPLIED fail-closed, unexpected
 *       throw — not returned by this function).
 */
describe('TC-EXIT-01 — A1 exit-code contract: verdict-neutral by default', () => {
  it('strict + blocking → exit 1 (the ONLY thing that moves off the default)', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 2 }))
      .toBe(EXIT_CODES.BLOCKED)   // 1
  })

  it('strict + no blocking → exit 0', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 0 }))
      .toBe(EXIT_CODES.SAFE)  // 0
  })

  it('strict + blocking (single finding) → exit 1', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 1 }))
      .toBe(EXIT_CODES.BLOCKED)   // 1
  })

  it('FAIL-BEFORE regression: non-strict + blocking findings → exit 0, NOT 1 or 2 ' +
     '(pre-A1 bug: default scan with a critical secret silently exited "safe" while ' +
     'claiming a written 0=safe contract — A1 makes this explicit/intentional: 0 means ' +
     '"completed, read the JSON", not "safe")', () => {
    expect(resolveExitCode({ strict: false, blockingCount: 5 }))
      .toBe(EXIT_CODES.SAFE)  // 0 — verdict lives in JSON `recommendation`, not the exit code
  })

  it('non-strict + blocking (many findings) → exit 0', () => {
    expect(resolveExitCode({ strict: false, blockingCount: 3 }))
      .toBe(EXIT_CODES.SAFE)  // 0
  })

  it('clean scan (not strict, no blocking) → exit 0', () => {
    expect(resolveExitCode({ strict: false, blockingCount: 0 }))
      .toBe(EXIT_CODES.SAFE)  // 0
  })

  it('resolveExitCode() signature no longer accepts `degraded` — TS enforces this ' +
     'at compile time, but assert here that passing extra `degraded` has NO runtime ' +
     'effect on the returned code (degradation is JSON-only, never exit-code-only)', () => {
    // @ts-expect-error — `degraded` is intentionally not part of the signature anymore
    const withDegradedIgnored = resolveExitCode({ strict: false, blockingCount: 0, degraded: true })
    expect(withDegradedIgnored).toBe(EXIT_CODES.SAFE)  // 0, not 2 — degraded has zero exit-code effect
  })
})

// ---------------------------------------------------------------------------
// ============================================================
// SECTION 4 — unknown coderef moduleId behavior
// TC-CREF-01: unknown moduleId → degraded=false, warning, exit 0 (silent)
// ============================================================
// ---------------------------------------------------------------------------

/**
 * FIXED: coderef-dispatch.ts — when moduleId:exportName is
 * not in the dispatch table, degraded is now set to true (same as version-skip).
 * A credit-costing pro rule that cannot run surfaces as degraded, not silent exit 0.
 */
describe('TC-CREF-01 — unknown coderef moduleId sets degraded=true (FIXED)', () => {
  it('unknown dispatch key → degraded=true, warning issued, no findings', () => {
    const rule = {
      id: 'rule-unknown-mod',
      framework: ['generic'],
      category: 'secrets' as const,
      tier: 'pro' as const,
      severity: 'high' as const,
      matcher: { type: 'pattern' as const, fileGlob: '**/*.ts', patterns: ['x'], antiPatterns: [] },
      explanation: 'Test',
      recommendation: 'Fix',
      implType: 'coderef',
      codeRef: { moduleId: 'nonexistent', exportName: 'ghost', minCliVersion: '0.1.0' },
    } as QualityGateRule

    const result = runCoderefRules([rule], [], POLICY_STUB, '1.0.0', {})

    // FIXED: unknown module sets degraded=true (same as version-skip path)
    expect(result.degraded).toBe(true)
    // Warning is emitted — coverage is not silent
    expect(result.warnings.length).toBeGreaterThan(0)
    expect(result.warnings[0]).toMatch(/Unknown coderef/)
    // Finding is missing — rule cannot run without its module
    expect(result.findings).toHaveLength(0)
  })

  it('unknown dispatch key → degraded=true + warning', () => {
    const rule = {
      id: 'rule-unknown-desired',
      framework: ['generic'],
      category: 'secrets' as const,
      tier: 'pro' as const,
      severity: 'high' as const,
      matcher: { type: 'pattern' as const, fileGlob: '**/*.ts', patterns: ['x'], antiPatterns: [] },
      explanation: 'Test',
      recommendation: 'Fix',
      implType: 'coderef',
      codeRef: { moduleId: 'nonexistent', exportName: 'ghost', minCliVersion: '0.1.0' },
    } as QualityGateRule

    const result = runCoderefRules([rule], [], POLICY_STUB, '1.0.0', {})

    // FIXED: degraded=true for unknown modules — incomplete coverage is surfaced
    expect(result.degraded).toBe(true)
    // Warning is also present — dual assertion
    expect(result.warnings.length).toBeGreaterThan(0)
    expect(result.warnings[0]).toMatch(/Unknown coderef/)
  })
})

// ---------------------------------------------------------------------------
// ============================================================
// SECTION 5 — SARIF 2.1.0 shape + severity/level + fingerprints
// TC-SARIF-01 to TC-SARIF-06
// ============================================================
// ---------------------------------------------------------------------------

function makeSarifResult(overrides: Partial<ScanResult> = {}): ScanResult {
  const findings: Finding[] = [
    {
      id: 'hardcoded_secret',
      title: 'Hardcoded API Key',
      severity: 'critical',
      category: 'secrets',
      file: 'lib/api.ts',
      line: 42,
      evidence: 'sk-proj-abc***',
      explanation: 'API key hardcoded in source.',
      recommendation: 'Use environment variables.',
      blocking: true,
      fix: 'Move key to env var.',
      cwe: ['CWE-798'],
    },
    {
      id: 'exposed_env',
      title: '.env tracked in git',
      severity: 'medium',
      category: 'secrets',
      file: '.env',
      explanation: '.env file committed.',
      recommendation: 'Add .env to .gitignore.',
      blocking: false,
    },
    {
      id: 'cors_wildcard',
      title: 'CORS wildcard',
      severity: 'high',
      category: 'deployment',
      file: 'next.config.js',
      line: 10,
      explanation: 'CORS wildcard allows any origin.',
      recommendation: 'Restrict CORS origins.',
      blocking: true,
    },
  ]
  return {
    findings,
    riskScore: {
      score: 80,
      recommendation: 'DO_NOT_SHIP',
      totalFindings: 3,
      criticalCount: 1,
      highCount: 1,
      mediumCount: 1,
      lowCount: 0,
      infoCount: 0,
      blockingCount: 2,
    },
    filesScanned: 15,
    timestamp: '2026-06-09T10:00:00.000Z',
    policyUsed: 'test-app',
    ...overrides,
  }
}

describe('TC-SARIF-01 — SARIF 2.1.0 envelope shape', () => {
  it('has correct $schema, version, runs array', () => {
    const log = toSarif(makeSarifResult())
    expect(log.$schema).toBe('https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json')
    expect(log.version).toBe('2.1.0')
    expect(Array.isArray(log.runs)).toBe(true)
    expect(log.runs).toHaveLength(1)
  })

  it('tool.driver.name is "shipguard"', () => {
    const log = toSarif(makeSarifResult())
    expect(log.runs[0].tool.driver.name).toBe('shipguard')
  })

  it('runs[0] has both tool and results', () => {
    const log = toSarif(makeSarifResult())
    expect(log.runs[0]).toHaveProperty('tool')
    expect(log.runs[0]).toHaveProperty('results')
  })
})

describe('TC-SARIF-02 — severity to SARIF level mapping', () => {
  const cases: Array<[Finding['severity'], string]> = [
    ['critical', 'error'],
    ['high', 'error'],
    ['medium', 'warning'],
    ['low', 'note'],
    ['info', 'note'],
  ]

  for (const [sev, expectedLevel] of cases) {
    it(`severity "${sev}" maps to level "${expectedLevel}"`, () => {
      const result = makeSarifResult({
        findings: [{
          id: `rule_${sev}`,
          title: `Title`,
          severity: sev,
          category: 'secrets',
          file: 'a.ts',
          explanation: 'e',
          recommendation: 'r',
          blocking: false,
        }],
      })
      const log = toSarif(result)
      expect(log.runs[0].results[0].level).toBe(expectedLevel)
    })
  }
})

describe('TC-SARIF-03 — security-severity scores', () => {
  const scoreMap: Record<string, number> = {
    critical: 9.0, high: 7.0, medium: 5.0, low: 3.0, info: 1.0,
  }
  for (const [sev, expected] of Object.entries(scoreMap)) {
    it(`security-severity for "${sev}" is ${expected}`, () => {
      const result = makeSarifResult({
        findings: [{
          id: `rule_${sev}`,
          title: 'T',
          severity: sev as Finding['severity'],
          category: 'secrets',
          file: 'b.ts',
          explanation: 'e',
          recommendation: 'r',
          blocking: false,
        }],
      })
      const log = toSarif(result)
      expect(log.runs[0].tool.driver.rules[0].properties['security-severity']).toBe(expected)
    })
  }
})

describe('TC-SARIF-04 — partialFingerprints.primary present + stable', () => {
  it('every result has partialFingerprints.primary as a non-empty string', () => {
    const log = toSarif(makeSarifResult())
    for (const r of log.runs[0].results) {
      expect(typeof r.partialFingerprints?.primary).toBe('string')
      expect((r.partialFingerprints.primary as string).length).toBeGreaterThan(0)
    }
  })

  it('fingerprints are stable across two identical calls', () => {
    const result = makeSarifResult()
    const log1 = toSarif(result)
    const log2 = toSarif(result)
    for (let i = 0; i < log1.runs[0].results.length; i++) {
      expect(log1.runs[0].results[i].partialFingerprints.primary)
        .toBe(log2.runs[0].results[i].partialFingerprints.primary)
    }
  })

  it('fingerprint changes when file or line changes', () => {
    const base: Finding = {
      id: 'rule1', title: 'T', severity: 'high', category: 'secrets',
      file: 'a.ts', line: 10, explanation: 'e', recommendation: 'r', blocking: false,
    }
    const altered: Finding = { ...base, file: 'b.ts' }

    const logBase = toSarif(makeSarifResult({ findings: [base] }))
    const logAltered = toSarif(makeSarifResult({ findings: [altered] }))

    expect(logBase.runs[0].results[0].partialFingerprints.primary)
      .not.toBe(logAltered.runs[0].results[0].partialFingerprints.primary)
  })
})

describe('TC-SARIF-05 — every result.ruleId exists in driver.rules', () => {
  it('all result ruleIds are backed by a rule in driver.rules', () => {
    const log = toSarif(makeSarifResult())
    const ruleIds = new Set(log.runs[0].tool.driver.rules.map((r: { id: string }) => r.id))
    for (const result of log.runs[0].results) {
      expect(ruleIds.has(result.ruleId), `ruleId "${result.ruleId}" missing from driver.rules`).toBe(true)
    }
  })
})

describe('TC-SARIF-06 — physicalLocation uri and startLine', () => {
  it('artifactLocation.uri matches finding.file', () => {
    const log = toSarif(makeSarifResult())
    const r = log.runs[0].results.find((x: SarifResultEntry) => x.ruleId === 'hardcoded_secret')!
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe('lib/api.ts')
  })

  it('region.startLine matches finding.line', () => {
    const log = toSarif(makeSarifResult())
    const r = log.runs[0].results.find((x: SarifResultEntry) => x.ruleId === 'hardcoded_secret')!
    expect(r.locations[0].physicalLocation.region.startLine).toBe(42)
  })

  it('region.startLine defaults to 1 when finding has no line', () => {
    const log = toSarif(makeSarifResult())
    const r = log.runs[0].results.find((x: SarifResultEntry) => x.ruleId === 'exposed_env')!
    expect(r.locations[0].physicalLocation.region.startLine).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// ============================================================
// SECTION 6 — report generator
// TC-RPT-01 to TC-RPT-04
// ============================================================
// ---------------------------------------------------------------------------

describe('TC-RPT-01 — report markdown structure', () => {
  it('generated report contains all required sections', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')
    const result: ScanResult = makeSarifResult()
    await generateReport(result, outputPath)

    const { readFileSync } = await import('node:fs')
    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('# ShipGuard Release Report')
    expect(content).toContain('## SUMMARY')       // new structure: SUMMARY at top
    expect(content).toContain('## Suggested Fix Order')
    expect(content).toContain('## Final Recommendation')
  })

  it('summary has status, risk score, files, finding count, timestamp', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')
    await generateReport(makeSarifResult(), outputPath)

    const { readFileSync } = await import('node:fs')
    const content = readFileSync(outputPath, 'utf-8')
    // New SUMMARY format: verdict + attitude + fields inline
    expect(content).toContain('DO_NOT_SHIP')
    expect(content).toContain('80/100')
    expect(content).toContain('15')          // Files scanned
    expect(content).toContain('2026-06-09')  // Generated timestamp
  })
})

describe('TC-RPT-02 — report groups findings by severity', () => {
  it('findings appear in correct severity sections', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')
    await generateReport(makeSarifResult(), outputPath)

    const { readFileSync } = await import('node:fs')
    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('## Critical Findings')
    expect(content).toContain('Hardcoded API Key')
    expect(content).toContain('## High Findings')
    expect(content).toContain('CORS wildcard')
    expect(content).toContain('## Medium Findings')
    expect(content).toContain('.env tracked in git')
  })
})

describe('TC-RPT-03 — report fix order and final recommendation', () => {
  it('final recommendation matches riskScore.recommendation', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')
    await generateReport(makeSarifResult(), outputPath)

    const { readFileSync } = await import('node:fs')
    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('**DO_NOT_SHIP**')
  })
})

describe('TC-RPT-04 — report handles zero findings', () => {
  it('generates valid report with no findings', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')
    const result: ScanResult = makeSarifResult({
      findings: [],
      riskScore: { score: 0, recommendation: 'SAFE_TO_SHIP', totalFindings: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0, blockingCount: 0 },
    })
    await generateReport(result, outputPath)

    const { readFileSync } = await import('node:fs')
    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('SAFE_TO_SHIP')
    expect(content).toContain('**Risk Score:** 0/100')
  })
})

// ---------------------------------------------------------------------------
// ============================================================
// SECTION 7 — policy loader
// TC-POL-01 to TC-POL-03
// ============================================================
// ---------------------------------------------------------------------------

describe('TC-POL-01 — policy loads default when no file exists', () => {
  it('returns DEFAULT_POLICY when shipguard.policy.yml absent', async () => {
    const dir = mkTemp()
    const orig = process.cwd()
    process.chdir(dir)
    try {
      const policy = await loadPolicy(dir)
      expect(policy.version).toBe(1)
      expect(Array.isArray(policy.block)).toBe(true)
      expect(policy.block).toContain('exposed_env')
    } finally { process.chdir(orig) }
  })
})

describe('TC-POL-02 — policy merges custom fields over defaults', () => {
  it('custom project.name overrides default', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'shipguard.policy.yml'), 'version: 1\nproject:\n  name: my-custom-app\n  framework: next\n  risk_profile: strict\n', 'utf-8')
    const policy = await loadPolicy(dir)
    expect(policy.project.name).toBe('my-custom-app')
    // Default block list is preserved via spread
    expect(Array.isArray(policy.block)).toBe(true)
  })
})

describe('TC-POL-03 — invalid YAML throws with clear error', () => {
  it('corrupt policy file throws Error containing "Invalid policy"', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'shipguard.policy.yml'), 'version: 1\n  bad: [unclosed', 'utf-8')
    await expect(loadPolicy(dir)).rejects.toThrow(/Invalid policy/)
  })
})

// ---------------------------------------------------------------------------
// ============================================================
// SECTION 8 — risk score
// TC-RS-01 to TC-RS-04
// ============================================================
// ---------------------------------------------------------------------------

describe('TC-RS-01 — risk score from no findings is 0 SAFE_TO_SHIP', () => {
  it('empty findings → score 0 + SAFE_TO_SHIP', () => {
    const rs = computeRiskScore([])
    expect(rs.score).toBe(0)
    expect(rs.recommendation).toBe('SAFE_TO_SHIP')
    expect(rs.totalFindings).toBe(0)
    expect(rs.blockingCount).toBe(0)
  })
})

describe('TC-RS-02 — critical finding drives score to 50 (boundary bug)', () => {
  /**
   * CONFIRMED BUG (RS-02-BOUNDARY): SEVERITY_WEIGHTS.critical = 50, but the
   * DO_NOT_SHIP threshold in risk-score.ts is `score > 50` (strictly greater).
   * A single critical finding scores exactly 50 → REVIEW_BEFORE_SHIP, not DO_NOT_SHIP.
   *
   * The spec (test-plan-v1.md, Risk Scoring section) says:
   *   "A single critical finding results in a score above 50"
   *   "Score 51–100 with high or critical findings → status is DO_NOT_SHIP"
   *
   * Fix: either raise critical weight to 51, or change threshold to `>= 50`.
   * File: packages/shared/src/constants.ts:5 (weight) and
   *        packages/cli/src/core/risk-score.ts:32 (threshold).
   */
  it('one critical finding → score exactly 50 → DO_NOT_SHIP (threshold is >= 50)', () => {
    const findings: Finding[] = [{
      id: 'c1', title: 'Critical', severity: 'critical', category: 'secrets',
      file: 'a.ts', explanation: 'e', recommendation: 'r', blocking: true,
    }]
    const rs = computeRiskScore(findings)
    // Fixed: score = 50, threshold is >= 50, so DO_NOT_SHIP
    expect(rs.score).toBe(50)
    expect(rs.recommendation).toBe('DO_NOT_SHIP')
  })

  it('two critical findings → score 100 → DO_NOT_SHIP', () => {
    const findings: Finding[] = [
      { id: 'c1', title: 'C1', severity: 'critical', category: 'secrets', file: 'a.ts', explanation: 'e', recommendation: 'r', blocking: true },
      { id: 'c2', title: 'C2', severity: 'critical', category: 'secrets', file: 'b.ts', explanation: 'e', recommendation: 'r', blocking: true },
    ]
    const rs = computeRiskScore(findings)
    expect(rs.score).toBe(100) // capped
    expect(rs.recommendation).toBe('DO_NOT_SHIP')
  })
})

describe('TC-RS-03 — score is capped at 100', () => {
  it('many high findings sum > 100 is capped at 100', () => {
    const findings: Finding[] = Array.from({ length: 10 }, (_, i): Finding => ({
      id: `h${i}`, title: `High ${i}`, severity: 'high', category: 'secrets',
      file: `f${i}.ts`, explanation: 'e', recommendation: 'r', blocking: true,
    }))
    const rs = computeRiskScore(findings)
    expect(rs.score).toBe(100)
  })
})

describe('TC-RS-04 — medium findings → REVIEW_BEFORE_SHIP', () => {
  it('two medium findings → score 21-50 + REVIEW_BEFORE_SHIP', () => {
    const findings: Finding[] = [
      { id: 'm1', title: 'Medium 1', severity: 'medium', category: 'secrets', file: 'a.ts', explanation: 'e', recommendation: 'r', blocking: false },
      { id: 'm2', title: 'Medium 2', severity: 'medium', category: 'secrets', file: 'b.ts', explanation: 'e', recommendation: 'r', blocking: false },
    ]
    const rs = computeRiskScore(findings)
    // 2 * 15 = 30 → REVIEW_BEFORE_SHIP
    expect(rs.score).toBe(30)
    expect(rs.recommendation).toBe('REVIEW_BEFORE_SHIP')
  })
})

// ---------------------------------------------------------------------------
// ============================================================
// SECTION 9 — coderef-dispatch comprehensive
// TC-CD-01 to TC-CD-06 (complement existing tests, not duplicates)
// ============================================================
// ---------------------------------------------------------------------------

const stubFinding: Finding = {
  id: 'stub-finding', title: 'Stub', severity: 'high', category: 'secrets',
  file: 'stub.ts', explanation: 'Stub.', recommendation: 'Fix.', blocking: false,
}
const stubModule: CheckModule = { id: 'stub', name: 'Stub', run: vi.fn(() => [stubFinding]) }
const STUB_TABLE = { 'stub:stubCheck': stubModule }

describe('TC-CD-01 — checksum mismatch → fail closed (degraded=true, C.10 fix)', () => {
  it('checksum mismatch → no findings, CODEREF_CHECKSUM_MISMATCH warning, degraded=true (fail closed, not silent skip)', () => {
    // C.10 fix: a mismatch must set degraded=true and refuse to run the module.
    // The old behavior was a silent continue WITHOUT setting degraded (the bug).
    const rule = {
      id: 'r-checksum', framework: ['generic'] as string[], category: 'secrets' as const,
      tier: 'pro' as const, severity: 'high' as const,
      matcher: { type: 'pattern' as const, fileGlob: '**/*.ts', patterns: ['x'], antiPatterns: [] },
      explanation: 'T', recommendation: 'F',
      implType: 'coderef', codeRef: { moduleId: 'stub', exportName: 'stubCheck', minCliVersion: '0.1.0', checksum: 'wrong' },
    } as QualityGateRule
    const manifest: ChecksumManifest = { stub: 'correct' }

    const result = runCoderefRules([rule], [], POLICY_STUB, '1.0.0', STUB_TABLE, manifest)
    expect(result.findings).toHaveLength(0)
    expect(result.degraded).toBe(true)
    expect(result.warnings[0]).toMatch(/CODEREF_CHECKSUM_MISMATCH/)
  })
})

describe('TC-CD-02 — no manifest → checksum check skipped, rule runs', () => {
  it('absent manifest allows rule to run regardless of checksum field', () => {
    const rule = {
      id: 'r-no-manifest', framework: ['generic'] as string[], category: 'secrets' as const,
      tier: 'pro' as const, severity: 'high' as const,
      matcher: { type: 'pattern' as const, fileGlob: '**/*.ts', patterns: ['x'], antiPatterns: [] },
      explanation: 'T', recommendation: 'F',
      implType: 'coderef', codeRef: { moduleId: 'stub', exportName: 'stubCheck', minCliVersion: '0.1.0', checksum: 'some-hash' },
    } as QualityGateRule

    const result = runCoderefRules([rule], [], POLICY_STUB, '1.0.0', STUB_TABLE)
    expect(result.findings).toHaveLength(1)
    expect(result.degraded).toBe(false)
  })
})

describe('TC-CD-03 — missing codeRef pointer warns, no crash', () => {
  it('rule with implType:coderef but no codeRef field → warn, skip, degraded=false', () => {
    const rule = {
      id: 'r-no-ptr', framework: ['generic'] as string[], category: 'secrets' as const,
      tier: 'pro' as const, severity: 'high' as const,
      matcher: { type: 'pattern' as const, fileGlob: '**/*.ts', patterns: ['x'], antiPatterns: [] },
      explanation: 'T', recommendation: 'F',
      implType: 'coderef',
      // codeRef intentionally omitted
    } as QualityGateRule

    const result = runCoderefRules([rule], [], POLICY_STUB, '1.0.0', STUB_TABLE)
    expect(result.findings).toHaveLength(0)
    expect(result.degraded).toBe(false)
    expect(result.warnings[0]).toMatch(/no codeRef pointer/)
  })
})

describe('TC-CD-04 — DEFAULT_DISPATCH_TABLE has all 5 modules', () => {
  it('table contains secrets, auth, database, deployment, payments', () => {
    const keys = Object.keys(DEFAULT_DISPATCH_TABLE)
    expect(keys).toContain('secrets:secretsCheck')
    expect(keys).toContain('auth:authCheck')
    expect(keys).toContain('database:databaseCheck')
    expect(keys).toContain('deployment:deploymentCheck')
    expect(keys).toContain('payments:payments')
    expect(keys).toHaveLength(5)
  })

  it('each entry has a callable run function', () => {
    for (const [key, mod] of Object.entries(DEFAULT_DISPATCH_TABLE)) {
      expect(typeof mod.run, `${key}.run should be a function`).toBe('function')
    }
  })
})

describe('TC-CD-05 — runProRulesWithDispatch mixed rules propagate degraded', () => {
  it('version-skipped coderef sets degraded=true even when declarative findings exist', () => {
    const declRule = {
      id: 'decl', framework: ['generic'] as string[], category: 'secrets' as const,
      tier: 'pro' as const, severity: 'high' as const,
      matcher: { type: 'pattern' as const, fileGlob: '**/*.ts', patterns: ['console\\.log'], antiPatterns: [] },
      explanation: 'T', recommendation: 'F',
      implType: 'declarative',
    } as QualityGateRule

    const coderefRule = {
      id: 'coderef', framework: ['generic'] as string[], category: 'secrets' as const,
      tier: 'pro' as const, severity: 'high' as const,
      matcher: { type: 'pattern' as const, fileGlob: '**/*.ts', patterns: ['x'], antiPatterns: [] },
      explanation: 'T', recommendation: 'F',
      implType: 'coderef', codeRef: { moduleId: 'stub', exportName: 'stubCheck', minCliVersion: '999.0.0' },
    } as QualityGateRule

    const files: FileInfo[] = [{ path: '/p/a.ts', content: 'console.log("hi")', relativePath: 'a.ts' }]
    const result = runProRulesWithDispatch([declRule, coderefRule], files, POLICY_STUB, '0.1.0', STUB_TABLE)

    expect(result.degraded).toBe(true)
    expect(result.findings).toHaveLength(1) // only declarative
    expect(result.warnings[0]).toMatch(/requires CLI|minCliVersion/)
  })
})

describe('TC-CD-06 — semverLt edge cases', () => {
  it('equal versions return false', () => {
    expect(semverLt('1.2.3', '1.2.3')).toBe(false)
  })
  it('major less returns true', () => {
    expect(semverLt('0.9.9', '1.0.0')).toBe(true)
  })
  it('patch less returns true', () => {
    expect(semverLt('1.2.2', '1.2.3')).toBe(true)
  })
  it('patch greater returns false', () => {
    expect(semverLt('1.2.4', '1.2.3')).toBe(false)
  })
})
