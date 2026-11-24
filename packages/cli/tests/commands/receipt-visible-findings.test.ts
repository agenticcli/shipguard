/**
 * D-19 (release test 0.13.0 rc5): the first-Pro receipt said "Findings from them: 17 (marked [Pro rule] above)"
 * while the screen showed 2 findings and none carried a marker. Two bugs, both in commands/scan.ts:
 *   1. the receipt counted every finding of a rulebook rule, including the ones a shipguard-ignore comment suppressed
 *      (15 of the 17), which the screen does not show;
 *   2. the screen renderer prints `[<plan> rule]` only for a finding with `origin: 'rulebook'`, but scan.ts never set
 *      that on the findings it handed over (only the JSON builder knows `origin`), so no line was marked.
 * Spec: OUTPUT-SPEC 05 "First Pro scan: the receipt": the count is the findings shown, each ends with `[Pro rule]`.
 *
 * Harness: scanner, policy and the rulebook download are mocked at the module edge (as scan-pro-scanid.test.ts does);
 * a signed-in HOME, a terminal stdout and everything else are the real thing.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import type { Finding, Policy, QualityGateRule, ScanResult } from '@agenticcli/shared'
import { loadBundledRules } from '../../src/core/bundled-rules.js'
import { mapAccountPayload, planBlockFrom, acctHash } from '../../src/core/plan.js'

const SUB = 'user_d19'
const NOW_S = Math.floor(Date.now() / 1000)
const EXTRA_ID = 'rulebook.only.extra-rule'

function finding(o: Partial<Finding>): Finding {
  return {
    id: EXTRA_ID, title: 'extra', severity: 'high', category: 'config', file: 'a.ts', line: 1, explanation: 'Extra. More.',
    recommendation: 'Fix it.', blocking: true, confidence: 'HIGH', ...o,
  }
}
// 2 shown + 15 suppressed findings of the rulebook-only rule, 1 shown finding of a general rule.
const FINDINGS: Finding[] = [
  finding({ file: 'shown1.ts' }),
  finding({ file: 'shown2.ts', blocking: false, severity: 'medium' }),
  ...Array.from({ length: 15 }, (_, i) => finding({ file: `hidden${i}.ts`, blocking: false, suppressed: true, suppressionState: 'suppressed' })),
  finding({ id: loadBundledRules()[0].id, file: 'general.ts', blocking: false, severity: 'low' }),
]

function scanResult(): ScanResult {
  const active = FINDINGS.filter((f) => !f.suppressed)
  return {
    findings: FINDINGS,
    riskScore: {
      score: 50, recommendation: 'DO_NOT_SHIP', totalFindings: FINDINGS.length, criticalCount: 0, highCount: 1, mediumCount: 1,
      lowCount: 1, infoCount: 0, blockingCount: active.filter((f) => f.blocking).length,
    },
    recommendation: 'DO_NOT_SHIP', filesScanned: 5, timestamp: new Date().toISOString(), policyUsed: 'test-app', degraded: false,
  } as ScanResult
}

const STUB_POLICY: Policy = {
  version: 1, project: { name: 'test-app', framework: 'auto', risk_profile: 'standard' }, scan: { changed_files_only: false, generate_report: false },
  block: [], warn: [], ignore: { paths: [] }, report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}

vi.mock('../../src/core/scanner.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/core/scanner.js')>()),
  scan: vi.fn().mockImplementation(async () => scanResult()),
}))
vi.mock('../../src/core/policy.js', () => ({
  loadPolicy: vi.fn().mockImplementation(async () => STUB_POLICY),
  DEFAULT_POLICY: STUB_POLICY,
}))
vi.mock('../../src/core/git.js', () => ({
  listGitIgnored: vi.fn(() => null), isGitRepo: vi.fn(() => false), getChangedFiles: vi.fn(() => []),
}))
vi.mock('../../src/core/framework.js', () => ({ detectFrameworks: vi.fn(() => ({ frameworks: [{ name: 'generic' }] })) }))
vi.mock('../../src/core/config-generator.js', () => ({ hasConfig: vi.fn(() => true), generateConfig: vi.fn(() => '.shipguard.yml') }))
vi.mock('../../src/core/pro-scanner.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/core/pro-scanner.js')>()),
  fetchProRules: vi.fn().mockImplementation(async () => ({
    rules: [{ ...loadBundledRules()[0] }, { ...loadBundledRules()[0], id: EXTRA_ID }] as QualityGateRule[],
    creditsRemaining: undefined,
    rulesVersion: 'test-release-1',
    plan: {
      block: planBlockFrom(mapAccountPayload({ iat: NOW_S, exp: NOW_S + 3600, label: 'Pro', account: { status: 'active', text: 'Renews soon.' } }), 'live'),
      token: 'doc', live: true,
    },
    acct: acctHash(SUB), partial: false, tiersApplied: ['free', 'pro'], areaByRuleId: {},
  })),
  // runProRulesWithDispatch is not reached: the scanner is mocked.
}))
vi.mock('../../src/core/telemetry.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/core/telemetry.js')>()),
  sendTelemetry: vi.fn(), telemetryState: () => 'on',
}))

const { scanCommand } = await import('../../src/commands/scan.js')

let home: string
let proj: string
let prevCwd: string
let out: string[]
const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url')
const realFetch = globalThis.fetch

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sg-d19-'))
  proj = join(home, 'proj')
  mkdirSync(proj)
  writeFileSync(join(proj, 'package.json'), '{"name":"d19"}')
  prevCwd = process.cwd()
  process.chdir(proj)
  vi.stubEnv('HOME', home)
  vi.stubEnv('SHIPGUARD_API_KEY', '')
  vi.stubEnv('DO_NOT_TRACK', '1')
  const dir = join(home, '.config', 'shipguard')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, 'credentials.json'), JSON.stringify({
    accessToken: `${b64({ alg: 'none' })}.${b64({ sub: SUB })}.x`, refreshToken: 'r', expiresAt: Date.now() + 3600_000, apiUrl: 'https://agenticcli.dev',
  }), { mode: 0o600 })
  Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true })
  globalThis.fetch = vi.fn().mockRejectedValue(new Error('offline')) as unknown as typeof fetch
  out = []
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')) })
})
afterEach(() => {
  process.chdir(prevCwd)
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
  delete (process.stdout as { isTTY?: boolean }).isTTY
  globalThis.fetch = realFetch
  rmSync(home, { recursive: true, force: true })
})

describe('D-19: the first-Pro receipt matches what the screen shows', () => {
  it('counts only the shown findings of the rulebook rule, and marks each of them', async () => {
    await scanCommand().parseAsync(['node', 'scan', '--pro'])
    const screen = out.join('\n')
    // Fail-before: "Findings from them: 17 (marked [Pro rule] above)."
    expect(screen).toContain('Findings from them: 2 (marked [Pro rule] above).')
    // Fail-before: neither line carried the marker.
    expect(screen).toMatch(/shown1\.ts:1 .*\[Pro rule\]/)
    expect(screen).toMatch(/shown2\.ts:1 .*\[Pro rule\]/)
    // The marker is on exactly the receipt's findings: the general-rule finding and the hidden ones stay unmarked.
    expect(screen.match(/\[Pro rule\]/g)).toHaveLength(2 + 1) // two finding lines + the receipt sentence
    expect(screen).not.toMatch(/general\.ts.*\[Pro rule\]/)
    expect(screen).not.toContain('hidden0.ts')
  })
})
