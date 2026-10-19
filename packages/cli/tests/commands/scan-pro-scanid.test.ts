/**
 * scan-pro-scanid.test.ts — scanId idempotency, command-layer wiring.
 *
 * runScan mints ONE stable scanId per logical scan (scan.ts: randomUUID() in the
 * command action) but — before this fix — never passed it to fetchProRules, so the
 * server minted a fresh UUID per request and every dropped-response retry consumed
 * a SECOND credit (money bug; the server-side (userId, scanId) idempotency machinery
 * was dead code for CLI callers).
 *
 * FAIL-BEFORE: fetchProRules was called with 3 args (no scanId — 4th arg undefined).
 * PASS-AFTER:  fetchProRules receives the command's scanId (UUID format) as arg 4.
 *
 * Harness mirrors tests/commands/scan.test.ts (vi.mock + parseAsync).
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
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

const STUB_POLICY: Policy = {
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
  loadPolicy: vi.fn().mockImplementation(async () => STUB_POLICY),
  DEFAULT_POLICY: STUB_POLICY,
}))

vi.mock('../../src/core/git.js', () => ({
  isGitRepo: vi.fn(() => false),
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

// --pro path dynamic imports — all mocked so no network/crypto is involved.
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

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const realFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = realFetch
  vi.clearAllMocks()
})

describe('scanId idempotency — scan --pro passes its stable scanId into fetchProRules', () => {
  it('fetchProRules receives the per-scan UUID scanId as its 4th argument', async () => {
    // The fire-and-forget telemetry-ingest fetch must not hit the network.
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('offline')) as unknown as typeof fetch

    const cmd = scanCommand()
    await cmd.parseAsync(['node', 'scan', '--json', '--pro'])

    expect(mockFetchProRules).toHaveBeenCalledTimes(1)
    const args = vi.mocked(mockFetchProRules).mock.calls[0]
    expect(args[0]).toEqual(['generic'])
    expect(args[2]).toBe('https://agenticcli.dev') // CLI default endpoint (the Next route)
    // FAIL-BEFORE: args[3] was undefined — the command never forwarded its scanId.
    expect(args[3]).toBeDefined()
    expect(String(args[3])).toMatch(UUID_RE)
  })

  it('C2: a Pro scan makes NO call to the dead /api/telemetry/ingest route (it also ignored the opt-out)', async () => {
    // Fail-before: scan.ts POSTed scanId/findings/riskScore to {apiUrl}/api/telemetry/ingest on every
    // non-degraded Pro scan, with no auth header and outside SHIPGUARD_TELEMETRY=0 / DO_NOT_TRACK=1.
    // The route does not exist on prod (404), so it was pure leakage with no consumer.
    const calls: string[] = []
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      calls.push(String(url))
      return Promise.resolve({ ok: true, status: 200 })
    }) as unknown as typeof fetch

    const cmd = scanCommand()
    await cmd.parseAsync(['node', 'scan', '--json', '--pro'])

    expect(mockFetchProRules).toHaveBeenCalledTimes(1) // the functional rules fetch is untouched
    expect(calls.filter((u) => u.includes('/api/telemetry/ingest'))).toEqual([])
    expect(calls).toEqual([]) // nothing else leaves the process from scan.ts (pro fetch is mocked)
  })
})
