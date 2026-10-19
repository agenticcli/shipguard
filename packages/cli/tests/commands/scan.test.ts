/**
 * scan.ts command wiring tests
 *
 * Tests that the exit code wiring in scanCommand() correctly reflects
 * result.degraded (which includes coderef-skip degradation from the scanner)
 * and not just the local `degraded` flag (which only covers pro-fetch failure).
 *
 * The resolveExitCode() function itself is already tested in ws2-core-orchestration.
 * These tests cover the *argument* passed to it from the command layer.
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
import type { ScanResult, Policy } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Minimal ScanResult + Policy stub helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Mocks — must use factory functions (vi.mock is hoisted, .mockResolvedValue
// is not available at hoist time, so we return implementation directly)
// ---------------------------------------------------------------------------

vi.mock('../../src/core/scanner.js', () => ({
  scan: vi.fn().mockResolvedValue(makeScanResult()),
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

// Load the command AFTER vi.mock() hoisting
const { scan: mockScan } = await import('../../src/core/scanner.js')
const { scanCommand } = await import('../../src/commands/scan.js')

afterEach(() => {
  vi.clearAllMocks()
  // Reset mock to default non-degraded result after each test
  vi.mocked(mockScan).mockResolvedValue(makeScanResult())
})

// ---------------------------------------------------------------------------
// TC-EXIT-17: A1 contract — degradation NEVER changes the exit code (2026-07-13)
// ---------------------------------------------------------------------------
//
// SUPERSEDES the pre-A1 "coderef-skip degradation reaches exit code 2" test
// that lived here. Under A1 (),
// `degraded`/`degradedReasons` are JSON-only fields — exit code stays 0
// (scan completed) regardless of degradation, because the exit-2 slot is
// reserved strictly for config errors now (review finding: exit 2 doubling
// as both "config error" and "degraded scan" left an agent unable to tell
// the two apart from the exit code alone).

describe('TC-EXIT-17 — degradation never changes the exit code (A1)', () => {
  it('FAIL-BEFORE regression: scan() returns degraded=true (coderef-skip, no --pro) ' +
     '→ exit 0, NOT 2 (degradation is surfaced via JSON `degraded`, exit code is unaffected)', async () => {
    vi.mocked(mockScan).mockResolvedValue(
      makeScanResult({ degraded: true }) // coderef-skip degradation from scanner
    )

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit(${code})`)
    })

    const cmd = scanCommand()
    // Under A1, a degraded-but-completed scan does not call process.exit at all
    // (falls through to the default return, same as a clean exit-0 scan).
    await expect(
      cmd.parseAsync(['node', 'scan', '--json'])
    ).resolves.toBeDefined()

    expect(exitSpy).not.toHaveBeenCalled()
  })

  it('scan() returns degraded=false → exit 0 (no degradation at all)', async () => {
    vi.mocked(mockScan).mockResolvedValue(
      makeScanResult({ degraded: false })
    )

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit(${code})`)
    })

    const cmd = scanCommand()
    // Should complete without calling process.exit (exit 0 means no process.exit call)
    await expect(
      cmd.parseAsync(['node', 'scan', '--json'])
    ).resolves.toBeDefined()

    expect(exitSpy).not.toHaveBeenCalled()
  })

  it('degraded=true + --strict + blocking findings → exit 1 (strict-blocking still wins; ' +
     'degradation does not soften a --strict hard gate)', async () => {
    vi.mocked(mockScan).mockResolvedValue(
      makeScanResult({
        degraded: true,
        riskScore: {
          score: 80,
          recommendation: 'DO_NOT_SHIP',
          totalFindings: 1,
          criticalCount: 1,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
          infoCount: 0,
          blockingCount: 1,
        },
      })
    )

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit(${code})`)
    })

    const cmd = scanCommand()
    await expect(
      cmd.parseAsync(['node', 'scan', '--json', '--strict'])
    ).rejects.toThrow('process.exit(1)')

    expect(exitSpy).toHaveBeenCalledWith(1)
  })
})
