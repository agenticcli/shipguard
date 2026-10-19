/**
 * fail-before/pass-after regression suite.
 *
 * BUG (verified, RCA at commands/scan.ts:283-308 pre-fix): every Pro-fetch failure
 * (auth error, 402 out-of-credits, 409, 429 rate-limit, 5xx) was caught, collapsed
 * into a single generic warning, `degraded:true` was set, local rules ran, and the
 * exit code depended ONLY on --strict + blocking findings. Net effect: an agent
 * that explicitly requested the full Pro gate (`--pro`) saw exit 0 exactly when
 * that gate did NOT run — a false-green in agentic loops.
 *
 * FIX: when `--pro` was explicitly requested and the fetch fails, the CLI now
 * fails loud by default — exit 3 (RUNTIME_ERROR) with a structured JSON error
 * carrying a distinct `code` per failure class (AUTH_FAILED / INSUFFICIENT_CREDITS /
 * RATE_LIMITED / SERVER_ERROR / BUNDLE_INVALID), `degraded:false`, and an `action`
 * hint. `--allow-degraded` opts back into the pre-fix fallback (free scan,
 * `degraded:true`, verdict-neutral exit).
 *
 * NOTE: this amends the A1 verdict-neutral exit-code decision for the
 * explicit-Pro-failure path only (see scan.ts resolveExitCode doc comment for the full note).
 *
 * Mock isolation: the network layer (fetchProRules) is mocked at the module
 * boundary — no real HTTP calls. process.exit is spied and made to throw so we
 * can assert the exit code without actually killing the test process.
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

// A minimal stand-in for pro-scanner.ts's ProFetchError — duck-typed via `code`
// (and, for RATE_LIMITED, `retryAfterSeconds`). scan.ts classifies purely by
// reading `.code` off the caught error (never `instanceof`, to keep pro-scanner.js
// lazily imported) — see the type-only import comment in scan.ts.
class FakeProFetchError extends Error {
  code: string
  retryAfterSeconds?: number
  constructor(code: string, message: string, retryAfterSeconds?: number) {
    super(message)
    this.name = 'ProFetchError'
    this.code = code
    this.retryAfterSeconds = retryAfterSeconds
  }
}

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

vi.mock('../../src/core/framework.js', () => ({
  detectFrameworks: vi.fn(() => ({ frameworks: [{ name: 'generic' }] })),
}))

vi.mock('../../src/core/config-generator.js', () => ({
  hasConfig: vi.fn(() => true), // skip auto-config generation noise
  generateConfig: vi.fn(() => '.shipguard.yml'),
}))

const mockFetchProRules = vi.fn()
vi.mock('../../src/core/pro-scanner.js', () => ({
  fetchProRules: mockFetchProRules,
}))

const { scanCommand } = await import('../../src/commands/scan.js')
const { logger } = await import('../../src/utils/logger.js')

afterEach(() => {
  vi.clearAllMocks()
})

/** Runs scanCommand with --pro + --json, spying process.exit so it throws instead of killing the test. */
async function runProScan(extraArgs: string[]): Promise<{ exitCode: number | undefined; stdoutJson: unknown }> {
  const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null) => {
    throw new Error(`__EXIT_${code}__`)
  })
  const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

  const cmd = scanCommand()
  let exitCode: number | undefined
  try {
    await cmd.parseAsync(['node', 'scan', '--pro', '--json', ...extraArgs])
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    const m = msg.match(/__EXIT_(\d+)__/)
    if (m) exitCode = Number(m[1])
    else throw err
  }

  // Find the JSON payload logged to stdout (console.log), if any.
  const jsonCalls = logSpy.mock.calls
    .map((args) => args[0])
    .filter((arg): arg is string => typeof arg === 'string')
  let stdoutJson: unknown
  for (const call of jsonCalls) {
    try {
      stdoutJson = JSON.parse(call)
    } catch {
      /* not JSON, skip */
    }
  }

  exitSpy.mockRestore()
  logSpy.mockRestore()
  return { exitCode, stdoutJson }
}

describe('explicit --pro fetch-failure behavior matrix', () => {
  const FAILURE_CLASSES: Array<{ code: string; message: string; retryAfterSeconds?: number }> = [
    { code: 'AUTH_FAILED', message: 'Auth expired. Run `shipguard login` again.' },
    { code: 'INSUFFICIENT_CREDITS', message: 'No credits. Buy at https://agenticcli.dev/dashboard/billing' },
    { code: 'RATE_LIMITED', message: 'Rate limited (429): too many pro rule fetches.', retryAfterSeconds: 30 },
    { code: 'SERVER_ERROR', message: 'Rule fetch failed (503): Service Unavailable' },
    { code: 'BUNDLE_INVALID', message: 'legacy-bundle-rejected: attestation required' },
    // platform-unavailable-20261018 — the platform's "over plan limits / deployment disabled" 503.
    { code: 'PLATFORM_UNAVAILABLE', message: 'Service temporarily unavailable. Please try again later.', retryAfterSeconds: 300 },
  ]

  for (const { code, message, retryAfterSeconds } of FAILURE_CLASSES) {
    it(`FAIL-BEFORE/PASS-AFTER: ${code} WITHOUT --allow-degraded → exit 3, structured JSON, degraded:false`, async () => {
      mockFetchProRules.mockRejectedValue(new FakeProFetchError(code, message, retryAfterSeconds))

      const { exitCode, stdoutJson } = await runProScan([])

      expect(exitCode).toBe(3)
      expect(stdoutJson).toMatchObject({
        code,
        degraded: false,
      })
      expect(typeof (stdoutJson as { error?: unknown }).error).toBe('string')
      expect(typeof (stdoutJson as { action?: unknown }).action).toBe('string')
      if (retryAfterSeconds !== undefined) {
        expect((stdoutJson as { retryAfterSeconds?: number }).retryAfterSeconds).toBe(retryAfterSeconds)
      }

      // every catch logs loudly (to stderr via logger.error).
      expect(vi.mocked(logger.error)).toHaveBeenCalled()
    })

    it(`${code} WITH --allow-degraded → exit 0 (verdict-neutral), degraded:true`, async () => {
      mockFetchProRules.mockRejectedValue(new FakeProFetchError(code, message, retryAfterSeconds))

      const { exitCode, stdoutJson } = await runProScan(['--allow-degraded'])

      // No process.exit call → default exit 0 (scanCommand falls through to a
      // clean return, same shape as the existing non-pro / no-degradation tests).
      expect(exitCode).toBeUndefined()
      expect(stdoutJson).toMatchObject({ degraded: true })
      expect((stdoutJson as { degradedReasons?: Array<{ code: string }> }).degradedReasons?.[0]?.code)
        .toBe('PRO_RULES_UNAVAILABLE')

      // Still logs loudly — via warn this time (opt-in fallback, not a hard failure).
      expect(vi.mocked(logger.warn)).toHaveBeenCalled()
    })
  }

  it('an UNTYPED/unknown error (no .code) WITHOUT --allow-degraded still fails loud, defaulting to SERVER_ERROR', async () => {
    mockFetchProRules.mockRejectedValue(new Error('some unexpected error with no code'))

    const { exitCode, stdoutJson } = await runProScan([])

    expect(exitCode).toBe(3)
    expect(stdoutJson).toMatchObject({ code: 'SERVER_ERROR', degraded: false })
  })

  it('NoRulesAppliedError (P0-5, pre-existing) is NEVER affected by --allow-degraded — always exit 3', async () => {
    const noRulesErr = new Error('Pro rule fetch resolved zero rules — fail-closed.')
    noRulesErr.name = 'NoRulesAppliedError'
    ;(noRulesErr as unknown as { code: string }).code = 'NO_RULES_APPLIED'
    mockFetchProRules.mockRejectedValue(noRulesErr)

    const { exitCode, stdoutJson } = await runProScan(['--allow-degraded'])

    expect(exitCode).toBe(3)
    expect(stdoutJson).toMatchObject({ code: 'NO_RULES_APPLIED' })
  })
})

describe('platform-unavailable-20261018 — PLATFORM_UNAVAILABLE human + JSON output', () => {
  const PLATFORM_MESSAGE = 'Service temporarily unavailable. Please try again later.'

  /** Runs scanCommand --pro in HUMAN mode (no --json); returns the exit code. */
  async function runHumanProScan(extraArgs: string[] = []): Promise<number | undefined> {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null) => {
      throw new Error(`__EXIT_${code}__`)
    })
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    let exitCode: number | undefined
    try {
      await scanCommand().parseAsync(['node', 'scan', '--pro', ...extraArgs])
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      const m = msg.match(/__EXIT_(\d+)__/)
      if (m) exitCode = Number(m[1])
      else throw err
    } finally {
      exitSpy.mockRestore()
      logSpy.mockRestore()
    }
    return exitCode
  }

  function errorLines(): string {
    return vi.mocked(logger.error).mock.calls.map((c) => String(c[0])).join('\n')
  }

  it('human mode: prints a calm "our side, not your project" message with the suggested wait, exit 3', async () => {
    mockFetchProRules.mockRejectedValue(new FakeProFetchError('PLATFORM_UNAVAILABLE', PLATFORM_MESSAGE, 300))

    const exitCode = await runHumanProScan()

    expect(exitCode).toBe(3)
    const text = errorLines()
    expect(text).toMatch(/ShipGuard's service is temporarily unavailable/)
    expect(text).toMatch(/on our side, not a problem with your project/)
    expect(text).toMatch(/try again in a few minutes/)
    expect(text).toMatch(/suggested wait: 5 min/)
    // The existing opt-in escape hatch is still offered, unchanged.
    expect(text).toMatch(/--allow-degraded/)
    expect(text).not.toMatch(/NaN|undefined/)
  })

  it('human mode without a Retry-After value: no wait hint, still no NaN/undefined', async () => {
    mockFetchProRules.mockRejectedValue(new FakeProFetchError('PLATFORM_UNAVAILABLE', PLATFORM_MESSAGE))

    const exitCode = await runHumanProScan()

    expect(exitCode).toBe(3)
    const text = errorLines()
    expect(text).toMatch(/temporarily unavailable/)
    expect(text).not.toMatch(/suggested wait/)
    expect(text).not.toMatch(/NaN|undefined/)
  })

  it('--json: stable code PLATFORM_UNAVAILABLE, retryAfterSeconds recorded, human action text', async () => {
    mockFetchProRules.mockRejectedValue(new FakeProFetchError('PLATFORM_UNAVAILABLE', PLATFORM_MESSAGE, 300))

    const { exitCode, stdoutJson } = await runProScan([])

    expect(exitCode).toBe(3)
    expect(stdoutJson).toMatchObject({ code: 'PLATFORM_UNAVAILABLE', degraded: false, retryAfterSeconds: 300 })
    expect((stdoutJson as { action: string }).action).toMatch(/not a problem with your project/)
    // review 2026-10-18 finding 3: the JSON action carries the --allow-degraded hint like every other class
    expect((stdoutJson as { action: string }).action).toMatch(/--allow-degraded/)
  })

  it('--json without Retry-After: no retryAfterSeconds key at all', async () => {
    mockFetchProRules.mockRejectedValue(new FakeProFetchError('PLATFORM_UNAVAILABLE', PLATFORM_MESSAGE))

    const { stdoutJson } = await runProScan([])

    expect(stdoutJson).toMatchObject({ code: 'PLATFORM_UNAVAILABLE' })
    expect(stdoutJson).not.toHaveProperty('retryAfterSeconds')
  })

  it('other 503s (SERVER_ERROR) keep the old wording, not the platform message', async () => {
    mockFetchProRules.mockRejectedValue(new FakeProFetchError('SERVER_ERROR', 'Rule fetch failed (503): Service Unavailable'))

    const exitCode = await runHumanProScan()

    expect(exitCode).toBe(3)
    expect(errorLines()).toMatch(/Pro rules request failed \[SERVER_ERROR\]/)
    expect(errorLines()).not.toMatch(/on our side/)
  })
})
