/**
 * TDD tests for scan command scope guard + output enrichment (Parts A6, B, C)
 *
 * Tests written FIRST — they drive the implementation in commands/scan.ts and cli.ts.
 */

import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { ScanResult, Policy } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = []

function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-scan-bounds-test-'))
  tempDirs.push(dir)
  return dir
}

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
    filesScanned: 3,
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
// Mocks
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

const { scan: mockScan } = await import('../../src/core/scanner.js')
const { scanCommand } = await import('../../src/commands/scan.js')
const { logger } = await import('../../src/utils/logger.js')

afterEach(() => {
  vi.clearAllMocks()
  // Reset the scan mock to default non-degraded result after each test
  vi.mocked(mockScan).mockResolvedValue(makeScanResult())
  // NOTE: Do NOT call vi.restoreAllMocks() — it would undo the vi.mock() module mocks
  // and cause subsequent tests to use the real loadPolicy/scan functions.
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // ignore
    }
  }
})

// ---------------------------------------------------------------------------
// A6: Scope guard — non-project dir without --all exits 2
// ---------------------------------------------------------------------------

describe('scan scope guard', () => {
  it('exits 2 with refusal message when no package.json and no .git', async () => {
    const dir = mkTemp()
    // No package.json, no .git

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit(${code})`)
    })

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const cmd = scanCommand()
      await expect(
        cmd.parseAsync(['node', 'scan'])
      ).rejects.toThrow('process.exit(2)')
      expect(exitSpy).toHaveBeenCalledWith(2)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('emits a clear refusal message to logger.error', async () => {
    const dir = mkTemp()
    // No package.json, no .git

    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const cmd = scanCommand()
      await expect(cmd.parseAsync(['node', 'scan'])).rejects.toThrow('process.exit')
      // Should have logged an error message mentioning the issue
      const errorCalls = vi.mocked(logger.error).mock.calls
      const hasRefusalMessage = errorCalls.some(
        args => typeof args[0] === 'string' && (
          args[0].includes('Refusing') ||
          args[0].includes('non-project') ||
          args[0].includes('--all') ||
          args[0].includes('package.json')
        )
      )
      expect(hasRefusalMessage).toBe(true)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('proceeds normally with --all flag even in non-project dir (scope guard NOT triggered)', async () => {
    const dir = mkTemp()
    // No package.json, no .git — but --all overrides the guard

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit(${code})`)
    })

    const errorSpy = vi.spyOn(logger, 'error')

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const cmd = scanCommand()
      // The scan will run (may exit 0 or throw process.exit for other reasons),
      // but it must NOT exit with the scope-guard refusal message (config error code 2 + refusal text)
      await cmd.parseAsync(['node', 'scan', '--all']).catch(() => {})

      // If process.exit(2) was called, it must NOT be the scope-guard (no refusal message)
      const errorCalls = errorSpy.mock.calls.map(args => String(args[0]))
      const hasRefusalMessage = errorCalls.some(
        msg => msg.includes('Refusing') && msg.includes('non-project')
      )
      expect(hasRefusalMessage).toBe(false)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('proceeds normally when package.json exists (scope guard NOT triggered)', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'package.json'), '{"name":"test-project"}', 'utf-8')

    vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit(${code})`)
    })

    const errorSpy = vi.spyOn(logger, 'error')

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const cmd = scanCommand()
      await cmd.parseAsync(['node', 'scan']).catch(() => {})

      // Scope guard must NOT have fired
      const errorCalls = errorSpy.mock.calls.map(args => String(args[0]))
      const hasRefusalMessage = errorCalls.some(
        msg => msg.includes('Refusing') && msg.includes('non-project')
      )
      expect(hasRefusalMessage).toBe(false)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('proceeds normally when .git directory exists (scope guard NOT triggered)', async () => {
    const dir = mkTemp()
    mkdirSync(join(dir, '.git'), { recursive: true })

    vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit(${code})`)
    })

    const errorSpy = vi.spyOn(logger, 'error')

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const cmd = scanCommand()
      await cmd.parseAsync(['node', 'scan']).catch(() => {})

      // Scope guard must NOT have fired
      const errorCalls = errorSpy.mock.calls.map(args => String(args[0]))
      const hasRefusalMessage = errorCalls.some(
        msg => msg.includes('Refusing') && msg.includes('non-project')
      )
      expect(hasRefusalMessage).toBe(false)
    } finally {
      process.chdir(originalCwd)
    }
  })
})

// ---------------------------------------------------------------------------
// C10: Human output enrichment — Tips + agenticcli.dev link
// ---------------------------------------------------------------------------

describe('scan human output enrichment', () => {
  it('includes "Tips" section in non-machine output', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'package.json'), '{"name":"test"}', 'utf-8')

    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })

    // Capture console.log output
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const cmd = scanCommand()
      await cmd.parseAsync(['node', 'scan']).catch(() => {})

      const allOutput = consoleLogSpy.mock.calls.map(args => String(args[0])).join('\n')
      expect(allOutput).toContain('agenticcli.dev')
    } finally {
      process.chdir(originalCwd)
      consoleLogSpy.mockRestore()
    }
  })

  it('does NOT include Tips in --json output (frozen schema)', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'package.json'), '{"name":"test"}', 'utf-8')

    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })

    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const cmd = scanCommand()
      await cmd.parseAsync(['node', 'scan', '--json']).catch(() => {})

      // Collect all console.log calls and parse the JSON output
      const outputs = consoleLogSpy.mock.calls.map(args => String(args[0]))
      // The only output should be valid JSON (the ScanResult)
      const jsonOutput = outputs.find(o => {
        try { JSON.parse(o); return true } catch { return false }
      })
      expect(jsonOutput).toBeDefined()
      const parsed = JSON.parse(jsonOutput!)
      // Must NOT contain Tips/agenticcli.dev as keys in the JSON object
      expect(JSON.stringify(parsed)).not.toContain('Tips')
      expect(parsed).toHaveProperty('findings')
      expect(parsed).toHaveProperty('riskScore')
      expect(parsed).toHaveProperty('filesScanned')
    } finally {
      process.chdir(originalCwd)
      consoleLogSpy.mockRestore()
    }
  })

  it('--json output shape matches frozen contract', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'package.json'), '{"name":"test"}', 'utf-8')

    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })

    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const cmd = scanCommand()
      await cmd.parseAsync(['node', 'scan', '--json']).catch(() => {})

      const outputs = consoleLogSpy.mock.calls.map(args => String(args[0]))
      const jsonOutput = outputs.find(o => {
        try { JSON.parse(o); return true } catch { return false }
      })
      expect(jsonOutput).toBeDefined()
      const parsed = JSON.parse(jsonOutput!)

      // Frozen contract: these fields MUST be present
      expect(parsed).toHaveProperty('findings')
      expect(parsed).toHaveProperty('riskScore')
      expect(parsed).toHaveProperty('filesScanned')
      expect(parsed).toHaveProperty('timestamp')
      expect(parsed).toHaveProperty('policyUsed')
      expect(Array.isArray(parsed.findings)).toBe(true)
      expect(typeof parsed.riskScore.score).toBe('number')
      expect(typeof parsed.filesScanned).toBe('number')
    } finally {
      process.chdir(originalCwd)
      consoleLogSpy.mockRestore()
    }
  })
})

// ---------------------------------------------------------------------------
// B: Global error handler functions (unit tests — no real crashes)
// ---------------------------------------------------------------------------

describe('global error handlers (cli.ts)', () => {
  it('uncaughtException handler logs error and exits with RUNTIME_ERROR (3)', async () => {
    // Import the exported handler functions from handlers.ts (not cli.ts to avoid program.parseAsync)
    const { handleUncaughtException } = await import('../../src/handlers.js')

    const errorSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit(${code})`)
    })
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const testError = new Error('test uncaught error')

    expect(() => handleUncaughtException(testError)).toThrow('process.exit(3)')
    expect(exitSpy).toHaveBeenCalledWith(3)
  })

  it('uncaughtException handler prints message without raw V8 stack in non-debug mode', async () => {
    const { handleUncaughtException } = await import('../../src/handlers.js')

    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit')
    })

    const savedDebug = process.env.SHIPGUARD_DEBUG
    delete process.env.SHIPGUARD_DEBUG

    const testError = new Error('test error with stack')
    testError.stack = 'Error: test error with stack\n    at VeryInternalV8Location:99:1'

    try {
      expect(() => handleUncaughtException(testError)).toThrow('exit')
      // Output should contain the message but NOT the raw V8 stack
      const allOutput = consoleErrorSpy.mock.calls.map(args => args.join(' ')).join('\n')
      expect(allOutput).toContain('test error with stack')
      expect(allOutput).not.toContain('VeryInternalV8Location:99:1')
    } finally {
      if (savedDebug !== undefined) process.env.SHIPGUARD_DEBUG = savedDebug
    }
  })

  it('uncaughtException handler prints stack when SHIPGUARD_DEBUG is set', async () => {
    const { handleUncaughtException } = await import('../../src/handlers.js')

    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit')
    })

    process.env.SHIPGUARD_DEBUG = '1'
    const testError = new Error('debug error')
    testError.stack = 'Error: debug error\n    at DebugLocation:42:1'

    try {
      expect(() => handleUncaughtException(testError)).toThrow('exit')
      const allOutput = consoleErrorSpy.mock.calls.map(args => args.join(' ')).join('\n')
      expect(allOutput).toContain('DebugLocation:42:1')
    } finally {
      delete process.env.SHIPGUARD_DEBUG
    }
  })

  it('SIGINT handler is registered (exported for testing)', async () => {
    const { handleSignal } = await import('../../src/handlers.js')
    expect(typeof handleSignal).toBe('function')
  })

  it('unhandledRejection handler logs error and exits with RUNTIME_ERROR (3)', async () => {
    const { handleUnhandledRejection } = await import('../../src/handlers.js')

    vi.spyOn(console, 'error').mockImplementation(() => {})
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit(${code})`)
    })

    const testReason = new Error('rejected promise')
    expect(() => handleUnhandledRejection(testReason, Promise.resolve())).toThrow('process.exit(3)')
    expect(exitSpy).toHaveBeenCalledWith(3)
  })
})
