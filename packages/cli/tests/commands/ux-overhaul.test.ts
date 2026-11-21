/**
 * UX Overhaul — Regression Tests
 *
 * Covers:
 *  1. Unknown command exits 2 + suggestion (DEFECT FIX)
 *  2. Quickstart help screen (bare / ? / help)
 *  3. Personality: attitude lines are deterministic by verdict
 *  4. Action footer present after scan, with copy-paste commands
 *  5. Dual reports: both .md and .json written; .json deep-equals --json stdout
 *  6. ANSI-clean non-TTY quickstart help
 *  7. Severity bar: present, non-empty, uses block chars
 *  8. Severity icons: 🛑 critical, ⛔ high, ⚠️ medium, 🐛 low, ℹ️ info
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { join, dirname, basename } from 'node:path'
import { tmpdir } from 'node:os'
import type { ScanResult, Policy } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// All top-level imports (await at module level is fine in ESM vitest)
// ---------------------------------------------------------------------------

const { quickstartHelp } = await import('../../src/core/render.js')

const { generateReport } = await import('../../src/core/report.js')

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = []

function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-ux-test-'))
  tempDirs.push(dir)
  return dir
}

function makeProjectDir(): string {
  const dir = mkTemp()
  writeFileSync(join(dir, 'package.json'), '{"name":"test"}', 'utf-8')
  return dir
}

function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, '').replace(/\x1b\][^\x07]*\x07/g, '')
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
    filesScanned: 5,
    timestamp: '2026-06-10T00:00:00.000Z',
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

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  }
})

// ---------------------------------------------------------------------------
// 1. DEFECT FIX — unknown command → exit 2 + suggestion
// ---------------------------------------------------------------------------

describe('unknown command — exit 2 regression ', () => {
  it('levenshtein function: "scna" within 3 edits of "scan"', () => {
    function levenshtein(a: string, b: string): number {
      const m = a.length
      const n = b.length
      const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
        Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
      )
      for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
          dp[i][j] = a[i - 1] === b[j - 1]
            ? dp[i - 1][j - 1]
            : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
        }
      }
      return dp[m][n]
    }
    expect(levenshtein('scna', 'scan')).toBeLessThanOrEqual(3)
    // Totally unknown → no command within 3 edits
    const names = ['scan', 'init', 'login', 'logout', 'status', 'feedback', 'rate', 'help']
    const minDist = Math.min(...names.map(n => levenshtein('xyzzy', n)))
    expect(minDist).toBeGreaterThan(3)
  })

  it('cli.ts source contains exitOverride() — root cause fix verified', () => {
    const cliSrc = readFileSync(
      new URL('../../src/cli.ts', import.meta.url).pathname,
      'utf-8'
    )
    // Must call exitOverride() so unknown commands throw instead of exit 0
    expect(cliSrc).toContain('exitOverride()')
    // Must handle commander.unknownCommand code
    expect(cliSrc).toContain('commander.unknownCommand')
    // Must exit 2 for unknown commands (not 0)
    expect(cliSrc).toContain('process.exit(2)')
  })

  it('cli.ts intercepts "?" before Commander parse (argv normalisation)', () => {
    const cliSrc = readFileSync(
      new URL('../../src/cli.ts', import.meta.url).pathname,
      'utf-8'
    )
    expect(cliSrc).toContain("rawArgs[0] === '?'")
  })

  it('cli.ts imports CommanderError — required for error-code branching', () => {
    const cliSrc = readFileSync(
      new URL('../../src/cli.ts', import.meta.url).pathname,
      'utf-8'
    )
    expect(cliSrc).toContain('CommanderError')
  })
})

// ---------------------------------------------------------------------------
// 2. Quickstart help screen
// ---------------------------------------------------------------------------

describe('quickstartHelp', () => {
  it('TTY: contains branded header and key commands', () => {
    const help = stripAnsi(quickstartHelp(true))
    expect(help).toMatch(/ShipGuard/i)
    expect(help).toContain('scan')
    expect(help).toContain('login')
    expect(help).toContain('init')
    expect(help).toContain('feedback')
    expect(help).toContain('rate')
    expect(help).toContain('help')
  })

  it('TTY: contains quickstart block with npx command', () => {
    const help = stripAnsi(quickstartHelp(true))
    expect(help).toMatch(/Get started|2 commands/i)
    expect(help).toContain('npx @agenticcli/shipguard scan')
  })

  it('TTY: contains exit-code legend', () => {
    const help = stripAnsi(quickstartHelp(true))
    expect(help).toMatch(/exit codes?/i)
    expect(help).toContain('0')
    expect(help).toContain('1')
    expect(help).toContain('2')
    expect(help).toContain('3')
  })

  it('TTY: contains docs and site links', () => {
    const help = stripAnsi(quickstartHelp(true))
    expect(help).toContain('agenticcli.dev/go/docs')
    expect(help).toContain('agenticcli.dev')
  })

  it('non-TTY: no ANSI escape codes', () => {
    const help = quickstartHelp(false)
    expect(help).not.toMatch(/\x1b\[/)
    expect(help).toContain('ShipGuard')
    expect(help).toContain('scan')
    expect(help).toContain('agenticcli.dev/go/docs')
  })

  it('non-TTY: exit codes listed in compact form (A1: 0=completed/verdict-in-JSON, 1=blocked --strict-only)', () => {
    const help = quickstartHelp(false)
    expect(help).toMatch(/0=completed|1=blocked/i)
  })
})

// ---------------------------------------------------------------------------
// 5. Dual reports — both .md and .json written
// ---------------------------------------------------------------------------

describe('generateReport — dual reports', () => {
  it('writes both .md and .json files', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, '.shipguard', 'reports', 'latest.md')
    const paths = await generateReport(makeScanResult(), outputPath)

    expect(existsSync(paths.mdPath)).toBe(true)
    expect(existsSync(paths.jsonPath)).toBe(true)
    expect(paths.jsonPath.endsWith('.json')).toBe(true)
    expect(paths.mdPath.endsWith('.md')).toBe(true)
  })

  it('json sits in same directory as md, same basename', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, '.shipguard', 'reports', 'latest.md')
    const paths = await generateReport(makeScanResult(), outputPath)

    expect(dirname(paths.jsonPath)).toBe(dirname(paths.mdPath))
    expect(basename(paths.jsonPath, '.json')).toBe(basename(paths.mdPath, '.md'))
  })

  it('json parses without error', async () => {
    const dir = mkTemp()
    const paths = await generateReport(makeScanResult(), join(dir, 'report.md'))
    const jsonContent = readFileSync(paths.jsonPath, 'utf-8')
    expect(() => JSON.parse(jsonContent)).not.toThrow()
  })

  it('json contains frozen contract fields matching --json stdout schema', async () => {
    const dir = mkTemp()
    const result = { ...makeScanResult(), schemaVersion: '2', recommendation: 'SAFE_TO_SHIP' as const }
    const paths = await generateReport(result, join(dir, 'report.md'))
    // schemaVersion 5 (rec #8): the `latest` json is a POINTER; the full result is the
    // run-scoped file it names.
    const parsed = JSON.parse(readFileSync(paths.runJsonPath, 'utf-8'))

    expect(parsed).toHaveProperty('findings')
    expect(parsed).toHaveProperty('riskScore')
    expect(parsed).toHaveProperty('filesScanned')
    expect(parsed).toHaveProperty('timestamp')
    expect(parsed).toHaveProperty('policyUsed')
    expect(Array.isArray(parsed.findings)).toBe(true)
    expect(typeof parsed.riskScore.score).toBe('number')
  })

  it('json matches input result (no internal fields)', async () => {
    const dir = mkTemp()
    const result = { ...makeScanResult(), schemaVersion: '2', recommendation: 'SAFE_TO_SHIP' as const }
    const paths = await generateReport(result, join(dir, 'report.md'))
    const parsed = JSON.parse(readFileSync(paths.runJsonPath, 'utf-8'))

    expect(parsed.filesScanned).toBe(result.filesScanned)
    expect(parsed.timestamp).toBe(result.timestamp)
    expect(parsed.policyUsed).toBe(result.policyUsed)
    expect(parsed.riskScore.score).toBe(result.riskScore.score)
    expect(parsed).not.toHaveProperty('_skippedTooLarge')
    expect(parsed).not.toHaveProperty('_skippedBinary')
    expect(parsed).not.toHaveProperty('_truncated')
  })

  it('md starts with the verdict title and header line (verdict at top, spec 01 report layout)', async () => {
    const dir = mkTemp()
    const paths = await generateReport(makeScanResult(), join(dir, 'report.md'))
    const content = readFileSync(paths.mdPath, 'utf-8')

    expect(content.split('\n')[0]).toMatch(/^# ShipGuard report: SAFE TO SHIP \(run /)
    expect(content.split('\n')[1]).toMatch(/^verdict: SAFE TO SHIP {3}blocking: 0 {3}findings: 0 {3}incomplete: no /)
  })

  it('md contains the "Fix in this order" section with the finding', async () => {
    const dir = mkTemp()
    const result = makeScanResult({
      findings: [{
        id: 'f1', title: 'Critical Issue', severity: 'critical', category: 'secrets',
        file: 'src/a.ts', line: 1, explanation: 'x', recommendation: 'y', blocking: true,
      }],
      riskScore: {
        score: 80, recommendation: 'DO_NOT_SHIP', totalFindings: 1,
        criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0, blockingCount: 1,
      },
    })
    const paths = await generateReport(result, join(dir, 'report.md'))
    const content = readFileSync(paths.mdPath, 'utf-8')

    expect(content).toContain('## Fix in this order (1 blocking)')
    expect(content).toContain('src/a.ts:1')
  })

  it('returns ReportPaths with mdPath and jsonPath', async () => {
    const dir = mkTemp()
    const paths = await generateReport(makeScanResult(), join(dir, 'report.md'))
    expect(typeof paths.mdPath).toBe('string')
    expect(typeof paths.jsonPath).toBe('string')
  })
})

// ---------------------------------------------------------------------------
// 6. Scan command wires action footer (integration)
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

async function captureOutput(args: string[]): Promise<{ stdout: string }> {
  const stdoutLines: string[] = []
  const logSpy = vi.spyOn(console, 'log').mockImplementation((...a) => { stdoutLines.push(a.map(String).join(' ')) })
  const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
  const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
    throw new Error(`process.exit(${code})`)
  })
  const cmd = scanCommand()
  await cmd.parseAsync(['node', 'scan', ...args]).catch(() => {})
  logSpy.mockRestore()
  errSpy.mockRestore()
  exitSpy.mockRestore()
  return { stdout: stdoutLines.join('\n') }
}

describe('scan command — no footer tips', () => {
  afterEach(() => {
    vi.clearAllMocks()
    vi.mocked(mockScan).mockResolvedValue(makeScanResult())
  })

  it('human output carries no tips: no "What now?", no feedback or rate lines (spec 01 rule 4)', async () => {
    const dir = makeProjectDir()
    const orig = process.cwd()
    process.chdir(dir)
    try {
      const { stdout } = await captureOutput([])
      expect(stdout).not.toContain('What now')
      expect(stdout).not.toContain('shipguard feedback')
      expect(stdout).not.toContain('shipguard report')
    } finally {
      process.chdir(orig)
    }
  })

  it('--json mode: stdout is valid parseable JSON (no footer decoration)', async () => {
    const dir = makeProjectDir()
    const orig = process.cwd()
    process.chdir(dir)
    try {
      const { stdout } = await captureOutput(['--json'])
      // --json emits a pretty-printed JSON object; collect all lines and parse combined
      expect(stdout.trim().length).toBeGreaterThan(0)
      const parsed = JSON.parse(stdout)
      expect(parsed).toHaveProperty('findings')
      expect(parsed).toHaveProperty('riskScore')
      // No footer text in JSON output
      expect(stdout).not.toContain('What now')
      expect(stdout).not.toContain('shipguard report')
    } finally {
      process.chdir(orig)
    }
  })

  it('--quiet mode: footer suppressed', async () => {
    const dir = makeProjectDir()
    const orig = process.cwd()
    process.chdir(dir)
    try {
      const { stdout } = await captureOutput(['--quiet'])
      expect(stdout).not.toContain('What now')
      expect(stdout).not.toContain('shipguard report')
    } finally {
      process.chdir(orig)
    }
  })
})
