import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { generateReport } from '../../src/core/report.js'
import type { Finding, ScanResult } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = []

function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-report-test-'))
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // ignore cleanup errors
    }
  }
})

function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  const findings: Finding[] = [
    {
      id: 'hardcoded_secret',
      title: 'Hardcoded API Key',
      severity: 'critical',
      category: 'secrets',
      file: 'lib/api.ts',
      line: 5,
      evidence: 'sk-proj-abc***',
      explanation: 'API key hardcoded in source.',
      recommendation: 'Use environment variables.',
      blocking: true,
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
  ]

  return {
    findings,
    riskScore: {
      score: 65,
      recommendation: 'DO_NOT_SHIP',
      totalFindings: 2,
      criticalCount: 1,
      highCount: 0,
      mediumCount: 1,
      lowCount: 0,
      infoCount: 0,
      blockingCount: 1,
    },
    filesScanned: 42,
    timestamp: '2026-05-27T12:00:00.000Z',
    policyUsed: 'test-app',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('generateReport', () => {
  it('generates valid markdown at specified path', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, '.shipguard', 'reports', 'latest.md')
    const result = makeResult()

    await generateReport(result, outputPath)

    expect(existsSync(outputPath)).toBe(true)
    const content = readFileSync(outputPath, 'utf-8')
    expect(content.split('\n')[0]).toMatch(/^# ShipGuard report: DO NOT SHIP \(run /)
  })

  it('creates parent directories automatically', async () => {
    const dir = mkTemp()
    // Deeply nested path that does not exist yet
    const outputPath = join(dir, 'nested', 'a', 'b', 'report.md')

    await generateReport(makeResult(), outputPath)

    expect(existsSync(outputPath)).toBe(true)
  })

  it('contains summary section with correct score', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')
    const result = makeResult()

    await generateReport(result, outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    // Header line (spec 01): same field names and order as the screen; no score on the report
    expect(content.split('\n')[1]).toMatch(/^verdict: DO NOT SHIP {3}blocking: 1 {3}findings: 2 {3}incomplete: no {3}files: 42 {3}rules: \S+ {3}when: 2026-05-27 12:00 UTC$/)
    expect(content).not.toContain('65/100')
  })

  it('lists findings by severity', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')
    const result = makeResult()

    await generateReport(result, outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('## Fix in this order (1 blocking)')
    expect(content).toContain('CRITICAL lib/api.ts:5  Hardcoded API Key')
    expect(content).toContain('## Also found (1, not blocking)')
    expect(content).toContain('.env tracked in git')
  })

  it('always has the Not scanned and Ignored sections, empty ones shown with a zero count', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')

    await generateReport(makeResult(), outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('## Not scanned (0)')
    expect(content).toContain('## Ignored (0)')
  })

  it('includes file and line number in finding entry', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')

    await generateReport(makeResult(), outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('lib/api.ts:5')
  })

  it('a secret finding never prints its evidence (value hidden)', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')

    await generateReport(makeResult(), outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    expect(content).not.toContain('sk-proj')
    expect(content).toContain('evidence: value hidden')
  })

  it('names the verdict in the title and the header', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')

    await generateReport(makeResult(), outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('# ShipGuard report: DO NOT SHIP')
    expect(content).toContain('verdict: DO NOT SHIP')
  })

  it('handles zero findings gracefully', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')
    const result = makeResult({
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
    })

    await generateReport(result, outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('# ShipGuard report: SAFE TO SHIP')
    expect(content).toContain('findings: 0')
  })
})
