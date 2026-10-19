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
    expect(content).toContain('# ShipGuard Release Report')
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
    // New format: ## SUMMARY at top with verdict + attitude
    expect(content).toContain('## SUMMARY')
    expect(content).toContain('65/100')
    expect(content).toContain('DO_NOT_SHIP')
    expect(content).toContain('42')        // Files scanned
    expect(content).toContain('2026-05-27')  // Generated timestamp
  })

  it('lists findings by severity', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')
    const result = makeResult()

    await generateReport(result, outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('## Critical Findings')
    expect(content).toContain('Hardcoded API Key')
    expect(content).toContain('## Medium Findings')
    expect(content).toContain('.env tracked in git')
  })

  it('shows "None" for severity sections with no findings', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')
    const result = makeResult()

    await generateReport(result, outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    // High and Low should show None since result has no high/low findings
    const highSection = content.split('## High Findings')[1]?.split('##')[0] ?? ''
    expect(highSection).toContain('None')
    const lowSection = content.split('## Low Findings')[1]?.split('##')[0] ?? ''
    expect(lowSection).toContain('None')
  })

  it('includes file and line number in finding entry', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')

    await generateReport(makeResult(), outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('**File:** lib/api.ts:5')
  })

  it('includes evidence in finding entry', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')

    await generateReport(makeResult(), outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('**Evidence:** `sk-proj-abc***`')
  })

  it('includes final recommendation', async () => {
    const dir = mkTemp()
    const outputPath = join(dir, 'report.md')

    await generateReport(makeResult(), outputPath)

    const content = readFileSync(outputPath, 'utf-8')
    expect(content).toContain('## Final Recommendation')
    expect(content).toContain('**DO_NOT_SHIP**')
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
    expect(content).toContain('SAFE_TO_SHIP')
    expect(content).toContain('**Risk Score:** 0/100')
  })
})
