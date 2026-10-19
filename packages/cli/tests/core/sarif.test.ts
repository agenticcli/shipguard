import { describe, it, expect } from 'vitest'
import { toSarif } from '../../src/core/sarif.js'
import type { Finding, ScanResult } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
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
      fix: 'Move the key to an environment variable and add the file to .gitignore.',
      cwe: ['CWE-798'],
    },
    {
      id: 'exposed_env',
      title: '.env tracked in git',
      severity: 'medium',
      category: 'secrets',
      file: '.env',
      explanation: '.env file committed to repository.',
      recommendation: 'Add .env to .gitignore.',
      blocking: false,
    },
  ]

  return {
    findings,
    riskScore: {
      score: 75,
      recommendation: 'DO_NOT_SHIP',
      totalFindings: 2,
      criticalCount: 1,
      highCount: 0,
      mediumCount: 1,
      lowCount: 0,
      infoCount: 0,
      blockingCount: 1,
    },
    filesScanned: 10,
    timestamp: '2026-05-27T12:00:00.000Z',
    policyUsed: 'test-app',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('toSarif', () => {
  it('produces a valid SARIF 2.1.0 envelope', () => {
    const log = toSarif(makeResult())

    expect(log.version).toBe('2.1.0')
    expect(log.$schema).toBe('https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json')
    expect(Array.isArray(log.runs)).toBe(true)
    expect(log.runs).toHaveLength(1)
  })

  it('sets tool driver name to "shipguard"', () => {
    const log = toSarif(makeResult())
    expect(log.runs[0].tool.driver.name).toBe('shipguard')
  })

  it('deduplicates rules by finding id', () => {
    // Two findings share the same id 'hardcoded_secret' → only one rule entry
    const result = makeResult()
    result.findings.push({
      id: 'hardcoded_secret',
      title: 'Another Hardcoded Secret',
      severity: 'high',
      category: 'secrets',
      file: 'src/config.ts',
      line: 7,
      explanation: 'Another hardcoded key.',
      recommendation: 'Use env vars.',
      blocking: true,
    })

    const log = toSarif(result)
    const rules = log.runs[0].tool.driver.rules
    const ids = rules.map((r: { id: string }) => r.id)
    expect(ids.filter((id: string) => id === 'hardcoded_secret')).toHaveLength(1)
  })

  it('maps rule fields correctly', () => {
    const log = toSarif(makeResult())
    const rules = log.runs[0].tool.driver.rules as Array<{
      id: string
      shortDescription: { text: string }
      fullDescription: { text: string }
      help: { text: string }
      properties: Record<string, unknown>
    }>

    const secretRule = rules.find((r) => r.id === 'hardcoded_secret')
    expect(secretRule).toBeDefined()
    expect(secretRule!.shortDescription.text).toBe('Hardcoded API Key')
    expect(secretRule!.fullDescription.text).toBe('API key hardcoded in source.')
    expect(secretRule!.help.text).toBe(
      'Move the key to an environment variable and add the file to .gitignore.',
    )
    // CWE from finding.cwe[]
    expect(secretRule!.properties.tags).toContain('CWE-798')
  })

  it('sets security-severity for each severity level', () => {
    const severityMap: Record<string, number> = {
      critical: 9.0,
      high: 7.0,
      medium: 5.0,
      low: 3.0,
      info: 1.0,
    }

    for (const [sev, expected] of Object.entries(severityMap)) {
      const result = makeResult({
        findings: [
          {
            id: `rule_${sev}`,
            title: `Title ${sev}`,
            severity: sev as Finding['severity'],
            category: 'secrets',
            file: 'foo.ts',
            explanation: 'test',
            recommendation: 'fix it',
            blocking: false,
          },
        ],
      })
      const log = toSarif(result)
      const rule = log.runs[0].tool.driver.rules[0]
      expect(rule.properties['security-severity']).toBe(expected)
    }
  })

  it('maps results with correct ruleId and message', () => {
    const log = toSarif(makeResult())
    const results = log.runs[0].results as Array<{
      ruleId: string
      message: { text: string }
    }>

    expect(results).toHaveLength(2)

    const secretResult = results.find((r) => r.ruleId === 'hardcoded_secret')
    expect(secretResult).toBeDefined()
    expect(secretResult!.message.text).toBe('API key hardcoded in source.')
  })

  it('sets level: error for critical and high, warning for medium, note for low/info', () => {
    const cases: Array<[Finding['severity'], string]> = [
      ['critical', 'error'],
      ['high', 'error'],
      ['medium', 'warning'],
      ['low', 'note'],
      ['info', 'note'],
    ]

    for (const [sev, expectedLevel] of cases) {
      const result = makeResult({
        findings: [
          {
            id: 'rule_x',
            title: 'X',
            severity: sev,
            category: 'secrets',
            file: 'a.ts',
            explanation: 'e',
            recommendation: 'r',
            blocking: false,
          },
        ],
      })
      const log = toSarif(result)
      expect(log.runs[0].results[0].level).toBe(expectedLevel)
    }
  })

  it('populates physicalLocation with file uri and line', () => {
    const log = toSarif(makeResult())
    const results = log.runs[0].results as Array<{
      ruleId: string
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string }
          region: { startLine: number }
        }
      }>
    }>

    const secretResult = results.find((r) => r.ruleId === 'hardcoded_secret')!
    const phys = secretResult.locations[0].physicalLocation
    expect(phys.artifactLocation.uri).toBe('lib/api.ts')
    expect(phys.region.startLine).toBe(42)
  })

  it('uses line 1 as fallback when finding has no line', () => {
    const log = toSarif(makeResult())
    const results = log.runs[0].results as Array<{
      ruleId: string
      locations: Array<{ physicalLocation: { region: { startLine: number } } }>
    }>

    const envResult = results.find((r) => r.ruleId === 'exposed_env')!
    expect(envResult.locations[0].physicalLocation.region.startLine).toBe(1)
  })

  it('includes a stable partialFingerprints.primary for each result', () => {
    const log = toSarif(makeResult())
    for (const result of log.runs[0].results) {
      expect(typeof result.partialFingerprints?.primary).toBe('string')
      expect((result.partialFingerprints.primary as string).length).toBeGreaterThan(0)
    }
  })

  it('fingerprints are stable across calls', () => {
    const result = makeResult()
    const log1 = toSarif(result)
    const log2 = toSarif(result)

    for (let i = 0; i < log1.runs[0].results.length; i++) {
      expect(log1.runs[0].results[i].partialFingerprints.primary).toBe(
        log2.runs[0].results[i].partialFingerprints.primary,
      )
    }
  })

  it('handles zero findings gracefully', () => {
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
    const log = toSarif(result)
    expect(log.runs[0].tool.driver.rules).toHaveLength(0)
    expect(log.runs[0].results).toHaveLength(0)
  })
})
