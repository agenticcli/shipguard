/**
 * TDD tests for core/render.ts — verbose-by-default gamified scan output.
 *
 * Tests cover:
 *  - findingsFpLabel: confidence → false-positive label mapping
 *  - findingsByCategoryTable: category breakdown counting
 *  - verdictPanel: panel contains verdict + agenticcli.dev links
 *  - welcomeBanner: shows once, suppressed second run (mock marker)
 *  - progressBar: correct bar rendering
 *  - shouldShowProgress: TTY + quiet + machine output gates
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { Finding, ScanResult } from '@agenticcli/shared'
import { bundledRulesMeta } from '../../src/core/bundled-rules.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = []

function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-render-test-'))
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  }
  vi.unstubAllEnvs()
})

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'test-finding',
    title: 'Test Finding',
    severity: 'high',
    category: 'secrets',
    file: 'src/config.ts',
    line: 42,
    explanation: 'A test finding',
    recommendation: 'Fix it',
    blocking: true,
    ...overrides,
  }
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
    filesScanned: 42,
    timestamp: '2026-06-10T00:00:00.000Z',
    policyUsed: 'my-app',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Import after test setup
// ---------------------------------------------------------------------------

const {
  findingFpLabel,
  findingsByCategoryTable,
  verdictPanel,
  welcomeBanner,
  renderProgressBar,
  shouldShowProgress,
  renderFindingsSummary,
  coverageLine,
  displayWidth,
} = await import('../../src/core/render.js')

// ---------------------------------------------------------------------------
// findingFpLabel — confidence → false-positive label
// ---------------------------------------------------------------------------

describe('findingFpLabel', () => {
  it('HIGH confidence → "low false-positive chance"', () => {
    const label = findingFpLabel('HIGH')
    expect(label).toMatch(/low false.positive/i)
  })

  it('MEDIUM confidence → "moderate"', () => {
    const label = findingFpLabel('MEDIUM')
    expect(label).toMatch(/moderate/i)
  })

  it('LOW confidence → "higher false-positive"', () => {
    const label = findingFpLabel('LOW')
    expect(label).toMatch(/higher false.positive/i)
  })

  it('undefined → "unrated"', () => {
    const label = findingFpLabel(undefined)
    expect(label).toMatch(/unrated/i)
  })

  it('null-like (treated as no confidence) → "unrated"', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const label = findingFpLabel(null as any)
    expect(label).toMatch(/unrated/i)
  })
})

// ---------------------------------------------------------------------------
// findingsByCategoryTable — per-category finding counts
// ---------------------------------------------------------------------------

describe('findingsByCategoryTable', () => {
  it('returns a string with each category that has findings', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'secrets', severity: 'critical' }),
      makeFinding({ category: 'secrets', severity: 'high' }),
      makeFinding({ category: 'auth', severity: 'medium' }),
    ]
    const table = findingsByCategoryTable(findings)
    expect(table).toContain('secrets')
    expect(table).toContain('auth')
    expect(table).toContain('2') // secrets count
    expect(table).toContain('1') // auth count
  })

  it('returns empty/no-findings message when findings array is empty', () => {
    const table = findingsByCategoryTable([])
    // Should say something like "none" or "0 findings" or empty string is fine
    // as long as it doesn't throw and doesn't contain phantom categories
    expect(typeof table).toBe('string')
    expect(table).not.toContain('secrets')
    expect(table).not.toContain('auth')
  })

  it('includes all categories present in findings', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'database' }),
      makeFinding({ category: 'payments' }),
      makeFinding({ category: 'deployment' }),
    ]
    const table = findingsByCategoryTable(findings)
    expect(table).toContain('database')
    expect(table).toContain('payments')
    expect(table).toContain('deployment')
  })

  it('groups by severity within category breakdown', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'secrets', severity: 'critical' }),
      makeFinding({ category: 'secrets', severity: 'high' }),
      makeFinding({ category: 'secrets', severity: 'high' }),
    ]
    const table = findingsByCategoryTable(findings)
    // table should reflect 1 critical + 2 high in secrets
    expect(table).toContain('secrets')
  })
})

// ---------------------------------------------------------------------------
// verdictPanel — gamified summary
// ---------------------------------------------------------------------------

describe('verdictPanel', () => {
  it('SAFE_TO_SHIP includes green check or "SAFE" and agenticcli.dev', () => {
    const result = makeScanResult({
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
      filesScanned: 10,
    })
    const panel = verdictPanel(result, 1234)
    // Strip ANSI for assertions
    const stripped = panel.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped).toMatch(/SAFE_TO_SHIP|SAFE TO SHIP/i)
    expect(stripped).toContain('agenticcli.dev')
  })

  it('DO_NOT_SHIP includes "DO_NOT_SHIP" or "DO NOT SHIP" and agenticcli.dev', () => {
    const result = makeScanResult({
      riskScore: {
        score: 80,
        recommendation: 'DO_NOT_SHIP',
        totalFindings: 5,
        criticalCount: 2,
        highCount: 3,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        blockingCount: 5,
      },
      findings: [
        makeFinding({ severity: 'critical', category: 'secrets' }),
        makeFinding({ severity: 'critical', category: 'secrets' }),
        makeFinding({ severity: 'high', category: 'auth' }),
      ],
    })
    const panel = verdictPanel(result, 2500)
    const stripped = panel.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped).toMatch(/DO_NOT_SHIP|DO NOT SHIP/i)
    expect(stripped).toContain('agenticcli.dev')
  })

  it('REVIEW_BEFORE_SHIP is present when recommendation is REVIEW_BEFORE_SHIP', () => {
    const result = makeScanResult({
      riskScore: {
        score: 35,
        recommendation: 'REVIEW_BEFORE_SHIP',
        totalFindings: 2,
        criticalCount: 0,
        highCount: 1,
        mediumCount: 1,
        lowCount: 0,
        infoCount: 0,
        blockingCount: 0,
      },
    })
    const panel = verdictPanel(result, 800)
    const stripped = panel.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped).toMatch(/REVIEW_BEFORE_SHIP|REVIEW BEFORE SHIP/i)
  })

  it('panel contains file count, elapsed time, and docs link', () => {
    const result = makeScanResult({ filesScanned: 99 })
    const panel = verdictPanel(result, 3000)
    const stripped = panel.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped).toContain('99')
    // Elapsed: 3000ms → "3.0s"
    expect(stripped).toMatch(/3\.0s|3000ms/)
    expect(stripped).toContain('https://agenticcli.dev/docs')
  })

  it('panel contains "How ShipGuard helped" line', () => {
    const result = makeScanResult()
    const panel = verdictPanel(result, 500)
    const stripped = panel.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped).toMatch(/helped|safe to ship|caught/i)
  })

  it('panel mentions critical count when critical findings exist', () => {
    const result = makeScanResult({
      riskScore: {
        score: 90,
        recommendation: 'DO_NOT_SHIP',
        totalFindings: 3,
        criticalCount: 3,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        blockingCount: 3,
      },
    })
    const panel = verdictPanel(result, 100)
    const stripped = panel.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped).toContain('3')
  })
})

// ---------------------------------------------------------------------------
// welcomeBanner — first-run, once only
// ---------------------------------------------------------------------------

describe('welcomeBanner', () => {
  it('returns a non-empty welcome string when marker does not exist', () => {
    const configDir = mkTemp()
    const banner = welcomeBanner(configDir)
    expect(typeof banner).toBe('string')
    // Non-empty on first call
    const stripped = banner.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped.trim().length).toBeGreaterThan(0)
    expect(stripped).toMatch(/ShipGuard|shipguard/i)
  })

  it('creates the .welcomed marker file after first call', () => {
    const configDir = mkTemp()
    welcomeBanner(configDir)
    expect(existsSync(join(configDir, '.welcomed'))).toBe(true)
  })

  it('returns empty string on second call (marker exists)', () => {
    const configDir = mkTemp()
    welcomeBanner(configDir) // First call — creates marker
    const second = welcomeBanner(configDir) // Second call
    expect(second).toBe('')
  })

  it('returns empty string when marker already exists at start', () => {
    const configDir = mkTemp()
    writeFileSync(join(configDir, '.welcomed'), '1', 'utf-8')
    const banner = welcomeBanner(configDir)
    expect(banner).toBe('')
  })

  it('welcome banner contains quick-start hint', () => {
    const configDir = mkTemp()
    const banner = welcomeBanner(configDir)
    const stripped = banner.replace(/\x1b\[[0-9;]*m/g, '')
    // Should mention shipguard scan
    expect(stripped).toMatch(/shipguard scan/i)
    // Should mention the docs URL
    expect(stripped).toContain('agenticcli.dev')
  })
})

// ---------------------------------------------------------------------------
// renderProgressBar — hand-rolled bar rendering
// ---------------------------------------------------------------------------

describe('renderProgressBar', () => {
  it('renders correct filled/empty sections', () => {
    // 50% progress with width 10 → 5 filled, 5 empty
    const bar = renderProgressBar(5, 10, 10)
    const stripped = bar.replace(/\x1b\[[0-9;]*m/g, '')
    // Bar should contain filled and empty chars
    expect(stripped).toMatch(/[█░]/)
  })

  it('renders 100% bar when current === total', () => {
    const bar = renderProgressBar(10, 10, 10)
    const stripped = bar.replace(/\x1b\[[0-9;]*m/g, '')
    // Should not contain any empty char
    expect(stripped).not.toContain('░')
    expect(stripped).toContain('█')
  })

  it('renders empty bar when current === 0', () => {
    const bar = renderProgressBar(0, 10, 10)
    const stripped = bar.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped).not.toContain('█')
    expect(stripped).toContain('░')
  })

  it('includes current/total counter', () => {
    const bar = renderProgressBar(3, 7, 10)
    const stripped = bar.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped).toContain('3')
    expect(stripped).toContain('7')
  })
})

// ---------------------------------------------------------------------------
// shouldShowProgress — TTY + quiet + machine output gates
// ---------------------------------------------------------------------------

describe('shouldShowProgress', () => {
  it('returns true when TTY + not quiet + not machine output', () => {
    expect(shouldShowProgress({ isTTY: true, quiet: false, machineOutput: false })).toBe(true)
  })

  it('returns false when isTTY is false (piped/CI)', () => {
    expect(shouldShowProgress({ isTTY: false, quiet: false, machineOutput: false })).toBe(false)
  })

  it('returns false when --quiet', () => {
    expect(shouldShowProgress({ isTTY: true, quiet: true, machineOutput: false })).toBe(false)
  })

  it('returns false when machineOutput (--json or --sarif)', () => {
    expect(shouldShowProgress({ isTTY: true, quiet: false, machineOutput: true })).toBe(false)
  })

  it('returns false when all three are gating', () => {
    expect(shouldShowProgress({ isTTY: false, quiet: true, machineOutput: true })).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// renderFindingsSummary — findings grouped by severity with FP labels
// ---------------------------------------------------------------------------

describe('renderFindingsSummary', () => {
  it('groups findings critical → high → medium → low → info order', () => {
    const findings: Finding[] = [
      makeFinding({ severity: 'info', title: 'Info Finding' }),
      makeFinding({ severity: 'critical', title: 'Critical Finding' }),
      makeFinding({ severity: 'medium', title: 'Medium Finding' }),
    ]
    const output = renderFindingsSummary(findings)
    const stripped = output.replace(/\x1b\[[0-9;]*m/g, '')
    const critIdx = stripped.indexOf('Critical Finding')
    const medIdx = stripped.indexOf('Medium Finding')
    const infoIdx = stripped.indexOf('Info Finding')
    expect(critIdx).toBeLessThan(medIdx)
    expect(medIdx).toBeLessThan(infoIdx)
  })

  it('shows FP label for HIGH confidence finding', () => {
    const findings: Finding[] = [
      makeFinding({ confidence: 'HIGH', title: 'High Conf Finding' }),
    ]
    const output = renderFindingsSummary(findings)
    const stripped = output.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped).toMatch(/low false.positive/i)
  })

  it('shows "unrated" for finding with no confidence', () => {
    const findings: Finding[] = [
      makeFinding({ confidence: undefined, title: 'Unrated Finding' }),
    ]
    const output = renderFindingsSummary(findings)
    const stripped = output.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped).toMatch(/unrated/i)
  })

  it('returns no-findings message when findings is empty', () => {
    const output = renderFindingsSummary([])
    const stripped = output.replace(/\x1b\[[0-9;]*m/g, '')
    expect(stripped.trim()).not.toBe('')
    // Should say something like "No findings" or "clean"
    expect(stripped).toMatch(/no findings|clean|0 findings/i)
  })

  it('includes a legend line explaining confidence levels', () => {
    const findings: Finding[] = [makeFinding()]
    const output = renderFindingsSummary(findings)
    const stripped = output.replace(/\x1b\[[0-9;]*m/g, '')
    // Legend should mention HIGH/MEDIUM/LOW confidence labels
    expect(stripped).toMatch(/confidence|false.positive/i)
  })
})

// ---------------------------------------------------------------------------
// displayWidth — display-width helper (FIX 1)
// ---------------------------------------------------------------------------

describe('displayWidth', () => {
  it('counts plain ASCII characters as width 1 each', () => {
    expect(displayWidth('hello')).toBe(5)
    expect(displayWidth('ab')).toBe(2)
  })

  it('strips ANSI escape sequences (they contribute 0 columns)', () => {
    const colored = '\x1b[32mhello\x1b[0m'
    expect(displayWidth(colored)).toBe(5)
  })

  it('counts common emoji as width 2 (double-width)', () => {
    // ⚠️ = U+26A0 (2) + U+FE0F variation selector (0) = 2
    expect(displayWidth('⚠️')).toBe(2)
    // ✅ U+2705 → in the misc symbols range (≥ U+2600) → 2
    expect(displayWidth('✅')).toBe(2)
    // ⛔ U+26D4 → 2
    expect(displayWidth('⛔')).toBe(2)
    // 🔴 U+1F534 → in U+1F000 range → 2
    expect(displayWidth('🔴')).toBe(2)
  })

  it('handles mixed emoji + plain text correctly', () => {
    // "⚠️ hello" = 2 (emoji) + 1 (space) + 5 (hello) = 8
    expect(displayWidth('⚠️ hello')).toBe(8)
  })

  it('handles ANSI-colored emoji correctly', () => {
    const s = '\x1b[33m⚠️\x1b[0m hello'
    // emoji (2) + space (1) + hello (5) = 8
    expect(displayWidth(s)).toBe(8)
  })

  it('returns 0 for empty string', () => {
    expect(displayWidth('')).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// verdictPanel border alignment — all content lines same display width (FIX 1)
// ---------------------------------------------------------------------------

describe('verdictPanel border alignment', () => {
  it('all content lines (between borders) have identical right-border display width', () => {
    const result = makeScanResult({
      riskScore: {
        score: 80,
        recommendation: 'DO_NOT_SHIP',
        totalFindings: 3,
        criticalCount: 2,
        highCount: 1,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        blockingCount: 3,
      },
      filesScanned: 42,
    })
    const panel = verdictPanel(result, 1500)
    const lines = panel.split('\n').filter((l) => l.trim().length > 0)

    // Content lines: start with │ and end with │ (after stripping ANSI)
    const contentLines = lines.filter((l) => {
      const stripped = l.replace(/\x1b\[[0-9;]*m/g, '')
      return stripped.startsWith('│') || stripped.startsWith('├') || stripped.startsWith('╭') || stripped.startsWith('╰')
    })

    // All border lines should have the same display width
    const widths = contentLines.map((l) => displayWidth(l))
    const uniqueWidths = new Set(widths)
    expect(uniqueWidths.size).toBe(1)
  })

  it('panel with emoji verdict (DO_NOT_SHIP has ⛔) still aligns right border', () => {
    const result = makeScanResult({
      riskScore: {
        score: 99,
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
    const panel = verdictPanel(result, 100)
    const lines = panel.split('\n')
    const contentLines = lines.filter((l) => {
      const stripped = l.replace(/\x1b\[[0-9;]*m/g, '')
      return stripped.startsWith('│') || stripped.startsWith('├') || stripped.startsWith('╭') || stripped.startsWith('╰')
    })
    const widths = contentLines.map((l) => displayWidth(l))
    const uniqueWidths = new Set(widths)
    expect(uniqueWidths.size).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// coverageLine — honest coverage statement
// ---------------------------------------------------------------------------

describe('coverageLine', () => {
  it('mentions checked categories', () => {
    const line = coverageLine()
    expect(line).toMatch(/secrets|auth|payments|database|deployment/i)
  })

  it('points at shipguard login as the way to get the full corpus', () => {
    const line = coverageLine()
    expect(line).toMatch(/login/i)
    expect(line).toMatch(/full current corpus/i)
  })

  // TRUTH GUARD (2026-08-04). This line used to read "Deeper agentic rules available via
  // Pro — some issue classes may be missed on free." No agentic rule exists at any tier
  // (`grep -ri agentic` over all 255 corpus rule files: zero matches), so the CLI was
  // advertising, on every free scan, a capability the product does not have. The claim was
  // even disclosed as false in our own published article. These assertions exist so it
  // cannot come back by accident.
  it('never advertises agentic rules — no such rule exists at any tier', () => {
    // Matched on the CLAIM, not the bare word — the pricing URL is agenticcli.dev, which
    // legitimately contains "agentic".
    expect(coverageLine()).not.toMatch(/agentic\s+(rules?|checks?|detections?)/i)
    expect(coverageLine()).not.toMatch(/may be missed on free/i)
  })

  it('states the real bundled rule count, read from the shipped bundle', () => {
    const line = coverageLine()
    expect(line).toMatch(new RegExp(`${bundledRulesMeta().ruleCount}\\s+bundled rules`))
  })

  it('makes no guarantee and claims no completeness', () => {
    const line = coverageLine()
    expect(line).not.toMatch(/guarantee|guaranteed|we promise|never miss|all issues|100%/i)
  })
})
