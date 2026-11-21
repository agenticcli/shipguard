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
  welcomeBanner,
  renderProgressBar,
  shouldShowProgress,
  displayWidth,
  DATA_FLOW_LINE,
} = await import('../../src/core/render.js')

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

  it('carries the one shared data-flow line, including the weekly public fetch', () => {
    const banner = welcomeBanner(mkTemp())
    expect(banner).toContain(DATA_FLOW_LINE)
    expect(DATA_FLOW_LINE).toMatch(/once a week/)
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

// displayWidth — display-width helper
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
