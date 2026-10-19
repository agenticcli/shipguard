/**
 * GD.6 — Inventory parser-gate
 *
 * Parses regex-inventory.yaml and FAILS if any entry has a blank or out-of-set
 * disposition.  Allowed values: migrated | non-content | removed.
 *
 * Purpose: ensures the inventory never goes stale (no blank dispositions slip
 * through) and catches any invalid value that is not in the defined set.
 *
 * Proof:
 *   - PASS: the real inventory file (all entries dispositioned after D.4 complete).
 *   - FAIL: a planted blank-disposition entry fails the gate — proved by the
 *     'planted blank entry fails the gate' test case below.
 */

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { parse as parseYaml } from 'yaml'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALLOWED_DISPOSITIONS = new Set(['migrated', 'non-content', 'removed'])

const INVENTORY_PATH = path.resolve(
  __dirname,
  'regex-inventory.yaml',
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface InventoryEntry {
  file: string
  line: number
  primitive: string
  detector: string
  scansContent: boolean
  disposition: string
  note?: string
}

interface Inventory {
  summary: {
    total_sites: number
    counts: Record<string, number>
  }
  entries: InventoryEntry[]
}

/**
 * Parse the inventory YAML and return entries with invalid dispositions.
 */
function findInvalidDispositions(yamlContent: string): Array<{ entry: InventoryEntry; problem: string }> {
  const doc = parseYaml(yamlContent) as Inventory
  const problems: Array<{ entry: InventoryEntry; problem: string }> = []

  for (const entry of doc.entries) {
    const d = entry.disposition
    if (d === '' || d == null) {
      problems.push({
        entry,
        problem: `blank/null disposition`,
      })
    } else if (!ALLOWED_DISPOSITIONS.has(d)) {
      problems.push({
        entry,
        problem: `unknown disposition "${d}" — allowed: ${[...ALLOWED_DISPOSITIONS].join(' | ')}`,
      })
    }
  }

  return problems
}

// ---------------------------------------------------------------------------
// Gate: real inventory must pass
// ---------------------------------------------------------------------------

describe('GD.6 inventory parser-gate', () => {
  it('real inventory: all entries have valid dispositions (migrated | non-content | removed)', () => {
    const yamlContent = fs.readFileSync(INVENTORY_PATH, 'utf8')
    const problems = findInvalidDispositions(yamlContent)

    expect(
      problems,
      `Found ${problems.length} entry/entries with blank or invalid dispositions:\n` +
      problems.map((p) =>
        `  ${p.entry.file}:${p.entry.line} (${p.entry.detector}) — ${p.problem}`
      ).join('\n') +
      '\n\nFix: update each entry to migrated | non-content | removed.',
    ).toHaveLength(0)
  })

  it('real inventory: total_sites count matches entries array length', () => {
    const yamlContent = fs.readFileSync(INVENTORY_PATH, 'utf8')
    const doc = parseYaml(yamlContent) as Inventory

    expect(
      doc.entries.length,
      `summary.total_sites (${doc.summary.total_sites}) must equal entries.length (${doc.entries.length})`,
    ).toBe(doc.summary.total_sites)
  })

  // ---------------------------------------------------------------------------
  // Planted-blank proof: the gate FAILS on a blank entry
  // ---------------------------------------------------------------------------

  it('planted blank entry fails the gate (proves gate detects staleness)', () => {
    // Build a minimal synthetic inventory with one valid entry + one blank-disposition entry
    const plantedYaml = `
summary:
  total_sites: 2
  counts:
    migrated: 1
    non-content: 0
    removed: 0
    pending: 1
entries:
  - file: packages/cli/src/checks/secrets.ts
    line: 48
    primitive: regex-literal
    detector: secrets
    scansContent: true
    disposition: migrated

  - file: packages/cli/src/checks/auth.ts
    line: 23
    primitive: regex-literal
    detector: auth
    scansContent: true
    disposition: ""
`
    const problems = findInvalidDispositions(plantedYaml)

    // Must find exactly 1 problem (the planted blank)
    expect(
      problems.length,
      `Expected the gate to find 1 invalid entry for the planted blank disposition, found ${problems.length}`,
    ).toBe(1)

    expect(problems[0].problem).toContain('blank')
    expect(problems[0].entry.file).toBe('packages/cli/src/checks/auth.ts')
  })

  it('planted out-of-set disposition fails the gate', () => {
    const plantedYaml = `
summary:
  total_sites: 1
  counts:
    migrated: 0
    non-content: 0
    removed: 0
    pending: 1
entries:
  - file: packages/cli/src/checks/secrets.ts
    line: 48
    primitive: regex-literal
    detector: secrets
    scansContent: true
    disposition: pending
`
    const problems = findInvalidDispositions(plantedYaml)

    expect(problems.length).toBe(1)
    expect(problems[0].problem).toContain('"pending"')
  })
})
