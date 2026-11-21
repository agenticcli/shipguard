/**
 * W5 expected-diff golden (decision G1 MF5). The 0.13 scan of the generated 812-file app plus the W5
 * overlay must equal tests/golden/expected-diff-0130.json:
 *   - the scan digest equals `expected.sha256`
 *   - baseline minus scan == the listed `removed` rows (each with a reason), nothing added
 *   - every true-positive row is still reported (0 lost)
 *
 * The baseline lines were recorded once from the pre-W5 CLI (cli-0130-20261121 at 7bea077). A later
 * change that adds or removes any finding fails here until the golden is reviewed and re-written.
 */
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'
import { scan } from '../../src/core/scanner.js'
import { buildApp } from '../golden/expected-diff-app.js'

vi.setConfig({ testTimeout: 300_000 })

interface Golden {
  baseline: { findings: number; sha256: string; lines: string[] }
  expected: { findings: number; sha256: string }
  removed: Array<{ id: string; file: string; line: number; category: string; reason: string }>
  added: string[]
  truePositivesKept: Array<{ id: string; file: string }>
  truePositivesLost: number
}
const golden = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../golden/expected-diff-0130.json'), 'utf8')) as Golden
const sha = (lines: string[]): string => createHash('sha256').update([...lines].sort().join('\n')).digest('hex')

describe('expected-diff golden: 812-file app vs the pre-W5 baseline', () => {
  it('baseline lines are intact, every removed row has a known reason, none is added', () => {
    expect(sha(golden.baseline.lines)).toBe(golden.baseline.sha256)
    expect(golden.baseline.lines).toHaveLength(golden.baseline.findings)
    const categories = new Set(['loud-rule', 'test-value', 'git-ignored', 'middleware/auth'])
    for (const row of golden.removed) {
      expect(categories.has(row.category), `${row.id} ${row.file}`).toBe(true)
      expect(row.reason.length).toBeGreaterThan(10)
    }
    expect(golden.added).toEqual([])
    expect(golden.truePositivesLost).toBe(0)
  })

  it('the 0.13 scan equals the golden: only the listed rows are gone, all true positives remain', async () => {
    const root = mkdtempSync(join(tmpdir(), 'sg-w5-golden-'))
    const cwd = process.cwd()
    try {
      buildApp(root)
      process.chdir(root)
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      const lines = result.findings.map((x) => `${x.id}|${x.file}|${x.line}`)
      const base = new Set(golden.baseline.lines)
      const now = new Set(lines)
      const gone = [...base].filter((l) => !now.has(l)).sort()
      const added = [...now].filter((l) => !base.has(l)).sort()
      expect(added).toEqual([])
      expect(gone).toEqual(golden.removed.map((r) => `${r.id}|${r.file}|${r.line}`).sort())
      expect(lines).toHaveLength(golden.expected.findings)
      expect(sha(lines)).toBe(golden.expected.sha256)
      for (const tp of golden.truePositivesKept) {
        expect(result.findings.some((x) => x.id === tp.id && x.file === tp.file), `${tp.id} in ${tp.file}`).toBe(true)
      }
      // the unreadable binary stays named and flagged
      expect(result.degradedReasons?.some((d) => d.code === 'UNSCANNED_UNKNOWN_BINARY')).toBe(true)
    } finally {
      process.chdir(cwd)
      rmSync(root, { recursive: true, force: true })
    }
  })
})
