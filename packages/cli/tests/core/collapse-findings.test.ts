/**
 * collapse-findings.test.ts — one issue must be one finding .
 *
 * FAIL-BEFORE: `res.setHeader('Access-Control-Allow-Origin', '*')` matched two patterns of
 * `generic.cors.wildcard-origin` (columns 31 and 42) and was reported twice. Severity is
 * additive in the risk score, so at `high` (30 pts) one line scored 60 -> DO_NOT_SHIP.
 * `collapseSameIssueFindings` did not exist and nothing in the scan path collapsed them.
 *
 * The properties worth pinning are the ways this could quietly go wrong in the OTHER
 * direction (hiding a real detection):
 *   - it must never merge different rules, files, or lines;
 *   - it must never fold an acknowledged (suppressed) finding into an active one;
 *   - it must never soften a report (legacy secrets share one id across differing severities);
 *   - it must never touch a finding with no line.
 */

import { describe, it, expect } from 'vitest'
import type { Finding } from '@agenticcli/shared'
import { collapseSameIssueFindings } from '../../src/core/collapse-findings.js'
import { computeRiskScore } from '../../src/core/risk-score.js'

function f(partial: Partial<Finding> & Pick<Finding, 'id' | 'file'>): Finding {
  return {
    title: 't',
    severity: 'high',
    category: 'deployment',
    explanation: 'e',
    recommendation: 'r',
    blocking: false,
    ...partial,
  } as Finding
}

describe('same rule, same file, same line -> one finding', () => {
  it('collapses the CORS double-match (cols 31 and 42) to the EARLIEST column', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'generic.cors.wildcard-origin', file: 'a.ts', line: 3, column: 42, evidence: 'later' }),
      f({ id: 'generic.cors.wildcard-origin', file: 'a.ts', line: 3, column: 31, evidence: 'earlier' }),
    ])
    expect(r.findings).toHaveLength(1)
    expect(r.findings[0].column).toBe(31)
    expect(r.findings[0].evidence).toBe('earlier')
    expect(r.notes).toEqual([
      { id: 'generic.cors.wildcard-origin', file: 'a.ts', line: 3, keptColumn: 31, droppedColumn: 42 },
    ])
  })

  it('the score of one line is one finding, not two (60 -> 30 => REVIEW_BEFORE_SHIP)', () => {
    const dup = [
      f({ id: 'generic.cors.wildcard-origin', file: 'a.ts', line: 3, column: 31 }),
      f({ id: 'generic.cors.wildcard-origin', file: 'a.ts', line: 3, column: 42 }),
    ]
    expect(computeRiskScore(dup).score).toBe(60)
    expect(computeRiskScore(dup).recommendation).toBe('DO_NOT_SHIP')
    const one = collapseSameIssueFindings(dup).findings
    expect(computeRiskScore(one).score).toBe(30)
    expect(computeRiskScore(one).recommendation).toBe('REVIEW_BEFORE_SHIP')
  })

  it('three matches on one line collapse to one', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts', line: 1, column: 5 }),
      f({ id: 'r', file: 'a.ts', line: 1, column: 20 }),
      f({ id: 'r', file: 'a.ts', line: 1, column: 60 }),
    ])
    expect(r.findings.map((x) => x.column)).toEqual([5])
    expect(r.notes).toHaveLength(2)
  })

  it('keeps the survivors in their original relative order', () => {
    const a = f({ id: 'b-rule', file: 'z.ts', line: 9, column: 1 })
    const b = f({ id: 'a-rule', file: 'a.ts', line: 1, column: 9 })
    const c = f({ id: 'a-rule', file: 'a.ts', line: 1, column: 2 })
    const r = collapseSameIssueFindings([a, b, c])
    expect(r.findings).toEqual([a, c])
  })
})

describe('never merges things that are different', () => {
  it('different lines stay separate', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts', line: 1, column: 1, evidence: 'x' }),
      f({ id: 'r', file: 'a.ts', line: 2, column: 1, evidence: 'x' }),
    ])
    expect(r.findings).toHaveLength(2)
  })

  it('different files stay separate', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts', line: 1, column: 1 }),
      f({ id: 'r', file: 'b.ts', line: 1, column: 1 }),
    ])
    expect(r.findings).toHaveLength(2)
  })

  it('different rule ids on the same line stay separate', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'rule.one', file: 'a.ts', line: 1, column: 1 }),
      f({ id: 'rule.two', file: 'a.ts', line: 1, column: 1 }),
    ])
    expect(r.findings).toHaveLength(2)
  })

  it('a finding with NO line is never collapsed', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts' }),
      f({ id: 'r', file: 'a.ts' }),
    ])
    expect(r.findings).toHaveLength(2)
  })

  it('a suppressed finding is never folded into an active one (and vice versa)', () => {
    const active = f({ id: 'r', file: 'a.ts', line: 1, column: 30 })
    const acked = f({ id: 'r', file: 'a.ts', line: 1, column: 5, suppressed: true })
    const r = collapseSameIssueFindings([active, acked])
    expect(r.findings).toHaveLength(2)
  })

  it('two suppressed duplicates still collapse to one suppressed finding', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts', line: 1, column: 30, suppressed: true }),
      f({ id: 'r', file: 'a.ts', line: 1, column: 5, suppressed: true }),
    ])
    expect(r.findings).toHaveLength(1)
    expect(r.findings[0].suppressed).toBe(true)
    expect(r.findings[0].column).toBe(5)
  })
})

describe('never softens a report', () => {
  it('keeps the HIGHEST severity when one shared id carries different severities', () => {
    // The legacy secrets check reports every pattern under `hardcoded_secret`, each with its
    // own severity. Earliest-wins alone would let a `high` mask a `critical` on the same line.
    const r = collapseSameIssueFindings([
      f({ id: 'hardcoded_secret', file: 'a.ts', line: 4, severity: 'high' }),
      f({ id: 'hardcoded_secret', file: 'a.ts', line: 4, severity: 'critical' }),
    ])
    expect(r.findings).toHaveLength(1)
    expect(r.findings[0].severity).toBe('critical')
  })

  it('on equal severity the EARLIEST position wins (line first, then column)', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts', line: 11, column: 1, evidence: 'b' }),
      f({ id: 'r', file: 'a.ts', line: 10, column: 3, evidence: 'a\nb' }),
    ])
    // Line 10 col 3 is earlier than line 11 col 1 even though 1 < 3.
    expect(r.findings).toHaveLength(1)
    expect(r.findings[0].line).toBe(10)
  })
})

describe('multi-line matches (deliberate: a later start INSIDE an earlier match is the same issue)', () => {
  it('collapses a match that starts on a line the earlier match already covers', () => {
    const r = collapseSameIssueFindings([
      // spans lines 10-12 (evidence holds two newlines)
      f({ id: 'r', file: 'a.ts', line: 10, column: 3, evidence: 'a\nb\nc' }),
      // a different pattern of the same rule, starting on line 11 inside that span
      f({ id: 'r', file: 'a.ts', line: 11, column: 1, evidence: 'b' }),
    ])
    expect(r.findings).toHaveLength(1)
    expect(r.findings[0].line).toBe(10)
  })

  it('keeps a match that starts AFTER the earlier one ends', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts', line: 10, column: 3, evidence: 'a\nb' }),
      f({ id: 'r', file: 'a.ts', line: 12, column: 1, evidence: 'c' }),
    ])
    expect(r.findings).toHaveLength(2)
  })

  it('chains: overlap is transitive across a growing cluster', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts', line: 1, column: 1, evidence: 'x\ny' }), // 1-2
      f({ id: 'r', file: 'a.ts', line: 2, column: 1, evidence: 'y\nz' }), // 2-3
      f({ id: 'r', file: 'a.ts', line: 3, column: 1, evidence: 'z' }), //   3
    ])
    expect(r.findings).toHaveLength(1)
    expect(r.findings[0].line).toBe(1)
  })
})

describe('purity', () => {
  it('does not mutate the input array or its findings', () => {
    const input = [
      f({ id: 'r', file: 'a.ts', line: 1, column: 9 }),
      f({ id: 'r', file: 'a.ts', line: 1, column: 1 }),
    ]
    const snapshot = JSON.stringify(input)
    collapseSameIssueFindings(input)
    expect(JSON.stringify(input)).toBe(snapshot)
    expect(input).toHaveLength(2)
  })

  it('returns the same array (no copy) when nothing collapses', () => {
    const input = [f({ id: 'r', file: 'a.ts', line: 1 }), f({ id: 'r', file: 'a.ts', line: 2 })]
    expect(collapseSameIssueFindings(input).findings).toBe(input)
  })
})

describe('distinct secrets never merge (follow-up 1)', () => {
  const aws = (evidence: string, column: number, extra: Partial<Finding> = {}) =>
    f({ id: 'generic.secrets.aws-access-key', category: 'secrets', file: 'a.ts', line: 1, column, evidence, ...extra })

  it('two DIFFERENT keys on one line stay two findings', () => {
    const r = collapseSameIssueFindings([aws('AKIAIOSFODNN7EXAMPLE', 10), aws('AKIAJ2GHKLMNOPQRSTUV', 40)])
    expect(r.findings).toHaveLength(2)
  })

  it('the SAME key matched by two patterns (quoted / bare evidence) merges to one', () => {
    const r = collapseSameIssueFindings([aws("'AKIAIOSFODNN7EXAMPLE'", 9), aws('AKIAIOSFODNN7EXAMPLE', 10)])
    expect(r.findings).toHaveLength(1)
    expect(r.findings[0].column).toBe(9)
  })

  it('a secrets rule is recognised by id even when the category is not `secrets`', () => {
    const mk = (ev: string, col: number) =>
      f({ id: 'generic.secrets.x', category: 'config', file: 'a.ts', line: 1, column: col, evidence: ev })
    expect(collapseSameIssueFindings([mk('AAA', 1), mk('BBB', 9)]).findings).toHaveLength(2)
  })

  it('column-less (legacy, redacted-evidence) secrets findings are never collapsed here', () => {
    const legacy = (sev: Finding['severity']) =>
      f({ id: 'hardcoded_secret', category: 'secrets', file: 'a.ts', line: 1, evidence: '...AKIAIOSF***...', severity: sev })
    expect(collapseSameIssueFindings([legacy('high'), legacy('medium')]).findings).toHaveLength(2)
  })

  it('non-secrets categories keep the old key: the CORS double match still collapses', () => {
    const cors = (col: number) =>
      f({ id: 'generic.cors.wildcard-origin', category: 'deployment', file: 'a.ts', line: 2, column: col, evidence: `e${col}` })
    expect(collapseSameIssueFindings([cors(18), cors(7)]).findings).toHaveLength(1)
  })
})

describe('a trailing newline does not cover the next line (follow-up 2)', () => {
  it("evidence 'a\n' at line 1 does not swallow a distinct match on line 2", () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts', line: 1, column: 1, evidence: 'a\n' }),
      f({ id: 'r', file: 'a.ts', line: 2, column: 1, evidence: 'b' }),
    ])
    expect(r.findings).toHaveLength(2)
  })

  it('CRLF trailing newline is ignored too', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts', line: 1, column: 1, evidence: 'a\r\n' }),
      f({ id: 'r', file: 'a.ts', line: 2, column: 1, evidence: 'b' }),
    ])
    expect(r.findings).toHaveLength(2)
  })

  it('an INTERIOR newline still counts (line 1-2 match absorbs a line-2 start)', () => {
    const r = collapseSameIssueFindings([
      f({ id: 'r', file: 'a.ts', line: 1, column: 1, evidence: 'a\nb\n' }),
      f({ id: 'r', file: 'a.ts', line: 2, column: 1, evidence: 'b' }),
    ])
    expect(r.findings).toHaveLength(1)
  })
})

