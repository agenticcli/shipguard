// One issue must be ONE finding.
//
// THE DEFECT THIS FIXES 
// ===============================================
// A rule can carry several patterns for one defect (`generic.cors.wildcard-origin` has four
// ways to spell "Access-Control-Allow-Origin: *"). The pattern engine runs every pattern
// independently and emits one finding per match, so
//
//     res.setHeader('Access-Control-Allow-Origin', '*')
//
// matched pattern #1 at column 31 AND pattern #2 at column 42 and became TWO findings for ONE
// line. Severity feeds the risk score additively (core/risk-score.ts), so one line of code
// cost double: at `high` (30 pts) that single line scored 60 and flipped the verdict to
// DO_NOT_SHIP when the honest answer is REVIEW_BEFORE_SHIP.
//
// The hand-written secrets check has the same shape: every one of its patterns reports under
// the single id `hardcoded_secret`, so a line matching two patterns was reported twice.
//
// WHY HERE (and not in the matcher engine)
// ========================================
// The defect exists in two producers (the declarative engine and the legacy check modules)
// and in the union of them. `matcher-contract` is a hash-attested, versioned contract whose
// per-occurrence output is part of the signed canonical form; changing what it emits is a
// contract change. Collapsing at the point where the CLI assembles its findings — after every
// producer, before scoring — fixes all producers in one place and leaves the contract alone.
//
// THE RULE
// ========
// Two findings are the SAME ISSUE when they have the same rule `id`, the same `file`, the same
// suppression state, and either
//   (a) they start on the same line, or
//   (b) the later one starts on a line the earlier one's matched text already covers.
// (b) is the multi-line case: a match's `line` is its START line and its `evidence` is the
// matched text, so `line + (newlines in evidence)` is the last line it touches. Two matches of
// one rule that overlap in the source are one construct reported twice.
//
// Per group of same-issue findings, exactly one survives:
//   - the HIGHEST severity (the legacy secrets check assigns severity per pattern under one
//     shared id, so a naive "keep the first" could silently downgrade a critical to a high —
//     this function never softens a report);
//   - ties broken by the EARLIEST position (line, then column) for findings that carry a
//     column (bundled corpus and pro rules); column-less legacy findings sort as column 0, so
//     for them a tie goes to ORIGINAL (pattern) ORDER;
//   - its fields are kept as-is. Nothing is merged or rewritten, so every `--json` field keeps
//     its meaning; the survivor's `evidence` is the earliest match's text.
//
// DELIBERATE LIMITS
// =================
//  - A finding with NO `line` is never collapsed: without a line we cannot prove two findings
//    are about the same code (mirrors legacy-corpus-map.ts guarantee 1).
//  - Suppression state is part of the key. A suppressed (user-acknowledged) finding is never
//    absorbed into an active one and an active finding is never hidden behind an acknowledged
//    one — both are retained, exactly as before.
//  - Different rule ids are never collapsed here, however similar. Cross-rule overlap between
//    the legacy checks and the corpus is legacy-corpus-map.ts's job.
//  - DISTINCT SECRETS NEVER MERGE. For secrets findings (category `secrets`, or a rule id
//    containing `.secrets.`) the normalised matched value (`evidence`: trimmed, surrounding
//    quotes and `...` stripped) is part of the key, so two different keys on one line stay two
//    findings and only repeat matches of the SAME value merge. Column-less legacy secrets
//    findings are never collapsed here at all: their evidence is redacted to 8 characters, so
//    equal evidence does not prove equal values. `checks/secrets.ts` (SecretDedupe) dedupes those
//    by match span and raw value: overlapping spans or an identical value = one secret.
//  - Order of the surviving findings is the original order, so report ordering is unchanged.

import type { Finding } from '@agenticcli/shared'

const SEVERITY_RANK: Readonly<Record<string, number>> = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
})

/** A dropped duplicate, so the collapse is observable rather than silent. */
export interface CollapseNote {
  id: string
  file: string
  line: number
  /** Column of the surviving finding (undefined for legacy findings, which have none). */
  keptColumn: number | undefined
  /** Column of the finding that was folded into it. */
  droppedColumn: number | undefined
}

export interface CollapseResult {
  findings: Finding[]
  notes: CollapseNote[]
}

function isSecretsFinding(f: Finding): boolean {
  return f.category === 'secrets' || f.id.includes('.secrets.')
}

/** Evidence with surrounding whitespace, quotes and redaction ellipses removed. */
function normaliseEvidence(evidence: string | undefined): string {
  return (evidence ?? '').trim().replace(/^(\.\.\.|['"`])+|(\.\.\.|['"`])+$/g, '').trim()
}

/** Last source line a finding's matched text touches. `line` must be defined. */
function endLineOf(f: Finding): number {
  const start = f.line as number
  if (!f.evidence) return start
  // A trailing newline ends the matched line; it does not cover the next one. Ignore it, or a
  // match like `a\n` on line 1 would swallow a distinct match starting on line 2.
  let end = f.evidence.length
  while (end > 0 && (f.evidence.charCodeAt(end - 1) === 10 || f.evidence.charCodeAt(end - 1) === 13)) end--
  let newlines = 0
  for (let i = 0; i < end; i++) {
    if (f.evidence.charCodeAt(i) === 10) newlines++
  }
  return start + newlines
}

/**
 * true when `a` should displace `b` as the survivor of a cluster. Severity only: the sweep
 * visits a cluster in source order (line, then column) and the incumbent is the earliest, so
 * a tie never displaces it — which is what makes the earliest match the survivor.
 */
function outranks(a: Finding, b: Finding): boolean {
  return (SEVERITY_RANK[a.severity] ?? 0) > (SEVERITY_RANK[b.severity] ?? 0)
}

/**
 * Collapse findings that report the same issue more than once. Pure: no I/O, no mutation of
 * the input array or its findings; survivors keep their original relative order.
 */
export function collapseSameIssueFindings(findings: Finding[]): CollapseResult {
  // Group candidates by (id, file, suppression state). Line-less findings are never candidates.
  const groups = new Map<string, number[]>()
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i]
    if (f.line === undefined) continue
    let valueKey = ''
    if (isSecretsFinding(f)) {
      // Legacy (column-less) secrets evidence is redacted — cannot prove equal values.
      if (f.column === undefined) continue
      valueKey = normaliseEvidence(f.evidence)
    }
    const key = `${f.id}\u0000${f.file}\u0000${f.suppressed ? 's' : 'a'}\u0000${valueKey}`
    const g = groups.get(key)
    if (g) g.push(i)
    else groups.set(key, [i])
  }

  const dropped = new Set<number>()
  const notes: CollapseNote[] = []

  for (const indices of groups.values()) {
    if (indices.length < 2) continue

    // Sweep in source order, growing a cluster while the next finding starts inside it.
    const ordered = [...indices].sort((x, y) => {
      const fx = findings[x]
      const fy = findings[y]
      return (
        (fx.line as number) - (fy.line as number) ||
        (fx.column ?? 0) - (fy.column ?? 0) ||
        x - y
      )
    })

    let cluster: number[] = []
    let clusterEnd = -1
    const flush = (): void => {
      if (cluster.length < 2) return
      let winner = cluster[0]
      for (const idx of cluster.slice(1)) {
        if (outranks(findings[idx], findings[winner])) winner = idx
      }
      for (const idx of cluster) {
        if (idx === winner) continue
        dropped.add(idx)
        const d = findings[idx]
        notes.push({
          id: d.id,
          file: d.file,
          line: d.line as number,
          keptColumn: findings[winner].column,
          droppedColumn: d.column,
        })
      }
    }

    for (const idx of ordered) {
      const f = findings[idx]
      const start = f.line as number
      if (cluster.length > 0 && start <= clusterEnd) {
        cluster.push(idx)
        clusterEnd = Math.max(clusterEnd, endLineOf(f))
      } else {
        flush()
        cluster = [idx]
        clusterEnd = endLineOf(f)
      }
    }
    flush()
  }

  if (dropped.size === 0) return { findings, notes }
  return { findings: findings.filter((_, i) => !dropped.has(i)), notes }
}
