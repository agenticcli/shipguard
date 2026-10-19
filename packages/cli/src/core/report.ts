import { mkdir, rename, writeFile } from 'node:fs/promises'
import { dirname, basename, join } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Finding, ScanResult } from '@agenticcli/shared'
import { effectiveRecommendation } from './verdict.js'

// ---------------------------------------------------------------------------
// Internal helpers — user-view markdown
// ---------------------------------------------------------------------------

function severitySection(title: string, findings: Finding[]): string {
  if (findings.length === 0) {
    return `## ${title}\n\nNone\n`
  }

  const entries = findings.map((f) => {
    const lines: string[] = [`### ${f.title}`]
    lines.push(`- **File:** ${f.file}${f.line != null ? `:${f.line}` : ''}`)
    lines.push(`- **Severity:** ${f.severity}`)
    if (f.evidence != null) lines.push(`- **Evidence:** \`${f.evidence}\``)
    lines.push(`- **Explanation:** ${f.explanation}`)
    lines.push(`- **Recommendation:** ${f.recommendation}`)
    return lines.join('\n')
  })

  return `## ${title}\n\n${entries.join('\n\n')}\n`
}

function buildFixOrder(findings: Finding[]): string {
  const blocking = findings.filter((f) => f.blocking)
  const nonBlocking = findings.filter((f) => !f.blocking)

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info']
  const sorted = [
    ...blocking.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)),
    ...nonBlocking.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)),
  ]

  if (sorted.length === 0) return 'No findings to address.\n'

  return sorted
    .map((f, i) => `${i + 1}. **${f.title}** (${f.severity}) — ${f.file}${f.line != null ? `:${f.line}` : ''}${f.blocking ? ' 🛑 blocking' : ''}`)
    .join('\n')
}

/**
 * Verdict attitude line — deterministic by recommendation.
 *
 * `degraded` gets its own wording: when the verdict is DO_NOT_SHIP because the scan was
 * INCOMPLETE (rec #1), telling the reader to "fix the criticals first" is simply false —
 * there may be no criticals; the problem is that parts of the scan never ran.
 */
function attitudeLine(recommendation: string, degraded?: boolean): string {
  if (degraded) return 'INCOMPLETE — parts of this scan did not run, so it cannot say this is safe.'
  if (recommendation === 'SAFE_TO_SHIP') return 'SHIP IT — nothing blocking. Go make something people want.'
  if (recommendation === 'DO_NOT_SHIP') return 'BLOCKED — shipping this would hurt. Fix the criticals first.'
  return `HOLD UP — findings need eyes before this ships.`
}

/** Top-3 findings to fix (blocking first, then by severity) */
function topThreeFindings(findings: Finding[]): string {
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info']
  const sorted = [...findings].sort((a, b) => {
    if (a.blocking !== b.blocking) return a.blocking ? -1 : 1
    return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  })
  const top = sorted.slice(0, 3)
  if (top.length === 0) return 'None — clean scan.\n'
  return top
    .map((f, i) => `${i + 1}. **${f.title}** (${f.severity}) — ${f.file}${f.line != null ? `:${f.line}` : ''}`)
    .join('\n')
}

/** Severity breakdown table for human report */
function severityBreakdownTable(riskScore: ScanResult['riskScore']): string {
  const rows: Array<[string, number]> = [
    ['Critical', riskScore.criticalCount],
    ['High', riskScore.highCount],
    ['Medium', riskScore.mediumCount],
    ['Low', riskScore.lowCount],
    ['Info', riskScore.infoCount],
  ]
  const lines = ['| Severity | Count |', '|----------|-------|']
  for (const [label, count] of rows) {
    lines.push(`| ${label} | ${count} |`)
  }
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// USER VIEW — .shipguard/reports/latest.md
// ---------------------------------------------------------------------------

function buildUserMarkdown(result: ScanResult, elapsedMs?: number): string {
  const { riskScore, findings, filesScanned, timestamp } = result
  const rec = effectiveRecommendation(result)
  const degraded = result.degraded === true
  const elapsedStr = elapsedMs != null
    ? (elapsedMs < 1000 ? `${elapsedMs}ms` : `${(elapsedMs / 1000).toFixed(1)}s`)
    : 'N/A'

  const critical = findings.filter((f) => f.severity === 'critical')
  const high = findings.filter((f) => f.severity === 'high')
  const medium = findings.filter((f) => f.severity === 'medium')
  const low = findings.filter((f) => f.severity === 'low')

  const sections: string[] = [
    '# ShipGuard Release Report',
    '',
    '## SUMMARY',
    '',
    `**Verdict:** ${rec} — ${attitudeLine(rec, degraded)}`,
    '',
    `**Files scanned:** ${filesScanned}  |  **Elapsed:** ${elapsedStr}  |  **Generated:** ${timestamp}`,
    '',
    ...(degraded
      ? [
          '### Why this scan is incomplete',
          '',
          ...((result.degradedReasons ?? []).length > 0
            ? (result.degradedReasons ?? []).map((r) => `- \`${r.code}\`${r.detail ? ` — ${r.detail}` : ''}`)
            : ['- Reason not recorded — see `degraded` in the JSON report.']),
          '',
        ]
      : []),
    '### Severity Breakdown',
    '',
    severityBreakdownTable(riskScore),
    '',
    `**Risk Score:** ${riskScore.score}/100  |  **Total Findings:** ${riskScore.totalFindings}`,
    '',
    '### Top 3 Things to Fix',
    '',
    topThreeFindings(findings),
    '',
    '---',
    '',
    severitySection('Critical Findings', critical),
    severitySection('High Findings', high),
    severitySection('Medium Findings', medium),
    severitySection('Low Findings', low),
    '## Suggested Fix Order',
    '',
    buildFixOrder(findings),
    '',
    '## Final Recommendation',
    '',
    `**${rec}**`,
    '',
  ]

  return sections.join('\n')
}

// ---------------------------------------------------------------------------
// AGENT VIEW — .shipguard/reports/latest.json
//
// Exact same object as --json stdout (same schemaVersion contract).
// Internal _ fields must NOT appear here.
// ---------------------------------------------------------------------------

function buildAgentJson(result: ScanResult): string {
  // Strip internal metadata fields (same logic as scan.ts publicResult)
  const publicResult = { ...result }
  delete (publicResult as Record<string, unknown>)._skippedTooLarge
  delete (publicResult as Record<string, unknown>)._skippedBinary
  delete (publicResult as Record<string, unknown>)._truncated
  return JSON.stringify(publicResult, null, 2)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ReportPaths {
  /** Path to the human-readable Markdown report (the stable "latest" path). */
  mdPath: string
  /**
   * Path to the machine-readable JSON POINTER (schemaVersion 5, rec #8).
   *
   * This file is NO LONGER the scan result. It is a small, always-rewritable pointer at
   * the run-scoped result — `runJsonPath` below. Read `runJson` out of it and open that.
   */
  jsonPath: string
  /** Immutable, run-scoped Markdown report: `<runId>.md`. */
  runMdPath: string
  /** Immutable, run-scoped JSON result: `<runId>.json` — this is the full ScanResult. */
  runJsonPath: string
}

/**
 * Directory (relative to the report output directory) holding the immutable per-run
 * reports. Exported so the scanner can exclude exactly this path from its own scan
 * surface — see `selfArtifactIgnorePatterns` in core/scanner.ts.
 */
export const RUNS_SUBDIR = 'runs'

/**
 * What `latest.json` contains since schemaVersion 5 (rec #8).
 *
 * WHY it was demoted: `latest.json` was a single mutable file that every scan overwrote in
 * place. Two scans in the same repo — an agent and a CI job, or two agents — raced: a
 * reader could open it between truncate and write and get a torn document, or read run B's
 * result believing it was run A's. Run-scoped files are written once and never rewritten,
 * so a reader that resolves the pointer can never be handed a half-written or wrong result.
 */
export interface LatestPointer {
  /** Always true — lets a consumer tell a pointer from a legacy full result immediately. */
  pointer: true
  /** Pointer format version, independent of the scan schemaVersion. */
  pointerVersion: 1
  runId: string
  timestamp: string
  recommendation?: string
  /** Filenames, relative to the directory this pointer lives in. */
  runJson: string
  runMarkdown: string
}

/**
 * Write a file atomically: temp file in the same directory, then rename.
 *
 * rename(2) within one filesystem is atomic, so a concurrent reader sees either the old
 * file or the complete new one — never a partial write. Avoids a read/write race (TOCTOU).
 */
async function writeAtomic(path: string, content: string): Promise<void> {
  const tmp = `${path}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`
  await writeFile(tmp, content, 'utf-8')
  await rename(tmp, path)
}

/**
 * Write BOTH the user-view Markdown report and the agent-view JSON report.
 *
 * The JSON file shares the same basename as the MD file but with .json extension,
 * placed in the same directory. This mirrors the --json stdout contract exactly.
 *
 * @param result      ScanResult to report on
 * @param outputPath  Path for the .md file (e.g. .shipguard/reports/latest.md)
 * @param elapsedMs   Optional elapsed scan time for summary header
 * @returns paths to both files written
 */
export async function generateReport(
  result: ScanResult,
  outputPath: string,
  elapsedMs?: number,
): Promise<ReportPaths> {
  // Derive JSON path: same dir, same basename, .json extension
  const dir = dirname(outputPath)
  const base = basename(outputPath, '.md')
  const jsonPath = join(dir, `${base}.json`)

  // Run-scoped names (rec #8). `runId` is the scan's own stable id; the fallback keeps
  // older/hand-built results working rather than throwing on a missing field.
  //
  // They live in a `runs/` SUBDIRECTORY, not beside `latest.*`. That is load-bearing, not
  // tidiness: the scan surface excludes ShipGuard's own artifacts by naming them (rec #6),
  // and per-run filenames are unpredictable, so a flat layout meant every scan dropped two
  // more files into the tree that the NEXT scan would read. Caught by the artifact-creep
  // regression test — file count grew 6 -> 8 across two runs. One directory is nameable;
  // an open-ended set of UUID filenames is not.
  const runId = sanitizeRunId(result.runId) ?? `run-${Date.now()}`
  const runMdName = join(RUNS_SUBDIR, `${runId}.md`)
  const runJsonName = join(RUNS_SUBDIR, `${runId}.json`)
  const runMdPath = join(dir, runMdName)
  const runJsonPath = join(dir, runJsonName)

  const mdContent = buildUserMarkdown(result, elapsedMs)
  const jsonContent = buildAgentJson(result)

  const pointer: LatestPointer = {
    pointer: true,
    pointerVersion: 1,
    runId,
    timestamp: result.timestamp,
    recommendation: effectiveRecommendation(result),
    runJson: runJsonName,
    runMarkdown: runMdName,
  }

  await mkdir(dir, { recursive: true })
  await mkdir(join(dir, RUNS_SUBDIR), { recursive: true })
  // Run-scoped files first: the pointer must never name a file that does not exist yet.
  await Promise.all([
    writeAtomic(runMdPath, mdContent),
    writeAtomic(runJsonPath, jsonContent),
  ])
  await Promise.all([
    writeAtomic(outputPath, mdContent),
    writeAtomic(jsonPath, JSON.stringify(pointer, null, 2) + '\n'),
  ])

  return { mdPath: outputPath, jsonPath, runMdPath, runJsonPath }
}

/**
 * Keep a runId safe to use as a filename. A runId is machine-generated (a UUID), but it
 * arrives through the JSON result, so treating it as a path component without checking
 * would be a path-traversal hole in a tool whose whole point is not doing that.
 */
function sanitizeRunId(runId: string | undefined): string | undefined {
  if (!runId) return undefined
  const safe = runId.replace(/[^A-Za-z0-9._-]/g, '')
  return safe.length > 0 && safe !== '.' && safe !== '..' ? safe.slice(0, 96) : undefined
}
