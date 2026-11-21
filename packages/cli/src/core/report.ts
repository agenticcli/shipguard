import { mkdir, rename, writeFile } from 'node:fs/promises'
import { dirname, basename, join } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Finding, ScanResult } from '@agenticcli/shared'
import { effectiveRecommendation, VERDICT_WORDS } from './verdict.js'
import { fixGuidance, orderFindings, fixOrderGroup } from './fix-guidance.js'
import { rulesRanLines, generalRuleCountOrNull } from './render.js'
import type { RulesRan } from './render.js'
import type { NotScannedSummary } from './not-scanned.js'
import { assertCwdAlive } from '../utils/cwd-guard.js'

// ---------------------------------------------------------------------------
// USER VIEW: .shipguard/reports/latest.md (spec 01 "report layout", spec 04 record)
//
// Same field names and order as the screen; the same one-line fix text as the screen, word for
// word. Secrets are never printed: the evidence line for a secret says `value hidden`.
// ---------------------------------------------------------------------------

/** Facts the report needs beyond the ScanResult. All optional: defaults give a plain Free report. */
export interface ReportContext {
  stacks?: readonly string[]
  rerunCommand?: string
  generalRuleCount?: number | null
  rulesRan?: RulesRan
  notScanned?: NotScannedSummary
  ignoredTestValues?: number
  /** W5 masking seam: `<type>, <n> characters, value hidden` for a secret finding. */
  secretEvidence?: (f: Finding) => string | null
}

function utcStamp(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

function oneLine(s: string): string {
  return s.replace(/\s+/g, ' ').trim()
}

function findingRecord(f: Finding, n: number, ctx: ReportContext, rerun: string): string[] {
  const g = fixGuidance(f, ctx.stacks)
  const loc = f.line != null ? `${f.file}:${f.line}` : f.file
  const lines: string[] = [`${n}. ${f.severity.toUpperCase()} ${loc}  ${g.what}   id: ${f.id}`]
  if (g.why) lines.push(`   why: ${g.why}`)
  const head = [g.fixLabel, g.effort ? `effort: ${g.effort}` : null].filter((x): x is string => x !== null).join(', ')
  lines.push(`   fix${head ? ` (${head})` : ''}: ${g.summary}`)
  for (const step of g.steps) lines.push(`     ${step}`)
  const manual = g.manual ? ` Manual: ${g.manual}` : ''
  lines.push(`   verify: ${rerun}   (this finding no longer appears; exit 0 only when nothing else blocks.${manual})`)
  if (f.category === 'secrets') {
    lines.push(`   evidence: ${ctx.secretEvidence?.(f) ?? 'value hidden'}`)
  } else if (f.evidence) {
    lines.push(`   evidence: ${oneLine(f.evidence)}`)
  }
  if (g.notAVulnerabilityIf) lines.push(`   not a vulnerability if: ${g.notAVulnerabilityIf}`)
  if (g.note) lines.push(`   ${g.note}`)
  return lines
}

function buildUserMarkdown(result: ScanResult, ctx: ReportContext): string {
  const { riskScore, findings } = result
  const rec = effectiveRecommendation(result)
  const word = VERDICT_WORDS[rec]
  const incomplete = result.degraded === true
  const rerun = ctx.rerunCommand ?? 'shipguard scan --strict'
  const n = ctx.generalRuleCount === undefined ? generalRuleCountOrNull() : ctx.generalRuleCount
  const rr = rulesRanLines(ctx.rulesRan, n)
  const rulesLabel =
    ctx.rulesRan && (ctx.rulesRan.kind === 'rulebook' || ctx.rulesRan.kind === 'partial')
      ? `rulebook:${ctx.rulesRan.count}`
      : n === null ? 'general' : `general:${n}`
  const runId = result.runId ? result.runId.replace(/[^A-Za-z0-9]/g, '').slice(0, 8) : 'unknown'
  const files = result.coverage ? result.coverage.scanned : result.filesScanned

  const ordered = orderFindings(findings)
  const blockers = ordered.filter((f) => f.blocking)
  const rest = ordered.filter((f) => !f.blocking)
  const alsoFound = rest.filter((f) => fixOrderGroup(f) === 2)
  const byHand = rest.filter((f) => fixOrderGroup(f) === 3)

  const out: string[] = [
    `# ShipGuard report: ${word} (run ${runId})`,
    `verdict: ${word}   blocking: ${riskScore.blockingCount}   findings: ${riskScore.totalFindings}   incomplete: ${incomplete ? 'yes' : 'no'}   files: ${files}   rules: ${rulesLabel}   when: ${utcStamp(result.timestamp)}`,
    `rerun: ${rerun}`,
    '',
  ]
  if (rr.runSentence) out.push(rr.runSentence, '')
  if (rec === 'SAFE_TO_SHIP' && !incomplete) {
    out.push('"Safe" here means no rule matched. It is not a security audit.', '')
  }

  let i = 0
  if (blockers.length > 0) {
    out.push(`## Fix in this order (${blockers.length} blocking)`)
    for (const f of blockers) out.push(...findingRecord(f, ++i, ctx, rerun))
    out.push('')
  }
  if (alsoFound.length > 0) {
    out.push(`## Also found (${alsoFound.length}, not blocking)`)
    for (const f of alsoFound) out.push(...findingRecord(f, ++i, ctx, rerun))
    out.push('')
  }
  if (byHand.length > 0) {
    out.push(`## Check by hand (${byHand.length}, not blocking)`)
    for (const f of byHand) out.push(...findingRecord(f, ++i, ctx, rerun))
    out.push('')
  }

  const ns = ctx.notScanned
  const entries = ns?.entries ?? []
  const nsCount = entries.reduce((c, e) => c + (e.path ? 1 : (e.count ?? 1)), 0)
  out.push(`## Not scanned (${nsCount})`)
  for (const e of entries) {
    out.push(`- ${e.path ?? '(names in the JSON degradedReasons)'}  ${e.reason}   code: ${e.code}`)
    e.fix.forEach((l, k) => out.push(k === 0 ? `  fix: ${l}` : `       ${l}`))
  }
  for (const r of ns?.otherReasons ?? []) out.push(`- did not run: ${r.text}   code: ${r.code}`)
  out.push('')

  const ignoredFiles = result.coverage?.ignoredByUser ?? 0
  const testValues = ctx.ignoredTestValues ?? 0
  out.push(`## Ignored (${ignoredFiles + testValues})`)
  if (ignoredFiles > 0) out.push(`- ${ignoredFiles} file(s) matched ignore.paths in the policy`)
  if (testValues > 0) out.push(`- ${testValues} test value(s): placeholder and sample values, not reported`)
  out.push('')

  out.push(rr.line)
  return out.join('\n') + '\n'
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
 * @param _elapsedMs  Unused (the report header no longer carries a timing; kept for call-site compatibility)
 * @param ctx         Stack, rerun command, rules that ran, not-scanned files (all optional)
 * @returns paths to both files written
 */
export async function generateReport(
  result: ScanResult,
  outputPath: string,
  _elapsedMs?: number,
  ctx: ReportContext = {},
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

  const mdContent = buildUserMarkdown(result, ctx)
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

  assertCwdAlive()
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
