/**
 * render.ts: pure rendering functions for the scan screen (spec 01) and the first-run text.
 *
 * All functions return strings (never print directly), so they are unit-testable without mocking
 * process/console. ANSI colour via chalk only (chalk turns itself off when piped or with NO_COLOR, so
 * the bytes are the same piped or on a terminal, except colour). No new dependencies.
 *
 * The screen (spec 01): line 1 of stdout is the verdict; at most 25 lines; no box art, no emoji, no
 * bar charts, no tips. Plan facts never appear here: the Free-to-Pro lines come from screen-plan-lines.ts
 * and are built from the one verified server block.
 */

import chalk from 'chalk'
import { existsSync } from 'node:fs'
import { ensureSecureDir, writeSecureFileSync } from '../utils/secure-fs.js'
import { join, basename } from 'node:path'
import { homedir } from 'node:os'
import { goLink } from './links.js'
import type { Finding, ScanResult, Recommendation } from '@agenticcli/shared'
import { effectiveRecommendation, VERDICT_WORDS } from './verdict.js'
import { fixGuidance, firstSentence, orderFindings, realStacks, stackDisplayName } from './fix-guidance.js'
import type { NotScannedSummary, NotScannedEntry } from './not-scanned.js'
import type { GateState, NextAgent } from './screen-context.js'
import { generalRulesText, rulesRanLines } from './rules-ran.js'
import type { RulesRan } from './rules-ran.js'
export { rulesRanLines } from './rules-ran.js'
export type { RulesRan } from './rules-ran.js'
export { generalRuleCountOrNull } from './general-rule-count.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const DOCS_URL = goLink('docs')
export const SITE_URL = goLink('site')
export const PRICING_URL = goLink('pricing')
const ISSUES_URL = 'https://github.com/agenticcli/shipguard/issues'

/** Hard budget for the human screen (spec 01 rule 5). */
export const SCREEN_MAX_LINES = 25

/**
 * The ONE shared data-flow line (spec 06). Every setup, status and first-run screen uses it by
 * reference; no screen keeps its own wording.
 */
export const DATA_FLOW_LINE =
  'Code never leaves your machine. Rules download from the rulebook; a signed-out scan may fetch public rule counts for your stack names once a week; usage-ping and request details: shipguard telemetry status.'

// Progress bar chars
const BAR_FULL = '█'
const BAR_EMPTY = '░'

// ---------------------------------------------------------------------------
// Spinner frames (for module-level progress when file count unknown)
// ---------------------------------------------------------------------------

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

export function spinnerFrame(tick: number): string {
  return SPINNER_FRAMES[tick % SPINNER_FRAMES.length]
}

// ---------------------------------------------------------------------------
// Branded quickstart screen (bare `shipguard`, `shipguard ?`, `shipguard help`)
// ---------------------------------------------------------------------------

/**
 * Render the branded quickstart screen.
 * TTY gets chalk color; non-TTY gets plain text (clean pipes/CI).
 * The `status` line is the server-neutral one from spec 05 (no credit wording).
 */
export function quickstartHelp(isTTY: boolean): string {
  const lines: string[] = []

  if (isTTY) {
    lines.push('')
    lines.push(chalk.bold('  ShipGuard by AgenticCLI'))
    lines.push('  The security scanner your coding agent runs before every commit.')
    lines.push('')
    lines.push(chalk.bold('  Get started in 2 commands:'))
    lines.push('')
    lines.push(`    ${chalk.green('npx @agenticcli/shipguard scan')}    ${chalk.dim('# zero install: scan right now')}`)
    lines.push(`    ${chalk.green('shipguard scan --strict')}           ${chalk.dim('# CI mode: exit 1 on blocking issues')}`)
    lines.push('')
    lines.push(chalk.bold('  Commands:'))
    lines.push('')
    lines.push(`    ${chalk.cyan('scan')}      ${chalk.dim('[path]')}   Scan a project for high-risk issues`)
    lines.push(`    ${chalk.cyan('init')}               Generate a .shipguard.yml policy file`)
    lines.push(`    ${chalk.cyan('login')}              Sign in to run rulebook scans`)
    lines.push(`    ${chalk.cyan('logout')}             Remove saved credentials`)
    lines.push(`    ${chalk.cyan('status')}             Sign-in, plan and usage, as the server reports them`)
    lines.push(`    ${chalk.cyan('upgrade')}            What the full rulebook would add for this repo`)
    lines.push(`    ${chalk.cyan('setup')}              Set up the gate for your coding agent`)
    lines.push(`    ${chalk.cyan('uninstall')}          Remove what setup wrote`)
    lines.push(`    ${chalk.cyan('gate')}               Run the gate (used by hooks)`)
    lines.push(`    ${chalk.cyan('ignore')}             Ignore a finding or file, with a reason`)
    lines.push(`    ${chalk.cyan('hook')}      ${chalk.dim('--target')} Install the hook at the merge boundary`)
    lines.push(`    ${chalk.cyan('schema')}    ${chalk.dim('--json')}   Print the machine-readable scan contract`)
    lines.push(`    ${chalk.cyan('feedback')}           Where to send feedback (GitHub issues)`)
    lines.push(`    ${chalk.cyan('rate')}      ${chalk.dim('<n> helpful|not-helpful')}  Rate a rule finding`)
    lines.push(`    ${chalk.cyan('telemetry')} ${chalk.dim('status')}   Show or change the pseudonymous usage ping`)
    lines.push(`    ${chalk.cyan('help')}  ${chalk.dim('/ ?')}        Show this screen`)
    lines.push('')
    lines.push(chalk.bold('  Exit codes (verdict-neutral: read the JSON for the verdict):'))
    lines.push(`    ${chalk.green('0')}  Scan completed: the verdict is in the JSON \`recommendation\` field`)
    lines.push(`    ${chalk.yellow('1')}  Blocked: ONLY with --strict, on blocking findings or an unfinished scan`)
    lines.push(`    ${chalk.red('2')}  Config error`)
    lines.push(`    ${chalk.red('3')}  Runtime error: scan could not meaningfully run`)
    lines.push('')
    lines.push(`  ${chalk.dim('Docs')}    ${chalk.underline(DOCS_URL)}`)
    lines.push(`  ${chalk.dim('Site')}    ${chalk.underline(SITE_URL)}`)
    lines.push(`  ${chalk.dim('Pricing')} ${chalk.underline(PRICING_URL)}`)
    lines.push(`  ${chalk.dim('Issues')}  ${chalk.underline(ISSUES_URL)}`)
    lines.push('')
  } else {
    // Plain text for non-TTY (piped, CI)
    lines.push('')
    lines.push('  ShipGuard by AgenticCLI')
    lines.push('  The security scanner your coding agent runs before every commit.')
    lines.push('')
    lines.push('  Get started in 2 commands:')
    lines.push('')
    lines.push('    npx @agenticcli/shipguard scan    # zero install')
    lines.push('    shipguard scan --strict           # CI mode')
    lines.push('')
    lines.push('  Commands:')
    lines.push('    scan      [path]       Scan a project')
    lines.push('    init                  Generate policy file')
    lines.push('    login                 Authenticate')
    lines.push('    logout                Remove credentials')
    lines.push('    status                Sign-in, plan and usage, as the server reports them')
    lines.push('    upgrade               What the full rulebook would add for this repo')
    lines.push('    setup                 Set up the gate for your coding agent')
    lines.push('    uninstall             Remove what setup wrote')
    lines.push('    gate                  Run the gate (used by hooks)')
    lines.push('    ignore                Ignore a finding or file, with a reason')
    lines.push('    hook      --target     Install the hook at the merge boundary')
    lines.push('    schema    --json       Machine-readable scan contract')
    lines.push('    feedback               Where to send feedback (GitHub issues)')
    lines.push('    rate      <n> helpful|not-helpful  Rate finding number n')
    lines.push('    telemetry status|enable|disable|reset  Pseudonymous usage ping')
    lines.push('    help / ?              Show this screen')
    lines.push('')
    lines.push('  Exit codes: 0=completed (verdict in JSON)  1=blocked (--strict only: blocking findings or unfinished scan)  2=config-error  3=runtime-error')
    lines.push('')
    lines.push(`  Docs:    ${DOCS_URL}`)
    lines.push(`  Site:    ${SITE_URL}`)
    lines.push(`  Pricing: ${PRICING_URL}`)
    lines.push(`  Issues:  ${ISSUES_URL}`)
    lines.push('')
  }

  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// Progress bar
// ---------------------------------------------------------------------------

/**
 * Render a hand-rolled progress bar line (suitable for \r in-place updates).
 *
 * @param current  - number of files processed so far
 * @param total    - total file count
 * @param width    - bar fill width in chars (default 20)
 * @param currentFile - optional current filename to display
 */
export function renderProgressBar(
  current: number,
  total: number,
  width: number = 20,
  currentFile?: string,
): string {
  const fraction = total > 0 ? Math.min(current / total, 1) : 0
  const filled = Math.round(fraction * width)
  const empty = width - filled
  const bar = chalk.cyan(BAR_FULL.repeat(filled)) + chalk.gray(BAR_EMPTY.repeat(empty))
  const counter = `${current}/${total}`
  // Show basename of current dir + filename to keep lines short
  const fileHint = currentFile
    ? `  ${chalk.dim(basename(currentFile) || truncatePath(currentFile, 30))}`
    : ''
  return `${chalk.cyan('🔍')} scanning [${bar}] ${chalk.bold(counter)}${fileHint}`
}

// ---------------------------------------------------------------------------
// TTY gate
// ---------------------------------------------------------------------------

export interface ProgressGates {
  isTTY: boolean
  quiet: boolean
  machineOutput: boolean
}

/**
 * Returns true only if it is safe to emit live progress/animation to stderr.
 * Conditions: TTY + not quiet + not machine output (--json/--sarif).
 */
export function shouldShowProgress(gates: ProgressGates): boolean {
  return gates.isTTY && !gates.quiet && !gates.machineOutput
}

// ---------------------------------------------------------------------------
// The scan screen (spec 01)
// ---------------------------------------------------------------------------

export interface NextContext {
  /** The agent running the scan, else repo signals; null = none. */
  agent: NextAgent | null
  gate: GateState
  /** e.g. `Claude project hook v2` (only printed for a verified, current gate). */
  gateLabel?: string | null
  /** The setup suggestion was already shown in the last 7 days (screen rule only). */
  suggestionShownRecently: boolean
}

export interface ScanScreenInput {
  result: ScanResult
  elapsedMs: number
  strict: boolean
  /** Process exit code of this run; 1 adds the last-line contract under --strict. */
  exitCode?: number
  /** The one re-run command (spec 01 rule 7); defaults to the bare form. */
  rerunCommand?: string
  /** Display path of the report; null/undefined = no report line. */
  reportPath?: string | null
  /** Detected framework names (lowercase; 'generic' = none recognised). */
  stacks?: readonly string[]
  /** Manifest that made the folder a project; used by the `Stack:` honesty line. */
  manifest?: string | null
  /** Number of bundled general rules, counted at run time (never typed). */
  generalRuleCount: number | null
  rulesRan?: RulesRan
  notScanned?: NotScannedSummary
  next?: NextContext
  /** Free-to-Pro lines already decided by screen-plan-lines.ts; printed after `Rules ran:`. */
  planLines?: readonly string[]
  /** Name of the plan for the `[<plan> rule]` tag; null = `[rulebook rule]`. */
  planLabel?: string | null
  /** Test values ignored in this scan (W5 counts them). */
  ignoredTestValues?: number
  /** Fix loop (spec 04): the "since the last run" header and the repeat line above `Next:`. */
  fixLoop?: { fixed: number; added: number; repeatLine?: string | null }
  /** Terminal width when stdout is a terminal; undefined = piped (no wrapping at all). */
  columns?: number | null
  /** W5 masking seam: `32 chars, value hidden` for a secret finding; null = just `value hidden`. */
  secretLabel?: (f: Finding) => string | null
  /** `--changed` found nothing changed. */
  nothingToCheck?: boolean
}

const DEFAULT_RERUN = 'shipguard scan --strict'


function formatElapsed(ms: number): string {
  return `${(Math.max(0, ms) / 1000).toFixed(1)}s`
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? `${n} ${one}` : `${n} ${many}`
}

/** Tokens glue everything inside parentheses, so a call like `f(a, b)` is never split. */
function tokens(text: string): string[] {
  const out: string[] = []
  let cur = ''
  let depth = 0
  for (const ch of text) {
    if (ch === '(') depth++
    if (ch === ')' && depth > 0) depth--
    if (ch === ' ' && depth === 0) {
      if (cur) out.push(cur)
      cur = ''
    } else cur += ch
  }
  if (cur) out.push(cur)
  return out
}

/**
 * Terminal width rule (spec 01 rule 8): wrap prose at word boundaries with a 4-space hanging indent;
 * a path, `file:line` or command word is never split. Piped (`columns` undefined): never wrap.
 */
export function wrapLine(line: string, columns: number | null | undefined): string[] {
  if (columns == null) return [line]
  const width = Math.min(100, Math.max(60, columns))
  // eslint-disable-next-line no-control-regex
  const visible = (t: string): number => t.replace(/\x1b\[[0-9;]*m/g, '').length
  if (visible(line) <= width) return [line]
  const lead = /^ */.exec(line)![0]
  const hang = lead + '    '
  const words = tokens(line.slice(lead.length))
  const out: string[] = []
  let cur = lead
  for (const w of words) {
    const candidate = cur.trim().length === 0 ? cur + w : `${cur} ${w}`
    if (visible(candidate) > width && cur.trim().length > 0) {
      out.push(cur)
      cur = hang + w
    } else cur = candidate
  }
  out.push(cur)
  return out
}

function sevColor(sev: string, text: string): string {
  if (sev === 'critical') return chalk.bold.red(text)
  if (sev === 'high') return chalk.red(text)
  if (sev === 'medium') return chalk.yellow(text)
  return chalk.blue(text)
}

function verdictColor(rec: Recommendation, text: string): string {
  if (rec === 'SAFE_TO_SHIP') return chalk.bold.green(text)
  if (rec === 'REVIEW_BEFORE_SHIP') return chalk.bold.yellow(text)
  return chalk.bold.red(text)
}

type FindingWithOrigin = Finding & { origin?: string }

function locOf(f: Finding): string {
  return f.line != null ? `${f.file}:${f.line}` : f.file
}

function dropPeriod(s: string): string {
  return s.replace(/[.]+$/, '')
}

function rulesCountText(r: RulesRan | undefined, generalRuleCount: number | null): string {
  if (r && r.kind === 'rulebook') return `${r.count} rules`
  if (r && r.kind === 'partial') return `${r.count} rules`
  return generalRulesText(generalRuleCount)
}

function otherReasonPhrase(ns: NotScannedSummary | undefined, input: ScanScreenInput): string {
  const cov = input.result.coverage
  if (input.nothingToCheck) return 'nothing was scanned (git reports no changed files)'
  if (cov && cov.scanned === 0) {
    return cov.discovered === 0 ? 'nothing was scanned (no readable files were found)' : `nothing was scanned (0 of ${cov.discovered} files could be read)`
  }
  if (ns && ns.fileCount > 0 && cov) return `${ns.fileCount} of ${cov.discovered} files were not scanned`
  if (ns && ns.entries.some((e) => e.code === 'OUTPUT_TRUNCATED')) return 'the scan stopped at a limit'
  if (ns && ns.otherReasons.length > 0) return dropPeriod(ns.otherReasons[0].text)
  return 'parts of this scan did not run'
}

function nextText(input: ScanScreenInput, rerun: string, blocking: number, nonBlocking: number, rec: Recommendation, incomplete: boolean): string {
  const ns = input.notScanned
  const files = ns?.fileCount ?? 0
  if (input.nothingToCheck) return 'Next: check the whole tree: shipguard scan'
  if (incomplete && blocking === 0) {
    if (input.result.coverage && input.result.coverage.scanned === 0) return `Next: find out why no files were read, then: ${rerun}`
    if (files > 0) return `Next: fix or exclude the ${plural(files, 'file', 'files')}, then: ${rerun}`
    return `Next: fix what did not run (see above), then: ${rerun}`
  }
  if (blocking > 0) {
    const extra = files > 0 ? ` and the ${plural(files, 'file', 'files')} not scanned` : ''
    return `Next: fix the ${blocking} above${extra}, then: ${rerun}`
  }
  if (rec === 'REVIEW_BEFORE_SHIP' || nonBlocking > 0) {
    const where = input.reportPath ?? 'the findings above'
    return `Next: review the ${plural(nonBlocking, 'finding', 'findings')} in ${where} (nothing blocks a push), then: ${rerun}`
  }
  const c = input.next
  const AGENT_NAME: Record<NextAgent, string> = { claude: 'Claude Code', codex: 'Codex', cursor: 'Cursor', git: 'a git repository' }
  if (c && c.gate === 'current') {
    return `Next: nothing to fix. The gate is on (${c.gateLabel ?? 'project hook'}). Re-check after changes: ${rerun}`
  }
  if (c && c.gate === 'stale') {
    return `Next: shipguard setup --agent ${c.agent ?? 'claude'}   (updates your older hook)`
  }
  if (c && c.suggestionShownRecently) return `Next: no gate is installed. Re-check after changes: ${rerun}`
  if (c && c.agent) {
    return `Next: shipguard setup --agent ${c.agent}   (${AGENT_NAME[c.agent]} detected, no gate installed yet; the gate blocks git push when ShipGuard finds a blocker)`
  }
  return 'Next: shipguard setup   (detects your agent and previews the changes)'
}

interface ScreenLimits {
  fix: number
  also: number
  files: number
}

function buildScreen(input: ScanScreenInput, lim: ScreenLimits): string[] {
  const { result } = input
  const rec = effectiveRecommendation(result)
  const word = VERDICT_WORDS[rec]
  const rerun = input.rerunCommand ?? DEFAULT_RERUN
  const stacks = input.stacks ?? []
  const ns = input.notScanned
  const incomplete = result.degraded === true
  const blocking = result.riskScore.blockingCount
  const total = result.riskScore.totalFindings
  const cov = result.coverage
  const files = cov ? cov.scanned : result.filesScanned
  const terminal = input.columns != null
  const out: string[] = []
  const push = (line: string): void => {
    for (const l of wrapLine(line, input.columns)) out.push(l)
  }

  // ---- line 1: the verdict ------------------------------------------------
  const rr = rulesRanLines(input.rulesRan, input.generalRuleCount, terminal)
  let header: string
  if (incomplete && blocking === 0) {
    const scannedFiles = cov ? cov.scanned : files
    const tail = cov && cov.scanned > 0 ? ` · ${plural(total, 'finding', 'findings')} in the ${scannedFiles} that ${scannedFiles === 1 ? 'was' : 'were'}` : ` · ${plural(total, 'finding', 'findings')}`
    header = `${word} · cannot clear this repo: ${otherReasonPhrase(ns, input)}${tail}`
  } else if (rec === 'DO_NOT_SHIP') {
    header = `${word} · ${blocking} blocking of ${plural(total, 'finding', 'findings')} · ${plural(files, 'file', 'files')}, ${rulesCountText(input.rulesRan, input.generalRuleCount)}, ${formatElapsed(input.elapsedMs)}`
  } else {
    const counts = total === 0 ? '0 findings' : `${plural(total, 'finding', 'findings')}, ${blocking} blocking`
    header = `${word} · ${counts} · ${plural(files, 'file', 'files')}, ${rulesCountText(input.rulesRan, input.generalRuleCount)}, ${formatElapsed(input.elapsedMs)}`
  }
  out.push(verdictColor(rec, header.slice(0, word.length)) + header.slice(word.length))

  // ---- line 2: the limit sentence -----------------------------------------
  if (incomplete && blocking === 0) {
    push('Not scanned means not checked. This is a stop because of coverage, not because of a finding.')
  } else if (rec === 'SAFE_TO_SHIP') {
    push('"Safe" here means no rule matched. It is not a security audit.')
  } else if (rec === 'DO_NOT_SHIP') {
    if (!input.strict) push('This scan finished (exit 0). Add --strict to exit 1 on DO NOT SHIP.')
  } else {
    push('Nothing here blocks a push. Review the findings below.')
  }
  if (incomplete && blocking > 0 && ns && ns.fileCount > 0 && cov) {
    push(`This scan is also incomplete: ${ns.fileCount} of ${cov.discovered} files were not scanned.`)
  }
  if (rr.runSentence) push(rr.runSentence)

  // ---- findings -------------------------------------------------------------
  const ordered = orderFindings(result.findings)
  const blockers = ordered.filter((f) => f.blocking)
  const rest = ordered.filter((f) => !f.blocking)
  const fixLabelFor = (f: Finding) => fixGuidance(f, stacks)

  if (blockers.length > 0) {
    out.push('')
    const since = input.fixLoop ? `; since the last run: ${input.fixLoop.fixed} fixed, ${input.fixLoop.added} new` : ''
    push(`Fix first (${blockers.length} blocking${since}):`)
    blockers.slice(0, lim.fix).forEach((f, i) => {
      const g = fixLabelFor(f)
      let what = g.what
      if (f.category === 'secrets') what += ` (${input.secretLabel?.(f) ?? 'value hidden'})`
      const origin = (f as FindingWithOrigin).origin === 'rulebook' ? ` [${input.planLabel && input.planLabel.length > 0 ? input.planLabel : 'rulebook'} rule]` : ''
      const sev = f.severity.toUpperCase().padEnd(8)
      push(`${String(i + 1).padStart(2)}. ${sevColor(f.severity, sev)} ${locOf(f)}  ${what}${origin}`)
      push(`    fix: ${g.summary}`)
    })
    if (blockers.length > lim.fix) push(`    +${blockers.length - lim.fix} more, see report`)
  }

  if (rest.length > 0) {
    out.push('')
    const sevs = new Set(rest.map((f) => f.severity))
    const sevWord = sevs.size === 1 ? [...sevs][0] : 'not blocking'
    const lowConf = rest.some((f) => f.confidence === 'LOW')
    push(`Also found (${rest.length} ${sevWord}${lowConf ? ', may be false positives, check by hand' : ''}):`)
    rest.slice(0, lim.also).forEach((f) => {
      const g = fixLabelFor(f)
      const origin = (f as FindingWithOrigin).origin === 'rulebook' ? ` [${input.planLabel && input.planLabel.length > 0 ? input.planLabel : 'rulebook'} rule]` : ''
      push(`    ${locOf(f)}  ${g.what}${origin}`)
      if (g.notAVulnerabilityIf) push(`      not a vulnerability if: ${dropPeriod(firstSentence(g.notAVulnerabilityIf))}`)
    })
    if (rest.length > lim.also) push(`    +${rest.length - lim.also} more in the report`)
  }

  // ---- not scanned ------------------------------------------------------------
  const entries: NotScannedEntry[] = ns?.entries ?? []
  if (entries.length > 0 || (ns && ns.otherReasons.length > 0) || input.nothingToCheck) {
    out.push('')
    const shown = entries.slice(0, lim.files)
    const count = entries.reduce((n, e) => n + (e.path ? 1 : (e.count ?? 1)), 0)
    if (entries.length > 0) {
      push(`Not scanned (${count}):`)
      const pad = Math.max(0, ...shown.filter((e) => e.path).map((e) => (e.path as string).length))
      for (const e of shown) {
        const label = e.path ? e.path.padEnd(pad) : '(names in the JSON)'
        push(` - ${label}  ${e.reason}`)
        e.fix.forEach((l, i) => {
          out.push(i === 0 ? `   fix: ${l}` : `        ${l}`)
        })
      }
      if (entries.length > lim.files) push(` +${entries.length - lim.files} more in the report`)
    }
    for (const r of ns?.otherReasons ?? []) push(`Did not run: ${r.text}`)
    if (input.nothingToCheck) push('Nothing was scanned: git reports no changed files. This is not a safe-to-ship result.')
  }

  // ---- closing lines -----------------------------------------------------------
  out.push('')
  if (input.ignoredTestValues && input.ignoredTestValues > 0) {
    push(`Ignored ${plural(input.ignoredTestValues, 'test value', 'test values')} (placeholder and sample values; listed in the report).`)
  }
  if (input.reportPath) {
    push(result.findings.length > 0 ? `Report: ${input.reportPath}   (all fixes; agents: shipguard scan --json)` : `Report: ${input.reportPath}`)
  }
  if (input.fixLoop?.repeatLine) push(input.fixLoop.repeatLine)
  push(nextText(input, rerun, blocking, rest.length, rec, incomplete))
  const manifest = input.manifest
  if (realStacks(stacks).length === 0 && manifest) {
    push(`Stack: project found, framework not recognised (${manifest}). Stack-specific checks may not have applied.`)
  }
  push(rr.line)
  for (const l of input.planLines ?? []) push(l)

  if (input.strict && input.exitCode === 1) {
    push('Exit 1: --strict stops on DO NOT SHIP. Fix the items above or use shipguard ignore with a reason.')
  }
  return out
}

/**
 * Render the human scan screen. At most 25 lines (spec 01 rule 5): when the first cut is longer, the
 * detail is trimmed in a fixed order (Also found, then Not scanned files, then Fix first items) and a
 * `+N more` line says what was left to the report.
 */
export function renderScanScreen(input: ScanScreenInput): string {
  const lim: ScreenLimits = { fix: 5, also: 3, files: 5 }
  const shrink = (): boolean => {
    if (lim.also > 0) { lim.also = Math.max(0, lim.also - 1); return true }
    if (lim.files > 1) { lim.files--; return true }
    if (lim.fix > 1) { lim.fix--; return true }
    return false
  }
  // Wrapped terminal output may legitimately exceed the budget in physical lines; the budget counts
  // logical lines, so measure on the unwrapped build.
  const measure = (l: ScanScreenInput): number => buildScreen({ ...l, columns: undefined }, lim).length
  while (measure(input) > SCREEN_MAX_LINES && shrink()) {
    // keep trimming until the screen fits or nothing is left to trim
  }
  return buildScreen(input, lim).join('\n')
}

/**
 * The one quiet line (spec 01, "Quiet mode"): pure `key=value` pairs after the fixed prefix.
 * Key order is fixed: verdict blocking findings incomplete notScanned fallback agentAction run report.
 */
export function renderQuietLine(input: {
  result: ScanResult
  agentAction?: string
  notScanned?: number
  fallbackCode?: string | null
  reportPath?: string | null
}): string {
  const rec = effectiveRecommendation(input.result)
  const r = input.result
  const incomplete = r.degraded === true
  const parts = [
    `verdict=${rec}`,
    `blocking=${r.riskScore.blockingCount}`,
    `findings=${r.riskScore.totalFindings}`,
    `incomplete=${incomplete ? 'yes' : 'no'}`,
  ]
  if (input.notScanned && input.notScanned > 0) parts.push(`notScanned=${input.notScanned}`)
  if (input.fallbackCode) parts.push(`fallback=${input.fallbackCode}`)
  parts.push(`agentAction=${input.agentAction ?? simpleAgentAction(r)}`)
  if (r.runId) parts.push(`run=${r.runId.replace(/[^A-Za-z0-9]/g, '').slice(0, 8)}`)
  if (input.reportPath && !/\s/.test(input.reportPath)) parts.push(`report=${input.reportPath}`)
  return `shipguard: ${parts.join(' ')}`
}

/** Fallback `agentAction` for the quiet line until W2b's outcome table supplies the real one. */
function simpleAgentAction(r: ScanResult): string {
  if (r.riskScore.blockingCount > 0) return 'fix_and_rerun'
  if (r.degraded === true) return 'ask_human'
  return 'proceed'
}

// ---------------------------------------------------------------------------
// First-run welcome (TTY only)
// ---------------------------------------------------------------------------

function getShipguardConfigDir(): string {
  return join(homedir(), '.config', 'shipguard')
}

/**
 * Show a one-time welcome text on first ever run (plain lines, no box).
 *
 * @param configDir  - override the config dir (used in tests)
 * @returns text (non-empty on first call; empty string thereafter)
 */
export function welcomeBanner(configDir?: string): string {
  const dir = configDir ?? getShipguardConfigDir()
  const marker = join(dir, '.welcomed')

  if (existsSync(marker)) {
    return ''
  }

  try {
    ensureSecureDir(dir)
    writeSecureFileSync(marker, '1')
  } catch {
    // Non-fatal: if we can't write the marker, just show the text every time
  }

  return [
    '',
    chalk.bold('ShipGuard by AgenticCLI') + ': the security scanner your coding agent runs before every commit.',
    DATA_FLOW_LINE,
    `Quick start: shipguard scan   |   machine-readable: shipguard scan --json   |   docs: ${DOCS_URL}`,
    '',
  ].join('\n')
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function truncatePath(filePath: string, maxLen: number): string {
  if (filePath.length <= maxLen) return filePath
  const parts = filePath.split('/')
  const tail = parts.slice(-2).join('/')
  return tail.length <= maxLen ? `…/${tail}` : `…${tail.slice(-maxLen)}`
}

// ---------------------------------------------------------------------------
// Display-width helper — counts terminal columns needed to render a string.
//
// Rules:
//   - Strip ANSI escape sequences first (they consume 0 columns)
//   - Variation selectors (U+FE00–U+FE0F) and zero-width chars (ZWJ U+200D,
//     ZWNJ U+200C, BOM U+FEFF) consume 0 columns
//   - CJK Unified Ideographs, fullwidth forms, many common emoji (≥ U+1F000)
//     and double-width symbols consume 2 columns
//   - Everything else consumes 1 column
//
// This is intentionally a compact implementation — no external dependency.
// It handles the emoji that appear in the verdict panel (⛔ ⚠️ ✅ 🔴 etc.)
// accurately enough for box-drawing alignment. It does NOT replicate the
// full Unicode East-Asian Width table — that would require a dependency.
// ---------------------------------------------------------------------------

export function displayWidth(str: string): number {
  // 1. Strip ANSI escape sequences
  const plain = str.replace(/\x1b\[[0-9;]*m/g, '')

  let width = 0
  for (const char of plain) {
    const cp = char.codePointAt(0) ?? 0

    // Zero-width characters: variation selectors, ZWJ, ZWNJ, BOM, combining marks
    if (
      (cp >= 0xFE00 && cp <= 0xFE0F) ||  // Variation selectors
      cp === 0x200C || cp === 0x200D ||   // ZWNJ, ZWJ
      cp === 0xFEFF ||                    // BOM / zero-width no-break space
      (cp >= 0x0300 && cp <= 0x036F) ||  // Combining Diacritical Marks
      (cp >= 0x1AB0 && cp <= 0x1AFF) ||  // Combining Diacritical Marks Extended
      (cp >= 0x1DC0 && cp <= 0x1DFF) ||  // Combining Diacritical Marks Supplement
      (cp >= 0x20D0 && cp <= 0x20FF) ||  // Combining Diacritical Marks for Symbols
      (cp >= 0xFE20 && cp <= 0xFE2F)     // Combining Half Marks
    ) {
      // Zero width — no column consumed
      continue
    }

    // Double-width characters: CJK and fullwidth forms, and emoji/symbol planes
    if (
      (cp >= 0x1100 && cp <= 0x115F) ||   // Hangul Jamo
      (cp >= 0x2E80 && cp <= 0x2EFF) ||   // CJK Radicals Supplement
      (cp >= 0x2F00 && cp <= 0x2FFF) ||   // Kangxi Radicals
      (cp >= 0x3000 && cp <= 0x303F) ||   // CJK Symbols and Punctuation
      (cp >= 0x3040 && cp <= 0x309F) ||   // Hiragana
      (cp >= 0x30A0 && cp <= 0x30FF) ||   // Katakana
      (cp >= 0x3100 && cp <= 0x312F) ||   // Bopomofo
      (cp >= 0x3130 && cp <= 0x318F) ||   // Hangul Compatibility Jamo
      (cp >= 0x3190 && cp <= 0x319F) ||   // Kanbun
      (cp >= 0x31A0 && cp <= 0x31BF) ||   // Bopomofo Extended
      (cp >= 0x31F0 && cp <= 0x31FF) ||   // Katakana Phonetic Extensions
      (cp >= 0x3200 && cp <= 0x32FF) ||   // Enclosed CJK Letters and Months
      (cp >= 0x3300 && cp <= 0x33FF) ||   // CJK Compatibility
      (cp >= 0x3400 && cp <= 0x4DBF) ||   // CJK Unified Ideographs Extension A
      (cp >= 0x4E00 && cp <= 0x9FFF) ||   // CJK Unified Ideographs
      (cp >= 0xA000 && cp <= 0xA48F) ||   // Yi Syllables
      (cp >= 0xA490 && cp <= 0xA4CF) ||   // Yi Radicals
      (cp >= 0xA960 && cp <= 0xA97F) ||   // Hangul Jamo Extended-A
      (cp >= 0xAC00 && cp <= 0xD7AF) ||   // Hangul Syllables
      (cp >= 0xD7B0 && cp <= 0xD7FF) ||   // Hangul Jamo Extended-B
      (cp >= 0xF900 && cp <= 0xFAFF) ||   // CJK Compatibility Ideographs
      (cp >= 0xFE10 && cp <= 0xFE1F) ||   // Vertical Forms
      (cp >= 0xFE30 && cp <= 0xFE4F) ||   // CJK Compatibility Forms
      (cp >= 0xFE50 && cp <= 0xFE6F) ||   // Small Form Variants
      (cp >= 0xFF00 && cp <= 0xFFEF) ||   // Halfwidth and Fullwidth Forms
      (cp >= 0x1B000 && cp <= 0x1B0FF) || // Kana Supplement
      (cp >= 0x1F000 && cp <= 0x1FFFF) || // Mahjong/Domino/Emoji block (includes ⛔ ✅ ⚠ 🔴 etc.)
      (cp >= 0x20000 && cp <= 0x2A6DF) || // CJK Unified Ideographs Extension B
      (cp >= 0x2A700 && cp <= 0x2CEAF) || // CJK Extensions C/D/E
      (cp >= 0x2CEB0 && cp <= 0x2EBEF) || // CJK Extension F
      (cp >= 0x30000 && cp <= 0x3134F) || // CJK Extension G
      // Common BMP symbols rendered as 2-wide in most terminals
      cp === 0x2139 ||  // ℹ️
      cp === 0x231A || cp === 0x231B ||    // ⌚ ⌛
      cp === 0x23E9 || cp === 0x23F3 ||   // ⏩ ⏳
      (cp >= 0x25FD && cp <= 0x25FE) ||   // ◽ ◾
      (cp >= 0x2600 && cp <= 0x27BF) ||   // Misc Symbols & Dingbats (includes ⚠ ⛔ ✅)
      (cp >= 0x2B50 && cp <= 0x2B55) ||   // ⭐ ⭕
      cp === 0x303F                        // 〿 CJK
    ) {
      width += 2
      continue
    }

    width += 1
  }

  return width
}
