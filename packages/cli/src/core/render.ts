/**
 * render.ts — Pure rendering functions for the verbose-by-default gamified scan output.
 *
 * All functions return strings (never print directly) so they are:
 *  - Unit-testable without mocking process/console
 *  - Composable in scan.ts behind TTY/quiet/machine-output gates
 *
 * ANSI color via chalk only. No new dependencies.
 */

import chalk from 'chalk'
import { existsSync } from 'node:fs'
import { ensureSecureDir, writeSecureFileSync } from '../utils/secure-fs.js'
import { join, basename } from 'node:path'
import { homedir } from 'node:os'
import { goLink } from './links.js'
import type { Finding, ScanResult, Confidence } from '@agenticcli/shared'
import { effectiveRecommendation } from './verdict.js'
import { bundledRulesMeta } from './bundled-rules.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const DOCS_URL = goLink('docs')
export const SITE_URL = goLink('site')
export const PRICING_URL = goLink('pricing')
const ISSUES_URL = 'https://github.com/agenticcli/shipguard/issues'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const

const BOX_WIDTH = 78  // fits 80-col terminal with 1-char margin

// Box-drawing chars
const H = '─'
const V = '│'
const TL = '╭'
const TR = '╮'
const BL = '╰'
const BR = '╯'
const SECTION = '├' + H.repeat(BOX_WIDTH - 2) + '┤'

// Progress bar chars
const BAR_FULL = '█'
const BAR_EMPTY = '░'

// Severity icons — used throughout output
export const SEVERITY_ICONS: Record<string, string> = {
  critical: '🛑',
  high:     '⛔',
  medium:   '⚠️',
  low:      '🐛',
  info:     'ℹ️',
}

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
 */
export function quickstartHelp(isTTY: boolean): string {
  const lines: string[] = []

  if (isTTY) {
    lines.push('')
    lines.push(chalk.bold.cyan('  ╭─────────────────────────────────────────────────────────────────────────╮'))
    lines.push(chalk.bold.cyan('  │') + chalk.bold('  🛡  ShipGuard — CLI-first release gate for AI-built apps          ') + chalk.bold.cyan('  │'))
    lines.push(chalk.bold.cyan('  │') + '     Catches secrets, auth gaps, and deployment issues before you ship  ' + chalk.bold.cyan('  │'))
    lines.push(chalk.bold.cyan('  ╰─────────────────────────────────────────────────────────────────────────╯'))
    lines.push('')
    lines.push(chalk.bold('  Get started in 2 commands:'))
    lines.push('')
    lines.push(`    ${chalk.green('npx @agenticcli/shipguard scan')}    ${chalk.dim('# zero install — scan right now')}`)
    lines.push(`    ${chalk.green('shipguard scan --strict')}           ${chalk.dim('# CI mode: exit 1 on blocking issues')}`)
    lines.push('')
    lines.push(chalk.bold('  Commands:'))
    lines.push('')
    lines.push(`    ${chalk.cyan('scan')}      ${chalk.dim('[path]')}   Scan a project for high-risk issues`)
    lines.push(`    ${chalk.cyan('init')}               Generate a .shipguard.yml policy file`)
    lines.push(`    ${chalk.cyan('login')}              Sign in to scan with the full rule corpus`)
    lines.push(`    ${chalk.cyan('logout')}             Remove saved credentials`)
    lines.push(`    ${chalk.cyan('status')}             Show auth status and credits`)
    lines.push(`    ${chalk.cyan('hook')}      ${chalk.dim('--target')} Install the gate at the merge boundary`)
    lines.push(`    ${chalk.cyan('schema')}    ${chalk.dim('--json')}   Print the machine-readable scan contract`)
    lines.push(`    ${chalk.cyan('feedback')}           Where to send feedback (GitHub issues)`)
    lines.push(`    ${chalk.cyan('rate')}      ${chalk.dim('<id> up|down')}  Rate a rule finding`)
    lines.push(`    ${chalk.cyan('telemetry')} ${chalk.dim('status')}   Show or change the pseudonymous usage ping`)
    lines.push(`    ${chalk.cyan('help')}  ${chalk.dim('/ ?')}        Show this screen`)
    lines.push('')
    lines.push(chalk.bold('  Exit codes (verdict-neutral — read the JSON for the verdict):'))
    lines.push(`    ${chalk.green('0')}  Scan completed — verdict is in the JSON \`recommendation\` field`)
    lines.push(`    ${chalk.yellow('1')}  Blocked — ONLY with --strict, on blocking findings or an unfinished scan`)
    lines.push(`    ${chalk.red('2')}  Config error`)
    lines.push(`    ${chalk.red('3')}  Runtime error — scan could not meaningfully run`)
    lines.push('')
    lines.push(`  ${chalk.dim('Docs')}    ${chalk.underline(DOCS_URL)}`)
    lines.push(`  ${chalk.dim('Site')}    ${chalk.underline(SITE_URL)}`)
    lines.push(`  ${chalk.dim('Pricing')} ${chalk.underline(PRICING_URL)}`)
    lines.push(`  ${chalk.dim('Issues')}  ${chalk.underline(ISSUES_URL)}`)
    lines.push('')
  } else {
    // Plain text for non-TTY (piped, CI)
    lines.push('')
    lines.push('  ShipGuard — CLI-first release gate for AI-built apps')
    lines.push('  Catches secrets, auth gaps, and deployment issues before you ship')
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
    lines.push('    status                Auth status + credits')
    lines.push('    hook      --target     Install the gate at the merge boundary')
    lines.push('    schema    --json       Machine-readable scan contract')
    lines.push('    feedback               Where to send feedback (GitHub issues)')
    lines.push('    rate      <id> up|down Rate a finding')
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
// False-positive / confidence label
// ---------------------------------------------------------------------------

/**
 * Map a finding's confidence level to a human-readable false-positive likelihood label.
 * Undefined/null/unrecognized → "unrated"
 */
export function findingFpLabel(confidence: Confidence | undefined | null): string {
  switch (confidence) {
    case 'HIGH':   return 'low false-positive chance'
    case 'MEDIUM': return 'moderate — review'
    case 'LOW':    return 'higher false-positive — verify manually'
    default:       return 'unrated'
  }
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
// Findings summary (grouped by severity, with confidence/FP labels)
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<string, (s: string) => string> = {
  critical: chalk.bgRed.white,
  high:     chalk.red,
  medium:   chalk.yellow,
  low:      chalk.blue,
  info:     chalk.gray,
}

// Local alias — SEVERITY_ICONS is already exported at top of file

/**
 * Render grouped findings list with severity headers and FP labels.
 * Returns empty-state message if no findings.
 */
export function renderFindingsSummary(findings: Finding[]): string {
  if (findings.length === 0) {
    return chalk.green('  ✓  No findings detected — clean scan.')
  }

  const lines: string[] = []

  // Legend (once at the top)
  lines.push(
    chalk.dim(
      '  Confidence legend: HIGH → low false-positive chance  ' +
      'MEDIUM → moderate — review  LOW → higher false-positive'
    )
  )
  lines.push('')

  for (const sev of SEVERITY_ORDER) {
    const group = findings.filter(f => f.severity === sev)
    if (group.length === 0) continue

    const colorFn = SEVERITY_COLORS[sev] || chalk.white
    const icon = SEVERITY_ICONS[sev] ?? ''
    lines.push(`  ${colorFn(` ${sev.toUpperCase().padEnd(8)} `)} ${icon} ${group.length} finding${group.length !== 1 ? 's' : ''}`)

    for (const f of group) {
      const location = f.line != null ? `${f.file}:${f.line}` : f.file
      const fpLabel = chalk.dim(`[${findingFpLabel(f.confidence)}]`)
      lines.push(`    ${chalk.bold(f.title)} — ${chalk.cyan(location)} ${fpLabel}`)
      if (f.evidence) {
        lines.push(`      Evidence: ${chalk.yellow(truncate(f.evidence, 100))}`)
      }
    }
    lines.push('')
  }

  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// Category breakdown table
// ---------------------------------------------------------------------------

/**
 * Render a per-category (CheckCategory) breakdown table showing finding counts.
 */
export function findingsByCategoryTable(findings: Finding[]): string {
  if (findings.length === 0) {
    return chalk.dim('  No findings across any category.')
  }

  // Count by category
  const catCounts: Record<string, number> = {}
  for (const f of findings) {
    catCounts[f.category] = (catCounts[f.category] ?? 0) + 1
  }

  const lines: string[] = []
  lines.push(chalk.bold('  Category breakdown:'))

  for (const [cat, count] of Object.entries(catCounts).sort()) {
    const bar = chalk.cyan('■'.repeat(Math.min(count, 10)))
    lines.push(`    ${cat.padEnd(14)} ${String(count).padStart(3)}  ${bar}`)
  }

  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// Coverage line (honest false-negative / coverage statement)
// ---------------------------------------------------------------------------

/**
 * Render an honest coverage statement: what this offline scan actually applied, and
 * what signing in actually changes.
 *
 * WHAT THIS LINE USED TO SAY, AND WHY IT WAS REPLACED (2026-08-04)
 * ===============================================================
 * The previous text was:
 *
 *   "Deeper agentic rules available via Pro — some issue classes may be missed on free."
 *
 * It was false, and we had already published the fact that it was false. No agentic rule
 * exists at any tier: `grep -ri agentic` across all 255 corpus rule files returns zero
 * matches, and the Pro corpus's `injection` module is classical code injection — SQLi,
 * SSRF, eval, deserialization — not agent-specific detection. There was no "deeper
 * agentic rule" to unlock, on Free or on Pro. Advertising an unbuilt capability as the
 * reason to pay is the one thing outward copy must never do.
 *
 * The replacement states only what is true today:
 *  - the offline scan applies N bundled corpus rules — a real, countable number read
 *    from the bundle itself, so it cannot go stale — plus the local check modules;
 *  - signing in scans against the full current corpus rather than the offline subset.
 *    That is the shipped differentiator (the maintained corpus), and it matches the
 *    ratified positioning: "the maintained rule corpus + observability, scans stay free."
 *    The observability layer is deliberately NOT mentioned — it is roadmap, not built.
 *
 * No guarantee, no absolute, no unbuilt capability. If the honest answer ever becomes
 * "nothing beyond X", this line says that or goes away.
 */
export function coverageLine(): string {
  const bundled = bundledRulesMeta()
  return (
    chalk.dim(
      `  Coverage: ${bundled.ruleCount} bundled rules from the maintained corpus, plus local checks\n` +
      '  for secrets, auth, payments, database and deployment. Runs offline, no account needed.\n' +
      '  `shipguard login` scans against the full current corpus, not just the offline subset.\n' +
      `  Plans: ${chalk.underline(PRICING_URL)}`
    )
  )
}

// ---------------------------------------------------------------------------
// Verdict panel (the gamified reward)
// ---------------------------------------------------------------------------

const VERDICT_CONFIG = {
  SAFE_TO_SHIP: {
    icon: '✅',
    color: chalk.greenBright,
    label: 'SAFE TO SHIP',
    // Deterministic verdict message — no RNG so tests are stable
    attitudeLine: () => chalk.green('  SHIP IT — nothing blocking. Go make something people want.'),
    helpLine: (blockingCount: number) =>
      blockingCount > 0
        ? chalk.green(`  No blocking issues — ${blockingCount} informational finding(s) noted.`)
        : chalk.green('  Clean — safe to ship. No issues found.'),
  },
  REVIEW_BEFORE_SHIP: {
    icon: '⚠️',
    color: chalk.yellowBright,
    label: 'REVIEW BEFORE SHIP',
    attitudeLine: (blockingCount: number) =>
      chalk.yellow(`  HOLD UP — ${blockingCount} finding${blockingCount !== 1 ? 's' : ''} want eyes before this ships.`),
    helpLine: (blockingCount: number) =>
      chalk.yellow(`  ${blockingCount} finding(s) need attention before shipping.`),
  },
  DO_NOT_SHIP: {
    icon: '🛑',
    color: chalk.redBright,
    label: 'DO NOT SHIP',
    attitudeLine: () => chalk.red('  BLOCKED — shipping this would hurt. Fix the criticals first.'),
    helpLine: (blockingCount: number) =>
      chalk.red(`  Blocked: ${blockingCount} critical/blocking issue(s) must be fixed first.`),
  },
} as const

function boxLine(content: string): string {
  // content is the inner text (no padding); we add 1 space padding each side
  const inner = ` ${content}`
  // Measure visible display width (handles emoji double-width, ANSI strips)
  const visibleLen = displayWidth(inner)
  const pad = Math.max(0, BOX_WIDTH - 2 - visibleLen)
  return `${V}${inner}${' '.repeat(pad)}${V}`
}

function boxEmpty(): string {
  return `${V}${' '.repeat(BOX_WIDTH - 2)}${V}`
}

function boxTop(): string {
  return chalk.dim(TL + H.repeat(BOX_WIDTH - 2) + TR)
}

function boxBottom(): string {
  return chalk.dim(BL + H.repeat(BOX_WIDTH - 2) + BR)
}

function boxSection(): string {
  return chalk.dim(SECTION)
}

// ---------------------------------------------------------------------------
// Severity breakdown bar (visual block representation)
// ---------------------------------------------------------------------------

/**
 * Render a compact severity breakdown bar using block chars.
 * Each severity slot is proportional to its count vs total findings.
 * Returns empty string if no findings.
 */
export function severityBar(riskScore: ScanResult['riskScore'], barWidth: number = 30): string {
  const total = riskScore.totalFindings
  if (total === 0) return chalk.green('  ' + BAR_FULL.repeat(barWidth) + '  all clear')

  const counts: Array<{ sev: string; count: number; color: (s: string) => string }> = [
    { sev: 'critical', count: riskScore.criticalCount, color: chalk.bgRed.white },
    { sev: 'high',     count: riskScore.highCount,     color: chalk.red },
    { sev: 'medium',   count: riskScore.mediumCount,   color: chalk.yellow },
    { sev: 'low',      count: riskScore.lowCount,      color: chalk.blue },
    { sev: 'info',     count: riskScore.infoCount,     color: chalk.gray },
  ].filter(c => c.count > 0)

  // Distribute bar width proportionally
  let assigned = 0
  const segments: Array<{ color: (s: string) => string; width: number; sev: string }> = []
  for (let i = 0; i < counts.length; i++) {
    const c = counts[i]
    const w = i === counts.length - 1
      ? barWidth - assigned
      : Math.max(1, Math.round((c.count / total) * barWidth))
    segments.push({ color: c.color, width: Math.min(w, barWidth - assigned), sev: c.sev })
    assigned += segments[segments.length - 1].width
    if (assigned >= barWidth) break
  }

  const bar = segments.map(s => s.color(BAR_FULL.repeat(s.width))).join('')
  const legend = counts.map(c => {
    const icon = SEVERITY_ICONS[c.sev] ?? ''
    return `${icon}${c.count}`
  }).join('  ')
  return `  ${bar}  ${legend}`
}

/**
 * Render the full gamified verdict panel.
 *
 * @param result      - completed scan result
 * @param elapsedMs   - time taken in milliseconds
 * @param skippedCount - total files/symlinks skipped (too large + binary + symlink,
 *                      symlink reporting) — optional, omitted if 0
 * @param topFindings - top findings to surface in "What now?" block (from scan)
 * @param strict      - whether --strict was passed. When a verdict has blocking
 *                      findings and --strict was NOT passed, the exit code is
 *                      still 0 (A1 contract) — the label must say so, so a human
 *                      reading "DO NOT SHIP" doesn't assume the process failed.
 * @param reportPaths - where the written report landed. The
 *                      path INSIDE the panel: it used to be printed after the box by
 *                      `logger.success`, whose green ✓ became the last glyph on screen
 *                      even for a DO_NOT_SHIP run.
 *
 * LAYOUT: the verdict is the LAST
 * thing in the panel, not the first. It used to sit ~70 lines up a 93-line screen, so a
 * scrolled or truncated terminal dropped exactly the one line the whole tool exists to
 * print. With the exit code deliberately silent by default, the printed
 * verdict carries the entire default-mode signal — burying it is a first-order defect.
 */
export function verdictPanel(
  result: ScanResult,
  elapsedMs: number,
  skippedCount?: number,
  topFindings?: ScanResult['findings'],
  strict?: boolean,
  reportPaths?: { mdPath: string; jsonPath: string; runJsonPath: string },
): string {
  const { riskScore, filesScanned } = result
  // Read the AUTHORITATIVE verdict, not the deprecated riskScore mirror (rec #2).
  const recommendation = effectiveRecommendation(result)
  const degraded = result.degraded === true
  const cfg = VERDICT_CONFIG[recommendation]
  const elapsedStr = elapsedMs < 1000 ? `${elapsedMs}ms` : `${(elapsedMs / 1000).toFixed(1)}s`

  const lines: string[] = ['']

  // Top border
  lines.push(boxTop())

  // Title
  lines.push(boxLine(chalk.bold('  ShipGuard — Release Gate Report')))

  // Severity bar
  lines.push(boxSection())
  lines.push(boxLine(chalk.bold('  Severity breakdown')))
  lines.push(boxLine(severityBar(riskScore)))

  // Stats
  lines.push(boxSection())
  lines.push(boxLine(chalk.bold('  Run summary')))
  const skippedSuffix = skippedCount && skippedCount > 0 ? chalk.dim(`  (${skippedCount} skipped)`) : ''
  lines.push(boxLine(`  Files scanned:  ${chalk.cyan(filesScanned)}${skippedSuffix}`))
  lines.push(boxLine(`  Elapsed time:   ${chalk.cyan(elapsedStr)}`))
  lines.push(boxLine(`  Total findings: ${chalk.cyan(riskScore.totalFindings)}`))

  // Severity counts (only non-zero) — inline breakdown
  const sevLines: string[] = []
  if (riskScore.criticalCount > 0) sevLines.push(chalk.red(`🛑 ${riskScore.criticalCount} critical`))
  if (riskScore.highCount > 0)     sevLines.push(chalk.red(`⛔ ${riskScore.highCount} high`))
  if (riskScore.mediumCount > 0)   sevLines.push(chalk.yellow(`⚠️ ${riskScore.mediumCount} medium`))
  if (riskScore.lowCount > 0)      sevLines.push(chalk.blue(`🐛 ${riskScore.lowCount} low`))
  if (riskScore.infoCount > 0)     sevLines.push(chalk.gray(`ℹ️ ${riskScore.infoCount} info`))

  if (sevLines.length > 0) {
    lines.push(boxLine(`  ${sevLines.join('  ')}`))
  }

  // "How ShipGuard helped"
  lines.push(boxSection())
  lines.push(boxLine(chalk.bold('  How ShipGuard helped')))
  if (degraded) {
    // Name WHAT did not run, using the stable machine codes the JSON also carries —
    // a degraded verdict the user cannot explain is as useless as a false green.
    lines.push(boxLine(chalk.red('  Incomplete scan — verdict is fail-closed until this is fixed:')))
    for (const reason of result.degradedReasons ?? []) {
      lines.push(boxLine(chalk.red(`    · ${reason.code}${reason.detail ? ` — ${truncate(reason.detail, 60)}` : ''}`)))
    }
    if ((result.degradedReasons ?? []).length === 0) {
      lines.push(boxLine(chalk.red('    · reason not recorded — see `degraded` in --json output')))
    }
  } else {
    lines.push(boxLine(cfg.helpLine(riskScore.blockingCount)))
  }

  // Report paths — INSIDE the panel (rec #4). Previously printed after the box by
  // logger.success(), whose green ✓ was then the last glyph a DO_NOT_SHIP run showed.
  if (reportPaths) {
    lines.push(boxSection())
    lines.push(boxLine(chalk.bold('  Report written')))
    lines.push(boxLine(`  ${truncatePath(reportPaths.mdPath, 68)}`))
    // The agent-facing path is the RUN-SCOPED result (rec #8), not the latest.json
    // pointer — pointing an agent at the pointer would just add a hop.
    lines.push(boxLine(chalk.dim(`  agent view: ${truncatePath(reportPaths.runJsonPath, 56)}`)))
  }

  // Learn more
  lines.push(boxSection())
  lines.push(boxLine(chalk.bold('  Learn more')))
  lines.push(boxLine(`  Docs     ${chalk.underline(DOCS_URL)}`))
  lines.push(boxLine(`  Site     ${chalk.underline(SITE_URL)}`))
  lines.push(boxLine(`  Pricing  ${chalk.underline(PRICING_URL)}`))

  // ── VERDICT — LAST (rec #4) ───────────────────────────────────────────────
  // Everything above is context; this is the answer. It is last so that a scrolled,
  // piped, or truncated terminal keeps it, and so the final glyph on screen is the
  // verdict's own glyph rather than a green ✓ from whatever printed afterwards.
  lines.push(boxSection())
  const verdictLabel = cfg.color(chalk.bold(`${cfg.icon}  ${cfg.label}`))
  lines.push(boxLine(`  ${verdictLabel}`))
  // A1 contract: blocking findings without --strict still exit 0. Say so next to the
  // verdict so "DO NOT SHIP" never implies a process failure that didn't happen.
  if ((riskScore.blockingCount > 0 || degraded) && !strict) {
    lines.push(boxLine(chalk.dim('  (informational — exit 0; use --strict to enforce as exit 1)')))
  }
  // Attitude line — a DEGRADED scan gets its own wording: the stock DO_NOT_SHIP line
  // ("fix the criticals first") would be false when the verdict came from an INCOMPLETE
  // scan rather than from findings (rec #1).
  const attitudeLine = degraded
    ? chalk.red('  INCOMPLETE — parts of this scan did not run, so it cannot say this is safe.')
    : recommendation === 'REVIEW_BEFORE_SHIP'
      ? cfg.attitudeLine(riskScore.blockingCount)
      : (cfg as typeof VERDICT_CONFIG['SAFE_TO_SHIP']).attitudeLine()
  lines.push(boxLine(attitudeLine))
  lines.push(boxEmpty())

  // Bottom border
  lines.push(boxBottom())
  lines.push('')

  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// End-of-scan action footer (copy-paste commands, zero learning curve)
// ---------------------------------------------------------------------------

/**
 * Render the "What now?" action footer shown after every scan.
 *
 * @param opts.hasFindings     - whether there are any findings (affects rate suggestion)
 * @param opts.topRuleId       - first finding's ruleId, used in `rate` example
 * @param opts.isLoggedIn      - if false, show login + --pro nudge
 */
export function actionFooter(opts: {
  hasFindings: boolean
  topRuleId?: string
  isLoggedIn?: boolean
}): string {
  const { hasFindings, topRuleId, isLoggedIn } = opts
  const lines: string[] = ['']

  lines.push(chalk.bold('  ── What now? ──────────────────────────────────────────────'))
  lines.push('')
  lines.push(`  ${chalk.cyan('shipguard report')}                    ${chalk.dim('# open the full report')}`)

  if (hasFindings && topRuleId) {
    lines.push(`  ${chalk.cyan(`shipguard rate ${topRuleId} up`)}           ${chalk.dim('# was this finding helpful?')}`)
    lines.push(`  ${chalk.cyan(`shipguard rate ${topRuleId} down`)}         ${chalk.dim('# false positive?')}`)
  } else if (hasFindings) {
    lines.push(`  ${chalk.cyan('shipguard rate <ruleId> up')}          ${chalk.dim('# rate a finding')}`)
  }

  lines.push(`  ${chalk.cyan('shipguard feedback "<thoughts>"')}     ${chalk.dim('# what do you think?')}`)

  if (!isLoggedIn) {
    lines.push('')
    // Truth check (2026-08-04): logging in does not unlock a separate "Pro rules" set —
    // it serves the FULL CURRENT corpus, the same content every paid tier gets, metered by
    // the plan's included credits (platform rules.md §9). Say that, not the old claim.
    lines.push(`  ${chalk.yellow('shipguard login')}                    ${chalk.dim('# sign in for the full rule corpus')}`)
    lines.push(`  ${chalk.yellow('shipguard scan --pro')}               ${chalk.dim('# scan with it (uses one scan credit)')}`)
  }

  lines.push('')
  lines.push(`  ${chalk.dim('Full docs: ' + DOCS_URL)}`)
  lines.push('')

  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// First-run welcome banner
// ---------------------------------------------------------------------------

function getShipguardConfigDir(): string {
  return join(homedir(), '.config', 'shipguard')
}

/**
 * Show a one-time welcome banner on first ever run.
 *
 * @param configDir  - override the config dir (used in tests)
 * @returns banner string (non-empty on first call; empty string thereafter)
 */
export function welcomeBanner(configDir?: string): string {
  const dir = configDir ?? getShipguardConfigDir()
  const marker = join(dir, '.welcomed')

  if (existsSync(marker)) {
    return ''
  }

  // Create marker (create dir if needed)
  try {
    ensureSecureDir(dir)
    writeSecureFileSync(marker, '1')
  } catch {
    // Non-fatal — if we can't write the marker, just show the banner every time
  }

  // Banner inner width matches BOX_WIDTH (78 total: 2 borders + 76 inner)
  // We offset the box by 2 spaces so it aligns nicely with terminal margins.
  const BANNER_INNER = BOX_WIDTH - 2  // 76 chars between │ and │

  function bannerLine(content: string): string {
    const inner = ` ${content}`
    const w = displayWidth(inner)
    const pad = Math.max(0, BANNER_INNER - w)
    return chalk.cyan('  │') + inner + ' '.repeat(pad) + chalk.cyan('│')
  }

  const top = chalk.bold(chalk.cyan('  ╭' + '─'.repeat(BANNER_INNER) + '╮'))
  const bottom = chalk.bold(chalk.cyan('  ╰' + '─'.repeat(BANNER_INNER) + '╯'))
  const empty = chalk.cyan('  │') + ' '.repeat(BANNER_INNER) + chalk.cyan('│')

  return [
    '',
    top,
    bannerLine('ShipGuard is a CLI-first release gate for AI-built apps.'),
    bannerLine('It catches secrets, auth flaws, and deployment issues before'),
    bannerLine('they ship — deterministic, fast, privacy-preserving.'),
    empty,
    bannerLine(chalk.bold('Quick start:')),
    bannerLine(`  ${chalk.green('shipguard scan <path>')}    Run a scan on your project`),
    bannerLine(`  ${chalk.green('shipguard login')}           Scan with the full rule corpus`),
    bannerLine(`  ${chalk.green('shipguard scan --json')}     Machine-readable output for CI/agents`),
    empty,
    bannerLine(`Docs: ${chalk.underline(DOCS_URL)}`),
    empty,
    bannerLine(chalk.dim('Pseudonymous usage ping — opt out: shipguard telemetry disable')),
    bannerLine(chalk.dim(`or SHIPGUARD_TELEMETRY=0 · Details: ${chalk.underline(goLink('telemetry'))}`)),
    bottom,
    '',
  ].join('\n')
}

// ---------------------------------------------------------------------------
// Quiet verdict line (for --quiet mode)
// ---------------------------------------------------------------------------

/**
 * Single-line verdict for --quiet mode.
 *
 * @param strict - whether --strict was passed. When blocking findings exist
 *                 without --strict, append an explicit note that the exit
 *                 code is still 0 (A1 contract) — see verdictPanel() comment.
 */
export function quietVerdict(result: ScanResult, strict?: boolean): string {
  const { score, totalFindings, blockingCount } = result.riskScore
  // Authoritative verdict (rec #2), not the deprecated riskScore mirror.
  const recommendation = effectiveRecommendation(result)
  const degraded = result.degraded === true
  const icon = recommendation === 'SAFE_TO_SHIP' ? '✅' : recommendation === 'DO_NOT_SHIP' ? '⛔' : '⚠️'
  const colorFn = recommendation === 'SAFE_TO_SHIP' ? chalk.green : recommendation === 'DO_NOT_SHIP' ? chalk.red : chalk.yellow
  // A one-line verdict that hides "this scan was incomplete" is the false-safe in
  // miniature — say it on the same line (rec #1).
  const degradedNote = degraded ? '  incomplete=yes' : ''
  const suffix = blockingCount > 0 && !strict ? '  (informational — exit 0; use --strict to enforce)' : ''
  return colorFn(`${icon} ${recommendation.replace(/_/g, ' ')}  score=${score}/100  findings=${totalFindings}  blocking=${blockingCount}${degradedNote}${suffix}`)
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function truncate(str: string, maxLen: number): string {
  return str.length <= maxLen ? str : `${str.slice(0, maxLen - 3)}...`
}

function truncatePath(filePath: string, maxLen: number): string {
  if (filePath.length <= maxLen) return filePath
  const parts = filePath.split('/')
  // Keep last 2 segments
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
