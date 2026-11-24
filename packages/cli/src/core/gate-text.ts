/**
 * gate-text.ts — every word the gate prints, as pure functions.
 *
 * One code path builds the text for every host; only the exit code and the output channel differ
 * (decided by commands/gate.ts). The last line of every text is the machine line:
 *   shipguard-gate: code=<CODE> agentAction=<action> run=<8-char id|none> [rerun=<JSON string>]
 * `rerun` is always last and is ONE JSON string (RFC 8259), because the command carries shell
 * quoting and may hold spaces, quotes and backslashes from the target path.
 *
 * No plan fact lives here: no price, count, pack, trial length or plan name. The weekly "Not run
 * here" line is server text handed in by the caller, already safe.
 */
import type { GateCommandKind } from './gate-target.js'

/** The command kinds the text knows: the three hook commands, and a CI run. */
export type TextKind = GateCommandKind | 'ci'

export type AgentAction = 'proceed' | 'fix_and_rerun' | 'retry' | 'ask_human' | 'stop'

export interface GateFinding {
  id: string
  title: string
  severity: string
  file: string
  line: number | null
  blocking: boolean
  /** One canonical fix sentence (`fix.summary`), already redacted by the scanner. */
  fix: string | null
  category: string | null
  occurrence: string
  /** For a secret finding: `36 chars, value hidden` (the one masked form, core/redact.ts); never any part of the value. */
  secretLabel?: string | null
}

export interface NotScanned {
  file: string | null
  code: string
  /** Plain reason, e.g. `too large (700 KB, limit 512 KB)`. */
  reason: string
}

export interface ScanSummary {
  verdict: 'SAFE_TO_SHIP' | 'REVIEW_BEFORE_SHIP' | 'DO_NOT_SHIP'
  findings: GateFinding[]
  filesScanned: number
  degraded: boolean
  notScanned: NotScanned[]
  /** Files the scan looked at plus the ones it skipped (for "N of M files were not scanned"). */
  filesTotal: number
  rulesApplied: number | null
  /** `general` or `rulebook`; null when the scan did not say. */
  corpus: string | null
  runId: string | null
  seconds: number
  fallbackCode: string | null
}

/** What the gate checked, in words. */
export interface CheckedInfo {
  dir: string
  sha: string
  /** `HEAD of main`, `incoming feature/x`, `local HEAD of main`. */
  label: string
  /** Uncommitted tracked files (never scanned by the gate); null = git could not say. */
  workingTree: string[] | null
  /** git hook merge: the staged merge result was checked, not an incoming commit. */
  mergeResult?: boolean
}

export interface GateTextContext {
  kind: TextKind
  command: string
  checked: CheckedInfo | null
  warnings: string[]
  reportPath: string | null
  rerun: string | null
  /** Plain explanation of a rulebook fallback, one of three fixed phrases, or null. */
  rulesNote: string | null
}

const FALLBACK_PHRASES: Record<string, string> = {
  RULEBOOK_UNREACHABLE: 'rulebook unreachable',
  RULEBOOK_WITHHELD: 'rulebook withheld',
  RULEBOOK_PARTIAL: 'rulebook partial',
}

/** The fixed phrase for a fallback code, or null when it is not printed (PLAN_INACTIVE is only recorded). */
export function fallbackPhrase(code: string | null): string | null {
  return code ? FALLBACK_PHRASES[code] ?? null : null
}

export function rulesNoteLine(phrase: string | null): string | null {
  return phrase ? `Rules: general only (${phrase}; not a full rulebook scan).` : null
}

/** POSIX shell quoting for one argument: left bare when it is plain, else single-quoted. */
export function shellQuote(arg: string): string {
  return /^[A-Za-z0-9_@%+=:,./~-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`
}

/** The one re-run builder for the gate: `shipguard scan [<target>] --strict`. */
export function rerunCommand(target: string | null): string {
  return target ? `shipguard scan ${shellQuote(target)} --strict` : 'shipguard scan --strict'
}

export function machineLine(m: { code: string; agentAction: AgentAction; run: string | null; rerun?: string | null }): string {
  const base = `shipguard-gate: code=${m.code} agentAction=${m.agentAction} run=${m.run ?? 'none'}`
  return m.rerun ? `${base} rerun=${JSON.stringify(m.rerun)}` : base
}

const SENTENCE_END = /(?<=[.!?])\s/

/** The first sentence of a longer fix text. */
export function firstSentence(text: string): string {
  const t = text.trim().replace(/\s+/g, ' ')
  const cut = t.split(SENTENCE_END)[0]
  return cut.length > 0 ? cut : t
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

/** Order: exposed secrets first, then critical and high, payments and auth before the rest. */
export function orderBlocking(findings: GateFinding[]): GateFinding[] {
  const isSecret = (f: GateFinding): boolean => f.category === 'secrets' || /(^|\.)secrets?(\.|$)/.test(f.id)
  const isMoney = (f: GateFinding): boolean => f.category === 'payments' || f.category === 'auth'
  const sev = (f: GateFinding): number => {
    const i = SEVERITY_ORDER.indexOf(f.severity.toLowerCase())
    return i === -1 ? SEVERITY_ORDER.length : i
  }
  return [...findings].sort((a, b) =>
    Number(isSecret(b)) - Number(isSecret(a)) ||
    sev(a) - sev(b) ||
    Number(isMoney(b)) - Number(isMoney(a)) ||
    a.file.localeCompare(b.file) ||
    (a.line ?? 0) - (b.line ?? 0),
  )
}

const VERB: Record<TextKind, { done: string; again: string; allowed: string }> = {
  push: { done: 'pushed', again: 'Push again.', allowed: 'Push allowed' },
  merge: { done: 'merged', again: 'Merge again.', allowed: 'Merge allowed' },
  'pr-merge': { done: 'merged', again: 'Run the PR merge again.', allowed: 'Merge command allowed' },
  ci: { done: 'merged', again: 'Push the fix to this branch; the check runs again.', allowed: 'Check passed' },
}

/** First sentence start of every block: names what did not run. */
function headline(ctx: GateTextContext): string {
  return ctx.kind === 'ci' ? 'SHIPGUARD BLOCKED: this CI run did not pass.' : `SHIPGUARD BLOCKED: \`${ctx.command}\` did not run.`
}

function checkedLine(ctx: GateTextContext): string {
  const c = ctx.checked
  if (!c) return ''
  const what =
    ctx.kind === 'push' ? 'the commit a push sends'
      : ctx.kind === 'merge' ? (c.mergeResult ? 'the merged result about to be committed' : 'the incoming commit of a merge')
        : ctx.kind === 'ci' ? 'the commit this CI run checks'
          : 'the local commit only (the PR head on GitHub and the merged result are not checked; CI covers those)'
  const wt =
    c.workingTree === null
      ? ' Working tree: could not be read, so uncommitted files are unknown (they are not checked).'
      : c.workingTree.length === 0
      ? ''
      : ` Working tree: ${c.workingTree.length} file${c.workingTree.length === 1 ? '' : 's'} changed, not committed (${c.workingTree.slice(0, 3).join(', ')}${c.workingTree.length > 3 ? ', ...' : ''}): a fix there is not ${VERB[ctx.kind].done} until you commit it.`
  return `Checked: ${c.dir} @ ${c.sha.slice(0, 7)} (${c.label}), ${what}.${wt}`
}

function pluralize(n: number, one: string, many: string): string {
  return n === 1 ? one : many
}

function sevLabel(s: string): string {
  return s.toUpperCase().padEnd(8)
}

function trim(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s
}

/** The repeat string of the fix loop; null on a first sighting. */
export function repeatString(maxRuns: number, sameCommit: boolean, reportPath: string | null): string | null {
  if (maxRuns >= 2) {
    return 'Repeated blocking result. Stop and ask the user; do not ignore or bypass it (shipguard ignore, --no-verify) on your own.'
  }
  if (maxRuns === 1) {
    return sameCommit
      ? 'Same blocking result on the same commit. If you changed a file, commit it, then push.'
      : `Same blocking result. Re-read the Verify step of this finding in the report (${reportPath ?? '.shipguard/reports/latest.md'}), then fix and re-run.`
  }
  return null
}

export interface BlockInput {
  ctx: GateTextContext
  scan: ScanSummary
  repeat: { maxRuns: number; sameCommit: boolean }
  agentAction: AgentAction
  code: 'BLOCKING_FINDINGS' | 'INCOMPLETE_SCAN'
}

/** The block text for a scan that found blockers and/or could not read everything. */
export function scanBlockText(input: BlockInput): string {
  const { ctx, scan } = input
  const v = VERB[ctx.kind]
  const blocking = orderBlocking(scan.findings.filter((f) => f.blocking))
  const shown = blocking.slice(0, 3)
  const out: string[] = [...ctx.warnings]
  const incomplete = scan.degraded
  const again = ctx.kind === 'push' ? 'push' : 'run it'

  if (incomplete && blocking.length === 0) {
    const missing = scan.notScanned.length
    out.push(
      `${headline(ctx)} The scan is incomplete: ${missing} of ${scan.filesTotal} files were not scanned (${scan.findings.length} ${pluralize(scan.findings.length, 'finding', 'findings')} in the other ${Math.max(0, scan.filesTotal - missing)}).`,
      `This is a coverage stop, not a finding. Nothing was ${v.done}.`,
    )
  } else {
    const where = ctx.kind === 'merge' && ctx.checked ? (ctx.checked.mergeResult ? ` in the merged result (${ctx.checked.sha.slice(0, 7)})` : ` in commit ${ctx.checked.sha.slice(0, 7)} (${ctx.checked.label})`) : ''
    out.push(
      `${headline(ctx)} DO NOT SHIP${where}: ${blocking.length} blocking ${pluralize(blocking.length, 'finding', 'findings')}${ctx.kind === 'merge' ? '' : ` in ${scan.filesTotal} files`}.`,
      `Nothing was ${v.done}. Do not retry with --no-verify or another route; fix, commit, then ${again} again.`,
    )
  }
  const checked = checkedLine(ctx)
  if (checked) out.push(checked)
  if (ctx.kind === 'merge' && !ctx.checked?.mergeResult) out.push('Not checked: the merged result.')
  const note = rulesNoteLine(ctx.rulesNote)
  if (note) out.push(note)
  out.push('')

  const listed = blocking.length > 0 ? shown : orderBlocking(scan.findings).slice(0, 3)
  if (listed.length > 0) {
    const detail = ctx.reportPath ? `all details: ${ctx.reportPath}${scan.runId ? `, run ${scan.runId}` : ''}` : scan.runId ? `run ${scan.runId}` : ''
    out.push(`Fix ${blocking.length > 3 ? 'these 3 first' : `these ${listed.length}`}${detail ? ` (${detail})` : ''}:`)
    listed.forEach((f, i) => {
      const loc = `${f.file}${f.line ? `:${f.line}` : ''}`
      out.push(` ${i + 1}. ${sevLabel(f.severity)} ${loc}  ${trim(f.title, 110)}${f.secretLabel ? ` (${f.secretLabel})` : ''}`)
      if (f.fix) out.push(`    fix: ${trim(f.fix, 300)}`)
    })
    if (blocking.length > 3) out.push(` +${blocking.length - 3} more blocking: see the report`)
    out.push('')
  }

  if (incomplete && scan.notScanned.length > 0) {
    out.push('Not scanned:')
    for (const n of scan.notScanned.slice(0, 10)) out.push(` - ${n.file ?? n.code}  ${n.reason}`)
    if (scan.notScanned.length > 10) out.push(` - +${scan.notScanned.length - 10} more: see the report`)
    out.push(
      'Fix: for a text file, raise limits.maxFileSizeBytes in shipguard.policy.yml first. Otherwise find out what each file is.',
      ' Ask the user before excluding any unscanned file, or give a reason you checked (for example: listed in .gitignore, generated by <script>). An unscanned file is exactly where a secret can hide.',
      '   shipguard ignore <file> --reason "<why: what this file is>"',
    )
    if (ctx.rerun) out.push(`Check: ${ctx.rerun}   (expect: exit 0; first line is not DO NOT SHIP)`)
    if (ctx.reportPath || scan.runId) out.push(`Report: ${ctx.reportPath ?? '(not written)'}${scan.runId ? `, run ${scan.runId}` : ''}`)
  } else {
    out.push('Then:', ' 1. Apply the fixes above.')
    if (ctx.rerun) out.push(` 2. Check: ${ctx.rerun}   (the ${listed.length} ${pluralize(listed.length, 'finding', 'findings')} above must be gone; exit 0 once nothing else blocks)`)
    out.push(
      ' 3. Commit the fix: check git status first, then  git add <the files you changed> && git commit -m "fix: ShipGuard findings"',
      `    (never commit .env files or other unrelated work; a ${ctx.kind === 'push' ? 'push sends' : 'merge uses'} only commits, so an uncommitted fix is not scanned and not ${v.done})`,
      ` 4. ${v.again}`,
    )
    const repeat = repeatString(input.repeat.maxRuns, input.repeat.sameCommit, ctx.reportPath)
    if (repeat) out.push(repeat)
    out.push(
      'If a finding is wrong for this repo: shipguard ignore <finding-id> --file <path> --reason "<why>"',
      ' A reason is required; it is saved in shipguard.policy.yml and shown in the report. Ask the user before ignoring a critical finding.',
    )
  }
  out.push(machineLine({ code: input.code, agentAction: input.agentAction, run: scan.runId, rerun: ctx.rerun }))
  return out.join('\n')
}

export interface FailClosed {
  code: string
  agentAction: AgentAction
  /** Sentence(s) after "did not run.", plain words. */
  what: string
  /** The lines under it (`Cause:`, `Fix:`, ...). */
  lines: string[]
  /** True when the machine line carries the re-run command. */
  withRerun?: boolean
}

/** The block text for everything that is not a scan result: config errors, deadline, uncommitted tree. */
export function failClosedText(ctx: GateTextContext, f: FailClosed): string {
  const out: string[] = [...ctx.warnings]
  out.push(`${headline(ctx)} ${f.what}`)
  out.push(...f.lines)
  out.push(machineLine({ code: f.code, agentAction: f.agentAction, run: null, rerun: f.withRerun ? ctx.rerun : null }))
  return out.join('\n')
}

export interface PassInput {
  ctx: GateTextContext
  scan: ScanSummary
  /** Weekly "Not run here" line (server text, already safe), or null. Only handed in on a clean pass. */
  gapLine: string | null
}

export interface PassText {
  text: string
  systemMessage: string
  code: 'SAFE_TO_SHIP' | 'REVIEW_BEFORE_SHIP'
}

const LIMIT_CLAUSE = 'no rule matched; not a security audit'
/** The verdict-line form: `(0 findings; no rule matched, not a security audit)`. */
const VERDICT_LIMIT = 'no rule matched, not a security audit'

/** The pass text: the gate is never silent. `Allowed` only means nothing blocks, it is not the verdict. */
export function passText(input: PassInput): PassText {
  const { ctx, scan } = input
  const v = VERB[ctx.kind]
  const safe = scan.verdict === 'SAFE_TO_SHIP'
  const code = safe ? 'SAFE_TO_SHIP' : 'REVIEW_BEFORE_SHIP'
  const c = ctx.checked
  const rules =
    scan.rulesApplied !== null ? `, ${scan.rulesApplied} ${scan.corpus === 'general' || scan.corpus === null ? 'general rules' : 'rules'}` : ''
  const out: string[] = [...ctx.warnings]

  if (ctx.kind === 'push' || ctx.kind === 'ci') {
    out.push(`Checked: ${c?.dir} @ ${c?.sha.slice(0, 7)} (${c?.label}), the commit this ${ctx.kind === 'ci' ? 'run checks' : 'push sends'}: ${scan.filesScanned} files${rules}, ${scan.seconds.toFixed(1)}s.${scan.runId ? ` Run ${scan.runId}.` : ''}`)
    out.push(
      safe
        ? `Verdict: SAFE TO SHIP (0 findings; ${VERDICT_LIMIT}). ${v.allowed}.`
        : `Verdict: REVIEW BEFORE SHIP (${scan.findings.length} ${pluralize(scan.findings.length, 'finding', 'findings')}, 0 blocking; see ${ctx.reportPath ?? '.shipguard/reports/latest.md'}). ${v.allowed}: only blocking findings stop ${ctx.kind === 'ci' ? 'the check' : 'a push'}.`,
    )
    if (ctx.kind !== 'ci') {
      const wt = c?.workingTree
      out.push(
        wt === null
          ? 'Working tree: could not be read, so uncommitted files are unknown (they are not checked).'
          : wt && wt.length > 0
            ? `Working tree: ${wt.length} file${wt.length === 1 ? '' : 's'} changed, not committed. They are not pushed and were not checked.`
            : 'Working tree: clean (nothing uncommitted is left out).',
      )
    }
  } else if (ctx.kind === 'merge') {
    const mr = c?.mergeResult === true
    out.push(`Checked: ${c?.dir} @ ${c?.sha.slice(0, 7)} (${c?.label})${mr ? ', the merged result about to be committed:' : ' only:'} ${scan.filesScanned} files${rules}, ${scan.seconds.toFixed(1)}s.${scan.runId ? ` Run ${scan.runId}.` : ''}`)
    out.push(
      `${mr ? 'Verdict' : 'NOT checked: the merged result in your branch. Verdict for that commit'}: ${safe ? `SAFE TO SHIP (0 findings; ${VERDICT_LIMIT})` : `REVIEW BEFORE SHIP (${scan.findings.length} ${pluralize(scan.findings.length, 'finding', 'findings')}, 0 blocking)`}. ${v.allowed}.`,
    )
    const wt = c?.workingTree
    if (mr && wt && wt.length > 0) out.push(`Working tree: ${wt.length} file${wt.length === 1 ? '' : 's'} changed or new, not staged: not part of this merge and not checked.`)
    else if (mr && wt === null) out.push('Working tree: could not be read, so unstaged and untracked files are unknown (not checked).')
  } else {
    out.push(`Checked: ${c?.dir} @ ${c?.sha.slice(0, 7)} (${c?.label}) only. NOT checked: the PR head on GitHub or the merged result; the CI check covers those.${scan.runId ? ` Run ${scan.runId}.` : ''}`)
    out.push(
      `Verdict for that commit: ${safe ? `SAFE TO SHIP (0 findings; ${VERDICT_LIMIT})` : `REVIEW BEFORE SHIP (${scan.findings.length} ${pluralize(scan.findings.length, 'finding', 'findings')}, 0 blocking)`}. ${v.allowed}.`,
    )
  }
  const note = rulesNoteLine(ctx.rulesNote)
  if (note) out.push(note)
  if (input.gapLine) out.push(input.gapLine)
  out.push(machineLine({ code, agentAction: 'proceed', run: scan.runId }))

  const word = safe ? 'SAFE TO SHIP' : 'REVIEW BEFORE SHIP'
  const detail = safe ? ` (${LIMIT_CLAUSE})` : ` (${scan.findings.length} ${pluralize(scan.findings.length, 'finding', 'findings')}, 0 blocking)`
  const systemMessage = `ShipGuard: ${word}${detail}. ${v.allowed}.${c ? ` Commit ${c.sha.slice(0, 7)}` : ''}${scan.runId ? `, run ${scan.runId}` : ''}.`
  return { text: out.join('\n'), systemMessage, code }
}

/** Claude host, exit 0: ONE JSON object on stdout (the model gets `additionalContext`, the user `systemMessage`). */
export function claudePassJson(pass: PassText): string {
  return JSON.stringify({
    systemMessage: pass.systemMessage,
    hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: pass.text },
  })
}
