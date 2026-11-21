/**
 * The agent contract (spec 02): schemaVersion "7" envelope, `agentAction`, `nextSteps`, the ONE error-code
 * table and the ONE error template. Pure functions (no I/O except the small last-run loop-state file
 * helpers at the bottom): scan.ts, schema.ts and utils/exit.ts call these, and the tables below are the
 * single source `shipguard schema --json` is generated from.
 *
 * HARD RULE (public repo): nothing in this file is a plan fact (no price, count, plan name or limit). Plan
 * data enters only through the `plan` input, copied from the verified server block by the plan modules.
 */
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import chalk from 'chalk'
import type { DegradeReason, Finding, Recommendation, RiskScore, ScanCoverage } from '@agenticcli/shared'

export const SCHEMA_VERSION = '7'
export const CORE_LINE = 'Review code with a rulebook to build secure code'

export type AgentAction = 'proceed' | 'fix_and_rerun' | 'retry' | 'ask_human' | 'stop'

// ---------------------------------------------------------------------------
// Error codes: THE single table (spec 02 "Code table"). Exit semantics: 2 = fix your command or config,
// 3 = environment, network, sign-in or internal, 130 = cancelled. `gate` codes carry the host values.
// ---------------------------------------------------------------------------
export interface ErrorCodeEntry {
  exit: number
  /** Only the gate codes: the exit a git host uses (the Claude host value is `exit`). */
  exitGit?: number
  cause: string
  fix: string
  agentAction: AgentAction
  /** Machine-runnable exactly as printed, or null when only a placeholder could be given. */
  command: string | null
}

export const ERROR_CODES = {
  PATH_NOT_FOUND: { exit: 2, cause: 'the scan path does not exist or cannot be read', fix: 'Pass the project folder, for example: shipguard scan ./my-app', agentAction: 'fix_and_rerun', command: null },
  PATH_NOT_A_DIRECTORY: { exit: 2, cause: 'the scan path is a file', fix: 'Pass the folder that contains the file', agentAction: 'fix_and_rerun', command: null },
  NOT_A_PROJECT: { exit: 2, cause: 'the folder has no project manifest', fix: 'Pass a project path (for example ./my-app) or use --all', agentAction: 'fix_and_rerun', command: null },
  INVALID_POLICY: { exit: 2, cause: 'shipguard.policy.yml cannot be parsed', fix: 'Fix shipguard.policy.yml at the file and line named in this error', agentAction: 'fix_and_rerun', command: null },
  UNKNOWN_OPTION: { exit: 2, cause: 'an option is not known to this command', fix: 'See shipguard <command> --help; error.argument names the option', agentAction: 'fix_and_rerun', command: null },
  UNKNOWN_COMMAND: { exit: 2, cause: 'the command does not exist', fix: 'See all commands: shipguard help', agentAction: 'fix_and_rerun', command: 'shipguard help' },
  REASON_REQUIRED: { exit: 2, cause: '`shipguard ignore` was called without --reason', fix: 'Add --reason "<why: what this is>" (ask the user first for an unscanned file or a critical finding)', agentAction: 'ask_human', command: null },
  CONFIRMATION_REQUIRED: { exit: 2, cause: 'setup or uninstall would change files and cannot ask (not a terminal)', fix: 'Read the printed plan, then re-run with --yes', agentAction: 'ask_human', command: null },
  LOGIN_REQUIRED: { exit: 3, cause: 'the command needs a ShipGuard account and you are signed out', fix: 'shipguard login', agentAction: 'ask_human', command: 'shipguard login' },
  TOKEN_EXPIRED: { exit: 3, cause: 'the saved sign-in is no longer valid', fix: 'shipguard login', agentAction: 'ask_human', command: 'shipguard login' },
  LOGIN_EXPIRED: { exit: 3, cause: 'the sign-in code expired before it was approved (10 min)', fix: 'shipguard login', agentAction: 'ask_human', command: 'shipguard login' },
  LOGIN_CONFIRM_FAILED: { exit: 3, cause: 'approval received, but the account service could not confirm it', fix: 'shipguard login (it checks for an existing approval first)', agentAction: 'retry', command: 'shipguard login' },
  LOGIN_START_FAILED: { exit: 3, cause: 'sign-in could not start (network)', fix: 'Check your connection, then: shipguard login', agentAction: 'retry', command: 'shipguard login' },
  LOGIN_CANCELLED: { exit: 130, cause: 'the user stopped sign-in', fix: 'shipguard login', agentAction: 'stop', command: 'shipguard login' },
  PLAN_INACTIVE: { exit: 3, cause: 'an explicit --pro scan: the account has no active plan', fix: 'shipguard upgrade; or run shipguard scan for general rules', agentAction: 'ask_human', command: 'shipguard upgrade' },
  RULEBOOK_UNREACHABLE: { exit: 3, cause: 'an explicit --pro scan could not download the rulebook (default scans and the gate fall back)', fix: 'Retry, or pass --allow-degraded to run general rules only', agentAction: 'retry', command: null },
  RULEBOOK_PARTIAL: { exit: 3, cause: 'an explicit --pro scan: only part of the rulebook was provided', fix: 'Retry, or pass --allow-degraded to run what was provided and say so', agentAction: 'retry', command: null },
  RULEBOOK_WITHHELD: { exit: 3, cause: 'an explicit --pro scan: the server answered without the rulebook and sent its reason', fix: 'Read error.message (the server text); shipguard upgrade for details, or pass --allow-degraded to run general rules only', agentAction: 'ask_human', command: null },
  RATE_LIMITED: { exit: 3, cause: 'too many requests', fix: 'Retry after error.retryAfterSeconds', agentAction: 'retry', command: null },
  NO_RULES_APPLIED: { exit: 3, cause: 'zero rules ran', fix: 'Re-run; if it repeats: shipguard feedback', agentAction: 'retry', command: null },
  INTERNAL_ERROR: { exit: 3, cause: 'ShipGuard crashed', fix: 'error.log names the log file (no secrets in it); shipguard feedback', agentAction: 'stop', command: null },
  GATE_TIMEOUT: { exit: 2, exitGit: 1, cause: 'the whole shim did not finish inside the shared 150 s deadline of the hook\'s 180 s', fix: 'Run shipguard scan --strict yourself, outside the hook; for a large repo raise gate.timeoutSeconds and re-run shipguard setup --agent claude. If that scan alone takes longer than the deadline, ask the human', agentAction: 'fix_and_rerun', command: null },
  GATE_CONFIG_INVALID: { exit: 2, exitGit: 1, cause: 'gate.timeoutSeconds plus the 30 s margin is longer than the host hook timeout', fix: 'Lower gate.timeoutSeconds, or raise it and re-run shipguard setup --agent claude, which sets the hook timeout to match', agentAction: 'ask_human', command: null },
  GATE_NOT_STARTED: { exit: 2, exitGit: 1, cause: 'the shim found no ShipGuard 0.13 or later to run, or the one it ran crashed', fix: 'npm i -D @agenticcli/shipguard', agentAction: 'fix_and_rerun', command: 'npm i -D @agenticcli/shipguard' },
  GATE_STARTUP_STALLED: { exit: 2, exitGit: 1, cause: 'a local ShipGuard did not answer its 5 s startup check, and no other candidate could run the gate', fix: 'Run `<that path> --version`; if it hangs, reinstall: npm i -D @agenticcli/shipguard', agentAction: 'ask_human', command: null },
  UNCOMMITTED_CHANGES: { exit: 2, exitGit: 1, cause: 'the commit being pushed could not be read and the working tree differs from HEAD, so the gate cannot tell what a push would send', fix: 'Commit your changes (git add <the files you changed>, never .env files), then push again', agentAction: 'fix_and_rerun', command: null },
  SETUP_VERIFY_FAILED: { exit: 3, cause: 'setup wrote its files but the self-test did not block a planted push', fix: 'error.fix names the failing check; nothing is protected yet', agentAction: 'ask_human', command: null },
  UNINSTALL_VERIFY_FAILED: { exit: 3, cause: 'a ShipGuard block is still present after uninstall', fix: 'Delete the lines named in error.file by hand', agentAction: 'ask_human', command: null },
} as const satisfies Record<string, ErrorCodeEntry>

export type ErrorCode = keyof typeof ERROR_CODES

/** Pro-fetch failure classes of pro-scanner.ts (internal names) -> the public code table. */
export function mapProFetchCode(code: string, message = ''): ErrorCode {
  switch (code) {
    case 'AUTH_FAILED':
      return /expired|no longer valid|refused/i.test(message) ? 'TOKEN_EXPIRED' : 'LOGIN_REQUIRED'
    case 'RATE_LIMITED':
      return 'RATE_LIMITED'
    // The 0.12 credit-balance refusal: the server withheld the rulebook (no credit wording in 0.13).
    case 'INSUFFICIENT_CREDITS':
      return 'RULEBOOK_WITHHELD'
    case 'NO_RULES_APPLIED':
      return 'NO_RULES_APPLIED'
    // SERVER_ERROR, BUNDLE_INVALID, NO_ACTIVE_RELEASE, PLATFORM_UNAVAILABLE, FRESHNESS_EXPIRED and anything
    // unknown: the rulebook could not be obtained. Unknown = fail loud, never a quiet fallback.
    default:
      return 'RULEBOOK_UNREACHABLE'
  }
}

// ---------------------------------------------------------------------------
// Outcomes (spec 02 "Outcomes and agent actions"): the one decision table. `schema --json` prints it.
// ---------------------------------------------------------------------------
export const OUTCOMES = [
  { precedence: 1, outcome: 'error: bad command or config, sign-in, network, plan, internal, gate failure, cancel', exit: '2 / 3 / 130', agentAction: 'per the code table', nextStep: 'error.command when set' },
  { precedence: 2, outcome: 'same blocking occurrence for the third time or more (runs 2 or more)', exit: '0 / 1 / block', agentAction: 'ask_human', nextStep: 'review step (stop string)' },
  { precedence: 3, outcome: 'DO_NOT_SHIP, INCOMPLETE_SCAN (alone or with blockers)', exit: '0 / 1 / block', agentAction: 'ask_human when a coverage step has askUser, else fix_and_rerun', nextStep: 'coverage steps, then rerun' },
  { precedence: 4, outcome: 'DO_NOT_SHIP, BLOCKING_FINDINGS', exit: '0 / 1 / block', agentAction: 'fix_and_rerun', nextStep: 'fix steps, then rerun or commit' },
  { precedence: 5, outcome: 'REVIEW_BEFORE_SHIP', exit: '0 / 0 / pass', agentAction: 'proceed', nextStep: 'review step, then rerun' },
  { precedence: 6, outcome: 'SAFE_TO_SHIP', exit: '0 / 0 / pass', agentAction: 'proceed', nextStep: 'first nextSteps entry (setup, update_hook or rerun)' },
  { precedence: null, outcome: 'rulebook not used on a default scan or the gate (modifier)', exit: 'unchanged', agentAction: 'none: the row above decides', nextStep: 'none' },
  { precedence: null, outcome: 'Free scan with no plan data (modifier)', exit: 'unchanged', agentAction: 'none: state no plan fact', nextStep: 'none' },
] as const

export const NEXT_STEP_KINDS = ['fix', 'coverage', 'ignore', 'rerun', 'install', 'login', 'review', 'upgrade_info', 'retry', 'setup', 'update_hook', 'rerun_gate', 'commit'] as const
export type NextStepKind = (typeof NEXT_STEP_KINDS)[number]

export const WARNING_CODES = {
  HOOK_STALE: 'the installed hook is from an older version: shipguard setup --agent claude',
  GATE_UNFINISHED: 'the last gate run never finished: shipguard scan --strict',
} as const

// ---------------------------------------------------------------------------
// Degraded (incomplete-scan) reasons: one fix text per code (spec 06 "Skipped files").
// ---------------------------------------------------------------------------
interface DegradedInfo { fix: string; askUser: boolean; coverageKey?: keyof ScanCoverage['files'] }
const IGNORE_HINT = 'shipguard ignore <file> --reason "<why: what this file is>"'
const DEGRADED_INFO: Record<string, DegradedInfo> = {
  FILE_TOO_LARGE: {
    fix: `text file: raise limits.maxFileSizeBytes in shipguard.policy.yml first; otherwise find out what it is, ask the user, and record a reason you checked (then: ${IGNORE_HINT})`,
    askUser: true, coverageKey: 'tooLarge',
  },
  UNSCANNED_UNKNOWN_BINARY: {
    fix: `find out what it is; only if the user confirms it is safe, exclude it (${IGNORE_HINT})`,
    askUser: true, coverageKey: 'unknownBinary',
  },
  FILE_UNREADABLE: { fix: 'fix the permissions, then re-run', askUser: false },
  INVALID_UTF8: { fix: `find out what it is; only if the user confirms it is safe, exclude it (${IGNORE_HINT})`, askUser: true },
  OUTPUT_TRUNCATED: { fix: 'limit reached; the remaining files were not scanned: raise limits.maxFiles or scan a subfolder', askUser: false },
  SYMLINK_SKIPPED: { fix: 'ShipGuard never follows symlinks; if this path holds real source, replace the symlink with the real file or folder', askUser: false, coverageKey: 'symlink' },
  CODEREF_SKIPPED: { fix: 'some rulebook rules need a newer ShipGuard: update it (npm i -D @agenticcli/shipguard@latest)', askUser: false },
  PRO_RULES_UNAVAILABLE: { fix: 'the rulebook could not be downloaded: retry, or run with general rules only', askUser: false },
  COMPILE_FAILURE: { fix: 'a rulebook bundle failed to compile and was refused: retry; if it repeats: shipguard feedback', askUser: false },
  NO_FILES_SCANNED: { fix: 'nothing was scanned: check the folder, your ignore paths, or run shipguard scan without --changed', askUser: false },
}
/**
 * Degraded codes keep the names 0.12 printed (rule 6: only three finding fields break in schema "7"). The spec's
 * table spells UNREADABLE_FILE as FILE_UNREADABLE; both are accepted below, the CLI keeps emitting the old one.
 */
const DEGRADED_CODE_RENAME: Record<string, string> = { UNREADABLE_FILE: 'FILE_UNREADABLE' }

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const CONFIDENCE_RANK: Record<string, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 }

/** The key of ONE finding: first 12 hex of SHA-256 over rule id and repo-relative file, nothing else (spec 02). */
export function occurrenceKey(ruleId: string, file: string): string {
  return createHash('sha256').update(`${ruleId}\0${file}`).digest('hex').slice(0, 12)
}

/** The one redaction text for a secret (spec 06): type and length, never any character of the value. */
export function secretEvidenceText(secretType: string, length: number | null): string {
  return length === null ? `${secretType}, value hidden` : `${secretType}, ${length} characters, value hidden`
}

function secretTypeOf(f: Finding): string {
  const last = f.id.split('.').pop() ?? f.id
  return last.replace(/-/g, '_')
}

/** Optional length a masking step (W5 `redact`) attaches to a secret finding. */
function secretLengthOf(f: Finding): number | null {
  const n = (f as Finding & { secretLength?: unknown }).secretLength
  return typeof n === 'number' && Number.isFinite(n) ? n : null
}

export type EvidenceJson =
  | { kind: 'secret'; secretType: string; length: number | null; valueHidden: true }
  | { kind: 'text'; text: string }
  | null

export function evidenceOf(f: Finding): EvidenceJson {
  if (f.category === 'secrets') {
    return { kind: 'secret', secretType: secretTypeOf(f), length: secretLengthOf(f), valueHidden: true }
  }
  return f.evidence ? { kind: 'text', text: f.evidence } : null
}

function firstSentence(text: string, cap = 200): string {
  const m = text.match(/^.*?[.!?](?=\s|$)/s)
  const s = (m ? m[0] : text).trim()
  return s.length > cap ? `${s.slice(0, cap - 1).trimEnd()}…` : s
}

export interface FindingContext {
  rerunCommand: string
  /** Rule ids that came from the downloaded rulebook (not in the bundled general set). */
  rulebookRuleIds: ReadonlySet<string>
}

export function buildFindingJson(f: Finding, ctx: FindingContext): Record<string, unknown> {
  const fixSummary = (f.fix ?? f.recommendation ?? '').trim()
  const steps: string[] = []
  return {
    id: f.id,
    occurrence: occurrenceKey(f.id, f.file),
    title: f.title,
    severity: f.severity,
    confidence: f.confidence ?? null,
    category: f.category,
    blocking: f.blocking,
    file: f.file,
    line: f.line ?? null,
    endLine: null,
    column: f.column ?? null,
    evidence: evidenceOf(f),
    why: firstSentence(f.explanation ?? ''),
    fix: {
      summary: fixSummary,
      // No stack-specific fix data ships yet: say so honestly (spec 04: generic when not known to be specific).
      certainty: 'generic',
      code: null,
      steps,
      verify: { command: ctx.rerunCommand, expect: 'no entry in findings[] has this occurrence key' },
      effort: null,
    },
    notAVulnerabilityIf: null,
    suppressed: f.suppressed ?? false,
    suppressionState: f.suppressionState ?? (f.suppressed ? 'suppressed' : 'active'),
    origin: ctx.rulebookRuleIds.has(f.id) ? 'rulebook' : 'general',
    matcherType: f.matcherType ?? null,
    aiCodeTarget: f.aiCodeTarget ?? false,
    cwe: f.cwe ?? [],
    // Deprecated alias (whole 0.13.x line): fix.summary plus fix.steps as one string.
    recommendation: [fixSummary, ...steps].filter(Boolean).join(' '),
  }
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    if (a.blocking !== b.blocking) return a.blocking ? -1 : 1
    const sev = (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
    if (sev !== 0) return sev
    const conf = (CONFIDENCE_RANK[a.confidence ?? ''] ?? 3) - (CONFIDENCE_RANK[b.confidence ?? ''] ?? 3)
    if (conf !== 0) return conf
    if (a.file !== b.file) return a.file < b.file ? -1 : 1
    return (a.line ?? 0) - (b.line ?? 0)
  })
}

// ---------------------------------------------------------------------------
// Loop state (spec 04 "Fix loop"): consecutive runs that still show the same blocking OCCURRENCE.
// ---------------------------------------------------------------------------
export interface SinceLastRun {
  runId: string
  treeChanged: boolean
  fixed: string[]
  new: string[]
  unchanged: Array<{ id: string; occurrence: string; runs: number }>
}

export interface LastRunState {
  runId: string
  treeDigest: string | null
  /** blocking occurrence -> rule id and how many consecutive runs (including the first) showed it. */
  seen: Record<string, { id: string; count: number }>
}

export function blockingOccurrences(findings: Finding[]): Map<string, string> {
  const m = new Map<string, string>()
  for (const f of findings) if (f.blocking && !f.suppressed) m.set(occurrenceKey(f.id, f.file), f.id)
  return m
}

/** Pure: compare this run's blocking occurrences with the previous state. */
export function computeSinceLastRun(
  prev: LastRunState | null,
  current: { runId: string; treeDigest: string | null; blocking: Map<string, string> },
): { since: SinceLastRun | null; next: LastRunState } {
  const seen: LastRunState['seen'] = {}
  for (const [occ, id] of current.blocking) {
    seen[occ] = { id, count: (prev?.seen[occ]?.count ?? 0) + 1 }
  }
  const next: LastRunState = { runId: current.runId, treeDigest: current.treeDigest, seen }
  if (!prev) return { since: null, next }
  const since: SinceLastRun = {
    runId: prev.runId,
    treeChanged: prev.treeDigest !== current.treeDigest,
    fixed: Object.keys(prev.seen).filter((o) => !(o in seen)),
    new: Object.keys(seen).filter((o) => !(o in prev.seen)),
    unchanged: Object.keys(seen)
      .filter((o) => o in prev.seen)
      .map((o) => ({ id: seen[o].id, occurrence: o, runs: seen[o].count - 1 })),
  }
  return { since, next }
}

const LAST_RUN_FILE = '.shipguard/last-run.json'

export function readLastRun(cwd: string, warn: (m: string) => void): LastRunState | null {
  const p = join(cwd, LAST_RUN_FILE)
  if (!existsSync(p)) return null
  try {
    const j = JSON.parse(readFileSync(p, 'utf-8')) as LastRunState
    if (typeof j?.runId !== 'string' || typeof j.seen !== 'object' || j.seen === null) throw new Error('unexpected shape')
    return j
  } catch (err) {
    warn(`Could not read ${LAST_RUN_FILE} (${err instanceof Error ? err.message : err}); the repeat count starts again.`)
    return null
  }
}

export function writeLastRun(cwd: string, state: LastRunState, warn: (m: string) => void): void {
  const p = join(cwd, LAST_RUN_FILE)
  try {
    mkdirSync(dirname(p), { recursive: true })
    const tmp = `${p}.${process.pid}.tmp`
    writeFileSync(tmp, JSON.stringify(state), { encoding: 'utf-8', mode: 0o600 })
    renameSync(tmp, p)
  } catch (err) {
    warn(`Could not write ${LAST_RUN_FILE} (${err instanceof Error ? err.message : err}); repeat detection is off for this run.`)
  }
}

// ---------------------------------------------------------------------------
// Coverage + degraded reasons
// ---------------------------------------------------------------------------
export interface NotScannedEntry { file: string | null; code: string; bytes: number | null; counts: boolean }

export function buildNotScanned(coverage: ScanCoverage | undefined, reasons: DegradeReason[]): NotScannedEntry[] {
  const out: NotScannedEntry[] = []
  if (!coverage) return out
  const degradedCodes = new Set(reasons.map((r) => r.code))
  const add = (files: string[], code: string, counts: boolean): void => {
    for (const file of files) out.push({ file, code, bytes: null, counts })
  }
  add(coverage.files.tooLarge, 'FILE_TOO_LARGE', true)
  add(coverage.files.unknownBinary, 'UNSCANNED_UNKNOWN_BINARY', true)
  add(coverage.files.symlink, 'SYMLINK_SKIPPED', degradedCodes.has('SYMLINK_SKIPPED'))
  // Known binaries and special files never degrade the verdict: listed, not counted.
  add(coverage.files.binary, 'BINARY', false)
  add(coverage.files.special, 'SPECIAL_FILE', false)
  return out
}

export function buildDegradedReasons(reasons: DegradeReason[], coverage: ScanCoverage | undefined): Array<Record<string, unknown>> {
  return reasons.map((r) => {
    const code = r.code
    const info = DEGRADED_INFO[DEGRADED_CODE_RENAME[code] ?? code]
    const files = info?.coverageKey && coverage ? [...coverage.files[info.coverageKey]] : []
    return {
      code,
      files,
      detail: r.detail ?? null,
      fix: info?.fix ?? null,
      command: null,
      askUser: info?.askUser ?? false,
    }
  })
}

export function buildCoverageJson(
  coverage: ScanCoverage | undefined,
  reasons: DegradeReason[],
  filesScanned: number,
  ignoredTestValues: number,
): Record<string, unknown> {
  // Every 0.12 `coverage` key keeps its name, type and meaning (counts, decoded, files, ignoredByDefault as
  // objects, ignoredByUser as a count); the 0.13 keys are added beside them.
  return {
    ...(coverage ?? { discovered: filesScanned, scanned: filesScanned, truncated: false, mode: 'full' }),
    complete: reasons.length === 0,
    notScanned: buildNotScanned(coverage, reasons),
    ignoredTestValues,
  }
}

// ---------------------------------------------------------------------------
// nextSteps + agentAction
// ---------------------------------------------------------------------------
export interface NextStep {
  order: number
  kind: NextStepKind
  label: string
  command: string | null
  safe: boolean
  blocking: boolean
  [extra: string]: unknown
}

export interface InstallHint {
  /** The coding agent detected for this run (claude, codex, cursor), or null. */
  agent: string | null
  gateInstalled: boolean
  hookStale: boolean
}

export interface OutcomeInput {
  value: Recommendation
  blockingFindings: Finding[]
  degraded: boolean
  degradedReasons: Array<Record<string, unknown>>
  notScanned: NotScannedEntry[]
  sinceLastRun: SinceLastRun | null
  warnings: Array<{ code: string; message: string; command: string | null }>
  rerunCommand: string
  install?: InstallHint | null
  reportMarkdown: string
}

export const REPEAT_LABELS = {
  changed: 'Same blocking result. Re-read the Verify step of this finding in the report (.shipguard/reports/latest.md), then fix and re-run.',
  unchangedScan: 'Same blocking result on the same content. If you changed a file, save it, then re-run.',
  stop: 'Repeated blocking result. Stop and ask the user; do not ignore or bypass it (shipguard ignore, --no-verify) on your own.',
} as const

const FIRST_CATEGORIES = ['payments', 'auth']

function fixOrder(a: Finding, b: Finding): number {
  const secretA = a.category === 'secrets' ? 0 : 1
  const secretB = b.category === 'secrets' ? 0 : 1
  if (secretA !== secretB) return secretA - secretB
  const sev = (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
  if (sev !== 0) return sev
  const catA = FIRST_CATEGORIES.includes(a.category) ? 0 : 1
  const catB = FIRST_CATEGORIES.includes(b.category) ? 0 : 1
  if (catA !== catB) return catA - catB
  if (a.file !== b.file) return a.file < b.file ? -1 : 1
  return (a.line ?? 0) - (b.line ?? 0)
}

export function maxRepeatRuns(since: SinceLastRun | null): number {
  return since ? since.unchanged.reduce((m, u) => Math.max(m, u.runs), 0) : 0
}

export function buildNextSteps(i: OutcomeInput): NextStep[] {
  const steps: Array<Omit<NextStep, 'order'>> = []
  const runs = maxRepeatRuns(i.sinceLastRun)
  const incomplete = i.degraded

  // One fix step per blocking occurrence (two matches of one rule in one file share one key).
  const seenOcc = new Set<string>()
  for (const f of [...i.blockingFindings].sort(fixOrder)) {
    const occ = occurrenceKey(f.id, f.file)
    if (seenOcc.has(occ)) continue
    seenOcc.add(occ)
    steps.push({
      kind: 'fix', findingId: f.id, occurrence: occ, label: f.title, file: f.file, line: f.line ?? null,
      command: null, safe: false, blocking: true,
    })
  }

  // Coverage: one step per unscanned file; a reason-less step for gaps with no file.
  const reasonByCode = new Map(i.degradedReasons.map((r) => [String(r.code), r]))
  const namedCodes = new Set<string>()
  for (const n of i.notScanned.filter((x) => x.counts && x.file)) {
    const r = reasonByCode.get(n.code)
    const askUser = Boolean(r?.askUser)
    namedCodes.add(n.code)
    steps.push({
      kind: 'coverage', file: n.file, code: n.code, label: `${n.file}: ${String(r?.fix ?? 'resolve this file')}`,
      command: null, safe: false, blocking: true, askUser,
    })
  }
  for (const r of i.degradedReasons) {
    const code = String(r.code)
    if (namedCodes.has(code) || (Array.isArray(r.files) && r.files.length > 0)) continue
    steps.push({
      kind: 'coverage', code, label: String(r.fix ?? r.detail ?? 'resolve this gap'),
      command: null, safe: false, blocking: true, askUser: Boolean(r.askUser),
    })
  }

  for (const w of i.warnings) {
    steps.push({ kind: w.code === 'HOOK_STALE' ? 'update_hook' : 'rerun_gate', label: w.message, command: w.command, safe: true, blocking: false })
  }

  if (i.blockingFindings.length > 0 && runs >= 2) {
    steps.push({ kind: 'review', label: REPEAT_LABELS.stop, command: null, safe: false, blocking: true, askUser: true })
  } else {
    if (i.blockingFindings.length > 0 && runs === 1) {
      const unchangedTree = i.sinceLastRun?.treeChanged === false
      steps.push({
        kind: 'rerun', label: unchangedTree ? REPEAT_LABELS.unchangedScan : REPEAT_LABELS.changed,
        command: i.rerunCommand, safe: true, blocking: false,
      })
    }
    const total = i.blockingFindings.length + steps.filter((s) => s.kind === 'coverage').length
    if (i.value === 'SAFE_TO_SHIP' && !incomplete) {
      // A clean scan's first step comes from the agent and install state (spec 02 field notes).
      if (i.install?.hookStale) {
        steps.unshift({ kind: 'update_hook', label: 'Update the installed hook', command: 'shipguard setup --agent claude', safe: false, blocking: false })
      } else if (i.install && !i.install.gateInstalled && i.install.agent) {
        steps.unshift({ kind: 'setup', label: `Install the ${i.install.agent} gate`, command: `shipguard setup --agent ${i.install.agent}`, safe: false, blocking: false })
      } else {
        steps.push({ kind: 'rerun', label: 'Nothing to fix. Re-check after changes', command: i.rerunCommand, safe: true, blocking: false })
      }
    } else if (i.value === 'REVIEW_BEFORE_SHIP' && !incomplete) {
      steps.push({ kind: 'review', label: `Read the findings in the report (${i.reportMarkdown})`, command: null, safe: true, blocking: false })
      steps.push({ kind: 'rerun', label: 'Re-run after reviewing', command: i.rerunCommand, safe: true, blocking: false, expect: 'exit 0' })
    } else {
      steps.push({
        kind: 'rerun',
        label: total > 0 ? `Re-run after fixing all ${total}` : 'Re-run after fixing the cause',
        command: i.rerunCommand,
        expect: 'exit 0 once every blocker and coverage gap is resolved',
        safe: true, blocking: false,
      })
    }
  }

  return steps.map((s, idx) => ({ order: idx + 1, ...s }) as NextStep)
}

/** The one agentAction rule (spec 02 precedence): the FIRST row that applies, top to bottom. */
export function decideAgentAction(i: {
  value: Recommendation
  blockingCount: number
  degraded: boolean
  steps: NextStep[]
  sinceLastRun: SinceLastRun | null
}): AgentAction {
  if (maxRepeatRuns(i.sinceLastRun) >= 2 && i.blockingCount > 0) return 'ask_human'
  if (i.degraded) return i.steps.some((s) => s.kind === 'coverage' && s.askUser === true) ? 'ask_human' : 'fix_and_rerun'
  if (i.value === 'DO_NOT_SHIP') return 'fix_and_rerun'
  return 'proceed'
}

// ---------------------------------------------------------------------------
// Verdict, exit, plan
// ---------------------------------------------------------------------------
export type VerdictReason = 'BLOCKING_FINDINGS' | 'INCOMPLETE_SCAN' | 'RISK_SCORE' | 'REVIEW_BEFORE_SHIP' | 'SAFE_TO_SHIP'

export function buildVerdictJson(i: {
  value: Recommendation
  blockingCount: number
  findingCount: number
  degraded: boolean
  filesScanned: number
  filesDiscovered: number
  rulebookFallback: boolean
}): Record<string, unknown> {
  const reason: VerdictReason = i.degraded
    ? 'INCOMPLETE_SCAN'
    : i.blockingCount > 0
      ? 'BLOCKING_FINDINGS'
      : i.value === 'DO_NOT_SHIP'
        ? 'RISK_SCORE'
        : i.value
  const summary = i.degraded
    ? `${Math.max(i.filesDiscovered - i.filesScanned, 0)} of ${i.filesDiscovered} files were not scanned, ${i.findingCount} findings in the other ${i.filesScanned}`
    : i.blockingCount > 0
      ? `${i.blockingCount} blocking finding${i.blockingCount === 1 ? '' : 's'} in ${i.filesScanned} files`
      : `${i.findingCount} finding${i.findingCount === 1 ? '' : 's'} in ${i.filesScanned} files`
  return {
    value: i.value,
    reason,
    blockingCount: i.blockingCount,
    findingCount: i.findingCount,
    complete: !i.degraded,
    summary,
    meaning:
      'Scan finished. DO_NOT_SHIP means a rule matched or coverage was incomplete. SAFE_TO_SHIP only means no rule matched, not that the app is secure.' +
      (i.rulebookFallback ? ' Verdict covers general rules only.' : ''),
  }
}

// ---- plan block (no plan data wired yet: the no-data branch of spec 02 "The plan block") ----

const STACK_DISPLAY: Record<string, string> = {
  nextjs: 'Next.js', express: 'Express', fastify: 'Fastify', prisma: 'Prisma', drizzle: 'Drizzle', supabase: 'Supabase',
}
export function stackDisplayName(name: string): string {
  return STACK_DISPLAY[name] ?? name
}

export interface PlanInput {
  /** Frameworks detected for this scan (not 'generic'). */
  stacks: string[]
  complete: boolean
  blockingCount: number
  /** The run used the downloaded rulebook. */
  rulebookRan: boolean
  rulebookFallbackCode: string | null
  /** Environment facts for suppression reasons. */
  ci: boolean
  muted: boolean
  /**
   * Whether the per-channel display cap (spec 02 "Counters") allows telling an agent now. Until the nag
   * counters are wired this is false, so the contract never tells an agent loop the same sentence twice.
   */
  jsonPitchAllowed: boolean
}

export function buildPlanJson(i: PlanInput): Record<string, unknown> {
  const names = i.stacks.map(stackDisplayName)
  const hasStack = names.length > 0
  const coverageBranch = hasStack && i.complete && !i.rulebookRan && i.rulebookFallbackCode === null
  let relay = false
  let reason: string | null
  let kind: 'coverage' | null
  let sentence: string | null = null

  if (i.rulebookRan) {
    kind = null; reason = 'NO_PLAN_DATA'
  } else if (coverageBranch) {
    kind = 'coverage'; reason = 'NO_PLAN_DATA'
    sentence = `Checks for ${names.join(' + ')} beyond the general rules did not run here; details: shipguard upgrade`
    if (i.blockingCount > 0) reason = 'BLOCKING_FINDINGS'
    else if (i.ci) reason = 'CI'
    else if (i.muted) reason = 'MUTED'
    else if (!i.jsonPitchAllowed) reason = 'RECENTLY_SHOWN'
    else relay = true
  } else {
    kind = null; reason = hasStack ? (i.complete ? 'NO_PLAN_DATA' : 'INCOMPLETE_SCAN') : 'NO_GAP'
  }

  return {
    status: 'unavailable',
    reason: 'NOT_FETCHED',
    command: 'shipguard upgrade',
    link: null,
    server: null,
    recommendation: {
      eligible: false,
      relay,
      kind,
      reason,
      sentence,
      next: { command: 'shipguard upgrade --json', link: null },
      mute: kind === null ? null : 'SHIPGUARD_NO_PROMO=1',
    },
    usageNote: { relay: false, reason: 'NO_USAGE' },
    receiptNote: { relay: false, reason: 'NO_RECEIPT' },
  }
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------
export interface ExtraErrorFields {
  path?: string
  file?: string
  line?: number
  argument?: string
  retryAfterSeconds?: number
  log?: string
}

export interface ErrorEnvelope {
  schemaVersion: string
  cliVersion: string
  runId: string | null
  ok: false
  error: {
    code: string
    message: string
    cause: string
    fix: string
    command: string | null
  } & ExtraErrorFields
  agentAction: AgentAction
  exit: { code: number }
}

export function buildErrorEnvelope(input: {
  code: ErrorCode
  message: string
  cliVersion: string
  runId?: string | null
  cause?: string
  fix?: string
  command?: string | null
  exitCode?: number
  agentAction?: AgentAction
  extra?: ExtraErrorFields
}): ErrorEnvelope {
  const entry: ErrorCodeEntry = ERROR_CODES[input.code]
  return {
    schemaVersion: SCHEMA_VERSION,
    cliVersion: input.cliVersion,
    runId: input.runId ?? null,
    ok: false,
    error: {
      code: input.code,
      message: input.message,
      cause: input.cause ?? entry.cause,
      fix: input.fix ?? entry.fix,
      command: input.command === undefined ? entry.command : input.command,
      ...input.extra,
    },
    agentAction: input.agentAction ?? entry.agentAction,
    exit: { code: input.exitCode ?? entry.exit },
  }
}

/**
 * The one error template (spec 06), printed to stderr for every error of every command:
 *   ✗ <CODE>: <what happened>
 *     Cause: <why>
 *     Fix: <one concrete step>
 *     Run: <command>     (only when a command fixes it AND the Fix line does not already contain it)
 */
export function errorTemplateLines(env: ErrorEnvelope): { head: string; rest: string[] } {
  const e = env.error
  const rest: string[] = []
  if (e.cause && !e.message.includes(e.cause)) rest.push(`  Cause: ${e.cause}`)
  rest.push(`  Fix: ${e.fix}`)
  if (e.command && !e.fix.includes(e.command)) rest.push(`  Run: ${e.command}`)
  return { head: `${e.code}: ${e.message}`, rest }
}

/** The whole template as one string (the first line carries the red ✗). */
export function renderErrorTemplate(env: ErrorEnvelope): string {
  const { head, rest } = errorTemplateLines(env)
  return [`${chalk.red('✗')} ${head}`, ...rest].join('\n')
}

export interface ScanEnvelopeInput {
  cliVersion: string
  runId: string
  timestamp: string
  elapsedMs: number
  verdictValue: Recommendation
  verdict: Record<string, unknown>
  exitCode: number
  strict: boolean
  strictWouldExit: number
  agentAction: AgentAction
  report: { markdown: string; json: string } | null
  stack: { detected: string[]; supported: boolean; manifest?: string | null }
  rules: Record<string, unknown>
  plan: Record<string, unknown>
  findings: Finding[]
  findingCtx: FindingContext
  coverage: Record<string, unknown>
  degraded: boolean
  degradedReasons: Array<Record<string, unknown>>
  warnings: Array<{ code: string; message: string; command: string | null }>
  nextSteps: NextStep[]
  telemetry: 'on' | 'off' | undefined
  regressions: unknown[]
  coverageChanged: unknown[]
  sinceLastRun: SinceLastRun | null
  treeDigest: string | undefined
  riskScore: RiskScore
  policyUsed: string
  scanIdReused: boolean
  /** Result fields kept as additive 0.12 keys (stateStatus etc.). */
  legacy: {
    stateStatus?: string
    regressionCheckSkipped?: boolean
    regressionCheckSkippedReason?: string
    creditsWarning: boolean
    filesScanned: number
    exitMeaning: string
    rulesVersion?: string
    rulesApplied?: number
    rulesBreakdown?: Record<string, number>
    aiCodeIssues?: number
  }
}

export function buildScanEnvelope(i: ScanEnvelopeInput): Record<string, unknown> {
  const out: Record<string, unknown> = {
    schemaVersion: SCHEMA_VERSION,
    cliVersion: i.cliVersion,
    runId: i.runId,
    ok: true,
    timestamp: i.timestamp,
    elapsedMs: i.elapsedMs,
    verdict: i.verdict,
    exit: { code: i.exitCode, strict: i.strict, strictWouldExit: i.strictWouldExit },
    agentAction: i.agentAction,
    report: i.report,
    stack: i.stack,
    rules: i.rules,
    plan: i.plan,
    findings: sortFindings(i.findings).map((f) => buildFindingJson(f, i.findingCtx)),
    coverage: i.coverage,
    degraded: i.degraded,
    degradedReasons: i.degradedReasons,
    warnings: i.warnings,
    nextSteps: i.nextSteps,
    telemetry: i.telemetry,
    regressions: i.regressions,
    coverageChanged: i.coverageChanged,
    sinceLastRun: i.sinceLastRun,
    treeDigest: i.treeDigest,
    policyUsed: i.policyUsed,
    scanIdReused: i.scanIdReused,
    scanIdReusedReason: i.scanIdReused ? 'Same folder content and options as an earlier run: this run reused its scan id.' : null,
    // Deprecated aliases for the whole 0.13.x line (gone in schema "8").
    recommendation: i.verdictValue,
    riskScore: i.riskScore,
    stateStatus: i.legacy.stateStatus,
    regressionCheckSkipped: i.legacy.regressionCheckSkipped,
    ...(i.legacy.regressionCheckSkippedReason ? { regressionCheckSkippedReason: i.legacy.regressionCheckSkippedReason } : {}),
    // Deprecated 0.12 aliases, same values as before: read `exit` and `verdict` instead.
    exitMeaning: i.legacy.exitMeaning,
    creditsWarning: i.legacy.creditsWarning,
    filesScanned: i.legacy.filesScanned,
    ...(i.legacy.rulesVersion !== undefined ? { rulesVersion: i.legacy.rulesVersion } : {}),
    ...(i.legacy.rulesApplied !== undefined ? { rulesApplied: i.legacy.rulesApplied } : {}),
    ...(i.legacy.rulesBreakdown !== undefined ? { rulesBreakdown: i.legacy.rulesBreakdown } : {}),
    ...(i.legacy.aiCodeIssues !== undefined ? { aiCodeIssues: i.legacy.aiCodeIssues } : {}),
  }
  return out
}

