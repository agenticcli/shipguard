import { Command } from 'commander'
import { readFileSync, existsSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import YAML from 'yaml'
import { setExitCode } from '../utils/exit.js'
import { isSafeMode } from '../core/telemetry-config.js'
import { logger } from '../utils/logger.js'
import {
  DEFAULT_GATE_TIMEOUT_SECONDS,
  computeRepeat,
  detectStaleHook,
  planDeadline,
  readGateRecord,
  scanBudgetSeconds,
  unfinishedGateWarning,
  writeGateRecord,
  type GateRecord,
} from '../core/gate-state.js'
import {
  copyReports,
  extractCommit,
  headLabel,
  listRefCommits,
  parseScanJson,
  removeExtraction,
  repoTopLevel,
  resolveCommit,
  runScanChild,
  scanErrorCode,
  stagedTree,
  uncommittedFiles,
  type ParsedScan,
  type ScanRun,
  type WorkingTreeOptions,
} from '../core/gate-scan.js'
import { parseGateCommand, type GateInvocation } from '../core/gate-target.js'
import { gateGapFromCache } from '../core/plan-client.js'
import { SHIM_VERSION } from '../core/hook-templates.js'
import { policyShapeProblem } from '../core/policy.js'
import {
  claudePassJson,
  failClosedText,
  fallbackPhrase,
  passText,
  rerunCommand,
  scanBlockText,
  type AgentAction,
  type CheckedInfo,
  type FailClosed,
  type GateTextContext,
  type PassText,
} from '../core/gate-text.js'

/**
 * `shipguard gate --host claude|git|ci|codex|cursor` — the one gate every hook runs (spec 03).
 *
 * It decides which directory and which commit the hooked command targets, scans exactly that commit
 * (never the working tree), and answers with one text for every host. Only the exit code and the
 * channel differ: Claude host = exit 2 on a block (stderr goes to the model) and ONE JSON object on
 * stdout on a pass; git, CI, Codex and Cursor = exit 1 on a block and text on stderr.
 *
 * Fail closed: every failure, configuration errors included, becomes a block text that says what
 * did not run and what to do. The gate never fetches anything (no rulebook, no offer): hooks do
 * not touch the network on their own.
 */

export const GATE_HOSTS = ['claude', 'git', 'ci', 'codex', 'cursor'] as const
export type GateHost = (typeof GATE_HOSTS)[number]

export interface GateOptions {
  host?: string
  /** git host: which git hook called (`pre-push`, `pre-merge-commit`). */
  hook?: string
  supports?: boolean
}

/** Everything the gate needs from the outside, so a test can drive it without a real scan. */
export interface GateDeps {
  now: () => number
  env: NodeJS.ProcessEnv
  cwd: string
  readStdin: () => Promise<string>
  writeStdout: (text: string) => void
  writeStderr: (text: string) => void
  repoTopLevel: (dir: string) => string | null
  resolveCommit: (dir: string, name: string) => string | null
  headLabel: (dir: string) => string
  uncommittedFiles: (dir: string, opts?: WorkingTreeOptions) => string[] | null
  stagedTree: (dir: string, indexFile?: string) => string | null
  /** The commits of every ref under the given ref prefixes; null when git fails or there are too many. */
  listRefCommits: (dir: string, prefixes: string[]) => Array<{ sha: string; label: string }> | null
  extractCommit: (topLevel: string, sha: string) => string
  removeExtraction: (dest: string) => void
  runScan: (opts: { dir: string; budgetMs: number; host: string; top: string; sha: string }) => Promise<ScanRun>
  /**
   * The weekly "Not run here" first line, read from the verified cache with no fetch, or null.
   * The default reads the plan modules' verified cache (plan-client.ts gateGapFromCache). Called only on a clean
   * pass, never in CI, safe mode or with the promotion mute set.
   */
  gapLine: (info: { dir: string; host: GateHost; scan: ParsedScan }) => string | null | Promise<string | null>
  isSafeMode: () => boolean
}

const HOOK_PUSH = 'pre-push'
const STALE_TEXT = 'WARNING: your hook script is from an older ShipGuard and can skip the gate silently. Update it: shipguard setup --agent claude'

function defaultDeps(): GateDeps {
  const cliEntry = resolve(process.argv[1] ?? '')
  return {
    now: () => Date.now(),
    env: process.env,
    cwd: process.cwd(),
    readStdin: () =>
      new Promise((res) => {
        if (process.stdin.isTTY) return res('')
        const chunks: Buffer[] = []
        process.stdin.on('data', (b: Buffer) => chunks.push(b))
        process.stdin.on('end', () => res(Buffer.concat(chunks).toString('utf-8')))
        process.stdin.on('error', () => res(Buffer.concat(chunks).toString('utf-8')))
      }),
    writeStdout: (t) => void process.stdout.write(t),
    writeStderr: (t) => void process.stderr.write(t),
    repoTopLevel,
    resolveCommit,
    headLabel,
    uncommittedFiles,
    stagedTree,
    listRefCommits,
    extractCommit,
    removeExtraction,
    // The child scan reports which gate asked (usage ping field gateKind: claude | git | ci); Codex and Cursor use git hooks.
    runScan: ({ dir, budgetMs, host, top, sha }) => runScanChild({ cliEntry, dir, budgetMs, host: host === 'codex' || host === 'cursor' ? 'git' : host, top, sha }),
    // The weekly gap line: the first line only, from the verified cache, no fetch (plan-client.ts); same 7-day counter as the scan screen.
    gapLine: ({ dir }) => gateGapFromCache(dir),
    isSafeMode: () => isSafeMode(),
  }
}

const isHost = (v: unknown): v is GateHost => typeof v === 'string' && (GATE_HOSTS as readonly string[]).includes(v)

/** Which text kind a host uses for the commands it does not name itself. */
interface Job {
  inv: GateInvocation
  /** Directory the hook ran in (the shell's working directory), for the re-run target. */
  hookCwd: string
  /** git host: commits named by git itself, in place of the refs in the command text. */
  shas?: Array<{ sha: string; label: string }>
  /** pre-merge-commit: MERGE_HEAD does not exist yet, so the staged merge result is checked. */
  mergeResult?: boolean
}

interface JobResult {
  blocked: boolean
  text: string
  pass?: PassText
}

// ---------------------------------------------------------------------------
// Hook input
// ---------------------------------------------------------------------------

interface ClaudeInput {
  command: string
  cwd: string
}

/** Read the Claude Code hook input (`tool_input.command`, `cwd`); null when it is not that JSON. */
function parseClaudeInput(raw: string, fallbackCwd: string): ClaudeInput | null {
  try {
    const j = JSON.parse(raw) as { cwd?: unknown; tool_input?: { command?: unknown } }
    const command = j?.tool_input?.command
    if (typeof command !== 'string') return null
    return { command, cwd: typeof j.cwd === 'string' && j.cwd.length > 0 ? j.cwd : fallbackCwd }
  } catch {
    return null
  }
}

const ZERO_SHA = /^0+$/

/** git host: the commits git is about to send, from the pre-push stdin lines `<lref> <lsha> <rref> <rsha>`. */
function gitPushShas(raw: string, deps: GateDeps, top: string): Array<{ sha: string; label: string }> {
  const out: Array<{ sha: string; label: string }> = []
  const seen = new Set<string>()
  for (const line of raw.split('\n')) {
    const parts = line.trim().split(/\s+/)
    if (parts.length < 4 || ZERO_SHA.test(parts[1]) || seen.has(parts[1])) continue
    seen.add(parts[1])
    const label = parts[0] === 'HEAD' || parts[1] === deps.resolveCommit(top, 'HEAD') ? deps.headLabel(top) : parts[0].replace(/^refs\/(heads|tags)\//, '')
    out.push({ sha: parts[1], label })
  }
  return out
}

function buildJobs(host: GateHost, hook: string | undefined, raw: string, deps: GateDeps): Job[] {
  if (host === 'claude') {
    const input = parseClaudeInput(raw, deps.cwd)
    if (input) {
      return parseGateCommand(input.command, input.cwd, deps.env.HOME).map((inv) => ({ inv, hookCwd: input.cwd }))
    }
    // Not the JSON we know: keep the old floor, any mention of a gated command counts, in the hook cwd.
    return parseGateCommand(raw, deps.cwd, deps.env.HOME).map((inv) => ({ inv, hookCwd: deps.cwd }))
  }
  if (host === 'ci') {
    return [{ inv: { kind: 'push', command: 'shipguard gate --host ci', dir: deps.cwd, refs: [], deleteOnly: false }, hookCwd: deps.cwd }]
  }
  // git, codex, cursor: run from a git hook (or an AGENTS.md instruction) in the repository.
  const merge = hook === 'pre-merge-commit'
  const base: GateInvocation = {
    kind: merge ? 'merge' : 'push',
    command: merge ? 'git merge' : 'git push',
    dir: deps.cwd,
    refs: [],
    deleteOnly: false,
  }
  if (merge) return [{ inv: base, hookCwd: deps.cwd, mergeResult: true }]
  const top = deps.repoTopLevel(deps.cwd)
  if (!merge && (hook ?? HOOK_PUSH) === HOOK_PUSH && top && raw.trim()) {
    const shas = gitPushShas(raw, deps, top)
    // A push that only deletes refs sends no commit: nothing to check, stay silent.
    if (shas.length === 0) return []
    return [{ inv: base, hookCwd: deps.cwd, shas }]
  }
  return [{ inv: base, hookCwd: deps.cwd }]
}

// ---------------------------------------------------------------------------
// Policy (read from the commit being checked)
// ---------------------------------------------------------------------------

type PolicyRead = { ok: true; timeoutSeconds: number | undefined } | { ok: false; line: number | null; cause: string }

const YAML_CAUSES: Record<string, string> = {
  BAD_INDENT: 'a line is indented wrongly',
  TAB_AS_INDENT: 'a line is indented with a tab; use spaces',
  DUPLICATE_KEY: 'a key appears twice',
  MISSING_CHAR: 'a list or text opened here is never closed',
  BLOCK_AS_IMPLICIT_KEY: 'a line is missing a colon or an indent',
  MULTILINE_IMPLICIT_KEY: 'a key runs over more than one line',
}

function readPolicy(dir: string): PolicyRead {
  const path = join(dir, 'shipguard.policy.yml')
  if (!existsSync(path)) return { ok: true, timeoutSeconds: undefined }
  try {
    const doc = YAML.parseDocument(readFileSync(path, 'utf-8'))
    const err = doc.errors[0]
    if (err) {
      return {
        ok: false,
        line: err.linePos?.[0]?.line ?? null,
        cause: YAML_CAUSES[err.code] ?? 'the file is not valid YAML',
      }
    }
    const parsed = doc.toJS() as { gate?: { timeoutSeconds?: unknown } } | null
    const shape = policyShapeProblem(parsed)
    if (shape !== null) return { ok: false, line: null, cause: shape }
    const t = parsed?.gate?.timeoutSeconds
    if (t !== undefined && (typeof t !== 'number' || !Number.isFinite(t) || t <= 0 || t > 3600)) {
      return { ok: false, line: null, cause: 'gate.timeoutSeconds must be a number of seconds between 1 and 3600' }
    }
    return { ok: true, timeoutSeconds: typeof t === 'number' ? t : undefined }
  } catch (err) {
    return { ok: false, line: null, cause: err instanceof Error ? err.message.split('\n')[0] : 'the file could not be read' }
  }
}

// ---------------------------------------------------------------------------
// One commit
// ---------------------------------------------------------------------------

function toCtx(job: Job, host: GateHost, checked: CheckedInfo | null, warnings: string[], top: string | null): GateTextContext {
  const target = top ? relative(job.hookCwd, top) : ''
  return {
    kind: host === 'ci' ? 'ci' : job.inv.kind,
    command: job.inv.command,
    checked,
    warnings,
    reportPath: null,
    rerun: rerunCommand(target || null),
    rulesNote: null,
  }
}

const block = (ctx: GateTextContext, f: FailClosed): JobResult => ({ blocked: true, text: failClosedText(ctx, f) })

const ERROR_TABLE: Record<string, { agentAction: AgentAction; what: string; fix: string }> = {
  RATE_LIMITED: { agentAction: 'retry', what: 'The scan was rate limited, so nothing was cleared.', fix: 'Retry once after a short wait.' },
  NO_RULES_APPLIED: { agentAction: 'retry', what: 'Zero rules ran, so nothing was cleared.', fix: 'Re-run; if it repeats: shipguard feedback' },
  INTERNAL_ERROR: { agentAction: 'stop', what: 'The scan crashed, so nothing was cleared.', fix: 'Run the check yourself to see the error; if it repeats: shipguard feedback' },
}

async function scanCommit(
  job: Job,
  host: GateHost,
  top: string,
  target: { sha: string; label: string },
  deps: GateDeps,
  warningsBase: string[],
): Promise<JobResult> {
  // A hook script older than this ShipGuard says so itself (the shim exports its version), whatever the files say.
  const shimVersion = Number(deps.env.SHIPGUARD_SHIM_VERSION)
  const staleHook = detectStaleHook(top) ?? (shimVersion > 0 && shimVersion < SHIM_VERSION ? { layer: 'claude' as const, text: STALE_TEXT } : null)
  const startedMs = deps.now()
  const checkedBase: CheckedInfo = { dir: top, sha: target.sha, label: target.label, workingTree: deps.uncommittedFiles(top, { untracked: true, against: job.mergeResult ? 'index' : 'head' }), ...(job.mergeResult ? { mergeResult: true } : {}) }
  const previous = readGateRecord(top)
  const warnings = [...warningsBase]
  const unfinished = unfinishedGateWarning(top, startedMs, previous)
  if (unfinished) warnings.push(unfinished)
  if (staleHook) warnings.push(staleHook.text)
  const ctx = toCtx(job, host, checkedBase, warnings, top)

  let dest: string
  try {
    dest = deps.extractCommit(top, target.sha)
  } catch (err) {
    logger.debug(`gate: ${err instanceof Error ? err.message : String(err)}`)
    return block(ctx, {
      code: 'INTERNAL_ERROR',
      agentAction: 'stop',
      what: `The commit ${target.sha.slice(0, 7)} could not be read, so nothing was scanned.`,
      lines: ['Fix: run `git fsck` and check that the repository is complete (a partial clone cannot be gated offline).'],
    })
  }
  try {
    const policy = readPolicy(dest)
    if (!policy.ok) {
      return block(ctx, {
        code: 'INVALID_POLICY',
        agentAction: 'fix_and_rerun',
        what: `shipguard.policy.yml could not be read${policy.line ? ` (line ${policy.line})` : ''}, so nothing was scanned.`,
        lines: [`Cause: ${policy.cause}.`, `Fix: correct ${policy.line ? `line ${policy.line} of ` : ''}shipguard.policy.yml, commit it, then run it again.`],
      })
    }
    const plan = planDeadline({ nowMs: startedMs, host, env: deps.env, gateTimeoutSeconds: policy.timeoutSeconds })
    if (plan.configInvalid) {
      const hostTimeout = plan.hostTimeoutSeconds ?? 0
      return block(ctx, {
        code: 'GATE_CONFIG_INVALID',
        agentAction: 'ask_human',
        what: `gate.timeoutSeconds is ${plan.gateTimeoutSeconds} s, but the hook is stopped at ${hostTimeout} s, so ShipGuard cannot promise an answer. Nothing was scanned.`,
        lines: [
          `Fix: lower gate.timeoutSeconds to ${Math.max(1, hostTimeout - 30)} or less, or keep ${plan.gateTimeoutSeconds} and run: shipguard setup --agent ${host === 'claude' ? 'claude' : 'git'}   (sets the hook timeout to ${plan.gateTimeoutSeconds + 60} s).`,
        ],
      })
    }
    const budget = scanBudgetSeconds(plan, deps.now())
    if (budget <= 0) return deadlineBlock(ctx, plan.hostTimeoutSeconds === null ? plan.gateTimeoutSeconds : plan.hostTimeoutSeconds - 30)

    const startedAt = new Date(startedMs).toISOString()
    // The running record keeps the previous counters, so a host kill cannot reset the loop count.
    writeGateRecord(top, {
      ...(previous ?? {}),
      schema: 1,
      status: 'running',
      host,
      command: job.inv.command,
      startedAt,
      dir: top,
      finishedAt: undefined,
      runningCommit: target.sha,
    } as GateRecord)

    const run = await deps.runScan({ dir: dest, budgetMs: budget * 1000, host, top, sha: target.sha })
    const elapsed = (deps.now() - startedMs) / 1000
    const finish = (record: Partial<GateRecord>): void => {
      writeGateRecord(top, {
        schema: 1,
        host,
        command: job.inv.command,
        startedAt,
        dir: top,
        commit: target.sha,
        blocking: {},
        finishedAt: new Date(deps.now()).toISOString(),
        ...record,
      } as GateRecord)
    }

    if (run.timedOut) {
      finish({ status: 'timeout', code: 'GATE_TIMEOUT', agentAction: 'fix_and_rerun', run: null, blocking: previous?.blocking ?? {} })
      return deadlineBlock(ctx, plan.hostTimeoutSeconds === null ? plan.gateTimeoutSeconds : plan.hostTimeoutSeconds - 30)
    }

    const parsed = run.exitCode === 0 || run.exitCode === 1 ? parseScanJson(run.stdout, elapsed) : null
    if (!parsed) {
      const code = scanErrorCode(run.stdout)
      const known = code ? ERROR_TABLE[code] : undefined
      const entry = known ?? ERROR_TABLE.INTERNAL_ERROR
      const used = known ? code! : 'INTERNAL_ERROR'
      if (!known) logger.debug(`gate: scan child ended with ${run.exitCode ?? 'no exit code'}; ${run.stderrTail.split('\n').pop() ?? ''}`)
      finish({ status: 'blocked', code: used, agentAction: entry.agentAction, run: null, blocking: previous?.blocking ?? {} })
      return block(ctx, {
        code: used,
        agentAction: entry.agentAction,
        what: entry.what,
        lines: [`Fix: ${entry.fix}`, `Check: ${ctx.rerun}`],
        withRerun: true,
      })
    }

    const scan = parsed.summary
    const reportPath = copyReports(dest, top, scan.runId) ?? null
    const note = fallbackPhrase(scan.fallbackCode)
    const ctx2: GateTextContext = { ...ctx, reportPath, rulesNote: note }
    const blockingFindings = scan.findings.filter((f) => f.blocking)
    const common: Partial<GateRecord> = {
      commit: target.sha,
      run: scan.runId,
      findings: scan.findings.slice(0, 200).map((f) => ({ id: f.id, file: f.file, line: f.line, severity: f.severity, blocking: f.blocking, occurrence: f.occurrence })),
      notScanned: scan.notScanned.flatMap((n) => (n.file ? [n.file] : [])).slice(0, 500),
      ignoresUsed: parsed.suppressed,
      rules: { fallback: scan.fallbackCode ? { code: scan.fallbackCode } : null, receipt: parsed.receipt },
      plan: { server: { usage: parsed.usageState ? { state: parsed.usageState } : null } },
    }

    const blocked = run.exitCode !== 0 || scan.verdict === 'DO_NOT_SHIP' || scan.degraded || blockingFindings.length > 0
    if (blocked) {
      const repeat = computeRepeat(previous, blockingFindings, target.sha)
      const code = scan.degraded ? 'INCOMPLETE_SCAN' : 'BLOCKING_FINDINGS'
      const agentAction: AgentAction = repeat.loopStop || scan.degraded ? 'ask_human' : 'fix_and_rerun'
      finish({ ...common, status: 'blocked', code, agentAction, blocking: repeat.counts })
      return {
        blocked: true,
        text: scanBlockText({ ctx: ctx2, scan, repeat, agentAction, code }),
      }
    }

    finish({ ...common, status: 'passed', code: scan.verdict, agentAction: 'proceed', blocking: {} })
    const clean = !scan.degraded && scan.findings.every((f) => !f.blocking)
    let gap: string | null = null
    if (clean && host !== 'ci' && !deps.isSafeMode() && deps.env.SHIPGUARD_NO_PROMO !== '1') {
      try {
        gap = await deps.gapLine({ dir: top, host, scan: parsed })
      } catch (err) {
        logger.debug(`gate: the gap line could not be read: ${err instanceof Error ? err.message : String(err)}`)
      }
    }
    const pass = passText({ ctx: ctx2, scan, gapLine: gap })
    return { blocked: false, text: pass.text, pass }
  } finally {
    deps.removeExtraction(dest)
  }
}

function deadlineBlock(ctx: GateTextContext, seconds: number): JobResult {
  return block(ctx, {
    code: 'GATE_TIMEOUT',
    agentAction: 'fix_and_rerun',
    what: `The gate did not finish inside its ${seconds} s deadline (startup checks, download and scan), so nothing was cleared. This is not a finding.`,
    lines: [
      `Run the check yourself, outside the hook: ${ctx.rerun}   (a retry would hit the same deadline on a large repo)`,
      `If that scan alone takes longer than ${seconds} s, or this repo is large: stop and ask the user to raise gate.timeoutSeconds in shipguard.policy.yml, then run shipguard setup --agent claude (it sets the hook timeout to the new value plus 60 s).`,
      'The user can run it from their own terminal; agents must not work around this.',
    ],
    withRerun: true,
  })
}

// ---------------------------------------------------------------------------
// One hooked command
// ---------------------------------------------------------------------------

/** Which commits does this command check? `unreadable` = a named ref could not be read. */
function pickCommits(job: Job, top: string, deps: GateDeps): { commits: Array<{ sha: string; label: string }> } | { unreadable: true } | { tooMany: true } {
  if (job.shas) return { commits: job.shas }
  const { inv } = job
  const head = deps.resolveCommit(top, 'HEAD')
  const headText = deps.headLabel(top)
  if (inv.kind === 'pr-merge') return head ? { commits: [{ sha: head, label: `local ${headText}` }] } : { unreadable: true }
  if (inv.kind === 'push') {
    // --all / --mirror / --tags send every ref of that kind: all of them are checked, or the gate refuses.
    if (inv.allRefs) {
      const prefixes = inv.allRefs === 'heads' ? ['refs/heads'] : inv.allRefs === 'tags' ? ['refs/tags'] : ['refs/']
      const listed = deps.listRefCommits(top, prefixes)
      // null = git failed or too many refs; an empty list is a push with nothing in it (no tags yet).
      return listed ? { commits: listed } : { tooMany: true }
    }
    if (inv.refs.length === 0) return head ? { commits: [{ sha: head, label: headText }] } : { unreadable: true }
    const commits: Array<{ sha: string; label: string }> = []
    for (const ref of inv.refs) {
      const sha = deps.resolveCommit(top, ref)
      if (!sha) return { unreadable: true }
      commits.push({ sha, label: ref === 'HEAD' ? headText : ref })
    }
    return { commits }
  }
  // merge: the incoming side.
  const refs = inv.refs.length > 0 ? inv.refs : ['@{upstream}']
  const commits: Array<{ sha: string; label: string }> = []
  for (const ref of refs) {
    const sha = deps.resolveCommit(top, ref)
    if (!sha) return { unreadable: true }
    commits.push({ sha, label: ref === 'MERGE_HEAD' ? 'incoming merge' : `incoming ${ref}` })
  }
  return { commits }
}

async function gateJob(job: Job, host: GateHost, deps: GateDeps): Promise<JobResult[]> {
  const { inv } = job
  // A push that only deletes refs sends no commit: nothing to check, stay silent.
  if (inv.deleteOnly) return []
  if (inv.dir === null) {
    return [block(toCtx(job, host, null, [], null), {
      code: 'NOT_A_PROJECT',
      agentAction: 'fix_and_rerun',
      what: 'The folder this command runs in could not be worked out, so nothing was scanned.',
      lines: [`Cause: ${inv.dirProblem ?? 'the folder is not known'}.`, 'Fix: run the command with a plain folder in cd or git -C (no variables or substitutions), then run it again.'],
    })]
  }
  const top = deps.repoTopLevel(inv.dir)
  if (!top) {
    return [block(toCtx(job, host, null, [], null), {
      code: 'NOT_A_PROJECT',
      agentAction: 'fix_and_rerun',
      what: `${inv.dir} is not a git repository, so nothing was scanned.`,
      lines: ['Cause: the folder this command runs in does not exist or is not inside a git repository.', 'Fix: run the command from inside the repository (or fix the folder in cd or git -C), then run it again.'],
    })]
  }

  if (job.mergeResult) {
    const indexFile = deps.env.GIT_INDEX_FILE ? resolve(deps.cwd, deps.env.GIT_INDEX_FILE) : undefined
    const tree = deps.stagedTree(top, indexFile)
    if (!tree) {
      return [block(toCtx(job, host, null, [], top), {
        code: 'INTERNAL_ERROR',
        agentAction: 'stop',
        what: 'The merge result could not be read from the index (git write-tree failed), so nothing was scanned.',
        lines: ['Fix: run `git status` to see what is wrong with the repository, then run the merge again.'],
      })]
    }
    return [await scanCommit(job, host, top, { sha: tree, label: 'merge result' }, deps, [])]
  }

  const picked = pickCommits(job, top, deps)
  let commits: Array<{ sha: string; label: string }>
  if ('tooMany' in picked) {
    const ctx = toCtx(job, host, null, [], top)
    return [block(ctx, {
      code: 'UNKNOWN_OPTION',
      agentAction: 'fix_and_rerun',
      what: 'This push sends every branch or tag, and the gate could not list and check them all (git failed, or there are more than 200).',
      lines: ['Fix: push the branch you mean by name (git push origin <branch>), then run it again.'],
    })]
  }
  if ('unreadable' in picked) {
    const changed = deps.uncommittedFiles(top)
    const head = deps.resolveCommit(top, 'HEAD')
    // Unknown working tree (git status failed) is treated as dirty: never guess HEAD in that case.
    if (changed === null || changed.length > 0 || !head) {
      const ctx = toCtx(job, host, null, [], top)
      return [block(ctx, changed === null || changed.length > 0
        ? {
            code: 'UNCOMMITTED_CHANGES',
            agentAction: 'fix_and_rerun',
            what: 'The commit this command uses could not be read and the working tree differs from HEAD, so the gate cannot tell what it would use.',
            lines: ['Fix: commit your changes (git add <the files you changed>, never .env files), then run it again.', `Check: ${ctx.rerun}`],
            withRerun: true,
          }
        : {
            code: 'NOT_A_PROJECT',
            agentAction: 'fix_and_rerun',
            what: 'This repository has no commit yet, so there is nothing to check.',
            lines: ['Fix: make a first commit, then run it again.'],
          })]
    }
    commits = [{ sha: head, label: deps.headLabel(top) }]
  } else {
    commits = picked.commits
  }
  const results: JobResult[] = []
  const seen = new Set<string>()
  for (const target of commits) {
    if (seen.has(target.sha)) continue
    seen.add(target.sha)
    results.push(await scanCommit(job, host, top, target, deps, []))
  }
  return results
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

/**
 * Run the gate once and return the process exit code. The caller sets it; this function never
 * exits and never throws: any failure becomes a block text.
 */
export async function runGate(opts: GateOptions, deps: GateDeps = defaultDeps()): Promise<number> {
  if (opts.supports) return 0
  const host = opts.host
  const blockExit = host === 'claude' ? 2 : 1
  if (!isHost(host)) {
    deps.writeStderr(
      [
        'SHIPGUARD BLOCKED: shipguard gate did not run. It needs --host claude, git, ci, codex or cursor, so nothing was scanned.',
        'Fix: run the gate the way the installed hook does: shipguard gate --host git',
        'shipguard-gate: code=UNKNOWN_OPTION agentAction=fix_and_rerun run=none',
      ].join('\n') + '\n',
    )
    return 2
  }
  try {
    const raw = host === 'ci' ? '' : await deps.readStdin()
    const jobs = buildJobs(host, opts.hook, raw, deps)
    // Not a gated command (git status, ls, ...): stay silent, never run, never record.
    if (jobs.length === 0) return 0

    const results: JobResult[] = []
    for (const job of jobs) results.push(...(await gateJob(job, host, deps)))
    if (results.length === 0) return 0
    const firstBlock = results.find((r) => r.blocked)
    if (firstBlock) {
      deps.writeStderr(firstBlock.text + '\n')
      return blockExit
    }
    const passes = results.map((r) => r.pass).filter((p): p is PassText => Boolean(p))
    if (host === 'claude') {
      const merged: PassText = { ...passes[0], text: results.map((r) => r.text).join('\n\n') }
      deps.writeStdout(claudePassJson(merged) + '\n')
    } else {
      deps.writeStderr(results.map((r) => r.text).join('\n\n') + '\n')
    }
    return 0
  } catch (err) {
    // Fail closed: an unexpected error is a block with a text that says so, never a silent pass.
    logger.debug(`gate: ${err instanceof Error ? err.stack ?? err.message : String(err)}`)
    deps.writeStderr(
      [
        'SHIPGUARD BLOCKED: the gate did not run. ShipGuard hit an internal error, so nothing was scanned.',
        'Fix: run the check yourself to see the error: shipguard scan --strict   (if it repeats: shipguard feedback)',
        'shipguard-gate: code=INTERNAL_ERROR agentAction=stop run=none',
      ].join('\n') + '\n',
    )
    return blockExit
  }
}

export function gateCommand(): Command {
  return new Command('gate')
    .description('Check the commit a git push, git merge or PR merge is about to use (run by the installed hooks).')
    .option('--host <host>', `Who is asking: ${GATE_HOSTS.join(' | ')}`)
    .option('--hook <name>', 'git host: the git hook that called (pre-push, pre-merge-commit)')
    .option('--supports', 'Exit 0 when this ShipGuard has the gate (0.13 or later); prints nothing')
    .addHelpText('after', `
Exit codes (host protocol, not the scan table):
  Claude host   0 = allowed (one JSON object on stdout), 2 = blocked (text on stderr)
  other hosts   0 = allowed, 1 = blocked (text on stderr)
The last line of every text is: shipguard-gate: code=<CODE> agentAction=<action> run=<id|none>

The default time limit is ${DEFAULT_GATE_TIMEOUT_SECONDS} s; set gate.timeoutSeconds in shipguard.policy.yml to change it.`)
    .action(async (opts: GateOptions) => {
      setExitCode(await runGate(opts))
    })
}
