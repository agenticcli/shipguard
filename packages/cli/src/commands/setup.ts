import { Command } from 'commander'
import { execFileSync, spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { createInterface } from 'node:readline'
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { EXIT_CODES } from '@agenticcli/shared'
import { logger } from '../utils/logger.js'
import { isGitRepo } from '../core/git.js'
import {
  CLAUDE_HOOK_COMMAND,
  CLAUDE_HOOK_TIMEOUT_SECONDS,
  GATE_HOST_COMMAND,
  GATE_MIN_VERSION,
  GIT_HOOK_NAMES,
  HOOK_BLOCK_VERSION,
  HOOK_MARKER_END,
  HOOK_MARKER_START,
  SHIM_RELATIVE_PATH,
  SHIM_VERSION,
  classifyClaudeHookCommand,
  claudeShimScript,
  gitHookBlock,
  gitHookScript,
  isManaged,
  managedBlockVersion,
  replaceManagedBlock,
  shimFileVersion,
} from '../core/hook-templates.js'
import {
  AGENT_BLOCK_VERSION,
  CI_TEMPLATE_VERSION,
  agentsMdBlock,
  ciWorkflowText,
  claudeMdBlock,
  extractMdBlock,
  mdBlockVersion,
  replaceMdBlock,
  MD_MARKER_PREFIX,
} from '../core/setup-templates.js'
import {
  INSTALL_AGENTS,
  INSTALL_STATE_FILE,
  INSTALL_STATE_GITIGNORE,
  mergeInstallState,
  readInstallState,
  sha256,
  writeInstallState,
  type InstallAgent,
  type InstallEntry,
} from '../core/install-state.js'
import { CLI_VERSION, decideTelemetry, detectCi } from '../core/telemetry.js'
import { getConfigDir, isSafeMode } from '../core/telemetry-config.js'
import { loadCredentials } from '../core/auth.js'
import { primeAllowed, primeOfferCache, type OfferAttempt, type OfferFetchGate } from '../core/offer-cache.js'
import { loadNag } from '../core/nag.js'

/**
 * `shipguard setup`: one command per agent (spec 07). Detect, preview EVERY file it will write, ask once,
 * write, record each write with a hash in `.shipguard/installed.json`, then verify with a real check.
 *
 * Writes go only to the project and to the documented hook locations (the project's `.claude/`, the git hooks
 * folder git itself runs, `.github/workflows/`), plus one verified public offer file in ~/.config/shipguard
 * when the priming rule allows it. A file somebody else wrote is never overwritten: the user gets the line to add.
 *
 * Claude Code hooks reference, read 2026-11-21: https://code.claude.com/docs/en/hooks (hook fields `timeout`
 * (seconds) and `onFailure` ("continue" | "block", Claude Code v2.1.295 or later); a project hook lives in
 * .claude/settings.json under hooks > PreToolUse; ${CLAUDE_PROJECT_DIR} names the project root).
 */

type Agent = InstallAgent
const ALL_AGENTS: readonly Agent[] = INSTALL_AGENTS

/** First Claude Code version with the `onFailure` hook field (hooks reference, "Block the action when a hook fails"). */
export const ONFAILURE_MIN_CLAUDE = '2.1.295'

export interface SetupOptions {
  agent?: string
  noInstall?: boolean
  dryRun?: boolean
  yes?: boolean
}

export interface CliBinary {
  where: 'local' | 'PATH'
  version: string
  path: string
}

export interface SetupDeps {
  cwd: string
  out: (line: string) => void
  /** stdin and stdout are a terminal. */
  isTty: boolean
  confirm: () => Promise<boolean>
  env: NodeJS.ProcessEnv
  now: () => number
  /** ~/.config/shipguard (the nag counter and the offer files live here). */
  configDir: string
  /** This CLI's own version (the version the dependency and the CI template pin). */
  cliVersion: string
  /** Output of `claude --version` parsed to x.y.z, or null when it cannot be found. */
  claudeVersion: () => string | null
  /** A ShipGuard 0.13 or later this project's hook would run: ./node_modules/.bin first, then PATH. */
  findCli: (cwd: string) => CliBinary | null
  /** Add the exact-pinned devDependency. Throws on failure. */
  installDependency: (cwd: string, version: string) => void
  /** The one generic offer fetch. */
  prime: (gate: OfferFetchGate, now: number) => Promise<OfferAttempt>
  signedIn: () => boolean
  /** Run a hook command in a sandbox for the fail-closed check; null means the sandbox could not be built. */
  sandbox: boolean
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const CLAUDE_MD = 'CLAUDE.md'
const AGENTS_MD = 'AGENTS.md'
const CI_WORKFLOW = '.github/workflows/shipguard.yml'

export function versionAtLeast(version: string | null, min: string): boolean {
  if (!version) return false
  const a = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(version)
  const b = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(min)
  if (!a || !b) return false
  for (let i = 1; i <= 3; i++) {
    const x = Number(a[i] ?? 0)
    const y = Number(b[i] ?? 0)
    if (x !== y) return x > y
  }
  return true
}

const toPosix = (p: string): string => p.split('\\').join('/')

function display(cwd: string, abs: string): string {
  const rel = relative(cwd, abs)
  return toPosix(rel !== '' && !rel.startsWith('..') && !isAbsolute(rel) ? rel : abs)
}

function readText(path: string): string | null {
  try {
    return readFileSync(path, 'utf-8')
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw err
  }
}

function gitOut(cwd: string, args: string[]): string | null {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10_000 }).trim()
  } catch (err) {
    logger.debug(`setup: git ${args.join(' ')} failed: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}

// ---------------------------------------------------------------------------
// The plan: every write is an Action, computed before anything is written
// ---------------------------------------------------------------------------

interface Action {
  path: string
  label: string
  /** What the plan says about this file. */
  note: string
  status: 'new' | 'update' | 'unchanged' | 'kept' | 'refused'
  /** For refused/kept: what the user does by hand. */
  manual?: string
  content?: string
  executable?: boolean
  /** Recorded in installed.json after a successful write (also for unchanged content). */
  entry?: InstallEntry
  /** Anything other than writing `content` (settings.json is rewritten whole, so it uses content too). */
  agents: Agent[]
}

const writes = (a: Action): boolean => a.status === 'new' || a.status === 'update'

function planClaudeSettings(cwd: string, claudeVersion: string | null): { action: Action; notes: string[] } {
  const path = join(cwd, '.claude', 'settings.json')
  const label = display(cwd, path)
  const supportsOnFailure = versionAtLeast(claudeVersion, ONFAILURE_MIN_CLAUDE)
  const notes: string[] = []
  const fresh = (): Record<string, unknown> => ({
    type: 'command',
    command: CLAUDE_HOOK_COMMAND,
    timeout: CLAUDE_HOOK_TIMEOUT_SECONDS,
    ...(supportsOnFailure ? { onFailure: 'block' } : {}),
  })
  const raw = readText(path)
  let settings: Record<string, unknown> = {}
  if (raw !== null) {
    try {
      const parsed: unknown = JSON.parse(raw)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not a JSON object')
      settings = parsed as Record<string, unknown>
    } catch (err) {
      logger.error(`Could not parse ${label}: ${err instanceof Error ? err.message : String(err)}. Refusing to touch it.`)
      return {
        action: { path, label, note: 'could not be read as JSON; not changed', status: 'refused', manual: `add this hook under "hooks" > "PreToolUse" yourself: ${JSON.stringify({ matcher: 'Bash', hooks: [fresh()] })}`, agents: ['claude'] },
        notes,
      }
    }
  }
  const hooksRoot = (typeof settings['hooks'] === 'object' && settings['hooks'] !== null && !Array.isArray(settings['hooks']) ? settings['hooks'] : {}) as Record<string, unknown>
  const pre = hooksRoot['PreToolUse']
  if (pre !== undefined && !Array.isArray(pre)) {
    return { action: { path, label, note: 'hooks > PreToolUse is not a list; not changed', status: 'refused', manual: 'fix hooks > PreToolUse by hand, then run setup again', agents: ['claude'] }, notes }
  }
  let ours: Record<string, unknown> | null = null
  let sawLegacy = false
  const next: unknown[] = []
  for (const entry of (pre ?? []) as unknown[]) {
    const e = entry as { hooks?: unknown } | null
    if (typeof e !== 'object' || e === null || !Array.isArray(e.hooks)) {
      next.push(entry)
      continue
    }
    const hooks: unknown[] = []
    for (const h of e.hooks as unknown[]) {
      const cmd = (h as { command?: unknown } | null)?.command
      const kind = typeof cmd === 'string' ? classifyClaudeHookCommand(cmd) : 'foreign'
      if (kind === 'shim' && ours === null) {
        const old = h as Record<string, unknown>
        // Keep what is there: a timeout or onFailure the user already set is theirs.
        ours = { ...old, type: 'command', command: CLAUDE_HOOK_COMMAND }
        if (old['timeout'] === undefined) ours['timeout'] = CLAUDE_HOOK_TIMEOUT_SECONDS
        if (old['onFailure'] === undefined && supportsOnFailure) ours['onFailure'] = 'block'
        else if (old['onFailure'] !== undefined && old['onFailure'] !== 'block') notes.push(`kept your existing onFailure "${String(old['onFailure'])}" (a push is not blocked when the hook cannot run)`)
        hooks.push(ours)
      } else if (kind === 'legacy') {
        sawLegacy = true
        if (ours === null) {
          ours = fresh()
          hooks.push(ours)
        } // else: the old inline entry is dropped, the new one already stands
      } else {
        hooks.push(h)
      }
    }
    if (hooks.length > 0) next.push({ ...(e as object), hooks })
  }
  if (ours === null) {
    ours = fresh()
    next.push({ matcher: 'Bash', hooks: [ours] })
  }
  const merged = { ...settings, hooks: { ...hooksRoot, PreToolUse: next } }
  const same = raw !== null && JSON.stringify(merged) === JSON.stringify(settings)
  if (!supportsOnFailure && ours['onFailure'] === undefined) {
    notes.push(
      claudeVersion === null
        ? `onFailure block not set: Claude Code was not found here (it needs ${ONFAILURE_MIN_CLAUDE} or later). Without it, a hook that cannot run lets the command through. Run setup again once Claude Code ${ONFAILURE_MIN_CLAUDE}+ is installed.`
        : `onFailure block not set: Claude Code ${claudeVersion} is older than ${ONFAILURE_MIN_CLAUDE}. Without it, a hook that cannot run lets the command through. Update Claude Code, then run setup again.`,
    )
  }
  const flags = `timeout ${String(ours['timeout'])} s, onFailure ${ours['onFailure'] === 'block' ? 'block' : String(ours['onFailure'] ?? 'not set')}`
  const note =
    raw === null || !JSON.stringify(settings).includes('PreToolUse')
      ? `add 1 PreToolUse hook (matcher Bash, ${flags}) that runs ${SHIM_RELATIVE_PATH}`
      : sawLegacy
        ? `Hook is v1 (0.11 or 0.12, can skip the gate silently): will be updated to v2 (${flags})`
        : `update the ShipGuard PreToolUse hook entry only (${flags})`
  const status: Action['status'] = same ? 'unchanged' : raw === null ? 'new' : 'update'
  return {
    action: {
      path,
      label,
      note,
      status,
      content: JSON.stringify(merged, null, 2) + '\n',
      entry: { path: toPosix(relative(cwd, path)), kind: 'json-hook', sha256: sha256(JSON.stringify(ours)), version: SHIM_VERSION },
      agents: ['claude'],
    },
    notes,
  }
}

function planShim(cwd: string, state: ReturnType<typeof readInstallState>): Action {
  const path = join(cwd, SHIM_RELATIVE_PATH)
  const label = display(cwd, path)
  const want = claudeShimScript()
  const entry: InstallEntry = { path: SHIM_RELATIVE_PATH, kind: 'file', sha256: sha256(want), version: SHIM_VERSION }
  const cur = readText(path)
  const base = { path, label, executable: true, agents: ['claude'] as Agent[] }
  if (cur === null) return { ...base, note: `new, about ${want.split('\n').length} lines: a small script that runs \`${GATE_HOST_COMMAND} --host claude\` and blocks if ShipGuard cannot start (you can read it)`, status: 'new', content: want, entry }
  if (cur === want) return { ...base, note: 'already current', status: 'unchanged', content: want, entry }
  const v = shimFileVersion(cur)
  if (v === 0) return { ...base, note: 'a file of yours is already here; not overwritten', status: 'refused', manual: `delete or move ${label}, then run setup again (or point a hook at your own script that runs \`${GATE_HOST_COMMAND} --host claude\`)` }
  const recorded = state?.entries.find((e) => e.path === SHIM_RELATIVE_PATH && e.kind === 'file')
  if (v < SHIM_VERSION || (recorded !== undefined && recorded.sha256 === sha256(cur))) {
    return { ...base, note: `update the hook script (v${v} to v${SHIM_VERSION})`, status: 'update', content: want, entry }
  }
  return { ...base, note: `edited by hand since it was written; kept as it is (delete it and run setup again to get the current script)`, status: 'kept' }
}

function planMdBlock(cwd: string, file: string, block: string, agents: Agent[], what: string): Action {
  const path = join(cwd, file)
  const label = display(cwd, path)
  const entry: InstallEntry = { path: file, kind: 'block', sha256: sha256(block), version: AGENT_BLOCK_VERSION }
  const lines = block.split('\n').length - 2
  const cur = readText(path)
  if (cur === null) return { path, label, note: `new file with a managed block (${lines} lines): ${what}`, status: 'new', content: block + '\n', entry, agents }
  if (cur.includes(MD_MARKER_PREFIX) && extractMdBlock(cur) === undefined) {
    return { path, label, note: 'has a ShipGuard start marker without its end marker; not changed', status: 'refused', manual: `fix the markers in ${label} by hand (or delete the block), then run setup again`, agents }
  }
  const have = extractMdBlock(cur)
  if (have === undefined) {
    return { path, label, note: `add a managed block (${lines} lines): ${what}`, status: 'update', content: cur.replace(/\s*$/, '') + '\n\n' + block + '\n', entry, agents }
  }
  if (have === block) return { path, label, note: 'managed block already current', status: 'unchanged', content: cur, entry, agents }
  const v = mdBlockVersion(have)
  const recorded = readInstallState(cwd)?.entries.find((e) => e.path === file && e.kind === 'block')
  if (v < AGENT_BLOCK_VERSION || (recorded !== undefined && recorded.sha256 === sha256(have))) {
    return { path, label, note: `update the managed block (${lines} lines)`, status: 'update', content: replaceMdBlock(cur, block) ?? cur, entry, agents }
  }
  return { path, label, note: 'the ShipGuard block was edited by hand; kept as it is (delete it and run setup again to get the current text)', status: 'kept', agents }
}

interface HooksDir {
  dir: string | null
  line: string
  problem?: string
}

function resolveHooksDir(cwd: string): HooksDir {
  const custom = gitOut(cwd, ['config', '--get', 'core.hooksPath'])
  const out = gitOut(cwd, ['rev-parse', '--git-path', 'hooks'])
  if (out === null) return { dir: null, line: 'git could not tell where its hooks folder is; git hooks are not installed', problem: 'git hooks folder unknown' }
  const dir = isAbsolute(out) ? out : resolve(cwd, out)
  if (custom) {
    // husky 9 generates .husky/_ on every install: a block written there would be lost.
    if (basename(dir) === '_') {
      return { dir: null, line: `core.hooksPath=${custom} is managed by husky: add \`${GATE_HOST_COMMAND} --host git\` to its pre-push hook yourself; setup did not change git hooks`, problem: 'git hooks folder is generated by another tool' }
    }
    return { dir, line: `Hooks folder: git config core.hooksPath is ${custom}, so git runs hooks from ${display(cwd, dir)}.` }
  }
  return { dir, line: `Hooks folder: git config core.hooksPath is not set, so git runs ${display(cwd, dir)}.` }
}

function planGitHook(cwd: string, dir: string, name: (typeof GIT_HOOK_NAMES)[number], agents: Agent[]): Action {
  const path = join(dir, name)
  const label = display(cwd, path)
  const block = gitHookBlock(name)
  const rel = relative(cwd, path)
  const entry: InstallEntry = { path: toPosix(isAbsolute(rel) || rel.startsWith('..') ? path : rel), kind: 'block', sha256: sha256(block), version: HOOK_BLOCK_VERSION }
  const cur = readText(path)
  const note = `git hook that runs \`${GATE_HOST_COMMAND} --host git\``
  if (cur === null) return { path, label, note: `new ${note}`, status: 'new', content: gitHookScript(name), executable: true, entry, agents }
  if (!isManaged(cur)) {
    return { path, label, note: 'a hook of yours is already here; not changed', status: 'refused', manual: `add \`${GATE_HOST_COMMAND} --host git\` to ${label} yourself`, agents }
  }
  const start = cur.indexOf(HOOK_MARKER_START)
  const endAt = cur.indexOf(HOOK_MARKER_END, start)
  const have = endAt === -1 ? undefined : cur.slice(start, endAt + HOOK_MARKER_END.length)
  if (have === undefined) return { path, label, note: 'has a ShipGuard start marker without its end marker; not changed', status: 'refused', manual: `fix the markers in ${label} by hand, then run setup again`, agents }
  if (have === block.trim()) return { path, label, note: 'already current', status: 'unchanged', content: cur, entry, agents }
  const v = managedBlockVersion(cur)
  const recorded = readInstallState(cwd)?.entries.find((e) => e.path === entry.path && e.kind === 'block')
  if (v < HOOK_BLOCK_VERSION || (recorded !== undefined && recorded.sha256 === sha256(have))) {
    return { path, label, note: `update the ShipGuard block (v${v} to v${HOOK_BLOCK_VERSION}; the rest of the file stays)`, status: 'update', content: replaceManagedBlock(cur, block) ?? cur, executable: true, entry, agents }
  }
  return { path, label, note: 'the ShipGuard block was edited by hand; kept as it is', status: 'kept', agents }
}

function planCi(cwd: string, version: string): Action {
  const path = join(cwd, CI_WORKFLOW)
  const label = display(cwd, path)
  const want = ciWorkflowText(version)
  const entry: InstallEntry = { path: CI_WORKFLOW, kind: 'file', sha256: sha256(want), version: CI_TEMPLATE_VERSION }
  const cur = readText(path)
  const agents: Agent[] = ['ci']
  if (cur === null) return { path, label, note: 'new: runs `shipguard scan --strict` on every pull request (Node 22, package pinned)', status: 'new', content: want, entry, agents }
  if (cur === want) return { path, label, note: 'already current', status: 'unchanged', content: want, entry, agents }
  if (!isManaged(cur)) return { path, label, note: 'a workflow of yours is already here; not overwritten', status: 'refused', manual: `delete or rename ${label}, then run setup again`, agents }
  const recorded = readInstallState(cwd)?.entries.find((e) => e.path === CI_WORKFLOW && e.kind === 'file')
  if (managedBlockVersion(cur) < CI_TEMPLATE_VERSION || (recorded !== undefined && recorded.sha256 === sha256(cur))) {
    return { path, label, note: 'update the workflow (Node 22, pinned package)', status: 'update', content: want, entry, agents }
  }
  return { path, label, note: 'edited by hand since it was written; kept as it is', status: 'kept', agents }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

const AGENT_NAMES: Record<Agent, string> = { claude: 'Claude Code', codex: 'Codex', cursor: 'Cursor', ci: 'CI', git: 'git hooks' }

function detect(cwd: string): Array<{ agent: Agent; why: string }> {
  const found: Array<{ agent: Agent; why: string }> = []
  const has = (p: string): boolean => existsSync(join(cwd, p))
  if (has('.claude')) found.push({ agent: 'claude', why: '.claude/ found' })
  else if (has(CLAUDE_MD)) found.push({ agent: 'claude', why: 'CLAUDE.md found' })
  if (has('.codex')) found.push({ agent: 'codex', why: '.codex/ found' })
  else if (has(AGENTS_MD)) found.push({ agent: 'codex', why: 'AGENTS.md found' })
  if (has('.cursor')) found.push({ agent: 'cursor', why: '.cursor/ found' })
  if (has('.github')) found.push({ agent: 'ci', why: '.github/ found' })
  if (has('.git')) found.push({ agent: 'git', why: '.git/ found' })
  return found
}

// ---------------------------------------------------------------------------
// Verification: a real check, run on the files as written
// ---------------------------------------------------------------------------

const SANDBOX_TOOLS = ['sh', 'mktemp', 'cat', 'rm', 'sed', 'head', 'grep', 'date', 'sleep', 'timeout']

function onPath(tool: string, env: NodeJS.ProcessEnv): string | null {
  for (const d of (env['PATH'] ?? '').split(':')) {
    if (d !== '' && existsSync(join(d, tool))) return join(d, tool)
  }
  return null
}

/**
 * Run a hook script with the ShipGuard binary and npx hidden (a bin folder that holds only the plain shell tools
 * the script needs) and expect the fail-closed code. Returns null when the sandbox cannot be built.
 */
function failClosedCheck(script: string, kind: 'claude' | 'git', env: NodeJS.ProcessEnv): { ok: boolean; code: number | null } | null {
  const root = mkdtempSync(join(tmpdir(), 'shipguard-setup-'))
  try {
    const bin = join(root, 'bin')
    mkdirSync(bin)
    for (const t of SANDBOX_TOOLS) {
      const real = onPath(t, env)
      if (real === null) {
        if (t === 'timeout') continue // the shim has a plain-shell watchdog for it
        return null
      }
      symlinkSync(real, join(bin, t))
    }
    const project = join(root, 'project')
    mkdirSync(project)
    let file: string
    let cmd: string
    let want: number
    let input: string
    if (kind === 'claude') {
      mkdirSync(join(project, '.claude', 'hooks'), { recursive: true })
      file = join(project, SHIM_RELATIVE_PATH)
      cmd = CLAUDE_HOOK_COMMAND
      want = 2
      input = JSON.stringify({ cwd: project, tool_input: { command: 'git push origin main' } })
    } else {
      file = join(project, 'hook.sh')
      cmd = 'sh "$P_HOOK"'
      want = 1
      input = ''
    }
    writeFileSync(file, script, 'utf-8')
    const r = spawnSync(join(bin, 'sh'), ['-c', cmd], {
      cwd: project,
      input,
      encoding: 'utf-8',
      timeout: 60_000,
      env: { PATH: bin, HOME: root, CLAUDE_PROJECT_DIR: project, P_HOOK: file },
    })
    return { ok: r.status === want, code: r.status }
  } catch (err) {
    logger.debug(`setup: fail-closed check could not run: ${err instanceof Error ? err.message : String(err)}`)
    return null
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

const EXPLAIN: Record<Agent, string[]> = {
  claude: [
    'Blocks `git push`, `git merge` and the GitHub CLI\'s PR merge, when run through Claude Code\'s Bash tool, if ShipGuard finds a blocker in the commit it checks, cannot finish, or cannot start. It checks one commit: the commit a push sends, the incoming commit of a merge, or your local HEAD for a PR merge. It does not check uncommitted files, the merged result, or the PR on GitHub.',
    'Does not cover other tools, commands run outside Claude Code, a hook entry someone removes, or a host stop (Claude Code then lets the command run unless onFailure is block).',
  ],
  codex: ['Instructions are advisory; git hooks are skipped by `--no-verify` and do not cover `gh pr merge` (it merges on GitHub). Codex has no blocking command hook that ShipGuard has verified.'],
  cursor: ['Instructions are advisory; git hooks are skipped by `--no-verify` and do not cover `gh pr merge` (it merges on GitHub).'],
  git: ['Git hooks bind humans and well-behaved agents for `git push` and local `git merge`. They are skipped by `--no-verify` and do not cover `gh pr merge` (it merges on GitHub).'],
  ci: ['This only becomes a hard stop when branch protection requires the "ShipGuard" check:', '  GitHub > Settings > Branches > require status check "ShipGuard"'],
}

export async function runSetup(opts: SetupOptions, d: SetupDeps): Promise<number> {
  const out = d.out
  const cwd = d.cwd

  // 1. Which agents
  let agents: Agent[]
  const detected: string[] = []
  if (opts.agent !== undefined) {
    const a = opts.agent.toLowerCase()
    if (a === 'all') agents = [...ALL_AGENTS]
    else if ((ALL_AGENTS as readonly string[]).includes(a)) agents = [a as Agent]
    else {
      logger.error(`Unknown --agent "${opts.agent}". Choose one of: ${ALL_AGENTS.join(', ')}, all.`)
      return EXIT_CODES.CONFIG_ERROR
    }
  } else {
    const found = detect(cwd)
    if (found.length === 0) {
      logger.error('Nothing to set up here: no .claude/, CLAUDE.md, .codex/, AGENTS.md, .cursor/, .github/ or .git/ found.')
      logger.info('Name one: shipguard setup --agent claude|codex|cursor|ci|git|all')
      return EXIT_CODES.CONFIG_ERROR
    }
    agents = found.map((f) => f.agent)
    for (const f of found) detected.push(`${AGENT_NAMES[f.agent]} (${f.why})`)
  }
  const wants = (a: Agent): boolean => agents.includes(a)
  const needsGit = wants('git') || wants('codex') || wants('cursor')
  const inGit = isGitRepo(cwd)
  if (!inGit && wants('git') && opts.agent !== undefined && opts.agent.toLowerCase() === 'git') {
    logger.error(`Not a git repository: ${cwd}. Run this inside your project, or use --agent ci / --agent claude.`)
    return EXIT_CODES.CONFIG_ERROR
  }

  // 2. The plan
  const state = readInstallState(cwd)
  const actions: Action[] = []
  const notes: string[] = []
  const claudeVersion = wants('claude') ? d.claudeVersion() : null
  if (detected.length > 0) out(`Detected: ${detected.join('; ')}.`)
  else out(`Setting up: ${agents.map((a) => AGENT_NAMES[a]).join(', ')}.`)

  if (wants('claude')) {
    const s = planClaudeSettings(cwd, claudeVersion)
    actions.push(s.action, planShim(cwd, state), planMdBlock(cwd, CLAUDE_MD, claudeMdBlock(), ['claude'], 'tells the agent to run `shipguard scan --json --strict` before a push and what to do when blocked'))
    notes.push(...s.notes)
  }
  if (wants('codex') || wants('cursor')) {
    actions.push(planMdBlock(cwd, AGENTS_MD, agentsMdBlock(), ['codex', 'cursor'].filter((a): a is Agent => wants(a as Agent)), 'run `shipguard scan --json --strict` before a push, what to do when blocked, never use --no-verify'))
  }
  let hooksLine: string | null = null
  if (needsGit) {
    if (!inGit) notes.push('Not a git repository: git hooks are not installed.')
    else {
      const hd = resolveHooksDir(cwd)
      hooksLine = hd.line
      if (hd.dir === null) notes.push(hd.line)
      else {
        const who: Agent[] = ALL_AGENTS.filter((a) => (a === 'git' || a === 'codex' || a === 'cursor') && wants(a))
        for (const name of GIT_HOOK_NAMES) actions.push(planGitHook(cwd, hd.dir, name, who))
        hooksLine = hd.line
      }
    }
  }
  if (wants('ci')) actions.push(planCi(cwd, d.cliVersion))

  // The CLI the hooks run
  const hooksPlanned = wants('claude') || actions.some((a) => GIT_HOOK_NAMES.some((n) => a.path.endsWith('/' + n)))
  let cliLine: string | null = null
  let willInstall = false
  if (hooksPlanned) {
    const cli = d.findCli(cwd)
    if (cli) cliLine = `ShipGuard CLI: found ${cli.where === 'local' ? `at ./node_modules/.bin/shipguard` : 'on PATH'} (${cli.version}). The hook uses it, so a push does not need the network.`
    else if (opts.noInstall) cliLine = `ShipGuard CLI: not installed in this project (--no-install). The gate then fetches ShipGuard with npx on every push, needs the network, and blocks when it cannot download within the 150 s deadline.`
    else if (existsSync(join(cwd, 'package.json')) && versionAtLeast(d.cliVersion, GATE_MIN_VERSION)) {
      willInstall = true
      cliLine = `ShipGuard CLI: not installed in this project. The plan also adds @agenticcli/shipguard@${d.cliVersion} as an exact-pinned devDependency (package.json and the lockfile change). Or skip it with --no-install: the gate then fetches ShipGuard with npx on every push, needs the network, and blocks when it cannot download within the 150 s deadline.`
    } else cliLine = `ShipGuard CLI: not installed in this project and setup cannot add it here (${existsSync(join(cwd, 'package.json')) ? `this ShipGuard is ${d.cliVersion}, older than ${GATE_MIN_VERSION}` : 'no package.json'}). The gate fetches ShipGuard with npx on every push, needs the network, and blocks when it cannot download within the 150 s deadline. Install it: npm i -D @agenticcli/shipguard`
  }

  const changing = actions.filter(writes)
  const recordWrite = actions.some((a) => a.entry !== undefined) && (changing.length > 0 || state === null)
  const row = (a: Action): string => `  ${a.label.padEnd(34)} ${a.note}`

  if (cliLine) out(cliLine)
  if (hooksLine) out(hooksLine)
  const total = changing.length + (recordWrite ? 2 : 0) + (willInstall ? 2 : 0)
  if (total > 0) {
    out(`This will change ${total} file${total === 1 ? '' : 's'}:`)
    for (const a of changing) out(row(a))
    if (willInstall) out(`  ${'package.json, lockfile'.padEnd(34)} add @agenticcli/shipguard@${d.cliVersion} as an exact-pinned devDependency (scripts are not run)`)
    if (recordWrite) {
      out(`  ${INSTALL_STATE_FILE.padEnd(34)} ${state === null ? 'new' : 'update'}: the record of what setup wrote, so uninstall is exact`)
      out(`  ${INSTALL_STATE_GITIGNORE.padEnd(34)} ${existsSync(join(cwd, INSTALL_STATE_GITIGNORE)) ? 'already there' : 'new'}: one line (*) so reports and history are never committed`)
    }
  }
  for (const a of actions.filter((x) => x.status === 'unchanged')) out(`  ${a.label.padEnd(34)} ${a.note} (no change)`)
  for (const a of actions.filter((x) => x.status === 'kept')) out(`  ${a.label.padEnd(34)} ${a.note}`)
  for (const a of actions.filter((x) => x.status === 'refused')) {
    out(`  ${a.label.padEnd(34)} NOT changed: ${a.note}`)
    out(`    Do this yourself: ${a.manual ?? ''}`)
  }
  for (const n of notes) out(n)
  if (total === 0) {
    if (actions.length === 0) out('Nothing to install for this agent here.')
    else if (!actions.some((a) => a.status === 'refused')) out('Already installed, no change.')
    return actions.some((a) => a.status === 'refused') ? EXIT_CODES.RUNTIME_ERROR : EXIT_CODES.SAFE
  }

  // The priming fetch is named in the preview so no network call is a surprise.
  const config = d.configDir
  const safe = isSafeMode(d.env)
  const gate = (dryRun: boolean): OfferFetchGate => ({
    signedIn: d.signedIn(),
    terminal: d.isTty,
    ci: detectCi(d.env),
    quiet: false,
    hookOrGate: false,
    safeMode: safe,
    trackingOff: !decideTelemetry({ env: d.env, projectDir: cwd }).enabled,
    dryRun,
  })
  const willPrime = primeAllowed(gate(false), loadNag({ configDir: config, safeMode: safe }), d.now())
  if (willPrime) out('Also: fetches one public offer document (no project data, no login) so a clean push can show what the full rulebook would add. Skipped when signed in, with DO_NOT_TRACK or in safe mode.')
  out('No other files are touched. Reports and history are created on your first scan. Code never leaves your machine. Rules download from the rulebook; a signed-out scan may fetch public rule counts for your stack names once a week; usage-ping and request details: shipguard telemetry status.')

  if (opts.dryRun) {
    out('Dry run: nothing was changed.')
    return EXIT_CODES.SAFE
  }

  // 3. Confirm once
  if (!opts.yes) {
    if (!d.isTty) {
      const again = opts.agent !== undefined ? `shipguard setup --agent ${opts.agent} --yes` : 'shipguard setup --yes'
      logger.error('CONFIRMATION_REQUIRED: setup changes files and was not given a terminal to ask in.')
      out(`Run: ${again}`)
      return EXIT_CODES.CONFIG_ERROR
    }
    if (!(await d.confirm())) {
      out('Nothing was changed.')
      return EXIT_CODES.SAFE
    }
  }

  // 4. Write
  if (willInstall) {
    try {
      d.installDependency(cwd, d.cliVersion)
      out(`✓ added @agenticcli/shipguard@${d.cliVersion} as a devDependency`)
    } catch (err) {
      logger.error(`SETUP_FAILED: could not add @agenticcli/shipguard@${d.cliVersion}: ${err instanceof Error ? err.message : String(err)}`)
      out('Nothing else was written. Install it yourself (npm i -D @agenticcli/shipguard) or run setup with --no-install.')
      return EXIT_CODES.RUNTIME_ERROR
    }
  }
  const written: string[] = []
  try {
    for (const a of changing) {
      mkdirSync(dirname(a.path), { recursive: true })
      writeFileSync(a.path, a.content ?? '', 'utf-8')
      if (a.executable) chmodSync(a.path, 0o755)
      written.push(a.path)
      out(`✓ wrote ${a.label}`)
    }
    const entries = actions.filter((a) => a.entry !== undefined && (a.status === 'new' || a.status === 'update' || a.status === 'unchanged')).map((a) => a.entry as InstallEntry)
    if (recordWrite) {
      const hookVersion = Math.max(wants('claude') ? SHIM_VERSION : 0, needsGit ? HOOK_BLOCK_VERSION : 0)
      const recordedAgents = agents.filter((g) => entries.length > 0 && actions.some((a) => a.agents.includes(g) && a.entry !== undefined && a.status !== 'refused' && a.status !== 'kept'))
      writeInstallState(cwd, mergeInstallState(state, { shipguardVersion: d.cliVersion, agents: recordedAgents, entries, hookVersion }))
      written.push(join(cwd, INSTALL_STATE_FILE), join(cwd, INSTALL_STATE_GITIGNORE))
      out(`✓ wrote ${INSTALL_STATE_FILE}`)
    }
  } catch (err) {
    logger.error(`SETUP_FAILED: could not write the files: ${err instanceof Error ? err.message : String(err)}`)
    return EXIT_CODES.RUNTIME_ERROR
  }

  // 5. Verify, with real checks on what was written
  out('Checking the result:')
  let failed = false
  const fail = (line: string): void => {
    failed = true
    out(`✗ ${line}`)
  }
  if (wants('claude')) {
    const settings = readText(join(cwd, '.claude', 'settings.json'))
    let present = false
    try {
      const parsed = JSON.parse(settings ?? '{}') as { hooks?: { PreToolUse?: Array<{ hooks?: Array<{ command?: unknown }> }> } }
      present = (parsed.hooks?.PreToolUse ?? []).some((e) => (e.hooks ?? []).some((h) => typeof h.command === 'string' && classifyClaudeHookCommand(h.command) === 'shim'))
    } catch (err) {
      logger.debug(`setup: verify could not parse settings.json: ${err instanceof Error ? err.message : String(err)}`)
    }
    const shim = readText(join(cwd, SHIM_RELATIVE_PATH))
    if (present && shim !== null && shimFileVersion(shim) >= SHIM_VERSION) out(`✓ hook entry present in .claude/settings.json and the script it names exists (hook v${shimFileVersion(shim)})`)
    else fail('SETUP_VERIFY_FAILED: the hook entry or the script it names is missing or old. Nothing is protected yet. Fix: run shipguard setup --agent claude again, or add the entry shown above by hand.')
    if (shim !== null && d.sandbox) {
      const r = failClosedCheck(shim, 'claude', d.env)
      if (r === null) out('Not run: the fail-closed check (the tools it needs were not found).')
      else if (r.ok) out('✓ with the ShipGuard binary hidden, a test `git push` was blocked (exit 2): the hook fails closed')
      else fail(`SETUP_VERIFY_FAILED: the hook did not block the test push when ShipGuard could not start (exit ${String(r.code)}, expected 2). Nothing is protected yet. Fix: read ${SHIM_RELATIVE_PATH}.`)
    }
  }
  if (wants('codex') || wants('cursor')) {
    const t = readText(join(cwd, AGENTS_MD))
    if (t !== null && extractMdBlock(t) !== undefined) out('✓ managed block present in AGENTS.md')
    else if (actions.some((a) => a.path === join(cwd, AGENTS_MD) && (a.status === 'refused'))) fail('SETUP_VERIFY_FAILED: AGENTS.md was not changed (see above).')
    else fail('SETUP_VERIFY_FAILED: the managed block is not in AGENTS.md. Fix: run shipguard setup again.')
  }
  if (needsGit && inGit) {
    for (const a of actions.filter((x) => GIT_HOOK_NAMES.some((n) => x.path.endsWith('/' + n)))) {
      if (a.status === 'refused') continue
      const t = readText(a.path)
      if (t === null || !isManaged(t)) {
        fail(`SETUP_VERIFY_FAILED: ${a.label} has no ShipGuard block. Fix: run shipguard setup again.`)
        continue
      }
      const r = d.sandbox ? failClosedCheck('#!/bin/sh\n' + t.slice(t.indexOf(HOOK_MARKER_START), t.indexOf(HOOK_MARKER_END) + HOOK_MARKER_END.length) + '\n', 'git', d.env) : null
      if (r === null) out(`✓ ${a.label}: ShipGuard block installed, not run end to end`)
      else if (r.ok) out(`✓ ${a.label}: with the ShipGuard binary hidden, the hook blocks (exit 1): it fails closed`)
      else fail(`SETUP_VERIFY_FAILED: ${a.label} did not block when ShipGuard could not start (exit ${String(r.code)}, expected 1). Nothing is protected yet.`)
    }
  }
  if (wants('ci')) {
    const t = readText(join(cwd, CI_WORKFLOW))
    let ok = false
    try {
      const { parse } = await import('yaml')
      const doc = parse(t ?? '') as { jobs?: Record<string, unknown> } | null
      ok = t !== null && doc !== null && typeof doc === 'object' && doc.jobs !== undefined && t.includes('@agenticcli/shipguard') && t.includes("node-version: '22'")
    } catch (err) {
      logger.debug(`setup: verify could not parse the workflow: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (ok) out('✓ workflow file is valid YAML and calls shipguard')
    else if (actions.some((a) => a.path === join(cwd, CI_WORKFLOW) && a.status === 'refused')) fail('SETUP_VERIFY_FAILED: the workflow was not changed (see above).')
    else fail('SETUP_VERIFY_FAILED: the workflow file is not valid or does not call shipguard. Fix: run shipguard setup --agent ci again.')
  }

  // 6. Prime the offer cache once, after the confirmation; a failed fetch is silent for setup
  if (!failed && willPrime) {
    try {
      const r = await d.prime(gate(false), d.now())
      if (r.attempted) logger.debug(`setup: offer priming ${r.result.ok ? 'stored the generic offer' : `did not store an offer (${r.result.reason})`}`)
    } catch (err) {
      logger.debug(`setup: offer priming failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  const refused = actions.filter((a) => a.status === 'refused')
  if (failed) return EXIT_CODES.RUNTIME_ERROR
  if (refused.length > 0) {
    out('Setup is incomplete: the files marked NOT changed above need your hand. Nothing else failed.')
    return EXIT_CODES.RUNTIME_ERROR
  }
  out('Installed. What this does and does not do:')
  for (const a of agents) for (const l of EXPLAIN[a]) out(`  ${l}`)
  if (!wants('ci')) out('  For a stop nothing local can skip: shipguard setup --agent ci, then turn on branch protection for the check.')
  out('Try it:     shipguard scan --strict   (the same check the hook runs on a push)')
  out(`Remove it:  shipguard uninstall${opts.agent !== undefined ? ` --agent ${opts.agent}` : ''}`)
  return EXIT_CODES.SAFE
}

// ---------------------------------------------------------------------------
// Real dependencies and the command
// ---------------------------------------------------------------------------

function probeVersion(bin: string, cwd: string): string | null {
  try {
    const text = execFileSync(bin, ['--version'], { cwd, encoding: 'utf-8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] })
    return /(\d+\.\d+\.\d+)/.exec(text)?.[1] ?? null
  } catch (err) {
    logger.debug(`setup: ${bin} --version failed: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}

function realDeps(cwd: string): SetupDeps {
  return {
    cwd,
    out: (l) => console.log(l),
    isTty: Boolean(process.stdin.isTTY && process.stdout.isTTY),
    confirm: () =>
      new Promise<boolean>((res) => {
        const rl = createInterface({ input: process.stdin, output: process.stdout })
        rl.question('Proceed? [y/N] ', (a) => {
          rl.close()
          res(/^y(es)?$/i.test(a.trim()))
        })
      }),
    env: process.env,
    now: () => Date.now(),
    configDir: getConfigDir(),
    cliVersion: CLI_VERSION,
    claudeVersion: () => probeVersion('claude', cwd),
    findCli: (dir) => {
      const local = join(dir, 'node_modules', '.bin', 'shipguard')
      if (existsSync(local)) {
        const v = probeVersion(local, dir)
        if (versionAtLeast(v, GATE_MIN_VERSION)) return { where: 'local', version: v as string, path: local }
      }
      const v = probeVersion('shipguard', dir)
      return versionAtLeast(v, GATE_MIN_VERSION) ? { where: 'PATH', version: v as string, path: 'shipguard' } : null
    },
    installDependency: (dir, version) => {
      const spec = `@agenticcli/shipguard@${version}`
      const pm = existsSync(join(dir, 'pnpm-lock.yaml')) ? 'pnpm' : existsSync(join(dir, 'yarn.lock')) ? 'yarn' : 'npm'
      const args = pm === 'npm' ? ['install', '--save-dev', '--save-exact', '--ignore-scripts', spec] : ['add', '-D', '-E', '--ignore-scripts', spec]
      execFileSync(pm, args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], timeout: 300_000 })
    },
    prime: (g, now) => primeOfferCache({ configDir: getConfigDir(), now, safeMode: g.safeMode }, g),
    signedIn: () => loadCredentials() !== null || Boolean(process.env['SHIPGUARD_API_KEY']),
    sandbox: true,
  }
}

export function setupCommand(): Command {
  return new Command('setup')
    .description('Set ShipGuard up for your coding agent (shows every file first, asks once)')
    .option('--agent <agent>', `Which agent: ${ALL_AGENTS.join(' | ')} | all (default: detect)`)
    .option('--no-install', 'Do not add ShipGuard as a devDependency (the gate then uses npx on every push)')
    .option('--dry-run', 'Show what would change and write nothing')
    .option('--yes', 'Proceed without asking (required when not run from a terminal)')
    .addHelpText('after', `
Examples:
  shipguard setup --agent claude        Claude Code hook + CLAUDE.md block
  shipguard setup --agent codex         AGENTS.md block + git hooks (Cursor: --agent cursor)
  shipguard setup --agent ci            GitHub Actions workflow (Node 22)
  shipguard setup --dry-run             Show the plan only

Exit codes:
  0  Installed, already installed, or dry run.
  2  Config error: unknown --agent, nothing detected, or no confirmation (not a terminal, no --yes).
  3  Runtime error: a file could not be written, or the check after install failed.`)
    .action(async (o: { agent?: string; install?: boolean; dryRun?: boolean; yes?: boolean }) => {
      let code: number
      try {
        code = await runSetup({ agent: o.agent, noInstall: o.install === false, dryRun: o.dryRun, yes: o.yes }, realDeps(process.cwd()))
      } catch (err) {
        logger.error(`Setup failed: ${err instanceof Error ? err.message : String(err)}`)
        code = EXIT_CODES.RUNTIME_ERROR
      }
      process.exit(code)
    })
}
