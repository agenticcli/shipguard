import { Command } from 'commander'
import { execFileSync } from 'node:child_process'
import { existsSync, lstatSync, readdirSync, readFileSync, rmSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { EXIT_CODES } from '@agenticcli/shared'
import { logger } from '../utils/logger.js'
import { detectJsonLayout, writeJsonLayout } from '../utils/json-layout.js'
import {
  CLAUDE_HOOK_FINGERPRINT,
  GIT_HOOK_NAMES,
  HOOK_MARKER_END,
  HOOK_MARKER_START,
  SHIM_RELATIVE_PATH,
  ciWorkflowYaml,
  classifyClaudeHookCommand,
  claudeShimScript,
  shimFileVersion,
} from '../core/hook-templates.js'
import { MD_MARKER_END, MD_MARKER_PREFIX, ciWorkflowText, extractMdBlock } from '../core/setup-templates.js'
import {
  INSTALL_AGENTS,
  INSTALL_STATE_DIR,
  INSTALL_STATE_FILE,
  readInstallState,
  sha256,
  writeInstallState,
  type InstallAgent,
  type InstallEntry,
  type InstallState,
} from '../core/install-state.js'
import { getConfigDir } from '../core/telemetry-config.js'

/**
 * `shipguard uninstall`: reverse exactly what `shipguard setup` wrote (spec 07), and nothing else.
 *
 * Safety rules, in order of importance:
 * - Only a fixed list of ShipGuard locations is ever looked at (the Claude hook entry and script, the CLAUDE.md
 *   and AGENTS.md blocks, the git hooks folder git itself runs, the CI workflow). Paths in
 *   `.shipguard/installed.json` are NEVER followed: the record only supplies content hashes, so a tampered
 *   record cannot point uninstall at another file.
 * - Content is removed only when it is ShipGuard's own: a whole file only when its hash matches the record (or, with
 *   no record, when it equals a known ShipGuard template); a block only between ShipGuard's own markers and, when
 *   there is a record, only when the hash still matches. Anything edited since is kept and named.
 * - The plan is computed and printed before any change; one confirmation; nothing is deleted without being named.
 * - A check of the project's own files runs after the removal; it fails (exit 3) when a ShipGuard block remains.
 */

type Agent = InstallAgent

export interface UninstallOptions {
  agent?: string
  dryRun?: boolean
  yes?: boolean
  keepReports?: boolean
  purge?: boolean
  purgeHome?: boolean
}

export interface UninstallDeps {
  cwd: string
  out: (line: string) => void
  isTty: boolean
  confirm: (question: string) => Promise<boolean>
  /** ~/.config/shipguard (only touched with --purge-home). */
  configDir: string
}

const CLAUDE_MD = 'CLAUDE.md'
const AGENTS_MD = 'AGENTS.md'
const SETTINGS = '.claude/settings.json'
const WORKFLOW = '.github/workflows/shipguard.yml'

const toPosix = (p: string): string => p.split('\\').join('/')

function display(cwd: string, abs: string): string {
  const rel = relative(cwd, abs)
  return toPosix(rel !== '' && !rel.startsWith('..') && !isAbsolute(rel) ? rel : abs)
}

function isSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink()
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw err
  }
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
    logger.debug(`uninstall: git ${args.join(' ')} failed: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}

/** 1-based line numbers of the first `start` needle and of the first `end` needle after it. */
function lineRange(text: string, start: string, end: string): [number, number] {
  const a = text.indexOf(start)
  if (a === -1) return [1, 1]
  const b = text.indexOf(end, a)
  const lineOf = (i: number): number => text.slice(0, i).split('\n').length
  return [lineOf(a), lineOf(b === -1 ? a : b)]
}

function dirSize(path: string): number {
  let total = 0
  try {
    for (const name of readdirSync(path)) {
      const p = join(path, name)
      const st = lstatSync(p)
      total += st.isDirectory() ? dirSize(p) : st.size
    }
  } catch (err) {
    logger.debug(`uninstall: could not size ${path}: ${err instanceof Error ? err.message : String(err)}`)
  }
  return total
}

function human(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// ---------------------------------------------------------------------------
// Items: every removal is planned first
// ---------------------------------------------------------------------------

interface Item {
  path: string
  label: string
  /** The agents whose setup wrote this (the item goes only when none of them stays installed). */
  owners: Agent[]
  state: 'remove' | 'keep-edited'
  /** Plan line (what goes) or the reason it stays. */
  note: string
  /** For a kept item: what the user does by hand. */
  manual?: string
  apply: () => void
  /** After the removal: failure text if a ShipGuard block is still in the file, else null. */
  verify: () => string | null
  /** The file is deleted by apply (its now-empty folders are tidied). */
  deletes: boolean
}

function recordedEntry(state: InstallState | null, path: string, kind: InstallEntry['kind']): InstallEntry | undefined {
  return state?.entries.find((e) => e.path === path && e.kind === kind)
}

function settingsItem(cwd: string, state: InstallState | null): Item | null {
  const path = join(cwd, SETTINGS)
  const label = SETTINGS
  const raw = readText(path)
  if (raw === null) return null
  if (!raw.includes(CLAUDE_HOOK_FINGERPRINT) && !/shipguard/i.test(raw)) return null
  const owners: Agent[] = ['claude']
  const stays = (note: string, manual: string): Item => ({ path, label, owners, state: 'keep-edited', note, manual, apply: () => undefined, verify: () => null, deletes: false })
  if (isSymlink(path)) return stays('is a symbolic link; not changed', `remove the ShipGuard hook entry (the one that names ${CLAUDE_HOOK_FINGERPRINT}) by hand`)
  let settings: Record<string, unknown>
  try {
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not a JSON object')
    settings = parsed as Record<string, unknown>
  } catch (err) {
    logger.error(`Could not parse ${label}: ${err instanceof Error ? err.message : String(err)}. Not touching it.`)
    if (!raw.includes(CLAUDE_HOOK_FINGERPRINT)) return null
    return stays('could not be read as JSON; not changed', `remove the hook entry that names ${CLAUDE_HOOK_FINGERPRINT} by hand`)
  }
  const hooksRoot = settings['hooks']
  if (typeof hooksRoot !== 'object' || hooksRoot === null || Array.isArray(hooksRoot)) return null
  const pre = (hooksRoot as Record<string, unknown>)['PreToolUse']
  if (!Array.isArray(pre)) return null

  const isOurs = (h: unknown): 'shim' | 'legacy' | null => {
    const cmd = (h as { command?: unknown } | null)?.command
    if (typeof cmd !== 'string') return null
    const kind = classifyClaudeHookCommand(cmd)
    if (kind === 'shim') return 'shim'
    // The 0.12 inline entry ran `shipguard scan --json --strict`; a command without the word shipguard is not ours.
    if (kind === 'legacy' && /shipguard/i.test(cmd)) return 'legacy'
    return null
  }
  const rec = recordedEntry(state, SETTINGS, 'json-hook')
  let found = 0
  let edited = 0
  let others = 0
  for (const e of pre) {
    const hooks = (e as { hooks?: unknown } | null)?.hooks
    if (!Array.isArray(hooks)) continue
    for (const h of hooks) {
      const kind = isOurs(h)
      if (kind === null) {
        others++
        continue
      }
      found++
      if (kind === 'shim' && rec !== undefined && rec.sha256 !== sha256(JSON.stringify(h))) edited++
    }
  }
  if (found === 0) return null
  if (edited > 0) {
    return stays(
      'the ShipGuard hook entry was edited since setup; kept as it is',
      `delete the hook entry that names ${CLAUDE_HOOK_FINGERPRINT} (and the script ${SHIM_RELATIVE_PATH}) yourself, or run shipguard setup --agent claude to rewrite it`,
    )
  }

  const stripped = (): Record<string, unknown> | null => {
    const nextPre: unknown[] = []
    for (const e of pre) {
      const hooks = (e as { hooks?: unknown } | null)?.hooks
      if (!Array.isArray(hooks)) {
        nextPre.push(e)
        continue
      }
      const kept = hooks.filter((h) => isOurs(h) === null)
      if (kept.length > 0) nextPre.push({ ...(e as object), hooks: kept })
    }
    const nextHooks: Record<string, unknown> = { ...(hooksRoot as Record<string, unknown>) }
    if (nextPre.length > 0) nextHooks['PreToolUse'] = nextPre
    else delete nextHooks['PreToolUse']
    const next: Record<string, unknown> = { ...settings }
    if (Object.keys(nextHooks).length > 0) next['hooks'] = nextHooks
    else delete next['hooks']
    return Object.keys(next).length > 0 ? next : null
  }
  const after = stripped()
  // Hand the file back in the layout it has now (setup kept the user's layout), so a clean round trip is byte for byte.
  const layout = detectJsonLayout(raw)
  return {
    path,
    label,
    owners,
    state: 'remove',
    note: `the ShipGuard PreToolUse hook entry only${others > 0 ? ` (${others} other ${others === 1 ? 'entry stays' : 'entries stay'})` : ''}${after === null ? '; the file is empty after that and is deleted' : ''}`,
    deletes: after === null,
    apply: () => {
      if (after === null) unlinkSync(path)
      else writeFileSync(path, writeJsonLayout(after, layout), 'utf-8')
    },
    verify: () => {
      const t = readText(path)
      if (t === null) return null
      try {
        const parsed = JSON.parse(t) as { hooks?: { PreToolUse?: unknown } }
        const list = Array.isArray(parsed.hooks?.PreToolUse) ? (parsed.hooks?.PreToolUse as Array<{ hooks?: unknown[] }>) : []
        if (!list.some((e) => Array.isArray(e.hooks) && e.hooks.some((h) => isOurs(h) !== null))) return null
      } catch (err) {
        logger.debug(`uninstall: verify could not parse ${label}: ${err instanceof Error ? err.message : String(err)}`)
      }
      const [a, b] = lineRange(t, CLAUDE_HOOK_FINGERPRINT, CLAUDE_HOOK_FINGERPRINT)
      return `${label} still contains a ShipGuard block. Fix: delete lines ${a}-${b} by hand.`
    },
  }
}

/** A whole file ShipGuard wrote: the shim script or the CI workflow. */
function wholeFileItem(
  cwd: string,
  state: InstallState | null,
  rel: string,
  owners: Agent[],
  describe: string,
  marker: (text: string) => boolean,
  knownTemplate: (text: string) => boolean,
): Item | null {
  const path = join(cwd, rel)
  const text = readText(path)
  if (text === null || !marker(text)) return null
  const stays = (note: string, manual: string): Item => ({ path, label: rel, owners, state: 'keep-edited', note, manual, apply: () => undefined, verify: () => null, deletes: false })
  if (isSymlink(path)) return stays('is a symbolic link; not changed', `delete ${rel} yourself if you want it gone`)
  const rec = recordedEntry(state, rel, 'file')
  const unedited = rec !== undefined ? rec.sha256 === sha256(text) : knownTemplate(text)
  if (!unedited) {
    return stays(
      rec !== undefined ? 'edited since setup wrote it; kept as it is' : 'has a ShipGuard marker but no install record, and it is not the text setup writes; kept as it is',
      `delete ${rel} yourself if you want it gone`,
    )
  }
  return {
    path,
    label: rel,
    owners,
    state: 'remove',
    note: describe,
    deletes: true,
    apply: () => unlinkSync(path),
    verify: () => (existsSync(path) ? `${rel} still contains a ShipGuard block. Fix: delete the file by hand.` : null),
  }
}

/** A marked block inside CLAUDE.md or AGENTS.md. */
function mdBlockItem(cwd: string, state: InstallState | null, file: string, owners: Agent[]): Item | null {
  const path = join(cwd, file)
  const text = readText(path)
  if (text === null || !text.includes(MD_MARKER_PREFIX)) return null
  const stays = (note: string, manual: string): Item => ({ path, label: file, owners, state: 'keep-edited', note, manual, apply: () => undefined, verify: () => null, deletes: false })
  if (isSymlink(path)) return stays('is a symbolic link; not changed', `delete the block between the ShipGuard markers in ${file} yourself`)
  const block = extractMdBlock(text)
  if (block === undefined) {
    const [a, b] = lineRange(text, MD_MARKER_PREFIX, MD_MARKER_END)
    return stays('has a ShipGuard start marker without its end marker; not changed', `delete lines ${a}-${b} (the start marker and the block under it) yourself`)
  }
  const rec = recordedEntry(state, file, 'block')
  if (rec !== undefined && rec.sha256 !== sha256(block)) {
    const [a, b] = lineRange(text, MD_MARKER_PREFIX, MD_MARKER_END)
    return stays('the ShipGuard block was edited since setup; kept as it is', `delete lines ${a}-${b} yourself`)
  }
  const start = text.indexOf(block)
  const before = text.slice(0, start).trimEnd()
  const after = text.slice(start + block.length).trim()
  const rest = [before, after].filter((p) => p !== '')
  return {
    path,
    label: file,
    owners,
    state: 'remove',
    note: rest.length === 0 ? 'the managed block between the ShipGuard markers (nothing else is in the file, so the file is deleted)' : 'the managed block between the ShipGuard markers (rest of the file stays)',
    deletes: rest.length === 0,
    apply: () => {
      if (rest.length === 0) unlinkSync(path)
      else writeFileSync(path, rest.join('\n\n') + '\n', 'utf-8')
    },
    verify: () => {
      const t = readText(path)
      if (t === null || !t.includes(MD_MARKER_PREFIX)) return null
      const [a, b] = lineRange(t, MD_MARKER_PREFIX, MD_MARKER_END)
      return `${file} still contains a ShipGuard block. Fix: delete lines ${a}-${b} by hand.`
    },
  }
}

/** The ShipGuard block inside a git hook file. */
function gitHookItem(cwd: string, state: InstallState | null, dir: string, name: string, owners: Agent[]): Item | null {
  const path = join(dir, name)
  const label = display(cwd, path)
  const text = readText(path)
  if (text === null || !text.includes(HOOK_MARKER_START)) return null
  const stays = (note: string, manual: string): Item => ({ path, label, owners, state: 'keep-edited', note, manual, apply: () => undefined, verify: () => null, deletes: false })
  if (isSymlink(path)) return stays('is a symbolic link; not changed', `delete the block between the two "shipguard managed block" lines in ${label} yourself`)
  const start = text.indexOf(HOOK_MARKER_START)
  const endAt = text.indexOf(HOOK_MARKER_END, start)
  if (endAt === -1) {
    const [a, b] = lineRange(text, HOOK_MARKER_START, HOOK_MARKER_END)
    return stays('has a ShipGuard start marker without its end marker; not changed', `delete lines ${a}-${b} yourself`)
  }
  const end = endAt + HOOK_MARKER_END.length
  const block = text.slice(start, end)
  const relRaw = relative(cwd, path)
  const recPath = toPosix(isAbsolute(relRaw) || relRaw.startsWith('..') ? path : relRaw)
  const rec = recordedEntry(state, recPath, 'block')
  if (rec !== undefined && rec.sha256 !== sha256(block)) {
    const [a, b] = lineRange(text, HOOK_MARKER_START, HOOK_MARKER_END)
    return stays('the ShipGuard block was edited since setup; kept as it is', `delete lines ${a}-${b} yourself`)
  }
  const before = text.slice(0, start)
  const after = text.slice(end)
  const yours = (before + after).split('\n').filter((l, i) => l.trim() !== '' && !(i === 0 && l.startsWith('#!')))
  const remaining = yours.length === 0 ? null : before.trimEnd() + '\n' + (after.trim() === '' ? '' : after.replace(/^\n+/, '\n'))
  const tidy = remaining === null ? null : remaining.replace(/\n*$/, '\n')
  return {
    path,
    label,
    owners,
    state: 'remove',
    note: tidy === null ? 'the ShipGuard block (nothing else is in the file, so the file is deleted)' : `the ShipGuard block (the hook file stays; ${yours.length} ${yours.length === 1 ? 'line' : 'lines'} of yours stay)`,
    deletes: tidy === null,
    apply: () => {
      if (tidy === null) unlinkSync(path)
      else writeFileSync(path, tidy, 'utf-8')
    },
    verify: () => {
      const t = readText(path)
      if (t === null || !t.includes(HOOK_MARKER_START)) return null
      const [a, b] = lineRange(t, HOOK_MARKER_START, HOOK_MARKER_END)
      return `${label} still contains a ShipGuard block. Fix: delete lines ${a}-${b} by hand.`
    },
  }
}

function hooksDir(cwd: string): string | null {
  const out = gitOut(cwd, ['rev-parse', '--git-path', 'hooks'])
  if (out === null || out === '') return null
  return isAbsolute(out) ? out : resolve(cwd, out)
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

function parseAgents(opt: string | undefined): Agent[] | null | 'bad' {
  if (opt === undefined) return null
  const a = opt.toLowerCase()
  if (a === 'all') return null
  return (INSTALL_AGENTS as readonly string[]).includes(a) ? [a as Agent] : 'bad'
}

/** Remove empty folders setup made, walking up from the file's folder, never above the project. */
const toPosixPath = (p: string): string => p.split('\\').join('/')

function tidyDirs(cwd: string, file: string, created: readonly string[]): void {
  let dir = dirname(file)
  const root = resolve(cwd)
  while (dir.startsWith(root + '/') && dir !== root) {
    // Only a folder the install record says setup created; a folder that was already there is never removed.
    if (!created.includes(toPosixPath(dir.slice(root.length + 1)))) return
    try {
      rmdirSync(dir)
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code
      if (code !== 'ENOTEMPTY' && code !== 'ENOENT') logger.debug(`uninstall: could not remove folder ${dir}: ${String(code)}`)
      return
    }
    dir = dirname(dir)
  }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export async function runUninstall(opts: UninstallOptions, d: UninstallDeps): Promise<number> {
  const out = d.out
  const cwd = d.cwd

  const selected = parseAgents(opts.agent)
  if (selected === 'bad') {
    logger.error(`Unknown --agent "${opts.agent}". Choose one of: ${INSTALL_AGENTS.join(', ')}, all.`)
    return EXIT_CODES.CONFIG_ERROR
  }
  if (opts.purge && opts.keepReports) {
    logger.error('--purge and --keep-reports contradict each other. Use one.')
    return EXIT_CODES.CONFIG_ERROR
  }
  if (opts.purge && selected !== null) {
    logger.error('--purge deletes the whole .shipguard/ folder, so it needs a full uninstall: leave out --agent.')
    return EXIT_CODES.CONFIG_ERROR
  }
  const configDir = resolve(d.configDir)
  if (opts.purgeHome && (selected !== null || !(configDir.endsWith('/.config/shipguard') || configDir.endsWith('/shipguard')))) {
    logger.error(selected !== null ? '--purge-home needs a full uninstall: leave out --agent.' : `--purge-home refuses to delete ${configDir}: it is not a folder named shipguard.`)
    return EXIT_CODES.CONFIG_ERROR
  }

  // 1. Find what is there
  const state = readInstallState(cwd)
  const items: Item[] = []
  const push = (i: Item | null): void => {
    if (i !== null) items.push(i)
  }
  push(settingsItem(cwd, state))
  push(
    wholeFileItem(
      cwd,
      state,
      SHIM_RELATIVE_PATH,
      ['claude'],
      'the hook script (unedited)',
      (t) => shimFileVersion(t) > 0,
      (t) => t === claudeShimScript(),
    ),
  )
  push(mdBlockItem(cwd, state, CLAUDE_MD, ['claude']))
  push(mdBlockItem(cwd, state, AGENTS_MD, ['codex', 'cursor']))
  const hd = hooksDir(cwd)
  if (hd !== null) for (const name of GIT_HOOK_NAMES) push(gitHookItem(cwd, state, hd, name, ['git', 'codex', 'cursor']))
  push(
    wholeFileItem(
      cwd,
      state,
      WORKFLOW,
      ['ci'],
      'the whole file (unedited)',
      (t) => t.includes(HOOK_MARKER_START),
      (t) => {
        const v = /@agenticcli\/shipguard@(\S+)/.exec(t)?.[1]
        return t === ciWorkflowYaml() || (v !== undefined && t === ciWorkflowText(v))
      },
    ),
  )

  // Which items this run takes: those whose owners are all being removed (a shared item stays while another agent still uses it)
  const installed = new Set<Agent>(state?.agents ?? [])
  const remaining = (): Set<Agent> => {
    if (selected === null) return new Set<Agent>()
    const left = new Set(installed)
    for (const a of selected) left.delete(a)
    return left
  }
  const stillUsed = remaining()
  const inScope = (i: Item): boolean => (selected === null ? true : i.owners.some((o) => selected.includes(o)))
  const scoped = items.filter(inScope)
  const sharedKept: Array<{ item: Item; by: Agent[] }> = []
  const taking: Item[] = []
  for (const i of scoped) {
    const by = i.owners.filter((o) => stillUsed.has(o))
    if (by.length > 0) sharedKept.push({ item: i, by })
    else taking.push(i)
  }
  // The hook script is useless without the settings entry that runs it: when that entry stays, the script stays with it.
  const settingsKept = taking.find((i) => i.path === join(cwd, SETTINGS) && i.state === 'keep-edited')
  const removing: Item[] = []
  const keptEdited: Item[] = []
  for (const i of taking) {
    if (i.path === join(cwd, SHIM_RELATIVE_PATH) && i.state === 'remove' && settingsKept !== undefined) {
      keptEdited.push({ ...i, state: 'keep-edited', note: 'still needed by the hook entry in .claude/settings.json that you edited; kept', manual: `delete it yourself together with that entry` })
    } else if (i.state === 'remove') removing.push(i)
    else keptEdited.push(i)
  }

  const dotDir = join(cwd, INSTALL_STATE_DIR)
  const hasDot = existsSync(dotDir)
  const dotEntries = hasDot ? readdirSync(dotDir) : []
  const onlyOurs = dotEntries.every((n) => n === 'installed.json' || n === '.gitignore')
  const recordFile = join(cwd, INSTALL_STATE_FILE)
  const hasRecord = existsSync(recordFile)
  const homeExists = opts.purgeHome === true && existsSync(configDir)

  if (items.length === 0 && !hasRecord && !(opts.purge && hasDot) && !homeExists) {
    out('ShipGuard is not set up in this project. Nothing to remove.')
    return EXIT_CODES.SAFE
  }

  // The record goes last, once nothing it describes is left to find. A partial run keeps it, minus what was removed.
  const fullRun = selected === null
  const removeRecordNow = hasRecord && (fullRun || (sharedKept.length === 0 && stillUsed.size === 0))
  const purge = opts.purge === true
  const purgeDot = purge && hasDot
  // With no reports or history in it, .shipguard/ holds only what setup made (named in the plan): remove it too.
  const dotGoes = hasDot && !opts.keepReports && (purgeDot || (removeRecordNow && onlyOurs))
  const dotKept = hasDot && !dotGoes
  const policyKept = existsSync(join(cwd, 'shipguard.policy.yml'))

  // 2. The plan
  out(`ShipGuard found in this project. ${opts.dryRun ? 'Dry run, nothing will be changed:' : 'Nothing is changed until you confirm:'}`)
  if (state === null && items.length > 0) out('Found by markers (no install record).')
  const toRemove: string[] = []
  const labelPad = 34
  const row = (label: string, note: string): string => `    ${label.padEnd(labelPad)} ${note}`
  const lines: string[] = []
  for (const i of removing) lines.push(row(i.label, i.note))
  if (hasRecord && removeRecordNow) lines.push(row(INSTALL_STATE_FILE, 'the install record (removed last; nothing is installed after this)'))
  if (dotGoes) {
    lines.push(
      row(
        `${INSTALL_STATE_DIR}/`,
        purgeDot && !onlyOurs ? `the whole folder: reports, history and its .gitignore (${human(dirSize(dotDir))})` : 'the folder setup made: the record and its .gitignore (no reports or history in it)',
      ),
    )
  }
  if (homeExists) lines.push(row('~/.config/shipguard/', `usage-ping id, offer cache and your sign-in (${human(dirSize(configDir))}); you are signed out`))
  toRemove.push(...lines)
  if (lines.length > 0) {
    out('  Will remove (ShipGuard wrote it, not edited since):')
    for (const l of lines) out(l)
  }
  if (keptEdited.length > 0) {
    out('  Will keep (edited since install, so yours now):')
    for (const i of keptEdited) {
      out(row(i.label, i.note))
      if (i.manual !== undefined) out(`      Do this yourself: ${i.manual}`)
    }
  }
  const keepLines: string[] = []
  if (policyKept) keepLines.push(row('shipguard.policy.yml', 'your policy and ignore reasons (delete it yourself if you want it gone)'))
  if (dotKept) keepLines.push(row(`${INSTALL_STATE_DIR}/`, `reports, history${existsSync(join(dotDir, '.gitignore')) ? " and its .gitignore" : ''} (--purge deletes them)`))
  for (const s of sharedKept) keepLines.push(row(s.item.label, `still used by ${s.by.join(', ')} (uninstall --agent ${s.by[0]} removes it)`))
  if (keepLines.length > 0) {
    out('  Will keep (yours or may be wanted):')
    for (const l of keepLines) out(l)
  }
  out('  Not touched by this command:')
  out(row('the npm package', 'remove with: npm uninstall @agenticcli/shipguard'))
  if (!homeExists) out(row('~/.config/shipguard/', 'usage-ping id (--purge-home), credentials (shipguard logout)'))

  const count = removing.length + (hasRecord && removeRecordNow ? 1 : 0)
  if (count === 0 && !dotGoes && !homeExists) {
    out('Nothing can be removed here without your hand: see the lines above.')
    return EXIT_CODES.SAFE
  }
  if (opts.dryRun) return EXIT_CODES.SAFE

  // 3. Confirm once
  if (!opts.yes) {
    if (!d.isTty) {
      logger.error('CONFIRMATION_REQUIRED: uninstall removes files and was not given a terminal to ask in.')
      const flags = [opts.agent !== undefined ? `--agent ${opts.agent}` : '', opts.purge ? '--purge' : '', opts.purgeHome ? '--purge-home' : '', '--yes'].filter(Boolean).join(' ')
      out(`Run: shipguard uninstall ${flags}`)
      return EXIT_CODES.CONFIG_ERROR
    }
    const n = count + (dotGoes ? 1 : 0) + (homeExists ? 1 : 0)
    if (!(await d.confirm(`Remove the ${n} ${n === 1 ? 'item' : 'items'} under "Will remove"? [y/N] `))) {
      out('Nothing was changed.')
      return EXIT_CODES.SAFE
    }
  }

  // 4. Remove, one item at a time; the first failure stops the run and leaves the record so a rerun can finish
  const done: Item[] = []
  try {
    for (const i of removing) {
      i.apply()
      if (i.deletes) tidyDirs(cwd, i.path, state?.createdDirs ?? [])
      done.push(i)
      out(`✓ removed ${i.label === SETTINGS ? 'hook entry from ' + i.label : i.note.includes('managed block') ? 'managed block from ' + i.label : i.note.includes('ShipGuard block') ? 'ShipGuard block from ' + i.label : i.label}`)
    }
  } catch (err) {
    logger.error(`UNINSTALL_FAILED: could not change ${done.length === removing.length ? 'a file' : removing[done.length]?.label ?? 'a file'}: ${err instanceof Error ? err.message : String(err)}`)
    out(`Stopped. ${done.length} done; the install record is kept so you can run uninstall again.`)
    return EXIT_CODES.RUNTIME_ERROR
  }

  // 5. Verify before the record goes
  const failures = removing.map((i) => i.verify()).filter((x): x is string => x !== null)

  try {
    if (hasRecord && removeRecordNow && failures.length === 0) {
      unlinkSync(recordFile)
      out(`✓ removed the install record ${INSTALL_STATE_FILE}`)
    } else if (hasRecord && !removeRecordNow && state !== null && failures.length === 0) {
      // Partial uninstall: keep the record for the agents that stay.
      const gone = new Set(removing.map((i) => display(cwd, i.path)))
      const goneRec = (e: InstallEntry): boolean => gone.has(e.path) || [...gone].some((g) => g === e.path || e.path.endsWith('/' + g))
      const next: InstallState = {
        ...state,
        agents: state.agents.filter((a) => !(selected ?? []).includes(a)),
        entries: state.entries.filter((e) => !goneRec(e) || sharedKept.some((s) => display(cwd, s.item.path) === e.path)),
      }
      writeInstallState(cwd, next)
      out(`✓ updated the install record ${INSTALL_STATE_FILE}`)
    }
    if (dotGoes && failures.length === 0) {
      if (!existsSync(join(dotDir, 'installed.json')) || purgeDot) {
        rmSync(dotDir, { recursive: true, force: true })
        out(purgeDot && !onlyOurs ? `✓ removed ${INSTALL_STATE_DIR}/ (reports, history)` : `✓ removed ${INSTALL_STATE_DIR}/`)
      }
    }
    if (homeExists && failures.length === 0) {
      rmSync(configDir, { recursive: true, force: true })
      out('✓ removed ~/.config/shipguard/ (you are signed out)')
    }
  } catch (err) {
    logger.error(`UNINSTALL_FAILED: could not remove the record or folders: ${err instanceof Error ? err.message : String(err)}`)
    return EXIT_CODES.RUNTIME_ERROR
  }

  if (failures.length > 0) {
    for (const f of failures) logger.error(`UNINSTALL_VERIFY_FAILED: ${f}`)
    for (const f of failures) out(`✗ UNINSTALL_VERIFY_FAILED: ${f}`)
    return EXIT_CODES.RUNTIME_ERROR
  }

  // 6. What is left, named
  const keptNames = [...(policyKept ? ['shipguard.policy.yml'] : []), ...(dotKept ? [`${INSTALL_STATE_DIR}/ (reports, history, its .gitignore)`] : [])]
  out(`Removed ${count} ${count === 1 ? 'item' : 'items'}.${keptNames.length > 0 ? ` Kept: ${keptNames.join(', ')}.` : ''}`)
  const active = [...keptEdited.map((i) => `${i.label} (${i.note})`), ...sharedKept.map((s) => `${s.item.label} (still used by ${s.by.join(', ')})`)]
  if (active.length === 0) {
    out("Checking this project's own files: no ShipGuard hook or block is left.      ✓")
  } else {
    out("Checking this project's own files: removed items are gone. Still active (named above):")
    for (const a of active) out(`  ${a}`)
  }
  out('Still to do by hand: npm uninstall @agenticcli/shipguard; shipguard logout')
  out('Reinstall any time: shipguard setup')
  return EXIT_CODES.SAFE
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

export function uninstallCommand(): Command {
  return new Command('uninstall')
    .description('Remove what shipguard setup installed (shows every change first, asks once)')
    .option('--agent <agent>', `Only this agent: ${INSTALL_AGENTS.join(' | ')} | all (default: everything)`)
    .option('--dry-run', 'Show what would be removed and change nothing')
    .option('--yes', 'Proceed without asking (required when not run from a terminal)')
    .option('--keep-reports', 'Keep .shipguard/ reports and history (the default)')
    .option('--purge', 'Also delete the rest of .shipguard/ (reports, history)')
    .option('--purge-home', 'Also delete ~/.config/shipguard/ (usage-ping id, offer cache) and sign out')
    .addHelpText('after', `
Examples:
  shipguard uninstall --dry-run         Show what would be removed
  shipguard uninstall --agent claude    Remove the Claude Code hook and CLAUDE.md block only
  shipguard uninstall --yes             Remove without asking (needed outside a terminal)

Exit codes:
  0  Removed, nothing to remove, or dry run.
  2  Config error: unknown --agent, conflicting flags, or no confirmation (not a terminal, no --yes).
  3  Runtime error: a file could not be changed, or a ShipGuard block is still there after the removal.`)
    .action(async (o: { agent?: string; dryRun?: boolean; yes?: boolean; keepReports?: boolean; purge?: boolean; purgeHome?: boolean }) => {
      let code: number
      try {
        code = await runUninstall(o, {
          cwd: process.cwd(),
          out: (l) => console.log(l),
          isTty: Boolean(process.stdin.isTTY && process.stdout.isTTY),
          confirm: (q) =>
            new Promise<boolean>((res) => {
              const rl = createInterface({ input: process.stdin, output: process.stdout })
              rl.question(q, (a) => {
                rl.close()
                res(/^y(es)?$/i.test(a.trim()))
              })
            }),
          configDir: getConfigDir(),
        })
      } catch (err) {
        logger.error(`Uninstall failed: ${err instanceof Error ? err.message : String(err)}`)
        code = EXIT_CODES.RUNTIME_ERROR
      }
      process.exit(code)
    })
}
