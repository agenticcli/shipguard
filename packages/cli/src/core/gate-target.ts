/**
 * gate-target.ts — which directory and which commit a hook command targets (owner decision A1).
 *
 * Pure: (command text, hook cwd) -> what the gate must scan. No filesystem, no git. The caller
 * resolves the directory and the refs.
 *
 * Why this exists: the hook's working directory is where Claude Code's shell STARTED the command,
 * not where the command runs. `cd ../wt && git push` and `git -C ../wt push` push the commit of the
 * worktree, so a gate that scanned the hook cwd would clear the wrong commit (a false SAFE; 25
 * dogfood scans checked `main` while the work ran on branches).
 *
 * Fail closed: when the target directory cannot be worked out from the text (a variable, a command
 * substitution, `cd -`, `--git-dir`, `--work-tree`) `dir` is null and the gate blocks with
 * NOT_A_PROJECT. It never falls back to scanning some other directory.
 */
import { homedir } from 'node:os'
import { isAbsolute, resolve } from 'node:path'

export type GateCommandKind = 'push' | 'merge' | 'pr-merge'

export interface GateInvocation {
  kind: GateCommandKind
  /** The command as the agent wrote it (the matching segment only, no leading `cd X &&`). */
  command: string
  /** Absolute directory the command runs in, or null when it cannot be worked out from the text. */
  dir: string | null
  /** Why `dir` is null (plain words, no secrets). */
  dirProblem?: string
  /** push: the source side of each named refspec; merge: each named ref. Empty = use the default. */
  refs: string[]
  /** push: true when the command only deletes remote refs (it sends no commit). */
  deleteOnly: boolean
}

/** Words that split a command line into separate commands (outside quotes). */
const SEPARATORS = ['&&', '||', ';', '|', '&', '\n']

interface Segment {
  /** The segment as written (used to show the command back to the agent). */
  text: string
  tokens: string[]
  /** True when any token contained a `$`, backtick or `$(` outside single quotes (not expanded by us). */
  unresolved: boolean[]
}

/**
 * Split a command line into segments and tokens, honouring single quotes, double quotes and
 * backslashes. Tokens keep a flag when they hold a shell expansion we do not evaluate.
 */
function splitSegments(input: string): Segment[] {
  const segments: Segment[] = []
  let tokens: string[] = []
  let flags: boolean[] = []
  let cur = ''
  let curUnresolved = false
  let inToken = false
  let segStart = 0
  let i = 0

  const pushToken = (): void => {
    if (inToken) {
      tokens.push(cur)
      flags.push(curUnresolved)
    }
    cur = ''
    curUnresolved = false
    inToken = false
  }
  const endSegment = (end: number): void => {
    pushToken()
    const text = input.slice(segStart, end).trim()
    if (tokens.length > 0) segments.push({ text, tokens, unresolved: flags })
    tokens = []
    flags = []
  }

  while (i < input.length) {
    const ch = input[i]
    if (ch === "'") {
      inToken = true
      const close = input.indexOf("'", i + 1)
      const end = close === -1 ? input.length : close
      cur += input.slice(i + 1, end)
      i = close === -1 ? input.length : close + 1
      continue
    }
    if (ch === '"') {
      inToken = true
      i++
      while (i < input.length && input[i] !== '"') {
        if (input[i] === '\\' && i + 1 < input.length) {
          cur += input[i + 1]
          i += 2
          continue
        }
        if (input[i] === '$' || input[i] === '`') curUnresolved = true
        cur += input[i]
        i++
      }
      i++
      continue
    }
    if (ch === '\\' && i + 1 < input.length) {
      inToken = true
      cur += input[i + 1]
      i += 2
      continue
    }
    const sep = SEPARATORS.find((s) => input.startsWith(s, i))
    if (sep) {
      endSegment(i)
      i += sep.length
      segStart = i
      continue
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      pushToken()
      i++
      continue
    }
    if (ch === '(' || ch === '{') {
      // A group opener at the start of a word is dropped; inside a word (`$(`) it stays.
      if (!inToken) {
        i++
        continue
      }
    }
    if ((ch === ')' || ch === '}') && !curUnresolved) {
      // A group closer ends the word (`git push)`); after an expansion (`$(pwd)`) it stays.
      pushToken()
      i++
      continue
    }
    if (ch === '$' || ch === '`') curUnresolved = true
    inToken = true
    cur += ch
    i++
  }
  endSegment(input.length)
  return segments
}

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh'])
const WRAPPERS = new Set(['sudo', 'command', 'time', 'nice', 'nohup', 'exec', 'builtin', 'env'])

const PUSH_VALUE_OPTS = new Set(['-o', '--push-option', '--receive-pack', '--exec', '--repo'])
const MERGE_VALUE_OPTS = new Set([
  '-m', '-F', '-s', '-X', '--message', '--file', '--strategy', '--strategy-option', '--into-name', '--cleanup',
])
const MERGE_NON_MERGING = new Set(['--abort', '--continue', '--quit'])

function basename(word: string): string {
  const slash = word.lastIndexOf('/')
  return slash === -1 ? word : word.slice(slash + 1)
}

/** Resolve `cd`/`-C` operand against the current directory; null when it cannot be done honestly. */
function applyDir(current: string | null, operand: string, unresolved: boolean, home: string): string | null {
  if (unresolved || operand === '-' || operand.includes('$') || operand.includes('`')) return null
  let target = operand
  if (target === '~' || target.startsWith('~/')) target = home + target.slice(1)
  else if (target.startsWith('~')) return null // ~user: not expanded here
  if (isAbsolute(target)) return resolve(target)
  if (current === null) return null
  return target === '' ? current : resolve(current, target)
}

interface ParseState {
  dir: string | null
  dirProblem: string | undefined
  /** True once any segment started with `git` or `gh`: the parser then understood the command. */
  sawGit: boolean
}

function problemFor(operand: string): string {
  return `the directory "${operand}" in the command cannot be worked out from its text (variable, substitution, or cd -)`
}

/** Parse one segment; returns an invocation when it is a gated command, and updates the directory state. */
function parseSegment(
  seg: Segment,
  state: ParseState,
  home: string,
  out: GateInvocation[],
  depth: number,
): void {
  let t = [...seg.tokens]
  let u = [...seg.unresolved]
  // Leading VAR=value assignments and wrapper words.
  for (;;) {
    if (t.length === 0) return
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t[0])) {
      t.shift(); u.shift()
      continue
    }
    if (WRAPPERS.has(basename(t[0])) && t.length > 1) {
      t.shift(); u.shift()
      continue
    }
    break
  }
  const word = basename(t[0])

  if (word === 'cd' || word === 'pushd') {
    // Skip options (-P, -L, --); `-` alone means the previous directory.
    let idx = 1
    while (idx < t.length && t[idx] !== '-' && t[idx].startsWith('-')) idx++
    const operand = t[idx]
    if (operand === undefined) {
      state.dir = state.dir === null ? null : home
      if (state.dir === null) state.dirProblem ??= problemFor('cd')
    } else {
      const next = applyDir(state.dir, operand, u[idx] ?? false, home)
      if (next === null) state.dirProblem ??= problemFor(operand)
      else state.dirProblem = undefined
      state.dir = next
    }
    return
  }

  // sh -c "<command string>": the string is a command line of its own, in the current directory.
  if (SHELLS.has(word) && depth < 3) {
    const c = t.findIndex((x, idx) => idx > 0 && /^-[a-z]*c[a-z]*$/.test(x))
    if (c !== -1 && t[c + 1] !== undefined) {
      const inner: ParseState = { dir: state.dir, dirProblem: state.dirProblem, sawGit: false }
      parseLine(t[c + 1], inner, home, out, depth + 1)
      state.sawGit ||= inner.sawGit
      return
    }
  }

  if (word === 'git' || word === 'gh') state.sawGit = true

  if (word === 'git') {
    let dir = state.dir
    let problem = state.dirProblem
    let i = 1
    for (; i < t.length; i++) {
      const a = t[i]
      if (a === '-C') {
        const operand = t[i + 1]
        if (operand === undefined) break
        const next = applyDir(dir, operand, u[i + 1] ?? false, home)
        if (next === null) problem ??= problemFor(operand)
        dir = next
        i++
        continue
      }
      if (a === '-c' || a === '--exec-path' || a === '--namespace' || a === '--super-prefix') {
        i += a === '--exec-path' ? 0 : 1
        continue
      }
      if (a.startsWith('--git-dir') || a.startsWith('--work-tree')) {
        // Names a repository by a path we do not follow: do not guess.
        dir = null
        problem ??= 'the command uses --git-dir or --work-tree, which ShipGuard does not follow'
        if (!a.includes('=')) i++
        continue
      }
      if (a.startsWith('-')) continue
      break
    }
    const sub = t[i]
    if (sub !== 'push' && sub !== 'merge') return
    const args = t.slice(i + 1)
    const base: Pick<GateInvocation, 'command' | 'dir' | 'dirProblem'> = {
      command: seg.text.replace(/^[({\s]+/, '').replace(/[)}\s]+$/, ''),
      dir,
      ...(dir === null ? { dirProblem: problem } : {}),
    }
    if (sub === 'push') out.push({ kind: 'push', ...base, ...pushRefs(args) })
    else if (!args.some((a) => MERGE_NON_MERGING.has(a))) out.push({ kind: 'merge', ...base, refs: mergeRefs(args), deleteOnly: false })
    return
  }

  if (word === 'gh') {
    // gh [global options] pr merge ...
    const rest = t.slice(1).filter((x) => !x.startsWith('-'))
    if (rest[0] === 'pr' && rest[1] === 'merge') {
      out.push({
        kind: 'pr-merge',
        command: seg.text.replace(/^[({\s]+/, '').replace(/[)}\s]+$/, ''),
        dir: state.dir,
        ...(state.dir === null ? { dirProblem: state.dirProblem } : {}),
        refs: [],
        deleteOnly: false,
      })
    }
  }
}

function pushRefs(args: string[]): { refs: string[]; deleteOnly: boolean } {
  const positional: string[] = []
  let deleting = false
  let afterDashDash = false
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (!afterDashDash && a === '--') {
      afterDashDash = true
      continue
    }
    if (!afterDashDash && a.startsWith('-')) {
      if (a === '-d' || a === '--delete') deleting = true
      if (PUSH_VALUE_OPTS.has(a)) i++
      continue
    }
    positional.push(a)
  }
  // positional[0] is the remote; the rest are refspecs. `tag <name>` means refs/tags/<name>.
  const specs: string[] = []
  const rest = positional.slice(1)
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === 'tag' && rest[i + 1] !== undefined) {
      specs.push(rest[i + 1])
      i++
    } else specs.push(rest[i])
  }
  const refs: string[] = []
  let deletes = 0
  for (const spec of specs) {
    const s = spec.replace(/^\+/, '')
    const colon = s.indexOf(':')
    const src = colon === -1 ? s : s.slice(0, colon)
    if (deleting || (colon !== -1 && src === '')) {
      deletes++
      continue
    }
    if (src) refs.push(src)
  }
  return { refs, deleteOnly: specs.length > 0 && deletes === specs.length }
}

function mergeRefs(args: string[]): string[] {
  const refs: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a.startsWith('-')) {
      if (MERGE_VALUE_OPTS.has(a)) i++
      continue
    }
    refs.push(a)
  }
  return refs
}

function parseLine(line: string, state: ParseState, home: string, out: GateInvocation[], depth: number): void {
  for (const seg of splitSegments(line)) parseSegment(seg, state, home, out, depth)
}

/** True when the raw text mentions a gated command anywhere (the old substring rule, kept as a floor). */
const MENTION_RE = /\bgit\b[^\n;&|]*\b(push|merge)\b|\bgh\s+pr\s+merge\b/

/**
 * What does this hook command target? Returns every gated invocation in the text, each with the
 * directory it runs in. An empty list means the command is not gated.
 *
 * A command that mentions `git push`/`git merge`/`gh pr merge` but that the parser cannot place
 * (an `eval`, a script, a here-doc) is still returned, once, in the hook cwd: the gate is a floor,
 * never narrower than the old substring match.
 */
export function parseGateCommand(command: string, cwd: string, home: string = process.env.HOME ?? homedir()): GateInvocation[] {
  const out: GateInvocation[] = []
  const state: ParseState = { dir: resolve(cwd), dirProblem: undefined, sawGit: false }
  parseLine(command, state, home, out, 0)
  // The floor only applies when no segment was a git or gh command (an eval, a script, an echo):
  // `git merge --abort` was understood and is not a merge, so it does not come back through here.
  if (out.length === 0 && !state.sawGit && MENTION_RE.test(command)) {
    const kind: GateCommandKind = /\bgh\s+pr\s+merge\b/.test(command) ? 'pr-merge' : /\bmerge\b/.test(command) && !/\bpush\b/.test(command) ? 'merge' : 'push'
    out.push({ kind, command: command.trim().split('\n')[0].slice(0, 200), dir: resolve(cwd), refs: [], deleteOnly: false })
  }
  return out
}
