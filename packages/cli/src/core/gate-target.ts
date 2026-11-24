/**
 * gate-target.ts — which directory and which commit a hook command targets.
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
import { dirname, isAbsolute, resolve } from 'node:path'

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
  /** push `--all`, `--mirror`, `--tags`: the push sends every ref of that kind, not just the named ones. */
  allRefs?: 'heads' | 'all' | 'tags'
  /** True when the parser could not place the command and gates it as a push of the directory (see parseGateCommand). */
  floor?: boolean
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
const WRAPPERS = new Set(['sudo', 'command', 'time', 'nice', 'nohup', 'exec', 'builtin'])
/** Shell keywords that start a command: `if cd X; then git push; fi`, `do git push`. */
const KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '!'])

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

/** A value that names a directory in the command text; `unresolved` when it holds an expansion we do not evaluate. */
interface Spec {
  value: string
  unresolved: boolean
}

interface ParseState {
  dir: string | null
  dirProblem: string | undefined
  /** True once any segment started with `git` or `gh`: the parser then understood the command. */
  sawGit: boolean
  /** True when a segment is a command the parser cannot positively place (see `unplaceable`). */
  suspicious: boolean
  /** The first such segment, shown back to the agent. */
  suspiciousText: string | undefined
  /** GIT_DIR / GIT_WORK_TREE set by an earlier segment (`export GIT_DIR=x`, `GIT_DIR=x`). */
  gitDir?: Spec
  workTree?: Spec
}

function problemFor(operand: string): string {
  return `the directory "${operand}" in the command cannot be worked out from its text (variable, substitution, or cd -)`
}

/** Subcommands git itself ships. Any other word after `git` may be an alias for `push`: it is not placed. */
const GIT_SUBCOMMANDS = new Set([
  'add', 'am', 'annotate', 'apply', 'archive', 'bisect', 'blame', 'branch', 'bundle', 'cat-file', 'check-attr', 'check-ignore',
  'checkout', 'checkout-index', 'cherry', 'cherry-pick', 'citool', 'clean', 'clone', 'column', 'commit', 'commit-tree', 'config',
  'count-objects', 'credential', 'daemon', 'describe', 'diff', 'diff-files', 'diff-index', 'diff-tree', 'difftool', 'fast-export',
  'fast-import', 'fetch', 'filter-branch', 'fmt-merge-msg', 'for-each-ref', 'format-patch', 'fsck', 'gc', 'get-tar-commit-id', 'grep',
  'gui', 'hash-object', 'help', 'index-pack', 'init', 'instaweb', 'interpret-trailers', 'log', 'ls-files', 'ls-remote', 'ls-tree',
  'maintenance', 'merge-base', 'merge-file', 'mergetool', 'mktag', 'mktree', 'mv', 'name-rev', 'notes', 'pack-objects', 'pack-refs',
  'patch-id', 'prune', 'pull', 'range-diff', 'read-tree', 'rebase', 'receive-pack', 'reflog', 'remote', 'repack', 'replace',
  'request-pull', 'rerere', 'reset', 'restore', 'rev-list', 'rev-parse', 'revert', 'rm', 'send-email', 'send-pack', 'shortlog', 'show',
  'show-branch', 'show-ref', 'sparse-checkout', 'stash', 'status', 'stripspace', 'submodule', 'switch', 'symbolic-ref', 'tag',
  'unpack-file', 'update-index', 'update-ref', 'upload-archive', 'upload-pack', 'var', 'verify-commit', 'verify-tag', 'version',
  'whatchanged', 'worktree', 'write-tree', 'lfs', 'svn',
])

/** Command words that run other text or code the parser cannot read. */
const OPAQUE_WORDS = new Set(['eval'])

/** A word the shell would rewrite before running it (variable, substitution, glob, brace) or that runs hidden text. */
function unplaceable(word: string, flagged: boolean): boolean {
  if (word === '[' || word === '[[') return flagged
  return flagged || OPAQUE_WORDS.has(word) || /[$`*?[\]{}]/.test(word)
}

function assignmentOf(token: string): { name: string; value: string } | null {
  const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(token)
  return m ? { name: m[1], value: m[2] } : null
}

/**
 * Which directory a git command acts on once `--git-dir` / `--work-tree` (or the GIT_DIR /
 * GIT_WORK_TREE variables) are applied: the work tree when named, else the folder that holds a
 * `.git` git-dir. A git-dir that is not a `.git` folder (a bare repository) cannot be scanned as a
 * work tree: null, so the gate blocks. Never the hook cwd.
 */
function repoDir(dir: string | null, gitDir: Spec | undefined, workTree: Spec | undefined, home: string): { dir: string | null; problem?: string } {
  if (!gitDir && !workTree) return { dir }
  if (workTree) {
    const d = applyDir(dir, workTree.value, workTree.unresolved, home)
    return d === null ? { dir: null, problem: problemFor(workTree.value) } : { dir: d }
  }
  const gd = applyDir(dir, gitDir!.value, gitDir!.unresolved, home)
  if (gd === null) return { dir: null, problem: problemFor(gitDir!.value) }
  if (basename(gd) !== '.git') return { dir: null, problem: `the command names a git directory (${gd}) that is not a .git folder, so there is no work tree to check` }
  return { dir: dirname(gd) }
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
  // Where THIS command runs: the shell's directory, unless `env -C` says otherwise for it alone.
  let dirNow = state.dir
  let problemNow = state.dirProblem
  let gitDirSpec = state.gitDir
  let workTreeSpec = state.workTree
  const assigned: Record<string, Spec> = {}
  const segText = seg.text.replace(/^[({\s]+/, '').replace(/[)}\s]+$/, '')

  // Leading VAR=value assignments, `env` options, wrapper words and shell keywords.
  for (;;) {
    if (t.length === 0) {
      // Only assignments: they are set for the rest of the line.
      if (assigned.GIT_DIR) state.gitDir = assigned.GIT_DIR
      if (assigned.GIT_WORK_TREE) state.workTree = assigned.GIT_WORK_TREE
      return
    }
    const a = assignmentOf(t[0])
    if (a) {
      if (a.name === 'GIT_DIR' || a.name === 'GIT_WORK_TREE') {
        const spec = { value: a.value, unresolved: u[0] || /[$`]/.test(a.value) }
        assigned[a.name] = spec
        if (a.name === 'GIT_DIR') gitDirSpec = spec
        else workTreeSpec = spec
      }
      t.shift(); u.shift()
      continue
    }
    if (basename(t[0]) === 'export' || basename(t[0]) === 'unset') {
      const unsetting = basename(t[0]) === 'unset'
      for (let i = 1; i < t.length; i++) {
        const e = unsetting ? { name: t[i], value: '' } : assignmentOf(t[i])
        if (!e) continue
        if (e.name === 'GIT_DIR') state.gitDir = unsetting ? undefined : { value: e.value, unresolved: u[i] || /[$`]/.test(e.value) }
        if (e.name === 'GIT_WORK_TREE') state.workTree = unsetting ? undefined : { value: e.value, unresolved: u[i] || /[$`]/.test(e.value) }
      }
      return
    }
    if (basename(t[0]) === 'env' && t.length > 1) {
      // env [-i] [-u NAME] [-C DIR] [NAME=value ...] command
      let i = 1
      for (; i < t.length; i++) {
        const o = t[i]
        if (o === '-C' || o === '--chdir') {
          const next = applyDir(dirNow, t[i + 1] ?? '', u[i + 1] ?? true, home)
          if (next === null) problemNow ??= problemFor(t[i + 1] ?? '')
          dirNow = next
          i++
        } else if (o.startsWith('--chdir=')) {
          const next = applyDir(dirNow, o.slice(8), u[i] ?? false, home)
          if (next === null) problemNow ??= problemFor(o.slice(8))
          dirNow = next
        } else if (o === '-u' || o === '--unset') {
          i++
        } else if (o.startsWith('-S') || o === '--split-string') {
          // A split string hides the real command line: not placed, fail closed.
          out.push({
            kind: 'push',
            command: segText,
            dir: null,
            dirProblem: 'the command uses env -S, which hides the command from ShipGuard',
            refs: [],
            deleteOnly: false,
            floor: true,
          })
          return
        } else if (o.startsWith('-')) {
          continue
        } else if (assignmentOf(o)) {
          const e = assignmentOf(o)!
          if (e.name === 'GIT_DIR' || e.name === 'GIT_WORK_TREE') {
            const spec = { value: e.value, unresolved: u[i] || /[$`]/.test(e.value) }
            if (e.name === 'GIT_DIR') gitDirSpec = spec
            else workTreeSpec = spec
          }
        } else break
      }
      t = t.slice(i)
      u = u.slice(i)
      continue
    }
    if ((WRAPPERS.has(basename(t[0])) || KEYWORDS.has(t[0])) && t.length > 1) {
      t.shift(); u.shift()
      continue
    }
    break
  }
  const firstWord = basename(t[0])
  const firstFlagged = u[0] ?? false
  let word = firstWord

  // An unknown launcher in front of git or gh (`timeout 60 git push`, `xargs git push`,
  // `stdbuf -o0 git push`): the command that runs is the first git or gh word. The directory state
  // is kept, so a `cd` seen before it still decides where it runs.
  if (word !== 'cd' && word !== 'pushd' && word !== 'git' && word !== 'gh' && !SHELLS.has(word)) {
    const k = t.findIndex((x, idx) => idx > 0 && (basename(x) === 'git' || basename(x) === 'gh'))
    if (k > 0) {
      t = t.slice(k)
      u = u.slice(k)
      word = basename(t[0])
    }
  }

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
      const inner: ParseState = { dir: dirNow, dirProblem: problemNow, sawGit: false, suspicious: false, suspiciousText: undefined, gitDir: gitDirSpec, workTree: workTreeSpec }
      parseLine(t[c + 1], inner, home, out, depth + 1)
      state.sawGit ||= inner.sawGit
      if (inner.suspicious && !state.suspicious) {
        state.suspicious = true
        state.suspiciousText = inner.suspiciousText
      }
      return
    }
  }

  if (word === 'git' || word === 'gh') state.sawGit = true

  if (word === 'git') {
    let dir = dirNow
    let problem = problemNow
    let gitDir = gitDirSpec
    let workTree = workTreeSpec
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
        const isGitDir = a.startsWith('--git-dir')
        const eq = a.indexOf('=')
        const value = eq !== -1 ? a.slice(eq + 1) : (t[i + 1] ?? '')
        const flagged = eq !== -1 ? u[i] : (u[i + 1] ?? true)
        const spec = { value, unresolved: flagged || /[$`]/.test(value) }
        if (isGitDir) gitDir = spec
        else workTree = spec
        if (eq === -1) i++
        continue
      }
      if (a.startsWith('-')) continue
      break
    }
    const sub = t[i]
    // The repository the command acts on: the work tree or the folder of the `.git` it names, else the directory.
    const repo = repoDir(dir, gitDir, workTree, home)
    dir = repo.dir
    if (repo.problem) problem = repo.problem
    if (sub !== undefined && sub !== 'push' && sub !== 'merge') {
      // Not a push or a merge: placed, unless the word is not a git subcommand at all (an alias may be a push).
      if (!GIT_SUBCOMMANDS.has(sub)) {
        if (!state.suspicious) state.suspiciousText = segText
        state.suspicious = true
      }
      return
    }
    if (sub === undefined) return
    const args = t.slice(i + 1)
    const base: Pick<GateInvocation, 'command' | 'dir' | 'dirProblem'> = {
      command: segText,
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
        command: segText,
        dir: dirNow,
        ...(dirNow === null ? { dirProblem: problemNow } : {}),
        refs: [],
        deleteOnly: false,
      })
    }
    return
  }

  // Any other command word: placed (not a push) unless the shell would rewrite it or it runs hidden text.
  if (unplaceable(firstWord, firstFlagged)) {
    if (!state.suspicious) state.suspiciousText = segText
    state.suspicious = true
  }
}

function pushRefs(args: string[]): { refs: string[]; deleteOnly: boolean; allRefs?: 'heads' | 'all' | 'tags' } {
  const positional: string[] = []
  let deleting = false
  let allRefs: 'heads' | 'all' | 'tags' | undefined
  let afterDashDash = false
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (!afterDashDash && a === '--') {
      afterDashDash = true
      continue
    }
    if (!afterDashDash && a.startsWith('-')) {
      if (a === '-d' || a === '--delete') deleting = true
      if (a === '--all' || a === '--branches') allRefs = allRefs === 'all' ? 'all' : 'heads'
      if (a === '--mirror') allRefs = 'all'
      if (a === '--tags') allRefs = allRefs === 'heads' || allRefs === 'all' ? 'all' : 'tags'
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
    if (/[*?[]/.test(src)) {
      // A pattern refspec (`refs/heads/*:refs/heads/*`) sends every ref it matches: treat it as that kind of push.
      const kind = src.startsWith('refs/tags') ? 'tags' : src.startsWith('refs/heads') ? 'heads' : 'all'
      allRefs = allRefs && allRefs !== kind ? 'all' : kind
      continue
    }
    if (src) refs.push(src)
  }
  return { refs, deleteOnly: specs.length > 0 && deletes === specs.length, ...(allRefs ? { allRefs } : {}) }
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
  const state: ParseState = { dir: resolve(cwd), dirProblem: undefined, sawGit: false, suspicious: false, suspiciousText: undefined }
  parseLine(command, state, home, out, 0)
  // Floor 1: a command the parser could not place (a glob or variable as the command word, eval, a
  // git alias) may be a push. It is gated as a push of the directory the line left us in, so it is
  // checked instead of waved through. The same commit as a plain push would be.
  if (state.suspicious && !out.some((o) => o.kind === 'push' && o.dir === state.dir)) {
    out.push({
      kind: 'push',
      command: (state.suspiciousText ?? command).split('\n')[0].slice(0, 200),
      dir: state.dir,
      ...(state.dir === null ? { dirProblem: state.dirProblem } : {}),
      refs: [],
      deleteOnly: false,
      floor: true,
    })
  }
  // The floor only applies when no segment was a git or gh command (an eval, a script, an echo):
  // `git merge --abort` was understood and is not a merge, so it does not come back through here.
  if (out.length === 0 && !state.sawGit && MENTION_RE.test(command)) {
    const kind: GateCommandKind = /\bgh\s+pr\s+merge\b/.test(command) ? 'pr-merge' : /\bmerge\b/.test(command) && !/\bpush\b/.test(command) ? 'merge' : 'push'
    // The directory is the one the `cd` chain left us in; when a cd could not be resolved it stays
    // null and the gate blocks, it never falls back to the hook cwd.
    out.push({
      kind,
      command: command.trim().split('\n')[0].slice(0, 200),
      dir: state.dir,
      ...(state.dir === null ? { dirProblem: state.dirProblem } : {}),
      refs: [],
      deleteOnly: false,
    })
  }
  return out
}
