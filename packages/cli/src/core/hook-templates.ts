/**
 * hook-templates.ts — the exact text `shipguard hook` installs, and the marker machinery that makes
 * re-running it idempotent.
 *
 * Kept separate from commands/hook.ts so the templates are unit-testable as pure strings, with no
 * filesystem involved.
 *
 * 0.13 shape (spec 03): every host (Claude Code hook, git hooks) runs the SAME small POSIX shim.
 * The shim is not `shipguard` itself: if ShipGuard is missing the shell would exit 127, Claude Code
 * treats any exit other than 2 as non-blocking, and the push would go through unchecked. The shim
 * guarantees a block (exit 2 on Claude, 1 on git) with a text that says why, and bounds every step
 * with one shared 150 s clock (the host timeout of 180 s minus a 30 s margin).
 *
 * The shim only ever runs a binary that answers `gate --supports` (0.13 or later); an older binary
 * is skipped, so a 0.12 "unknown command" can never be read as a block it did not decide.
 *
 * Names exported here are the contract W4a (`shipguard setup`) builds on: SHIM_RELATIVE_PATH,
 * CLAUDE_HOOK_COMMAND, CLAUDE_HOOK_TIMEOUT_SECONDS, SHIM_VERSION, claudeShimScript(), gitHookScript().
 */

/** Bumped when the installed git hook text changes, so a re-run visibly updates old blocks. */
export const HOOK_BLOCK_VERSION = 2
/** The version of the Claude shim file; line 2 of the file names it. */
export const SHIM_VERSION = 2

export const HOOK_MARKER_START = '# >>> shipguard managed block >>>'
export const HOOK_MARKER_END = '# <<< shipguard managed block <<<'
/** Line 2 of every shim: `# shipguard-hook v2 (managed by ShipGuard) ...`. */
export const SHIM_MARKER_PREFIX = '# shipguard-hook v'

export type HookTarget = 'git' | 'claude' | 'ci'

/**
 * GitHub Actions the generated workflows use, pinned by full commit SHA (a tag can be moved; a SHA cannot). Each SHA was
 * read from the GitHub API (repos/actions/<name>/git/ref/tags/<tag> -> commit, checked with repos/actions/<name>/commits/<sha>
 * and the published release, 2026-11-22). Bump both together, by hand, from the API: never type a SHA from memory.
 */
export const ACTION_CHECKOUT = 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0'
export const ACTION_SETUP_NODE = 'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0'

/** The CI job invocation (the CI template keeps this exact command). */
export const GATE_COMMAND = 'shipguard scan --json --strict'

/** What each host runs through the shim. */
export const GATE_HOST_COMMAND = 'shipguard gate'

/** The hook script setup writes for Claude Code, relative to the project. */
export const SHIM_RELATIVE_PATH = '.claude/hooks/shipguard-gate.sh'
/** The command the Claude Code settings entry runs. */
export const CLAUDE_HOOK_COMMAND = 'sh "$CLAUDE_PROJECT_DIR/.claude/hooks/shipguard-gate.sh"'
/** Seconds. The shim's deadline is this minus the 30 s margin. Setup writes it into settings.json. */
export const CLAUDE_HOOK_TIMEOUT_SECONDS = 180
/** The shim's own deadline in seconds (hook timeout minus a 30 s margin). */
export const GATE_DEADLINE_SECONDS = CLAUDE_HOOK_TIMEOUT_SECONDS - 30

/** Text in a settings.json command that identifies OUR entry (new shim). */
export const CLAUDE_HOOK_FINGERPRINT = 'shipguard-gate.sh'
/** Text in the 0.12 inline hook command; such an entry is ours and is upgraded in place. */
export const LEGACY_CLAUDE_HOOK_FINGERPRINT = ' scan --json --strict'

/**
 * The scoped package, pinned to the first version that has `shipguard gate`. The UNSCOPED npm
 * package `shipguard` is a different, unrelated project: never resolve it.
 */
export const GATE_MIN_VERSION = '0.13'
export const NPX_SPEC = `@agenticcli/shipguard@${GATE_MIN_VERSION}`

export type ShimHost = 'claude' | 'git'

interface ShimOptions {
  host: ShimHost
  /** git only: the hook name (pre-push, pre-merge-commit); passed to `shipguard gate --hook`. */
  hookName?: string
}

/**
 * The POSIX shim, host `claude` or `git`. About 45 lines; readable and editable by a human.
 * Every text it prints is fixed; its code and agentAction never depend on a run.
 */
function shimBody(opts: ShimOptions): string {
  const claude = opts.host === 'claude'
  const blockExit = claude ? 2 : 1
  const hostArgs = claude ? 'gate --host claude' : `gate --host git --hook ${opts.hookName ?? 'pre-push'}`
  const setupAgent = claude ? 'claude' : 'git'
  const cmdLine = claude
    ? `R=$(sed -nE 's/.*"command"[[:space:]]*:[[:space:]]*"(([^"\\\\]|\\\\.)*)".*/\\1/p' "$IN" | head -n 1); C=$(printf '%s\\n' "$R" | sed 's/\\\\"/"/g; s/\\\\\\\\/\\\\/g'); [ -n "$C" ] || C="the git command"`
    : `C="git ${opts.hookName === 'pre-merge-commit' ? 'merge' : 'push'}"`
  // The project root, never the hook's working directory: a local binary is looked up there, so a
  // folder the agent cd'd into cannot supply the program that decides whether a push is allowed.
  const cdLine = claude
    ? [
        `if [ -n "$CLAUDE_PROJECT_DIR" ]; then P=$(cd "$CLAUDE_PROJECT_DIR" 2>/dev/null && pwd) && cd "$P" || { say "SHIPGUARD BLOCKED: \${Q}\${C}\${Q} did not run. The project folder cannot be entered, so nothing was scanned." 'shipguard-gate: code=NOT_A_PROJECT agentAction=fix_and_rerun run=none'; exit 2; }; else P=; fi   # no project folder given: no local binary is used at all (PATH or npx only), the hook cwd is never trusted for one; \`shipguard gate\` reads the hook cwd from the same JSON and decides the scan directory itself`,
      ]
    : [`P=$(pwd)`]
  const removal = claude
    ? 'If the user no longer wants the gate, remove it by hand (ShipGuard itself is not available): delete the file .claude/hooks/shipguard-gate.sh and the entry that names it under "hooks" > "PreToolUse" in .claude/settings.json.'
    : `If the user no longer wants the gate, remove it by hand (ShipGuard itself is not available): delete the block between the two "shipguard managed block" lines in the git hook file ${opts.hookName ?? 'pre-push'}.`
  const lines = [
    `# shipguard-hook v${SHIM_VERSION} (managed by ShipGuard, host ${opts.host}). Manual removal: ${claude ? 'delete this file and the entry naming it in .claude/settings.json' : 'delete this block'}`,
    `IN=$(mktemp 2>/dev/null || echo "\${TMPDIR:-/tmp}/shipguard-in.$$"); trap 'rm -f "$IN"' EXIT; cat > "$IN"   # the hook input (${claude ? 'JSON on stdin: tool_input.command and cwd' : 'the refs git sends on stdin'})`,
    `Q='\`'; say() { printf '%s\\n' "$@" >&2; }`,
    cmdLine,
    ...(claude
      ? [
          `if [ -n "$R" ]; then case "$R" in *[\\\\\\$\\\`\\'\\*\\?\\[\\{]*) ;; *) printf '%s\\n' "$R" | grep -Eq '(^|[^A-Za-z0-9_])(git|gh)([^A-Za-z0-9_]|$)' || exit 0;; esac; fi   # the hook sees EVERY Bash command: only a command with no quote, backslash, $, backtick, glob or brace character AND no git or gh word cannot be a push or a merge, so only that is not gated (and never blocked when ShipGuard is missing); anything the shell could rewrite goes to the gate`,
        ]
      : []),
    ...cdLine,
    `SHIPGUARD_HOST_TIMEOUT=${CLAUDE_HOOK_TIMEOUT_SECONDS}; SHIPGUARD_GATE_START=$(date +%s); export SHIPGUARD_HOST_TIMEOUT SHIPGUARD_GATE_START   # ${CLAUDE_HOOK_TIMEOUT_SECONDS} = the hook timeout setup writes to settings.json`,
    `SHIPGUARD_SHIM_VERSION=${SHIM_VERSION}; export SHIPGUARD_SHIM_VERSION`,
    `DEADLINE=${GATE_DEADLINE_SECONDS}   # the whole shim, every step below included: ${CLAUDE_HOOK_TIMEOUT_SECONDS} minus a 30 s margin`,
    `left() { echo $((DEADLINE - ($(date +%s) - SHIPGUARD_GATE_START))); }`,
    `cap() { l=$(left); [ "$l" -gt "$1" ] && echo "$1" || echo "$l"; }   # a step gets its own cap or what is left, whichever is smaller`,
    `bounded() { n=$1; shift; [ "$n" -gt 0 ] || return 124`,
    `  if T=$(command -v timeout || command -v gtimeout); then "$T" -k 2 "$n" "$@" < "$IN"; return $?; fi   # coreutils when present`,
    `  "$@" < "$IN" & p=$!; ( sleep "$n"; kill -TERM "$p" 2>/dev/null; sleep 2; kill -KILL "$p" 2>/dev/null ) & w=$!   # otherwise a plain-shell watchdog: no extra tool needed`,
    `  wait "$p"; rc=$?; kill "$w" 2>/dev/null; return $rc; }`,
    `probe() { bounded "$(cap 5)" "$1" gate --supports >/dev/null 2>&1; rc=$?; case $rc in 124|137|143) STALLED=$1;; esac; return $rc; }   # true only for 0.13+; an older binary is skipped; a binary that hangs costs 5 s at most, is remembered in STALLED and skipped`,
    claude
      ? `run() { bounded "$(cap ${GATE_DEADLINE_SECONDS})" "$@"; rc=$?; [ "$rc" = 0 ] && exit 0; [ "$rc" = 2 ] && exit 2; case $rc in 124|137|143) TIMEDOUT=1;; esac; }   # no exec: we must see the code. 2 is always a gate block; a stopped gate is remembered`
      : `run() { bounded "$(cap ${GATE_DEADLINE_SECONDS})" "$@"; rc=$?; [ "$rc" = 0 ] && exit 0; [ "$rc" = 1 ] && exit 1; case $rc in 124|137|143) TIMEDOUT=1;; esac; }   # no exec: we must see the code. 1 is always a gate block on a git host; a stopped gate is remembered`,
    `if   [ -n "$P" ] && [ -x "$P/node_modules/.bin/shipguard" ] && probe "$P/node_modules/.bin/shipguard"; then run "$P/node_modules/.bin/shipguard" ${hostArgs}`,
    `elif command -v shipguard >/dev/null 2>&1 && probe shipguard; then run shipguard ${hostArgs}`,
    `elif [ -z "$STALLED" ] && command -v npx >/dev/null 2>&1; then run npx --yes ${NPX_SPEC} ${hostArgs}   # download and gate share what is left of the ${GATE_DEADLINE_SECONDS} s; a binary that hung means a broken install: npx would only eat the deadline offline, so block now (GATE_STARTUP_STALLED)`,
    `fi`,
    `# nothing resolved (a ShipGuard older than 0.13 counts as nothing), or a code the gate does not use (127, a crash, 124 or 143 from a stalled or slow step): fail closed, with the text that says why`,
    `if [ "$(left)" -le 0 ] || [ -n "$TIMEDOUT" ]; then`,
    `  say "SHIPGUARD BLOCKED: \${Q}\${C}\${Q} did not run. The gate did not finish inside its ${GATE_DEADLINE_SECONDS} s deadline (startup checks, download and scan), so nothing was cleared. This is not a finding." \\`,
    `    "Run the check yourself, outside the hook: shipguard scan --strict   (a retry would hit the same deadline on a large repo)" \\`,
    `    "If that scan alone takes longer than ${GATE_DEADLINE_SECONDS} s, or this repo is large: stop and ask the user to raise gate.timeoutSeconds in shipguard.policy.yml, then run shipguard setup --agent ${setupAgent} (it sets the hook timeout to the new value plus 60 s; today ${CLAUDE_HOOK_TIMEOUT_SECONDS} s)." \\`,
    `    "The user can run it from their own terminal; agents must not work around this." \\`,
    `    'shipguard-gate: code=GATE_TIMEOUT agentAction=fix_and_rerun run=none rerun="shipguard scan --strict"'`,
    `elif [ -n "$STALLED" ]; then`,
    `  say "SHIPGUARD BLOCKED: \${Q}\${C}\${Q} did not run. ShipGuard ($STALLED) did not answer its 5 s startup check, so nothing was scanned." \\`,
    `    "Cause: the program hangs when started (a broken install or a stuck process)." \\`,
    `    "Fix: run \${Q}$STALLED --version\${Q} yourself. If it hangs, reinstall: npm i -D @agenticcli/shipguard" \\`,
    `    "Then: shipguard scan --strict   (retry once that works)" \\`,
    `    'shipguard-gate: code=GATE_STARTUP_STALLED agentAction=ask_human run=none'`,
    `else`,
    `  say "SHIPGUARD BLOCKED: \${Q}\${C}\${Q} did not run. ShipGuard could not start (not installed, older than 0.13, or it crashed), so nothing was scanned." \\`,
    `    "Fix: npm i -D @agenticcli/shipguard   (or: npm i -g @agenticcli/shipguard)" \\`,
    `    "Without a local install, npx needs network access to fetch it." \\`,
    `    "${removal.replace(/"/g, '\\"')}" \\`,
    `    'shipguard-gate: code=GATE_NOT_STARTED agentAction=fix_and_rerun run=none'`,
    `fi`,
    `exit ${blockExit}`,
  ]
  return lines.join('\n')
}

/** The Claude Code hook script: `.claude/hooks/shipguard-gate.sh`. Line 2 carries the version marker. */
export function claudeShimScript(): string {
  return ['#!/bin/sh', shimBody({ host: 'claude' }), ''].join('\n')
}

/**
 * A git hook script (pre-push / pre-merge-commit): the same shim with host `git` (exit 1 on block).
 *
 * HONEST LIMIT, printed in the file itself: a git hook binds humans and well-behaved agents ONLY.
 * `--no-verify` skips it, and coding agents have been observed using it across consecutive commits
 * despite explicit deny rules (anthropics/claude-code#40117). This layer is convenience, not a
 * guarantee.
 */
export function gitHookScript(hookName: string): string {
  return ['#!/bin/sh', gitHookBlock(hookName), ''].join('\n')
}

/**
 * Just the marked block, WITHOUT the shebang.
 *
 * Update path uses this, create path uses gitHookScript(). Splitting them is not cosmetic:
 * replacing a marked block with a full-file template re-inserted the shebang inside the file body,
 * so a second install produced a hook starting with two `#!/bin/sh` lines (idempotency regression test).
 */
export function gitHookBlock(hookName: string): string {
  return [
    `${HOOK_MARKER_START} v${HOOK_BLOCK_VERSION} (${hookName})`,
    '# Installed by `shipguard hook`. Re-run that command to update this block.',
    `# Runs ShipGuard as a hard stop: ${GATE_HOST_COMMAND} --host git`,
    '#',
    '# HONEST LIMIT: a git hook binds humans and well-behaved agents only.',
    '# `--no-verify` skips it. For a stop an agent cannot route around, also run:',
    '#   shipguard hook --target claude   (runs outside the model)',
    '#   shipguard hook --target ci       (server-side; pair with branch protection)',
    shimBody({ host: 'git', hookName }),
    HOOK_MARKER_END,
  ].join('\n')
}

/** Git hooks `shipguard hook --target git` installs, in install order. */
export const GIT_HOOK_NAMES = ['pre-push', 'pre-merge-commit'] as const

/**
 * GitHub Actions verdict job.
 *
 * Shaped like GitHub's own Agentic Workflows pattern: one isolated deterministic job whose red
 * check is the signal. This is the ONLY layer that binds everyone: it is server-side, so nothing
 * local can skip it. Pair it with branch protection to make it binding rather than advisory.
 */
export function ciWorkflowYaml(): string {
  return `# ${HOOK_MARKER_START.replace('# ', '')} v${HOOK_BLOCK_VERSION} (github-actions)
# Installed by \`shipguard hook --target ci\`. Re-run that command to update this file.
#
# This is the only layer that binds EVERYONE — it runs server-side, so nothing
# local can skip it. Turn on branch protection for this check to make it binding.
name: ShipGuard security scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  shipguard:
    name: ShipGuard verdict
    runs-on: ubuntu-latest
    steps:
      - uses: ${ACTION_CHECKOUT}
      - uses: ${ACTION_SETUP_NODE}
        with:
          node-version: '20'
      - name: Run ShipGuard
        run: npx --yes @agenticcli/shipguard scan --json --strict
# ${HOOK_MARKER_END.replace('# ', '')}
`
}

/**
 * Which layer binds whom — printed by the command itself on every install, not only buried in
 * docs. Overstating what a git hook guarantees would be the same class of defect as a false
 * SAFE_TO_SHIP. (The old "the agent cannot argue past it" claim is gone, spec 07.)
 */
export const BINDING_NOTES: Record<HookTarget, string> = {
  git:
    'Binds humans and well-behaved agents only. `git push --no-verify` skips it, and coding ' +
    'agents have been seen doing exactly that. Treat this as convenience, not a guarantee.',
  claude:
    'Blocks well-behaved agents. It runs outside the model, but an agent can still edit or remove ' +
    'the hook entry, other commands are not covered, and if Claude Code stops the hook the command ' +
    'runs unchecked. It checks one commit, not uncommitted files or the merged result.',
  ci:
    'Binds everyone. It runs on GitHub, so nothing local can skip it. Turn on branch protection ' +
    'for this check to make it binding rather than advisory.',
}

/** Replace an existing managed block in `content`, or return undefined if there is none. */
export function replaceManagedBlock(content: string, replacement: string): string | undefined {
  const start = content.indexOf(HOOK_MARKER_START)
  if (start === -1) return undefined
  const endMarker = content.indexOf(HOOK_MARKER_END, start)
  if (endMarker === -1) return undefined
  const end = endMarker + HOOK_MARKER_END.length
  return content.slice(0, start) + replacement.trim() + content.slice(end)
}

/** True when this file was written (or is still managed) by `shipguard hook`. */
export function isManaged(content: string): boolean {
  return content.includes(HOOK_MARKER_START)
}

/** The block version a managed git hook file carries (0 when the file has no ShipGuard block). */
export function managedBlockVersion(content: string): number {
  const m = /shipguard managed block >>> v(\d+)/.exec(content)
  return m ? Number(m[1]) : 0
}

/** The shim version a Claude hook script carries (0 when there is no marker, an old or foreign file). */
export function shimFileVersion(content: string): number {
  const m = new RegExp(`^${SHIM_MARKER_PREFIX}(\\d+)`, 'm').exec(content)
  return m ? Number(m[1]) : 0
}

/** Which kind of entry a settings.json PreToolUse command string is. */
export function classifyClaudeHookCommand(command: string): 'shim' | 'legacy' | 'foreign' {
  if (command.includes(CLAUDE_HOOK_FINGERPRINT)) return 'shim'
  // Legacy only when it also names shipguard: someone else's `scan --json --strict` (trivy, semgrep) is not ours.
  if (command.includes(LEGACY_CLAUDE_HOOK_FINGERPRINT) && command.includes('shipguard')) return 'legacy'
  return 'foreign'
}
