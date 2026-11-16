/**
 * hook-templates.ts — the exact text `shipguard hook` installs, and the marker
 * machinery that makes re-running it idempotent.
 *
 * Kept separate from commands/hook.ts so the templates are unit-testable as pure
 * strings, with no filesystem involved.
 *
 * ONE command installs the
 * merge-boundary gate, at one of three targets. Every installed layer runs
 * `shipguard scan --json --strict` — a hook that does not use --strict is a no-op
 * by definition, because ShipGuard is passive by default and
 * --strict is its only hard stop.
 *
 * NOT BUILT, deliberately: hook auto-detection magic, a
 * hook daemon, per-hook config files, or any non---strict hook.
 */

/** Bumped when the installed text changes, so a re-run visibly updates old blocks. */
export const HOOK_BLOCK_VERSION = 1

export const HOOK_MARKER_START = '# >>> shipguard managed block >>>'
export const HOOK_MARKER_END = '# <<< shipguard managed block <<<'

export type HookTarget = 'git' | 'claude' | 'ci'

/**
 * The invocation every layer runs:
 * `shipguard scan --json --strict`.
 */
export const GATE_COMMAND = 'shipguard scan --json --strict'

/**
 * Shared shell body. Runs the gate, stays quiet on success, prints the machine
 * output only when the gate blocks — so a passing push is not buried in JSON.
 *
 * Fail-closed on a missing binary: if ShipGuard cannot be found, the gate did not
 * run, and a gate that did not run must not report a pass. That is the same rule
 * the verdict applies to a degraded scan.
 */
function gateShellBody(indent = ''): string {
  const l = (s: string) => `${indent}${s}`
  return [
    l('if command -v shipguard >/dev/null 2>&1; then'),
    l('  _sg_run() { shipguard "$@"; }'),
    l('elif command -v npx >/dev/null 2>&1; then'),
    l('  _sg_run() { npx --no-install shipguard "$@"; }'),
    l('else'),
    l('  echo "ShipGuard: not installed, so the release gate did not run — refusing to pass." >&2'),
    l('  echo "  Install it:  npm i -g @agenticcli/shipguard" >&2'),
    l('  exit 1'),
    l('fi'),
    l('_sg_out=$(_sg_run scan --json --strict 2>&1) || {'),
    l('  echo "ShipGuard blocked this: the release gate did not pass." >&2'),
    l('  printf "%s\\n" "$_sg_out" >&2'),
    l('  exit 1'),
    l('}'),
  ].join('\n')
}

/**
 * A git hook script (pre-push / pre-merge-commit).
 *
 * HONEST LIMIT, printed in the file itself: a git hook binds humans and
 * well-behaved agents ONLY. `--no-verify` skips it, and coding agents have been
 * observed using it across consecutive commits despite explicit deny rules
 * (anthropics/claude-code#40117). This layer is convenience, not a guarantee.
 */
export function gitHookScript(hookName: string): string {
  return ['#!/bin/sh', gitHookBlock(hookName), ''].join('\n')
}

/**
 * Just the marked block, WITHOUT the shebang.
 *
 * Update path uses this, create path uses gitHookScript(). Splitting them is not
 * cosmetic: replacing a marked block with a full-file template re-inserted the
 * shebang inside the file body, so a second `shipguard hook` run produced a hook
 * starting with two `#!/bin/sh` lines. Caught by the idempotency regression test.
 */
export function gitHookBlock(hookName: string): string {
  return [
    HOOK_MARKER_START + ` v${HOOK_BLOCK_VERSION} (${hookName})`,
    '# Installed by `shipguard hook`. Re-run that command to update this block.',
    `# Runs the release gate as a HARD STOP: ${GATE_COMMAND}`,
    '#',
    '# HONEST LIMIT: a git hook binds humans and well-behaved agents only.',
    '# `--no-verify` skips it. For a stop an agent cannot route around, also run:',
    '#   shipguard hook --target claude   (runs outside the model)',
    '#   shipguard hook --target ci       (server-side; pair with branch protection)',
    gateShellBody(),
    HOOK_MARKER_END,
  ].join('\n')
}

/** Git hooks `shipguard hook --target git` installs, in install order. */
export const GIT_HOOK_NAMES = ['pre-push', 'pre-merge-commit'] as const

/**
 * The Claude Code PreToolUse hook command.
 *
 * Reads the tool-call payload on stdin, and only gates Bash commands that are a
 * `git merge` or `git push`. Exit 2 tells Claude Code to BLOCK the tool call.
 * This runs outside the model, so it cannot be prompted, pressured, or injected
 * away — the layer Anthropic's own steering doctrine puts enforcement in.
 */
export const CLAUDE_HOOK_COMMAND =
  `sh -c '_sg_in=$(cat); case "$_sg_in" in *"git merge"*|*"git push"*) ` +
  `_sg_out=$(${GATE_COMMAND} 2>&1) || { ` +
  `echo "ShipGuard blocked this merge/push: the release gate did not pass." >&2; ` +
  `printf "%s\\n" "$_sg_out" >&2; exit 2; };; esac; exit 0'`

/** Marker used to recognise OUR entry inside an existing .claude/settings.json. */
export const CLAUDE_HOOK_FINGERPRINT = 'shipguard scan --json --strict'

/**
 * GitHub Actions verdict job.
 *
 * Shaped like GitHub's own Agentic Workflows pattern: one isolated deterministic
 * job whose red check is the signal. This is the ONLY layer that binds everyone —
 * it is server-side, so nothing local can skip it. Pair it with branch protection
 * to make it binding rather than advisory.
 */
export function ciWorkflowYaml(): string {
  return `# ${HOOK_MARKER_START.replace('# ', '')} v${HOOK_BLOCK_VERSION} (github-actions)
# Installed by \`shipguard hook --target ci\`. Re-run that command to update this file.
#
# This is the only layer that binds EVERYONE — it runs server-side, so nothing
# local can skip it. Turn on branch protection for this check to make it binding.
name: ShipGuard release gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  shipguard:
    name: ShipGuard verdict
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Run the release gate
        run: npx --yes @agenticcli/shipguard scan --json --strict
# ${HOOK_MARKER_END.replace('# ', '')}
`
}

/**
 * Which layer binds whom — printed by the command itself on every install, not
 * only buried in docs. Overstating what a git hook guarantees would be
 * the same class of defect as a false SAFE_TO_SHIP.
 */
export const BINDING_NOTES: Record<HookTarget, string> = {
  git:
    'Binds humans and well-behaved agents only. `git push --no-verify` skips it, and coding ' +
    'agents have been seen doing exactly that. Treat this as convenience, not a guarantee.',
  claude:
    'Binds the agent. It runs outside the model, so the agent cannot argue, prompt, or inject ' +
    'its way past it inside a session.',
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
