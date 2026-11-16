import { Command } from 'commander'
import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { EXIT_CODES } from '@agenticcli/shared'
import { logger } from '../utils/logger.js'
import { isGitRepo } from '../core/git.js'
import {
  BINDING_NOTES,
  CLAUDE_HOOK_COMMAND,
  CLAUDE_HOOK_FINGERPRINT,
  GATE_COMMAND,
  GIT_HOOK_NAMES,
  ciWorkflowYaml,
  gitHookScript,
  gitHookBlock,
  isManaged,
  replaceManagedBlock,
  type HookTarget,
} from '../core/hook-templates.js'

/**
 * `shipguard hook` — install the merge-boundary gate.
 *
 * This is the feature that makes the passive default coherent: ShipGuard never blocks on
 * its own, so the INSTALLATION — a deliberate human act — is what turns the power stop on
 * at the boundary where it matters. Everything installed here runs
 * `shipguard scan --json --strict`, because a hook without --strict is a no-op.
 *
 * Three targets, three honesty levels. The command prints which layer binds whom
 * every time it installs, not only in the docs.
 */

interface InstallOutcome {
  /** Path written (or that would be written). */
  path: string
  status: 'created' | 'updated' | 'unchanged' | 'refused'
  /** Present when status is 'refused' — what the user should do by hand instead. */
  manualLine?: string
}

// ---------------------------------------------------------------------------
// Filesystem helpers — every write goes through here so behaviour is uniform.
// ---------------------------------------------------------------------------

/**
 * @param whole  full file text, used when the file does not exist yet
 * @param block  just the marked block, used to replace an existing managed block —
 *               splitting the two is what keeps a re-run from re-inserting a file
 *               preamble (e.g. a shebang) into the middle of the file
 */
function writeManaged(path: string, whole: string, block: string, executable: boolean): InstallOutcome {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, whole, 'utf-8')
    if (executable) chmodSync(path, 0o755)
    return { path, status: 'created' }
  }

  const current = readFileSync(path, 'utf-8')

  if (!isManaged(current)) {
    // A foreign file. NEVER overwrite someone else's hook — print the line to add
    // by hand instead.
    return {
      path,
      status: 'refused',
      manualLine: GATE_COMMAND,
    }
  }

  // Ours: replace the managed block in place. Idempotent — re-running updates,
  // never appends a second copy.
  const merged = replaceManagedBlock(current, block) ?? whole
  if (merged === current) return { path, status: 'unchanged' }
  writeFileSync(path, merged, 'utf-8')
  if (executable) chmodSync(path, 0o755)
  return { path, status: 'updated' }
}

/**
 * Resolve the directory git actually reads hooks from — honours `core.hooksPath`
 * and worktrees, which a naive `.git/hooks` join gets wrong.
 */
function resolveGitHooksDir(cwd: string): string {
  const out = execFileSync('git', ['rev-parse', '--git-path', 'hooks'], {
    cwd,
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
  }).trim()
  return isAbsolute(out) ? out : resolve(cwd, out)
}

// ---------------------------------------------------------------------------
// Per-target installers
// ---------------------------------------------------------------------------

function installGit(cwd: string): InstallOutcome[] {
  const hooksDir = resolveGitHooksDir(cwd)
  return GIT_HOOK_NAMES.map((name) =>
    writeManaged(join(hooksDir, name), gitHookScript(name), gitHookBlock(name), true),
  )
}

/** Minimal shape of the bits of .claude/settings.json this command touches. */
interface ClaudeSettings {
  hooks?: {
    PreToolUse?: Array<{
      matcher?: string
      hooks?: Array<{ type?: string; command?: string }>
    }>
  }
  [key: string]: unknown
}

function installClaude(cwd: string): InstallOutcome[] {
  const path = join(cwd, '.claude', 'settings.json')
  const entry = { matcher: 'Bash', hooks: [{ type: 'command', command: CLAUDE_HOOK_COMMAND }] }

  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, JSON.stringify({ hooks: { PreToolUse: [entry] } }, null, 2) + '\n', 'utf-8')
    return [{ path, status: 'created' }]
  }

  const raw = readFileSync(path, 'utf-8')
  let settings: ClaudeSettings
  try {
    settings = JSON.parse(raw) as ClaudeSettings
  } catch (err) {
    // Loud. Never rewrite a settings file we could not parse; the user's
    // own configuration is not ours to guess at.
    logger.error(
      `Could not parse ${path}: ${err instanceof Error ? err.message : err}. ` +
      `Refusing to touch it.`,
    )
    return [{ path, status: 'refused', manualLine: CLAUDE_HOOK_COMMAND }]
  }

  const preToolUse = settings.hooks?.PreToolUse ?? []
  // Ours is identified by the gate invocation inside the command string — the same
  // fingerprint idea as the shell marker, adapted to JSON.
  const ourIndex = preToolUse.findIndex((e) =>
    (e.hooks ?? []).some((h) => typeof h.command === 'string' && h.command.includes(CLAUDE_HOOK_FINGERPRINT)),
  )

  const next = [...preToolUse]
  let status: InstallOutcome['status']
  if (ourIndex === -1) {
    next.push(entry)
    status = 'created'
  } else if (JSON.stringify(next[ourIndex]) === JSON.stringify(entry)) {
    status = 'unchanged'
  } else {
    next[ourIndex] = entry
    status = 'updated'
  }

  if (status !== 'unchanged') {
    const merged: ClaudeSettings = {
      ...settings,
      hooks: { ...(settings.hooks ?? {}), PreToolUse: next },
    }
    writeFileSync(path, JSON.stringify(merged, null, 2) + '\n', 'utf-8')
  }
  return [{ path, status }]
}

function installCi(cwd: string): InstallOutcome[] {
  const path = join(cwd, '.github', 'workflows', 'shipguard.yml')
  const yaml = ciWorkflowYaml()
  return [writeManaged(path, yaml, yaml, false)]
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

const TARGETS: readonly HookTarget[] = ['git', 'claude', 'ci']

export function hookCommand(): Command {
  return new Command('hook')
    .description('Install the ShipGuard release gate at the merge boundary (git hook, Claude Code hook, or CI job)')
    .option(
      '--target <target>',
      `Where to install the gate: ${TARGETS.join(' | ')}`,
      'git',
    )
    .addHelpText('after', `
What each target installs (all of them run \`${GATE_COMMAND}\`):

  --target git     .git/hooks/pre-push and pre-merge-commit
                   ${BINDING_NOTES.git}

  --target claude  .claude/settings.json — a PreToolUse hook on Bash \`git merge\`/\`git push\`
                   ${BINDING_NOTES.claude}

  --target ci      .github/workflows/shipguard.yml
                   ${BINDING_NOTES.ci}

Install all three where you can. ShipGuard never blocks on its own — installing a
hook is the deliberate act that turns the hard stop on.

Re-running is safe: an existing ShipGuard block is updated in place, never duplicated.
A hook file somebody else wrote is never overwritten — you get the line to add by hand.

Exit codes:
  0  Installed (or already up to date).
  2  Config error — unknown --target, or --target git outside a git repository.
  3  Runtime error — the files could not be written.`)
    .action((opts: { target?: string }) => {
      const cwd = process.cwd()
      const target = String(opts.target ?? 'git') as HookTarget

      if (!TARGETS.includes(target)) {
        logger.error(`Unknown --target "${opts.target}". Choose one of: ${TARGETS.join(', ')}.`)
        process.exit(EXIT_CODES.CONFIG_ERROR)
        return
      }

      if (target === 'git' && !isGitRepo(cwd)) {
        logger.error(
          `Not a git repository: ${cwd}. ` +
          `Run this inside your project, or use --target ci / --target claude.`,
        )
        process.exit(EXIT_CODES.CONFIG_ERROR)
        return
      }

      let outcomes: InstallOutcome[]
      try {
        outcomes =
          target === 'git' ? installGit(cwd)
            : target === 'claude' ? installClaude(cwd)
              : installCi(cwd)
      } catch (err) {
        logger.error(`Could not install the hook: ${err instanceof Error ? err.message : err}`)
        process.exit(EXIT_CODES.RUNTIME_ERROR)
        return
      }

      const refused = outcomes.filter((o) => o.status === 'refused')

      for (const outcome of outcomes) {
        const shown = isAbsolute(outcome.path) ? (relative(cwd, outcome.path) || outcome.path) : outcome.path
        switch (outcome.status) {
          case 'created':
            logger.success(`Installed the release gate: ${shown}`)
            break
          case 'updated':
            logger.success(`Updated the release gate: ${shown}`)
            break
          case 'unchanged':
            logger.info(`Already up to date: ${shown}`)
            break
          case 'refused':
            logger.warn(`${shown} was written by something else — not touching it.`)
            logger.warn(`  Add this line to it yourself:  ${outcome.manualLine}`)
            break
        }
      }

      // The honesty note — printed on every install, because a user who
      // thinks a git hook stops an agent has been misled by us.
      logger.info(`What this binds: ${BINDING_NOTES[target]}`)
      if (target === 'git') {
        logger.info('For a stop an agent cannot route around, also run: shipguard hook --target claude')
        logger.info('And for one nothing local can skip:                shipguard hook --target ci')
      }

      // A refusal is not a failure of the command — the user was told exactly what to
      // do, and nothing was destroyed. Exit 0 keeps `shipguard hook` scriptable.
      if (refused.length > 0) {
        logger.info('Nothing was overwritten.')
      }
    })
}
