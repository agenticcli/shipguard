import { Command } from 'commander'
import { spawnSync } from 'node:child_process'
import { EXIT_CODES } from '@agenticcli/shared'
import { logger } from '../utils/logger.js'

/**
 * `shipguard hook --target X` (0.12 name, kept for scripts): it now hands over to `shipguard setup --agent X`
 *, the one installer. The old per-target installers and the Node 20 CI workflow template are gone, so there
 * is exactly one writer of hook files and one install record (.shipguard/installed.json).
 * Targets map one to one: git, claude, ci.
 */
const TARGETS = ['git', 'claude', 'ci'] as const

export function hookCommand(): Command {
  return new Command('hook')
    .description('Install the merge-boundary gate (now runs: shipguard setup --agent <target>)')
    .option('--target <target>', `Where to install the gate: ${TARGETS.join(' | ')} (default: git)`, 'git')
    .option('--dry-run', 'Show what setup would change without writing')
    .option('--yes', 'Do not ask for confirmation')
    .addHelpText('after', `
\`shipguard hook --target X\` is the 0.12 spelling. It runs \`shipguard setup --agent X\` (same flags: --dry-run, --yes).

Exit codes: setup's own (0 done, 2 config error, 3 environment error).`)
    .action((opts: { target?: string; dryRun?: boolean; yes?: boolean }) => {
      const target = String(opts.target ?? 'git')
      if (!(TARGETS as readonly string[]).includes(target)) {
        logger.error(`Unknown --target "${opts.target}". Choose one of: ${TARGETS.join(', ')}.`)
        process.exitCode = EXIT_CODES.CONFIG_ERROR
        return
      }
      const args = ['setup', '--agent', target, ...(opts.dryRun ? ['--dry-run'] : []), ...(opts.yes ? ['--yes'] : [])]
      logger.info(`\`shipguard hook --target ${target}\` now runs: shipguard ${args.join(' ')}`)
      // Same entry point, same flags, our own stdio: the user sees setup's own preview and questions.
      const child = spawnSync(process.execPath, [process.argv[1], ...args], { stdio: 'inherit' })
      if (child.error) {
        logger.error(`Could not run shipguard setup: ${child.error.message}`)
        process.exitCode = EXIT_CODES.RUNTIME_ERROR
        return
      }
      process.exitCode = child.status ?? EXIT_CODES.RUNTIME_ERROR
    })
}
