#!/usr/bin/env node
import { Command, CommanderError } from 'commander'
import { initCommand } from './commands/init.js'
import { scanCommand } from './commands/scan.js'
import { loginCommand } from './commands/login.js'
import { logoutCommand } from './commands/logout.js'
import { statusCommand } from './commands/status.js'
import { historyCommand } from './commands/history.js'
import { hookCommand } from './commands/hook.js'
import { schemaCommand } from './commands/schema.js'
import { feedbackCommand, rateCommand } from './commands/feedback.js'
import { telemetryCommand } from './commands/telemetry.js'
import { sendLifecycleEvent } from './core/telemetry-events.js'
import { logger } from './utils/logger.js'
import { quickstartHelp } from './core/render.js'
import {
  handleUncaughtException,
  handleUnhandledRejection,
  handleSignal,
} from './handlers.js'

// Re-export handlers so tests that import cli.ts can reach them without
// triggering program.parseAsync. (The preferred import path is './handlers.js'.)
export { handleUncaughtException, handleUnhandledRejection, handleSignal }

// ---------------------------------------------------------------------------
// Register global error handlers — must run before program.parseAsync.
//
// NOTE: A true heap-OOM is not catchable; it is PREVENTED by the per-file size
// cap in utils/fs.ts. These handlers cover all other uncaught errors.
// ---------------------------------------------------------------------------

process.on('uncaughtException', handleUncaughtException)
process.on('unhandledRejection', handleUnhandledRejection)
process.on('SIGINT', handleSignal)
process.on('SIGTERM', handleSignal)

// ---------------------------------------------------------------------------
// Program setup
// ---------------------------------------------------------------------------

// __SHIPGUARD_VERSION__ is injected by tsup `define` from package.json at build
// time. At runtime in vitest (no tsup define), the identifier is undeclared —
// but `typeof` is ReferenceError-safe and returns 'undefined', so we fall back
// to npm_package_version or a dev sentinel. This ensures a single source of
// truth (package.json) and never crashes in tests.
declare const __SHIPGUARD_VERSION__: string | undefined

const ISSUES_URL = 'https://github.com/agenticcli/shipguard/issues'

const program = new Command()

// Intercept `?` before Commander sees it — `?` is not a valid command name token
// in Commander, so we normalise it to `help` here.
const rawArgs = process.argv.slice(2)
if (rawArgs[0] === '?') {
  process.argv = [process.argv[0], process.argv[1], 'help']
}

program
  .name('shipguard')
  .description('CLI-first release gate for AI-built apps')
  .version(
    typeof __SHIPGUARD_VERSION__ !== 'undefined'
      ? __SHIPGUARD_VERSION__
      : (process.env.npm_package_version ?? '0.0.0-dev')
  )
  // Override default help to show branded quickstart screen
  .helpCommand(false)  // suppress built-in help subcommand; we add our own
  .addHelpText('after', `
Learn more:
  Docs     https://agenticcli.dev/docs
  Site     https://agenticcli.dev
  Pricing  https://agenticcli.dev/pricing
  Issues   ${ISSUES_URL}`)

// Use exitOverride so that Commander errors throw instead of calling process.exit.
// This lets us intercept unknown-command errors and emit a friendly message with
// exit code 2 (config/usage error) rather than silently exiting 0.
program.exitOverride()

// Attach a subcommand AND propagate exitOverride to it.
//
// RCA: exitOverride() on the ROOT program is NOT inherited by child Command
// objects. So on `shipguard scan --badopt`, the `scan` subcommand handled the
// unknown-option error itself via Commander's default action — calling
// process.exit(1) (BLOCKED) BEFORE the error could propagate to the root catch
// that maps Commander errors to exit 2 (CONFIG_ERROR). Result: usage typos on
// subcommands exited 1 instead of 2, silently miscoded as "blocked" for any CI
// keying on the exit-code contract.
//
// Fix: call .exitOverride() on every subcommand too, so an unknown option throws
// a CommanderError (code 'commander.unknownOption') that bubbles to the root
// parseAsync catch and is mapped to exit 2. The root's own exitOverride still
// covers root-level option errors. Applied via this helper so a future-added
// subcommand can never silently regress (a subcommand without exitOverride would
// reintroduce the exit-1 bug).
function addSubcommand(cmd: ReturnType<typeof scanCommand>): void {
  cmd.exitOverride()
  program.addCommand(cmd)
}

addSubcommand(initCommand())
addSubcommand(scanCommand())
addSubcommand(loginCommand())
addSubcommand(logoutCommand())
addSubcommand(statusCommand())
addSubcommand(historyCommand())
addSubcommand(hookCommand())
addSubcommand(schemaCommand())
addSubcommand(feedbackCommand())
addSubcommand(rateCommand())
addSubcommand(telemetryCommand())

// ---------------------------------------------------------------------------
// First-run event: ONE anonymous `cli_first_run` per install id, sent before the first real command
// runs (bounded <= 1.5 s, never rejects, never changes the command's output or exit code).
// Not for `telemetry ...` (a user inspecting or opting out must not trigger a send), the root
// quickstart screen, or `help`; --help/--version exit before any action hook. All opt-outs, the
// debug print-only mode and the once-only marker live in core/telemetry-events.ts.
// ---------------------------------------------------------------------------
program.hook('preAction', async (_thisCommand, actionCommand) => {
  try {
    if (actionCommand === program || actionCommand.name() === 'help') return
    for (let c: Command | null = actionCommand; c; c = c.parent) {
      if (c.name() === 'telemetry') return
    }
    await sendLifecycleEvent(
      'cli_first_run',
      {
        cliVersion:
          typeof __SHIPGUARD_VERSION__ !== 'undefined'
            ? __SHIPGUARD_VERSION__
            : (process.env.npm_package_version ?? '0.0.0-dev'),
      },
      { projectDir: process.cwd() },
    )
  } catch (err) {
    logger.debug(`telemetry: first-run event skipped (ignored): ${err instanceof Error ? err.message : String(err)}`)
  }
})

// ---------------------------------------------------------------------------
// `help` / `?` subcommand — branded quickstart screen
// ---------------------------------------------------------------------------
program.addCommand(
  new Command('help')
    .description('Show the quickstart guide')
    .action(() => {
      const isTTY = Boolean(process.stdout.isTTY)
      process.stdout.write(quickstartHelp(isTTY) + '\n')
    })
)

// ---------------------------------------------------------------------------
// Bare invocation (no subcommand) → branded quickstart screen
// Allow excess arguments so unknown commands don't get swallowed as "too many args".
// We detect unrecognised tokens in the IIFE below and route them to the friendly
// unknown-command handler.
// ---------------------------------------------------------------------------
program.allowExcessArguments(true)
program.action(() => {
  const isTTY = Boolean(process.stdout.isTTY)
  process.stdout.write(quickstartHelp(isTTY) + '\n')
})

// ---------------------------------------------------------------------------
// Levenshtein distance — for closest-command suggestion
// ---------------------------------------------------------------------------
function levenshtein(a: string, b: string): number {
  const m = a.length
  const n = b.length
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  )
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    }
  }
  return dp[m][n]
}

function closestCommand(input: string): string | undefined {
  const names = ['scan', 'init', 'login', 'logout', 'status', 'history', 'hook', 'schema', 'feedback', 'rate', 'telemetry', 'help']
  let best: string | undefined
  let bestDist = Infinity
  for (const name of names) {
    const d = levenshtein(input.toLowerCase(), name)
    if (d < bestDist) {
      bestDist = d
      best = name
    }
  }
  // Only suggest if reasonably close (within 3 edits)
  return bestDist <= 3 ? best : undefined
}

// ---------------------------------------------------------------------------
// Parse — catch Commander errors for unknown commands / options
// ---------------------------------------------------------------------------
;(async () => {
  // Pre-parse check: if first non-flag token is not a known command name
  // and is not a flag, it's an unknown command — intercept before Commander
  // so we can emit a friendly message and exit 2 cleanly.
  const KNOWN_COMMANDS = new Set(['scan', 'init', 'login', 'logout', 'status', 'history', 'hook', 'schema', 'feedback', 'rate', 'telemetry', 'help'])
  const firstNonFlag = process.argv.slice(2).find(a => !a.startsWith('-'))

  if (firstNonFlag && firstNonFlag !== '?' && !KNOWN_COMMANDS.has(firstNonFlag)) {
    const suggestion = closestCommand(firstNonFlag)
    const hint = suggestion ? `\n  Did you mean \`shipguard ${suggestion}\`?` : ''
    process.stderr.write(
      `shipguard: unknown command "${firstNonFlag}"${hint}\n` +
      `  Run \`shipguard help\` to see available commands.\n`
    )
    process.exit(2)
  }

  try {
    await program.parseAsync(process.argv)
  } catch (err) {
    if (err instanceof CommanderError) {
      // Unknown command: code is 'commander.unknownCommand'
      if (err.code === 'commander.unknownCommand') {
        const unknownToken = process.argv.slice(2).find(a => !a.startsWith('-')) ?? '?'
        const suggestion = closestCommand(unknownToken)
        const hint = suggestion ? `\n  Did you mean \`shipguard ${suggestion}\`?` : ''
        process.stderr.write(
          `shipguard: unknown command "${unknownToken}"${hint}\n` +
          `  Run \`shipguard help\` to see available commands.\n`
        )
        process.exit(2)
      }
      // Commander handled the event cleanly (--version, --help displayed) → exit 0
      if (err.exitCode === 0) {
        process.exit(0)
      }
      // Other Commander errors (unknown option, missing arg, etc.) → exit 2
      process.stderr.write(`shipguard: ${err.message}\n`)
      process.exit(2)
    }
    // Non-Commander errors propagate to the uncaughtException handler
    throw err
  }
})()
