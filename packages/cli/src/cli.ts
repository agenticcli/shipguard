#!/usr/bin/env node
import { Command, CommanderError } from 'commander'
import { goLink } from './core/links.js'
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
import { quickstartHelp } from './core/render.js'
import { CLI_VERSION, sendLifecycleEvent, setGateKind } from './core/telemetry.js'
import { announceSafeMode } from './core/telemetry-config.js'
import { installStreamErrorHandlers, exitWhenDrained, emitError } from './utils/exit.js'
import { buildErrorEnvelope, CORE_LINE } from './core/outcome.js'
import { NEW_COMMAND_NAMES } from './core/command-names.js'
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

// A reader that closes the pipe early (`| head -c 100`) raises EPIPE on stdout/stderr. Install the
// stream error handlers NOW, before any output and before parseAsync (the JSON is written and then
// the scan still awaits telemetry), so EPIPE never reaches handleUncaughtException (exit 3) and the
// scan's computed exit code is kept. See utils/exit.ts.
installStreamErrorHandlers()

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
  .description(`${CORE_LINE}. The security scanner your coding agent runs before every commit.`)
  .version(
    typeof __SHIPGUARD_VERSION__ !== 'undefined'
      ? __SHIPGUARD_VERSION__
      : (process.env.npm_package_version ?? '0.0.0-dev')
  )
  // Override default help to show branded quickstart screen
  .helpCommand(false)  // suppress built-in help subcommand; we add our own
  .addHelpText('after', `
Exit codes:
  0  scan completed (not "safe": read the verdict; the JSON \`verdict.value\` field has it)
  1  blocked only with --strict (a blocking finding, an unfinished scan, or DO_NOT_SHIP)
  2  config error (bad flags, bad policy file, not a project folder)
  3  runtime error (the scan could not run, or --pro could not fetch its rules)

Learn more:
  Docs     ${goLink('docs')}
  Site     ${goLink('site')}
  Pricing  ${goLink('pricing')}
  Issues   ${ISSUES_URL}`)

// First command on an install: one `cli_first_run` event (opt-outs, CI and dev-build rules live in
// sendLifecycleEvent; it never throws and is bounded). Skipped for `telemetry` so a user can opt out first.
// Safe mode (spec 06): the global flag is registered here so commander accepts it; the decision itself lives in
// core/telemetry-config.ts (isSafeMode, W0 PR #39). announceSafeMode prints SAFE_MODE_LINE as the FIRST stderr line.
program.option('--safe-mode', 'No usage pings and no writes outside the project except the sign-in token')
program.hook('preAction', () => {
  announceSafeMode()
})
program.hook('preAction', () => {
  // Which gate runs this process (W0 ping field). Only the three known values count; the setter ignores
  // anything else, so the kind stays "none".
  const kind = process.env.SHIPGUARD_GATE_KIND
  if (kind) setGateKind(kind)
})
program.hook('preAction', async (_thisCommand, actionCommand) => {
  // `gate` (also `gate --supports`) makes zero network calls: no first-run ping.
  if (actionCommand.name() === 'gate') return
  if (actionCommand.name() === 'telemetry' || actionCommand.parent?.name() === 'telemetry') return
  await sendLifecycleEvent('cli_first_run', { cliVersion: CLI_VERSION }, { projectDir: process.cwd() })
})

// Use exitOverride so that Commander errors throw instead of calling process.exit.
// This lets us intercept unknown-command errors and emit a friendly message with
// exit code 2 (config/usage error) rather than silently exiting 0.
program.exitOverride()
// Commander's own error line is replaced by the one error template (see the catch below): exactly one message.
program.configureOutput({ outputError: () => {} })

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
  cmd.configureOutput({ outputError: () => {} })
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

// The commands of 0.13. The six in NEW_COMMAND_NAMES (core/command-names.ts, one list for every stream) are
// registered by their own streams; a name here without a registered command answers UNKNOWN_COMMAND until then.
const ALL_COMMAND_NAMES: readonly string[] = [
  'scan', 'init', 'login', 'logout', 'history', 'hook', 'schema', 'feedback', 'rate', 'telemetry', 'help',
  ...NEW_COMMAND_NAMES,
]

/** The one UNKNOWN_COMMAND / UNKNOWN_OPTION exit: template on stderr, envelope on stdout with --json, exit 2. */
function failUsage(code: 'UNKNOWN_COMMAND' | 'UNKNOWN_OPTION', message: string, fixHint?: string): void {
  const optionHelp = `shipguard ${process.argv.slice(2).find((a) => !a.startsWith('-')) ?? ''} --help`.replace('  ', ' ')
  const env = buildErrorEnvelope({
    code,
    message,
    cliVersion: CLI_VERSION,
    ...(code === 'UNKNOWN_OPTION'
      ? { fix: `See the options with: ${optionHelp}`, command: optionHelp, extra: { argument: /'(--?[\w-]+)/.exec(message)?.[1] } }
      : fixHint ? { fix: fixHint } : {}),
  })
  emitError(env, { machine: process.argv.includes('--json') || process.argv.includes('--sarif') })
}

function closestCommand(input: string): string | undefined {
  const names = [...ALL_COMMAND_NAMES]
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
  const KNOWN_COMMANDS = new Set(ALL_COMMAND_NAMES)
  const firstNonFlag = process.argv.slice(2).find(a => !a.startsWith('-'))

  if (firstNonFlag && firstNonFlag !== '?' && !KNOWN_COMMANDS.has(firstNonFlag)) {
    const suggestion = closestCommand(firstNonFlag)
    failUsage(
      'UNKNOWN_COMMAND',
      `shipguard has no command "${firstNonFlag}".`,
      suggestion ? `Did you mean \`shipguard ${suggestion}\`? See all commands: shipguard help` : undefined,
    )
    process.exit(2)
  }

  try {
    await program.parseAsync(process.argv)
    // A command may have only SET process.exitCode (it never calls process.exit with output queued).
    // Exit now, once stdout and stderr are drained, so a late open handle cannot hold the run open.
    exitWhenDrained()
  } catch (err) {
    if (err instanceof CommanderError) {
      // Unknown command: code is 'commander.unknownCommand'
      if (err.code === 'commander.unknownCommand') {
        const unknownToken = process.argv.slice(2).find(a => !a.startsWith('-')) ?? '?'
        const suggestion = closestCommand(unknownToken)
        failUsage(
          'UNKNOWN_COMMAND',
          `shipguard has no command "${unknownToken}".`,
          suggestion ? `Did you mean \`shipguard ${suggestion}\`? See all commands: shipguard help` : undefined,
        )
        process.exit(2)
      }
      // Commander handled the event cleanly (--version, --help displayed) → exit 0
      if (err.exitCode === 0) {
        process.exit(0)
      }
      // Other Commander errors (unknown option, missing arg, bad value) → UNKNOWN_OPTION, exit 2
      failUsage('UNKNOWN_OPTION', err.message.replace(/^error:\s*/i, '').replace(/^./, (c) => c.toLowerCase()))
      process.exit(2)
    }
    // Non-Commander errors propagate to the uncaughtException handler
    throw err
  }
})()
