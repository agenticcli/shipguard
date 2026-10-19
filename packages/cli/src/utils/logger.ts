import chalk from 'chalk'

// ---------------------------------------------------------------------------
// Logger — ALL output goes to STDERR.
//
// Rationale (Unix convention + agent-first design): the logger only ever emits
// human-readable status, warnings, and decoration — never machine data. The
// machine payload (--json / --sarif) is written separately via
// console.log(JSON.stringify(...)) in commands/scan.ts and MUST be the ONLY
// thing on stdout so `scan … --json | jq .` parses cleanly.
//
// Before this fix, logger.warn/info/success/finding/score/divider used
// console.log (stdout). When `--pro` degraded, logger.warn('Pro rules
// unavailable…') printed to stdout and corrupted the JSON document. Routing
// every logger method to stderr (console.error) keeps stdout pure.
//
// The rich human report in default (non-machine) mode is printed in scan.ts via
// console.log directly — that is intentional and correct (stdout is the report
// channel in human mode), and is unaffected by this logger change.
// ---------------------------------------------------------------------------

export const logger = {
  info: (msg: string) => console.error(chalk.blue('ℹ'), msg),
  success: (msg: string) => console.error(chalk.green('✓'), msg),
  warn: (msg: string) => console.error(chalk.yellow('⚠'), msg),
  error: (msg: string) => console.error(chalk.red('✗'), msg),

  // Diagnostics that are true and worth being able to inspect, but too detailed for a
  // normal run — e.g. "this legacy finding was superseded by a governed corpus rule on
  // the same line". Deliberately NOT a silent drop: the information is always produced
  // and one env var makes it visible. Stderr only, like every other logger method.
  debug: (msg: string) => {
    if (process.env.SHIPGUARD_DEBUG) console.error(chalk.gray('·'), msg)
  },

  finding: (severity: string, msg: string) => {
    const colors: Record<string, (s: string) => string> = {
      critical: chalk.bgRed.white,
      high: chalk.red,
      medium: chalk.yellow,
      low: chalk.blue,
      info: chalk.gray,
    }
    const colorFn = colors[severity] || chalk.white
    const label = severity.toUpperCase().padEnd(8)
    console.error(`  ${colorFn(label)} ${msg}`)
  },

  score: (score: number, recommendation: string) => {
    const color = score <= 20 ? chalk.green : score <= 50 ? chalk.yellow : chalk.red
    const icon = score <= 20 ? '✓' : score <= 50 ? '⚠' : '✗'
    console.error('')
    console.error(chalk.bold('ShipGuard Scan Result'))
    console.error(`Risk Score: ${color(`${score}/100`)}`)
    console.error(`Status: ${color(`${icon} ${recommendation.replace(/_/g, ' ')}`)}`)
  },

  divider: () => console.error(chalk.gray('─'.repeat(50))),
}
