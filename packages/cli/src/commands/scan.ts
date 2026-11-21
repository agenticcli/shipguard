import { Command, Option } from 'commander'
import { existsSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { scan } from '../core/scanner.js'
import { generateReport } from '../core/report.js'
import { toSarif } from '../core/sarif.js'
import { loadPolicy } from '../core/policy.js'
import { isGitRepo } from '../core/git.js'
import { logger } from '../utils/logger.js'
import { goLink } from '../core/links.js'
import {
  renderScanScreen,
  renderQuietLine,
  generalRuleCountOrNull,
  welcomeBanner,
  shouldShowProgress,
  renderProgressBar,
} from '../core/render.js'
import type { RulesRan } from '../core/render.js'
import { collectNotScanned } from '../core/not-scanned.js'
import { probeGate, detectNextAgent, detectManifest } from '../core/screen-context.js'
import { runRulebookStep, readPublicOffer } from '../core/rulebook-step.js'
import type { RulebookStepResult, StepError } from '../core/rulebook-step.js'
import { getPlanEnv, isHookOrGate, loadNagFor, nagCtx, repoIdOf } from '../core/plan-client.js'
import { repoKey, markMoment, momentDue, isMuted } from '../core/nag.js'
import { maybeFetchWeeklyOffer } from '../core/offer-cache.js'
import { computeReceipt, receiptLines, screenPitch, usageNoticeLines, updateNoticeLines } from '../core/plan-lines.js'
import { unavailableBlock } from '../core/plan.js'
import { reportPathsFor } from '../core/report.js'
import type { DetectedStack, Receipt } from '../core/plan-lines.js'
import { parseMaskedSecret } from '../core/redact.js'

import { EXIT_CODES, DEFAULT_REPORT_FILE } from '@agenticcli/shared'
import type { ScanOptions, QualityGateRule, DegradeReason, Recommendation, Finding } from '@agenticcli/shared'
import { recordScanHistory, resolveScanId } from '../core/history/index.js'
import { gateReuseFromEnv } from '../core/history/scan-id.js'
import { gateHealthWarnings, healthWarningLine } from '../core/gate-state.js'
import { applyVerdict, effectiveRecommendation } from '../core/verdict.js'
import type { FrameworkEntry } from '../core/framework.js'
import { sendTelemetry, telemetryState } from '../core/telemetry.js'
import { isSafeMode } from '../core/telemetry-config.js'
import { emitError, setExitCode } from '../utils/exit.js'
import {
  CORE_LINE, SCHEMA_VERSION, buildErrorEnvelope, buildScanEnvelope, buildVerdictJson, buildPlanJson,
  buildNextSteps, buildCoverageJson, buildDegradedReasons, buildNotScanned, decideAgentAction, blockingOccurrences,
  computeSinceLastRun, readLastRun, writeLastRun, maxRepeatRuns, REPEAT_LABELS, stackDisplayName,
} from '../core/outcome.js'
import type { ErrorCode, ExtraErrorFields, SinceLastRun } from '../core/outcome.js'
import { buildRerunCommand } from '../core/rerun.js'
import { loadBundledRules } from '../core/bundled-rules.js'
import type { TelemetryOutput, TelemetryVerdict } from '../core/telemetry.js'
// Type-only import — deliberately NOT a value import. pro-scanner.ts (re2js, matcher-contract,
// coderef-dispatch, etc.) is dynamically imported ONLY inside the `if (opts.pro)` branch below to
// keep non-pro scans fast; a value import here would force it to load eagerly on every scan.
import type { ProFetchErrorCode } from '../core/pro-scanner.js'
import { PRO_RULES_UNAVAILABLE_MESSAGE } from '../core/platform-status.js'

const LEARN_MORE = `Docs ${goLink('docs')} · Site ${goLink('site')} · Pricing ${goLink('pricing')} · Issues https://github.com/agenticcli/shipguard/issues`

// __SHIPGUARD_VERSION__ is injected by tsup `define` from package.json at build
// time — the SAME single source cli.ts uses for program.version(). At runtime in
// vitest (no tsup define) the identifier is undeclared, but `typeof` is
// ReferenceError-safe, so we fall back to npm_package_version / a dev sentinel.
// This kills the telemetry version-drift class: the
// hardcoded '0.1.2' literal is gone; the version can only ever be package.json.
declare const __SHIPGUARD_VERSION__: string | undefined

const CLI_VERSION =
  typeof __SHIPGUARD_VERSION__ !== 'undefined'
    ? __SHIPGUARD_VERSION__
    : (process.env.npm_package_version ?? '0.0.0-dev')

/**
 * Resolve the process exit code from scan outcome.
 *
 * Contract:
 * exit code is VERDICT-NEUTRAL by default. ShipGuard *informs*; the caller
 * chooses soft vs hard gating. The verdict always lives in the JSON
 * `recommendation` field (and `degraded`/`degradedReasons` for partial scans)
 * — never inferred from the exit code alone.
 *
 *   0 — scan COMPLETED. Verdict is in the JSON `recommendation` field.
 *       Returned even when findings are blocking, and even when the scan is
 *       degraded/partial (e.g. a pro-rules fetch failure or an oversized file
 *       was skipped) — degradation is surfaced via `degraded`/`degradedReasons`
 *       in the JSON output, not by hijacking a different exit code.
 *   1 — BLOCKED. Opt-in hard gates, nothing else moves the exit code off the
 *       default 0: --strict (a blocking finding, an unfinished/degraded scan, or
 *       a DO_NOT_SHIP verdict) and --check-regressions (a previously-passing rule
 *       now fails). Everything else is informational.
 *   2 — CONFIG ERROR, strictly. Malformed policy file, unknown CLI option,
 *       non-project directory without --all, etc. Never reused for a
 *       degraded-but-completed scan (that is exit 0 + `degraded:true` in JSON).
 *   3 — RUNTIME ERROR. The scan could not meaningfully run at all (e.g. a
 *       NO_RULES_APPLIED fail-closed 422 — zero rules were applied, so there
 *       is no verdict to report) or threw unexpectedly. Distinct from a
 *       partial/degraded-but-completed scan, which is exit 0 (see above).
 *
 *       AMENDMENT (explicit-Pro-failure path ONLY): when `--pro` was explicitly requested
 *       and the rule fetch fails (auth/credits/rate-limit/server/bundle
 *       see ProFetchErrorCode), this is now ALSO exit 3 by default, with a
 *       structured JSON error (`code`, `error`, `degraded:false`, `action`).
 *       Previously every one of these failure classes was silently collapsed
 *       into `degraded:true` + exit 0 — a false-green for a caller that asked
 *       for the pro gate and did not get it. `--allow-degraded` restores the
 *       old fallback (free scan, `degraded:true`, exit unaffected). This does
 *       NOT touch verdict-neutrality for anything else: a completed scan's
 *       exit code is still governed only by --strict + blockingCount below.
 *
 * Precedence: --strict (exit 1) is the ONLY thing that overrides the default
 * exit 0 for a COMPLETED scan. Config errors (2) and runtime errors (3,
 * including the explicit-Pro-failure amendment above) are resolved elsewhere in
 * scan.ts, before a ScanResult even exists.
 *
 * AMENDMENT:
 * `--strict` also blocks on a DEGRADED scan, not only on blocking findings.
 *
 *   Verbatim: "Regression test: `--strict` on the maxfiles fixture must exit 1
 *              — highest-stakes untested combination; `--strict` is now the
 *              product's only hard stop."
 *
 * WHY: `--strict` is the one switch able to stop a
 * ship, and the hook feature installs exactly that invocation at
 * the merge boundary. Before this, a scan that truncated at the file cap, lost
 * its Pro rules, or could not read a file exited 0 under `--strict` whenever the
 * files it DID manage to read happened to be clean — so the product's only hard
 * stop inherited the same false-safe #1 removed from the report. A hard stop that
 * passes on an unfinished scan is not a hard stop.
 *
 * This does NOT touch passivity: without `--strict` a degraded scan still exits
 * 0 (verified by tests/commands/scan-verdict-failclosed.test.ts).
 *
 * AMENDMENT: `--strict` also blocks when
 * the EFFECTIVE recommendation (verdict.ts `effectiveRecommendation`) is
 * `DO_NOT_SHIP`, not only when `blockingCount > 0` or `degraded === true`.
 *
 * ORIGINAL ROOT CAUSE: `computeRiskScore()` used to sum severity weight for every finding,
 * including ones marked `suppressed:true`, so a scan whose only findings were suppressed
 * could print DO_NOT_SHIP with `blockingCount` 0 while `--strict` (keyed on
 * `blockingCount`/`degraded` alone) exited 0. Every installed hook
 * (`shipguard scan --json --strict`, `core/hook-templates.ts`) inherited that.
 *
 * DESIGN DECISION (supersedes the earlier "should suppressed findings score at
 * all" open question): suppressed findings - a `shipguard-ignore` comment OR a rule's own
 * antiPattern exemption - no longer count toward the risk score, severity counts or verdict
 * (core/risk-score.ts), matching suppression.ts ("cannot fail a gate"). They stay in
 * `findings[]` with `suppressed: true` and in `riskScore.totalFindings`. The invariant this
 * function protects is unchanged: the exit code and the printed verdict never disagree, so
 * the `recommendation` OR term stays (a DO_NOT_SHIP reached by ACTIVE findings still blocks).
 *
 * This still does not widen `--strict` beyond "the printed verdict/degraded state
 * and the exit code must agree" — it does not touch `blockingCount`/`degraded`
 * blocking (both are kept, unchanged, as an OR term: this only ADDS a new blocking
 * condition, it never removes one), and it does not change what gets PRINTED.
 */
export function resolveExitCode(opts: {
  strict: boolean
  blockingCount: number
  /**
   * true when any part of the scan did not run (see ScanResult.degraded).
   * Under --strict this blocks on its own — an unfinished scan cannot clear a gate.
   */
  degraded?: boolean
  /**
   * The EFFECTIVE recommendation (verdict.ts `effectiveRecommendation()`) — the
   * exact value the human panel / --json `recommendation` field prints. Under
   * --strict, DO_NOT_SHIP blocks on its own, even when every contributing finding
   * is suppressed (blockingCount 0) — see the CLI-2/J-3 amendment above. Optional
   * so existing callers/tests that only care about blockingCount/degraded keep
   * working unchanged.
   */
  recommendation?: Recommendation
}): number {
  if (
    opts.strict &&
    (opts.blockingCount > 0 || opts.degraded === true || opts.recommendation === 'DO_NOT_SHIP')
  ) {
    return EXIT_CODES.BLOCKED
  }
  return EXIT_CODES.SAFE
}

/**
 * Human-readable "what the caller can do" hint per Pro-fetch failure class.
 * Surfaced both in the human-mode logger.error output and the --json `action`
 * field .
 */
export function proFetchActionHint(code: ProFetchErrorCode, retryAfterSeconds?: number): string {
  switch (code) {
    case 'AUTH_FAILED':
      return 'Run `shipguard login` to re-authenticate, or pass --allow-degraded to run local rules only.'
    case 'INSUFFICIENT_CREDITS':
    case 'ALLOWANCE_USED':
    case 'PLAN_INACTIVE':
      return `The server did not provide the rulebook for this scan. Run \`shipguard upgrade\` for details, or pass --allow-degraded to run general rules only.`
    case 'RATE_LIMITED':
      return retryAfterSeconds !== undefined
        ? `Rate limited — retry after ${retryAfterSeconds}s, or pass --allow-degraded to run local rules only.`
        : 'Rate limited — wait and retry, or pass --allow-degraded to run local rules only.'
    case 'SERVER_ERROR':
      return 'This looks like a transient server/network issue — retry the scan, or pass --allow-degraded to run local rules only.'
    case 'PLATFORM_UNAVAILABLE':
      return platformUnavailableMessage(retryAfterSeconds)
    case 'FRESHNESS_EXPIRED':
      return PRO_RULES_UNAVAILABLE_MESSAGE
    case 'BUNDLE_INVALID':
      return 'The rulebook download failed validation (server-side issue) — retry, or pass --allow-degraded to run local rules only. If this persists, contact support.'
    case 'NO_ACTIVE_RELEASE':
      return 'The rulebook server has no active rule release yet — this is a server-side configuration gap, not something a retry or re-login will fix. Check ' + goLink('docs') + ' or contact support, or pass --allow-degraded to run local rules only in the meantime.'
    default:
      return 'Retry the scan, or pass --allow-degraded to run local rules only.'
  }
}

/**
 * Turns a wait in seconds into plain words for the human message: 300 -> "5 min", 90 -> "90 s".
 * (platform-unavailable-20261018)
 */
function formatSuggestedWait(seconds: number): string {
  return seconds >= 60 && seconds % 60 === 0 ? `${seconds / 60} min` : `${seconds} s`
}

/**
 * The calm, plain-English message for the PLATFORM_UNAVAILABLE failure class: the hosted service
 * is temporarily down on OUR side (plan limits / disabled deployment), not the user's project.
 * Shared by the human-mode error line and the --json `action` field. (platform-unavailable-20261018)
 */
function platformUnavailableMessage(retryAfterSeconds?: number): string {
  const wait = retryAfterSeconds !== undefined ? ` (suggested wait: ${formatSuggestedWait(retryAfterSeconds)})` : ''
  return `ShipGuard's service is temporarily unavailable. This is on our side, not a problem with your project. ` +
    `Please try again in a few minutes${wait}, or pass --allow-degraded to run local rules only.`
}

/**
 * The one sentence that says what exit 0 means when the scan found something blocking and `--strict`
 * was not passed. Printed as the last line of human output and returned as `exitMeaning` in --json.
 */
export const EXIT_NOTICE = 'exit 0 = scan finished, not safe. Add --strict to fail on blocking findings.'

/** `exitMeaning` for --json: what THIS run's exit code means, in one sentence. */
export function exitMeaning(opts: { exitCode: number; strict: boolean; notSafe: boolean; regressionBlocks: boolean }): string {
  if (opts.exitCode === EXIT_CODES.BLOCKED) {
    return opts.regressionBlocks
      ? 'exit 1 = blocked: --check-regressions found a rule that passed before and now fails.'
      : 'exit 1 = blocked: --strict found a blocking finding, a scan that did not finish, or a DO_NOT_SHIP verdict.'
  }
  if (opts.strict) return 'exit 0 = scan finished and --strict found nothing that blocks.'
  if (opts.notSafe) return EXIT_NOTICE
  return 'exit 0 = scan finished. Read recommendation for the verdict; add --strict to fail on blocking findings.'
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const

/**
 * Determine if a directory is a project root.
 * A project root has a package.json or a .git directory.
 */
function isProjectRoot(dir: string): boolean {
  return existsSync(join(dir, 'package.json')) || existsSync(join(dir, '.git'))
}

export function scanCommand(): Command {
  return new Command('scan')
    .description(`${CORE_LINE}. Scan your project for high-risk issues (use --quiet for a one-line verdict)`)
    .argument('[path]', 'Path to project root to scan (defaults to current directory)')
    .option('--changed', 'Only scan changed files from git diff')
    .option('--report', 'Generate a detailed Markdown report')
    .option('--strict', 'Opt-in hard gate: exit 1 if blocking findings exist, the scan did not finish, OR the verdict is DO_NOT_SHIP (default exit is 0 — verdict is informational, read the JSON `recommendation`)')
    .option('--json', 'Output results as JSON (machine-readable; suppresses all decoration)')
    .option('--sarif', 'Output results as SARIF 2.1.0 (for GitHub Code Scanning)')
    .option('-q, --quiet', 'One-line verdict only (suppresses progress, panel, and tips)')
    .option('--pro', 'Require the full rulebook; exit 3 if it is not used (signed out, unreachable, partial, withheld by the server, plan inactive). A plain scan uses the rulebook when it is served and otherwise runs general rules and says so; its exit code does not change. At the monthly limit, when the server says so in a signed reply, a plain scan and --pro both run general rules and the exit code does not change.')
    .option('--general', 'Run the general rules only (no rulebook request)')
    .option('--api-url <url>', 'API server URL', 'https://agenticcli.dev')
    .option('--category <categories>', 'Comma-separated category filter for rulebook rules')
    .option('--beta', 'Include beta-stage rules')
    .option('--all', 'Scan any directory, even without package.json or .git')
    .option('--allow-degraded', 'With --pro: fall back to local-only rules if the rulebook download fails, instead of failing loud (opt-in; restores the pre-2026-07-14 fallback behavior — see exit code 3 below)')
    .option('--check-regressions', 'Opt-in hard gate: exit 1 if a previously-passing blocking rule now fails under the same scan scope + rulebook release (informational-only in --json unless this flag is set)')
    .addHelpText('after', `
Output modes:
  (default)         Verbose: live progress (TTY), categorized findings, gamified verdict panel
  --quiet / -q      One-line verdict + exit code only — ideal for scripts
  --json            Machine-readable JSON to stdout; all decoration suppressed
  --sarif           SARIF 2.1.0 to stdout (GitHub Code Scanning)

Auto-quiet: progress animations are suppressed in non-TTY (piped/CI) environments automatically.

Examples:
  shipguard scan                  Scan current project (rich output)
  shipguard scan --quiet          One-line verdict only
  shipguard scan ./my-app         Scan a specific directory
  shipguard scan --changed        Scan only git-diff files (faster)
  shipguard scan --json           Machine-readable output for CI/agents
  shipguard scan --pro            Require the full rulebook (needs login; exit 3 if it is not used)
  shipguard scan --general        General rules only, no rulebook request
  shipguard scan --pro --allow-degraded  Fall back to local rules if the rulebook download fails (opt-in)
  shipguard scan --all            Scan any directory regardless of project markers
  shipguard scan --strict         CI hard gate: exit 1 on blocking findings
  shipguard scan --check-regressions  CI hard gate: exit 1 if a previously-passing rule now fails
  shipguard history               Show recent local scan history for this repo

Exit codes (verdict-neutral by default — ShipGuard informs, you choose the gate):
  0  Scan completed. Verdict is in the JSON \`recommendation\` field — this
     is returned EVEN IF findings are blocking, or the scan is degraded/
     partial (see \`degraded\`/\`degradedReasons\` in --json output).
  1  Blocked — with --strict AND at least one of: a blocking finding, a scan
     that did not finish (\`degraded:true\` — an unfinished scan cannot clear
     a hard gate: an oversized file, a symlink, an unreadable file, a truncated
     scan, a file with unexplained binary data, or a scan that read NOTHING), or an effective \`recommendation\` of DO_NOT_SHIP (suppressed
     findings still count toward the risk score, so a scan can cross the
     DO_NOT_SHIP threshold with zero blocking findings — the exit code always
     agrees with the printed verdict). OR with --check-regressions AND at
     least one regression (see \`regressions\` in --json output —
     informational-only unless this flag is set).
  2  Config error (bad policy file, bad flags, non-project directory, scan path
     that does not exist or is not a directory).
  3  Runtime error — the scan could not meaningfully run at all. This
     INCLUDES an explicit --pro request whose rulebook could not be had (sign-in,
     rate limit, server, an invalid bundle, no active release, or the platform
     being temporarily unavailable: --json error.code RULEBOOK_UNREACHABLE, with
     error.retryAfterSeconds when known) — the requested gate did not run, so
     ShipGuard fails loud instead of silently falling back to a free
     scan. Pass --allow-degraded to opt back into the free-scan
     fallback (degraded:true, exit code unaffected).

Local history: every scan is recorded to a local SQLite store
(\`.shipguard/history.db\` by default; override via \`history.path\` in
shipguard.policy.yml or SHIPGUARD_HISTORY_PATH). \`stateStatus\` in --json
reports whether that recording succeeded (complete/unavailable/corrupt) —
a regression is only ever claimed when it's \`complete\` for both runs
being compared. A rulebook or rule update is reported as \`coverageChanged\`,
never as a regression.

${LEARN_MORE}`)
    .action(async (scanPath: string | undefined, opts) => {
      const startTime = Date.now()

      // Resolve scan root: explicit path arg, else cwd
      // Use resolve() not join() so absolute paths work correctly:
      // resolve('/home/user', '/tmp/app') === '/tmp/app'
      // join('/home/user', '/tmp/app') === '/home/user/tmp/app'  ← WRONG
      const cwd = scanPath ? resolve(scanPath) : process.cwd()

      const machineOutput = Boolean(opts.json) || Boolean(opts.sarif)
      const quiet = Boolean(opts.quiet)

      // Explicit path must exist and be a directory BEFORE anything chdir()s into it. Without this
      // guard process.chdir threw ENOENT inside the async action and surfaced as "Unhandled
      // rejection" (exit 3, no telemetry). A bad user-supplied path is a config/usage error
      // (exit 2) - same class as the non-project-directory refusal below - not a runtime failure.
      if (scanPath) {
        const pathProblem = checkScanPath(cwd)
        if (pathProblem) {
          return failWith(
            buildErrorEnvelope({
              code: pathProblem.code,
              message: pathProblem.message,
              cliVersion: CLI_VERSION,
              cause: pathProblem.code === 'PATH_NOT_FOUND' ? `The folder ${cwd} was not found or cannot be read.` : undefined,
              extra: { path: cwd },
            }),
            { startTime, projectDir: process.cwd(), opts },
          )
        }
      }

      // ---------------------------------------------------------------------------
      // A6: Scope guard — refuse to scan a non-project directory unless --all or path given
      // A true heap-OOM is prevented by Part A bounds (size/binary/total caps in readFiles),
      // but scanning an arbitrary filesystem root (e.g. /home or /tmp) is still dangerous
      // and almost certainly unintentional. Require either a project root or --all.
      // ---------------------------------------------------------------------------
      if (!scanPath && !opts.all && !isProjectRoot(cwd)) {
        return failWith(
          buildErrorEnvelope({
            code: 'NOT_A_PROJECT',
            message: `${cwd} does not look like a project (no package.json or .git).`,
            cliVersion: CLI_VERSION,
            cause: 'ShipGuard refuses to scan a folder that is not a project, to avoid scanning your home folder by mistake.',
            fix: 'Pass the path of your project folder (for example ./my-app), or use --all to scan this folder anyway.',
            extra: { path: cwd },
          }),
          { startTime, projectDir: process.cwd(), opts },
        )
      }

      // Change working directory to the resolved scan root so scanner uses it as cwd
      const originalCwd = process.cwd()
      if (scanPath) {
        process.chdir(cwd)
      }

      try {
        await runScan({ cwd, invocationCwd: originalCwd, opts, machineOutput, quiet, startTime })
      } finally {
        if (scanPath) {
          process.chdir(originalCwd)
        }
      }
    })
}

/** The one repeat sentence above `Next:` (spec 04 "Fix loop"): states only what was measured. */
function repeatLineFor(since: SinceLastRun, blockingCount: number): string | null {
  if (blockingCount === 0) return null
  const runs = maxRepeatRuns(since)
  if (runs >= 2) return REPEAT_LABELS.stop
  if (runs === 1) return since.treeChanged === false ? REPEAT_LABELS.unchangedScan : REPEAT_LABELS.changed
  return null
}

/** A rulebook step failure (an explicit --pro that could not get the rulebook, or a zero-rule bundle) as the one error envelope. */
function stepErrorEnvelope(err: StepError, ctx: { scanId: string; planEnv: ReturnType<typeof getPlanEnv> }): ReturnType<typeof buildErrorEnvelope> {
  const code: ErrorCode = err.code
  const calm = err.proErrorCode === 'PLATFORM_UNAVAILABLE' || err.proErrorCode === 'FRESHNESS_EXPIRED'
  const signedOutPro = code === 'LOGIN_REQUIRED' && err.message.startsWith('--pro uses')
  // The pointer to `upgrade` is left off in CI and when promotion is muted (spec 05).
  const pointer = ctx.planEnv.ci || process.env.SHIPGUARD_NO_PROMO === '1' ? '' : '   (what the full rulebook adds for this repo: shipguard upgrade)'
  return buildErrorEnvelope({
    code,
    message:
      code === 'NO_RULES_APPLIED' ? 'This scan applied zero rules, so it checked nothing and cannot report a clean pass.'
      : calm ? proFetchActionHint(err.proErrorCode as ProFetchErrorCode, err.retryAfterSeconds)
      : code === 'TOKEN_EXPIRED' ? `${err.message} Your plan follows your account, so signing in again picks it up.`
      : err.message,
    cliVersion: CLI_VERSION,
    runId: ctx.scanId,
    ...(code === 'NO_RULES_APPLIED' ? { cause: err.message } : {}),
    ...(signedOutPro ? { fix: `shipguard login${pointer}\n  Or run the free scan now: shipguard scan` } : {}),
    ...(code === 'RATE_LIMITED' && err.retryAfterSeconds !== undefined ? { fix: `Retry after ${err.retryAfterSeconds} seconds` } : {}),
    extra: err.retryAfterSeconds !== undefined ? { retryAfterSeconds: err.retryAfterSeconds } : {},
  })
}

const MANIFESTS = ['package.json', 'pyproject.toml', 'requirements.txt', 'go.mod', 'Cargo.toml', 'Gemfile', 'composer.json', 'pom.xml', 'build.gradle']

/** The manifest that made this folder a project (spec 06 "unsupported stack"), or null when none is known. */
function firstManifest(dir: string): string | null {
  return MANIFESTS.find((m) => existsSync(join(dir, m))) ?? null
}

/** Output kind for the usage ping. Same precedence as the output switch below: --sarif, then --json, else human (--quiet is human). */
function outputKind(opts: Record<string, unknown>): TelemetryOutput {
  return opts.sarif ? 'sarif' : opts.json ? 'json' : 'human'
}

/**
 * The ONE exit path for every scan error (config 2 / runtime 3 / 130): the error template on stderr and, with
 * --json/--sarif, the error envelope on stdout (utils/exit.ts emitError); then a single telemetry ping with
 * verdict "error" (all opt-outs honoured inside sendTelemetry; it never rejects), awaited so the hard exit
 * cannot drop it. Callers must `return` it. Keep every error exit going through here - a source-guard test
 * fails on a bare process.exit(CONFIG_ERROR|RUNTIME_ERROR) in this file.
 */
async function failWith(
  env: ReturnType<typeof buildErrorEnvelope>,
  ctx: { startTime: number; projectDir: string; opts: Record<string, unknown>; policy?: unknown },
): Promise<void> {
  emitError(env, {
    machine: Boolean(ctx.opts.json) || Boolean(ctx.opts.sarif),
  })
  try {
    await sendTelemetry(
      { cliVersion: CLI_VERSION, verdict: 'error', durationMs: Date.now() - ctx.startTime, output: outputKind(ctx.opts) },
      { policy: ctx.policy, projectDir: ctx.projectDir },
    )
  } catch (err) {
    // sendTelemetry never rejects; belt and braces so telemetry can never change the exit code.
    logger.debug(`telemetry: error ping skipped (ignored): ${err instanceof Error ? err.message : String(err)}`)
  }
}

/** Why an explicit scan path cannot be scanned, or null when it is an existing directory. */
function checkScanPath(absPath: string): { code: 'PATH_NOT_FOUND' | 'PATH_NOT_A_DIRECTORY'; message: string } | null {
  let isDir: boolean
  try {
    isDir = statSync(absPath).isDirectory()
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      return { code: 'PATH_NOT_FOUND', message: `Scan path does not exist: ${absPath}` }
    }
    return { code: 'PATH_NOT_FOUND', message: `Scan path cannot be read (${code ?? 'unknown error'}): ${absPath}` }
  }
  return isDir ? null : { code: 'PATH_NOT_A_DIRECTORY', message: `Scan path is not a directory: ${absPath}` }
}

async function runScan(ctx: {
  cwd: string
  /** The folder the command was run from (before any chdir): the re-run command is relative to it. */
  invocationCwd: string
  opts: Record<string, unknown>
  machineOutput: boolean
  quiet: boolean
  startTime: number
}) {
  const { cwd, invocationCwd, opts, machineOutput, quiet, startTime } = ctx

  // Load policy for header info and report path resolution
  let policy
  try {
    policy = await loadPolicy(cwd)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const line = /line (\d+)/i.exec(message)
    return failWith(
      buildErrorEnvelope({
        code: 'INVALID_POLICY',
        message: `shipguard.policy.yml could not be read${line ? ` (line ${line[1]})` : ''}.`,
        cliVersion: CLI_VERSION,
        cause: message,
        fix: `Fix shipguard.policy.yml${line ? ` at line ${line[1]}` : ''}, or move the file aside and run shipguard init to make a fresh one.`,
        extra: { file: 'shipguard.policy.yml', ...(line ? { line: Number(line[1]) } : {}) },
      }),
      { startTime, projectDir: cwd, opts },
    )
  }

  // -----------------------------------------------------------------------------------
  // ScanId reuse — resolve THIS scan's scanId, reusing a prior local
  // reservation when one exists for the identical (repo, requested scope, working-tree
  // content) key within the reuse window, instead of always minting a fresh
  // `randomUUID()`. MUST run before the `--pro` rules fetch below (not after, and not only
  // in recordScanHistory at the very end) — that fetch call is exactly what needs the
  // reused id on its Idempotency-Key header for the server-side dedup (scanId idempotency) to close
  // the loop on a WHOLE-PROCESS retry, not just a within-process one. Never throws, never
  // blocks the scan — see history/scan-id.ts.
  // -----------------------------------------------------------------------------------
  const changedOnly = Boolean(opts.changed)
  const categories: string[] = opts.category
    ? (opts.category as string).split(',').map((c: string) => c.trim())
    : []

  // Detect frameworks BEFORE resolveScanId (hoisted up from the `--pro` block below) — the
  // detected set feeds the scanId reuse key. It selects WHICH paid rule bundle the server
  // builds/charges for, so a change in it must mint a fresh scanId; otherwise a retry would
  // reuse the prior scanId and the server would re-deliver the already-paid STALE bundle,
  // and a newly-added framework's Pro rules would never run (false-green on the paid gate).
  // detectFrameworks is a pure local read of package.json (no side effects), so running it
  // here — for both free and pro scans — is safe; the `--pro` block below reuses this result
  // (config auto-generation, which DOES write to disk, stays in that block). A detection
  // failure must never break a scan, so it degrades to `['generic']` (its own no-package.json
  // default) and is logged.
  let detectedFrameworks: FrameworkEntry[] = [{ name: 'generic' }]
  try {
    const { detectFrameworks } = await import('../core/framework.js')
    detectedFrameworks = detectFrameworks(cwd).frameworks
  } catch (err) {
    logger.warn(`Framework detection failed — using 'generic' for the scan scope: ${err instanceof Error ? err.message : err}`)
  }
  const frameworkNames = detectedFrameworks.map((f) => f.name)

  const planEnv = getPlanEnv({ policy, projectDir: cwd })
  const signedInForScanId = planEnv.apiKeyMode || existsSync(join(planEnv.configDir, 'credentials.json'))
  const { scanId, scanIdReused } = await resolveScanId({
    cwd,
    policy,
    cliVersion: CLI_VERSION,
    changedOnly,
    categories,
    // "Rulebook requested" (not just the --pro flag): the key of the reservation behind the server-side
    // dedup. An explicit --pro asks for it, and so does the signed-in default scan (unless --general).
    rulebookRequested: !opts.general && (Boolean(opts.pro) || signedInForScanId),
    frameworks: frameworkNames,
    gate: gateReuseFromEnv(),
  })

  const inGitRepo = isGitRepo(cwd)

  const scanOptions: ScanOptions = {
    changedOnly,
    generateReport: Boolean(opts.report),
    strict: Boolean(opts.strict),
    json: Boolean(opts.json),
    reportPath: policy.report.output ?? DEFAULT_REPORT_FILE,
  }

  // Print header (skip in machine-output and --quiet modes)
  if (!machineOutput && !quiet) {
    logger.divider()
    logger.info(`ShipGuard — scanning ${policy.project.name}`)
    logger.info(`Scan path: ${cwd}`)
    if (scanOptions.changedOnly && inGitRepo) {
      logger.info('Mode: changed files only')
    } else {
      logger.info('Mode: full project scan')
    }
    logger.divider()
  }

  // ---- how this scan gets its rules (spec 02 "One rule for the rulebook did not run") ----
  // One decision for every cause: general rules + what ran, or exit 3 for an explicit --pro. The rulebook is used only
  // when the server serves a verified, attested bundle; the plan block is display data and unlocks nothing.
  const explicitPro = Boolean(opts.pro)
  const stackNames = detectedFrameworks.filter((f) => f.name !== 'generic').map((f) => f.name)
  // The weekly public offer fetch (signed-out terminal scans only; stack names only) runs beside the scan itself.
  const weeklyOffer = !signedInForScanId && !explicitPro && !opts.general
    ? maybeFetchWeeklyOffer(nagCtx(planEnv), {
        signedIn: false, terminal: planEnv.terminal, ci: planEnv.ci, quiet, hookOrGate: isHookOrGate(),
        safeMode: planEnv.safeMode, trackingOff: planEnv.trackingOff, dryRun: false,
      }, stackNames, { apiUrl: opts.apiUrl as string }).catch((err: unknown) => {
        logger.debug(`offer fetch failed (ignored): ${err instanceof Error ? err.message : String(err)}`)
        return { attempted: false } as const
      })
    : null
  const step: RulebookStepResult = await runRulebookStep({
    env: planEnv,
    explicitPro,
    general: Boolean(opts.general),
    allowDegraded: Boolean(opts.allowDegraded),
    hookOrGate: isHookOrGate(),
    apiUrl: opts.apiUrl as string,
    frameworks: detectedFrameworks.map((f) => f.name),
    categories,
    scanId,
    fetchProRules: async (f, c, u, sid) => (await import('../core/pro-scanner.js')).fetchProRules(f, c, u, sid),
  })
  if (step.error) {
    return failWith(stepErrorEnvelope(step.error, { scanId, planEnv }), { startTime, projectDir: cwd, opts, policy })
  }
  if (!machineOutput && !quiet) for (const n of step.notes) logger.warn(n)
  // --allow-degraded kept a scan going without the rulebook that --pro required: say so on stderr, always.
  if (step.degradedReason) logger.warn('--allow-degraded set — degrading to a local scan; the full rulebook will not be applied')

  const proRules: QualityGateRule[] | undefined = step.proRules
  const rulesVersion: string | undefined = step.rulesVersion
  // An explicit --pro that --allow-degraded turned into a general run keeps the 0.12 degraded record.
  const proFetchDegradeReason: DegradeReason | undefined = step.degradedReason ?? undefined
  const degraded = proFetchDegradeReason !== undefined
  // Public-contract view of the same event (`rules.fallback`): code, one fixed sentence, and the server's own reason.
  const rulesFallback: { code: string; message: string; reason: string | null } | null = step.fallback
    ? { code: step.fallback.code, message: step.fallback.message, reason: step.fallback.reason }
    : null
  if (!machineOutput && !quiet && proRules && proRules.length > 0 && step.rulebookRan) {
    const breakdown: Record<string, number> = {}
    for (const r of proRules) breakdown[r.category] = (breakdown[r.category] ?? 0) + 1
    logger.info(`  + ${proRules.length} rules loaded (${Object.entries(breakdown).map(([cat, count]) => `${cat}: ${count}`).join(', ')})`)
  }

  // -----------------------------------------------------------------------
  // Live progress (TTY + not quiet + not machine output)
  // Emitted to STDERR so stdout stays clean for redirection.
  // Hand-rolled progress bar — no external dependency.
  // Throttled to ~60ms redraws to avoid flicker.
  // onProgress is forwarded from readFiles so we get real file counts + names.
  // -----------------------------------------------------------------------
  const showProgress = shouldShowProgress({
    isTTY: Boolean(process.stdout.isTTY),
    quiet,
    machineOutput,
  })

  let lastDrawMs = 0

  const onProgress = showProgress
    ? (current: number, total: number, file: string): void => {
        const now = Date.now()
        // Throttle: draw at most every 60ms, always draw on final file
        if (now - lastDrawMs >= 60 || current === total) {
          lastDrawMs = now
          process.stderr.write(`\r\x1b[K${renderProgressBar(current, total, 20, file)}`)
        }
      }
    : undefined

  if (!showProgress && !machineOutput && !quiet) {
    logger.info('Scanning files...')
  }

  let result
  try {
    result = await scan(scanOptions, proRules, onProgress)
  } catch (error) {
    if (showProgress) {
      process.stderr.write('\r\x1b[K')  // Clear the progress line
    }
    const crash = error instanceof Error ? error.message : String(error)
    return failWith(
      buildErrorEnvelope({ code: 'INTERNAL_ERROR', message: `ShipGuard stopped unexpectedly (run ${scanId.slice(0, 8)}).`, cliVersion: CLI_VERSION, runId: scanId, cause: crash }),
      { startTime, projectDir: cwd, opts, policy },
    )
  }

  // Clear progress line before printing results
  if (showProgress) {
    process.stderr.write('\r\x1b[K')  // Clear the progress bar line
  }

  // Populate new ScanResult fields
  // Bumped 4 → 5 (recommendations #1/#2/#8): the verdict is now fail-closed and the
  // duplicate `riskScore.recommendation` is a deprecated mirror; receipt fields
  // (`runId`, `treeDigest`, `cliVersion`) are additive — see the schema-freeze test's
  // own documented evolution procedure (tests/commands/scan-json-schema-freeze.test.ts).
  // Bumped 5 → 6: the additive `coverage` object (what was scanned, skipped and ignored) and the
  // new degrade codes UNSCANNED_UNKNOWN_BINARY and NO_FILES_SCANNED.
  result.schemaVersion = SCHEMA_VERSION
  result.scanIdReused = scanIdReused
  // OR-merge: preserve coderef version-skip degradation from scanner,
  // combined with the pro-fetch failure flag from this command layer.
  result.degraded = degraded || Boolean(result.degraded)

  // OR-merge degradedReasons: append PRO_RULES_UNAVAILABLE from the command layer
  // to whatever scanner-layer reasons (FILE_TOO_LARGE, OUTPUT_TRUNCATED,
  // CODEREF_SKIPPED) were already recorded. degradedReasons is only set when
  // result.degraded is true, so consumers can key on degraded:true first.
  if (result.degraded) {
    const existingReasons = result.degradedReasons ?? []
    const commandReasons: DegradeReason[] = proFetchDegradeReason ? [proFetchDegradeReason] : []
    result.degradedReasons = [...existingReasons, ...commandReasons]
  }
  // Deprecated alias (0.13.x): true when the SERVER's usage.state is warn or used. The CLI never decides a
  // threshold itself (no plan facts); with no verified plan data there is no such state.
  const serverUsageState = step.plan.server?.usage?.state
  result.creditsWarning = serverUsageState === 'warn' || serverUsageState === 'used'
  result.rulesVersion = rulesVersion
  // Receipt fields (rec #8). runId is the SAME id used for retry idempotency and for the
  // run-scoped report filenames, so a report on disk can always be traced back to a run.
  // treeDigest is set by the scanner (it is the only layer that has the file contents).
  result.runId = scanId
  result.cliVersion = CLI_VERSION

  // stamp the FINAL verdict, fail-closed, in one place. This must
  // run AFTER the degraded OR-merge above (the pro-fetch failure is only known here) and
  // BEFORE any consumer reads a verdict: the human panel, the JSON payload, the markdown
  // report, the history store and the telemetry bucket all read what this writes.
  applyVerdict(result)

  if (proRules?.length) {
    const breakdown: Record<string, number> = {}
    for (const r of proRules) {
      breakdown[r.category] = (breakdown[r.category] ?? 0) + 1
    }
    result.rulesApplied = proRules.length
    result.rulesBreakdown = breakdown
    result.aiCodeIssues = result.findings.filter((f) => f.aiCodeTarget).length
  }

  // ---------------------------------------------------------------------------
  // Local audit-trail store write + the ONE regression claim.
  // Side-effect-free to the verdict/exit code above: every failure mode inside
  // recordScanHistory (unsupported Node runtime, disk full, corrupt file, lock
  // timeout) resolves to stateStatus + regressionCheckSkipped rather than throwing.
  // Runs for every scan (not just --pro) — free-tier rules are tracked too, versioned
  // by the CLI build (see history/index.ts).
  // ---------------------------------------------------------------------------
  const proApplied = Boolean(proRules?.length) && !degraded
  const historyOutcome = await recordScanHistory({
    cwd,
    scanId,
    cliVersion: CLI_VERSION,
    policy,
    changedOnly: scanOptions.changedOnly,
    categories,
    proRules,
    proApplied,
    rulesVersion,
    result,
  })
  result.stateStatus = historyOutcome.stateStatus
  result.regressionCheckSkipped = historyOutcome.regressionCheckSkipped
  if (historyOutcome.regressionCheckSkipped) {
    result.regressionCheckSkippedReason = historyOutcome.regressionCheckSkippedReason
  } else {
    result.regressions = historyOutcome.regressions
    result.coverageChanged = historyOutcome.coverageChanged
  }

  // The public JSON result. The skip/truncation counts used to be private `_skipped*` fields that
  // were deleted here, so the JSON never carried them. They now live in the public `coverage`
  // object, so there is nothing left to strip.
  const publicResult: typeof result = { ...result }
  publicResult.telemetry = telemetryState({ policy, projectDir: cwd })

  // -----------------------------------------------------------------------
  // Write the report BEFORE rendering (rec #4): the human panel embeds the report
  // path, so the path has to exist by the time the panel is built. The write is
  // unconditional-on-request and independent of output mode, exactly as before.
  // -----------------------------------------------------------------------
  // Facts shared by the report and the screen (one source, so they never disagree).
  const generalRuleCount = generalRuleCountOrNull()
  const bundledGeneral = loadBundledRules()
  const generalIds = new Set(bundledGeneral.map((r) => r.id))
  const fb = step.fallback
  const rulebookRan = step.rulebookRan && !degraded && Boolean(proRules?.length)
  const screenRulesRan: RulesRan = step.partial && proRules
    ? { kind: 'partial', count: proRules.length }
    : fb && fb.code !== 'RULEBOOK_PARTIAL'
      ? { kind: 'fallback', code: fb.code, serverText: fb.serverText }
      : rulebookRan && proRules
        ? { kind: 'rulebook', label: step.plan.server?.label ?? null, count: proRules.length }
        : { kind: 'general' }
  const notScannedSummary = collectNotScanned(result, { cwd, maxFileSizeBytes: policy.limits?.maxFileSizeBytes })
  const detectedStackNames = detectedFrameworks.map((f) => f.name)
  const ignoredTestValues = result.coverage?.ignoredTestValues ?? 0
  // W5 masking: the one masked text `<type>, <length> characters, value hidden` is read back for the screen and the report.
  const maskedOf = (f: Finding) => (f.evidence ? parseMaskedSecret(f.evidence) : undefined)
  const secretLabel = (f: Finding): string | null => {
    const m = maskedOf(f)
    return m ? `${m.length} chars, value hidden` : null
  }
  const secretEvidence = (f: Finding): string | null => (maskedOf(f) && f.evidence ? f.evidence : null)

  // Exit code resolution (A1 contract) — computed BEFORE any output so the JSON can say what the
  // exit code means (`exitMeaning`) and the human output can end with the exit-code notice. The
  // computation is pure; nothing here changes which code is returned.
  let exitCode = resolveExitCode({
    strict: scanOptions.strict,
    blockingCount: result.riskScore.blockingCount,
    // the hard stop must not inherit the false-safe on an
    // unfinished scan. Uses the FINAL degraded value (post pro-fetch OR-merge).
    degraded: result.degraded === true,
    // CLI-2/J-3 — the hard stop must not disagree with the printed verdict:
    // a scan can print DO_NOT_SHIP with blockingCount 0 (active non-blocking findings,
    // degradation). effectiveRecommendation
    // reads the SAME field the human panel / --json `recommendation` print.
    recommendation: effectiveRecommendation(result),
  })
  const strictBlocked = exitCode === EXIT_CODES.BLOCKED
  // --check-regressions (opt-in ONLY) — see the note at the exit below.
  const regressionBlocks =
    Boolean(opts.checkRegressions) && exitCode === EXIT_CODES.SAFE && (result.regressions?.length ?? 0) > 0
  if (regressionBlocks) exitCode = EXIT_CODES.BLOCKED
  const notSafe = result.riskScore.blockingCount > 0 || effectiveRecommendation(result) === 'DO_NOT_SHIP'
  publicResult.exitMeaning = exitMeaning({ exitCode, strict: scanOptions.strict, notSafe, regressionBlocks })

  // The loop state (spec 04 "Fix loop"): how many runs in a row still show the same blocking rule + file.
  // Partial (--changed) scans never count: a blocker outside the changed files would look "fixed".
  let sinceLastRun: SinceLastRun | null = null
  if (!changedOnly) {
    const warnLoop = (m: string): void => logger.warn(m)
    const loop = computeSinceLastRun(readLastRun(cwd, warnLoop), {
      runId: scanId,
      treeDigest: result.treeDigest ?? null,
      blocking: blockingOccurrences(result.findings),
    })
    sinceLastRun = loop.since
    writeLastRun(cwd, loop.next, warnLoop)
  }

  const verdictValue = effectiveRecommendation(result)
  const rerunCommand = buildRerunCommand({
    invocationCwd,
    scanRoot: cwd,
    all: Boolean(opts.all),
    pro: explicitPro,
    general: Boolean(opts.general),
    allowDegraded: Boolean(opts.allowDegraded),
  })

  // ---- the plan block for this run (display state only) ----
  // Signed in: what the rulebook request (or the cache) said. Signed out: the cached public offer, plus the one weekly fetch
  // that ran beside the scan (stack names only).
  let plan = step.plan
  if (!step.signedIn) {
    const attempt = weeklyOffer ? await weeklyOffer : null
    plan = attempt?.attempted && attempt.result.ok ? attempt.result.block : await readPublicOffer(planEnv, stackNames)
    if (attempt?.attempted && !attempt.result.ok && plan.status === 'unavailable' && plan.reason !== 'PLAN_UNVERIFIED') {
      plan = unavailableBlock(attempt.result.reason)
    }
  }
  const nag = loadNagFor(planEnv)
  const muted = isMuted(nag)
  const rk = repoKey(repoIdOf(cwd))
  const acctId = step.acct
  const hookOrGate = isHookOrGate()
  const detected: DetectedStack[] = detectedFrameworks
    .filter((f) => f.name !== 'generic')
    .map((f) => ({ key: f.name, display: stackDisplayName(f.name), version: f.version ?? null }))
  const generalCountN = bundledGeneral.length
  const complete = result.degraded !== true
  const blockingCount = result.riskScore.blockingCount
  const rulebookRuleIds = new Set<string>(proRules && (rulebookRan || step.partial) ? proRules.filter((r) => !generalIds.has(r.id)).map((r) => r.id) : [])
  // First-Pro receipt data: what the rulebook ran that the bundled general set did not (never on a partial or fallback run).
  const receipt: Receipt | null = rulebookRan && fb === null && proRules
    ? computeReceipt(
        proRules.map((r) => ({ id: r.id, category: r.category, area: step.areaByRuleId[r.id] ?? null })),
        generalIds,
        result.findings.map((f) => f.id),
      )
    : null

  // Facts the next-steps and the screen share.
  const reasons = result.degradedReasons ?? []
  const degradedJson = buildDegradedReasons(reasons, result.coverage)
  const notScanned = buildNotScanned(result.coverage, reasons)
  const blockingFindings = result.findings.filter((f) => f.blocking && !f.suppressed)
  // Gate health (spec 03): a stale hook and a gate the host killed are reported on every run, outside the gate too.
  const healthWarnings = gateHealthWarnings(cwd)
  const warnings: Array<{ code: string; message: string; command: string | null }> = healthWarnings.map((w) => ({ code: w.code, message: w.message, command: w.command }))
  const gate = probeGate(cwd)
  const nextAgent = detectNextAgent(cwd)
  const steps = buildNextSteps({
    value: verdictValue,
    blockingFindings,
    degraded: result.degraded === true,
    degradedReasons: degradedJson,
    notScanned,
    sinceLastRun,
    warnings,
    rerunCommand,
    install: { agent: nextAgent, gateInstalled: gate.state !== 'none', hookStale: gate.state === 'stale' || healthWarnings.some((w) => w.code === 'HOOK_STALE') },
    reportMarkdown: scanOptions.reportPath,
  })
  const agentAction = decideAgentAction({ value: verdictValue, blockingCount, degraded: result.degraded === true, steps, sinceLastRun })
  const marks = { pitch: false, usage: false, receipt: false }

  // The schema-7 result object: the SAME object goes to stdout (--json) and to the run's JSON record.
  const buildEnvelope = (forStdout: boolean, reportPaths: { mdPath: string; runJsonPath: string } | null): Record<string, unknown> => {
    const rulebookResult = rulebookRan && fb === null
    const planOut = buildPlanJson({
      plan, signedIn: step.signedIn, accountStatus: step.accountStatus, stacks: detected, generalRuleCount: generalCountN,
      complete, blockingCount, fallbackActive: fb !== null, ci: planEnv.ci, safeMode: planEnv.safeMode, muted,
      jsonPitchDue: forStdout && momentDue(nag, 'jsonPitch', rk, planEnv.now),
      usageJsonDue: forStdout && acctId !== null && momentDue(nag, 'usageJson', acctId, planEnv.now),
      receiptJsonDue: forStdout && acctId !== null && momentDue(nag, 'receiptJson', acctId, planEnv.now),
      receipt: rulebookResult ? receipt : null,
    })
    if (forStdout) { marks.pitch = planOut.mark.pitch; marks.usage = planOut.mark.usage; marks.receipt = planOut.mark.receipt }
    const strictWouldExit = resolveExitCode({
      strict: true, blockingCount, degraded: result.degraded === true, recommendation: verdictValue,
    })
    return buildScanEnvelope({
      cliVersion: CLI_VERSION,
      runId: scanId,
      timestamp: result.timestamp,
      elapsedMs: Date.now() - startTime,
      verdictValue,
      verdict: buildVerdictJson({
        value: verdictValue,
        blockingCount,
        findingCount: result.findings.length,
        degraded: result.degraded === true,
        filesScanned: result.filesScanned,
        filesDiscovered: result.coverage?.discovered ?? result.filesScanned,
        rulebookFallback: fb !== null && fb.code !== 'RULEBOOK_PARTIAL',
      }),
      exitCode,
      strict: scanOptions.strict,
      strictWouldExit,
      agentAction,
      report: reportPaths ? { markdown: reportPaths.mdPath, json: reportPaths.runJsonPath } : null,
      stack: {
        detected: detected.map((f) => `${f.key}${f.version ? `@${f.version}` : ''}`),
        supported: detected.length > 0,
        ...(detected.length === 0 ? { manifest: firstManifest(cwd) } : {}),
      },
      rules: {
        corpus: rulebookRan ? 'rulebook' : 'general',
        version: rulebookRan ? (rulesVersion ?? null) : CLI_VERSION,
        applied: rulebookRan ? proRules!.length : generalCountN,
        localChecks: true,
        fallback: rulesFallback,
        ...(step.partial ? { tiersApplied: step.tiersApplied ?? [] } : {}),
        receipt: rulebookResult && receipt ? receipt : null,
      },
      plan: planOut.json,
      findings: result.findings,
      findingCtx: { rerunCommand, rulebookRuleIds },
      coverage: buildCoverageJson(result.coverage, reasons, result.filesScanned, ignoredTestValues),
      degraded: result.degraded === true,
      degradedReasons: degradedJson,
      warnings,
      nextSteps: steps,
      telemetry: publicResult.telemetry,
      regressions: publicResult.regressions ?? [],
      coverageChanged: publicResult.coverageChanged ?? [],
      sinceLastRun,
      treeDigest: result.treeDigest,
      riskScore: result.riskScore,
      policyUsed: result.policyUsed,
      scanIdReused,
      legacy: {
        stateStatus: result.stateStatus,
        regressionCheckSkipped: result.regressionCheckSkipped,
        regressionCheckSkippedReason: result.regressionCheckSkippedReason,
        creditsWarning: Boolean(result.creditsWarning),
        filesScanned: result.filesScanned,
        exitMeaning: publicResult.exitMeaning ?? '',
        rulesVersion: result.rulesVersion,
        rulesApplied: result.rulesApplied,
        rulesBreakdown: result.rulesBreakdown,
        aiCodeIssues: result.aiCodeIssues,
      },
    })
  }

  // The envelope is built once: for stdout under --json, for the report's JSON record otherwise. The report's paths are
  // known before it is written, so the result can carry them.
  const shouldReport = scanOptions.generateReport || policy.scan.generate_report
  const plannedReport = shouldReport ? reportPathsFor(scanOptions.reportPath, scanId) : null
  const envelope = scanOptions.json || shouldReport ? buildEnvelope(Boolean(scanOptions.json), plannedReport) : null
  let reportPaths: Awaited<ReturnType<typeof generateReport>> | undefined
  if (shouldReport) {
    const reportElapsedMs = Date.now() - startTime
    try {
      reportPaths = await generateReport(result, scanOptions.reportPath, reportElapsedMs, {
        stacks: detectedStackNames,
        rerunCommand,
        generalRuleCount,
        rulesRan: screenRulesRan,
        notScanned: notScannedSummary,
        ignoredTestValues,
        secretEvidence,
        agentJson: envelope ?? undefined,
      })
    } catch (error) {
      // Loud. A failed report write never changes the verdict or the exit
      // code, but it is never swallowed either.
      logger.error(`Report generation failed: ${error instanceof Error ? error.message : error}`)
    }
  }

  // Warnings that carry a command go to stderr, one line each (spec 01, 03): stdout line 1 stays the verdict. The JSON
  // and SARIF outputs keep stderr quiet: the same facts are in warnings[]. The gate's own child run is a JSON run.
  if (!opts.sarif && !scanOptions.json && !isHookOrGate()) {
    for (const w of healthWarnings) process.stderr.write(`${healthWarningLine(w)}\n`)
  }

  // Machine-readable output — exactly one format emitted to stdout
  if (opts.sarif) {
    console.log(JSON.stringify(toSarif(publicResult), null, 2))
  } else if (scanOptions.json) {
    console.log(JSON.stringify(envelope, null, 2))
    // What this JSON read told an agent is marked as shown (its own counters: the terminal never loses its window).
    const nctx = nagCtx(planEnv)
    if (marks.pitch) markMoment(nctx, 'jsonPitch', rk)
    if (acctId !== null && marks.usage) markMoment(nctx, 'usageJson', acctId)
    if (acctId !== null && marks.receipt) markMoment(nctx, 'receiptJson', acctId)
  } else if (quiet) {
    // --quiet mode: one `key=value` line (spec 01); nothing else on stdout.
    console.log(renderQuietLine({
      result,
      agentAction,
      notScanned: notScannedSummary.fileCount,
      // PLAN_INACTIVE (a lapsed plan) is shown on a terminal only; the quiet line never carries it.
      fallbackCode: fb && fb.code !== 'PLAN_INACTIVE' ? fb.code : null,
      reportPath: reportPaths?.mdPath ?? null,
    }))
  } else {
    // -----------------------------------------------------------------------
    // Human screen (spec 01): verdict first, at most 25 lines, same bytes piped or on a terminal.
    // -----------------------------------------------------------------------
    const elapsedMs = Date.now() - startTime
    const nctx = nagCtx(planEnv)

    // First-run welcome text (TTY only, not in --json/--sarif/--quiet)
    const isTTY = Boolean(process.stdout.isTTY)
    if (isTTY) {
      const banner = welcomeBanner()
      if (banner) console.log(banner)
    }

    // Free-to-Pro line (one shared 7-day counter per repo) and the first-Pro receipt: after the result, terminal only.
    const pitch = screenPitch({
      plan, signedIn: step.signedIn, accountStatus: step.accountStatus, detected, rulesApplied: generalCountN,
      scanComplete: complete, blocking: blockingCount > 0, fallbackActive: fb !== null, ci: planEnv.ci, hookOrGate,
      safeMode: planEnv.safeMode, muted, recentlyShown: false, terminal: planEnv.terminal, quiet: false,
      screenDue: momentDue(nag, 'screenPitch', rk, planEnv.now),
    })
    const receiptOpen = receipt !== null && receipt.extraRules > 0 && acctId !== null && planEnv.terminal && !planEnv.ci && !hookOrGate &&
      !planEnv.safeMode && momentDue(nag, 'receiptShown', acctId, planEnv.now)
    const receiptOut = receiptOpen && receipt ? receiptLines(receipt, plan) : []
    const setupDue = momentDue(nag, 'setupHint', rk, planEnv.now)

    const screen = renderScanScreen({
      result,
      elapsedMs,
      strict: scanOptions.strict,
      exitCode,
      rerunCommand,
      reportPath: reportPaths?.mdPath ?? null,
      stacks: detectedStackNames,
      manifest: detectManifest(cwd),
      generalRuleCount,
      rulesRan: screenRulesRan,
      notScanned: notScannedSummary,
      next: {
        agent: nextAgent,
        gate: gate.state,
        gateLabel: gate.label,
        // The setup suggestion is shown once per 7 days; JSON always carries the setup step.
        suggestionShownRecently: !setupDue,
      },
      planLines: [...pitch.lines, ...receiptOut],
      planLabel: plan.server?.label ?? null,
      ignoredTestValues,
      secretLabel,
      fixLoop: sinceLastRun
        ? { fixed: sinceLastRun.fixed.length, added: sinceLastRun.new.length, repeatLine: repeatLineFor(sinceLastRun, blockingCount) }
        : undefined,
      columns: isTTY ? (process.stdout.columns ?? 100) : undefined,
      nothingToCheck: Boolean(result.coverage?.changed?.nothingToCheck),
    })
    console.log(screen)

    if (pitch.mark && pitch.lines.length > 0) markMoment(nctx, 'screenPitch', rk)
    if (receiptOut.length > 0 && acctId !== null) markMoment(nctx, 'receiptShown', acctId)
    if (screen.includes('shipguard setup --agent')) markMoment(nctx, 'setupHint', rk)

    // Allowance and update notices: stderr, interactive terminal only, once per day per account.
    if (acctId !== null) {
      const nc = { terminal: planEnv.terminal, quiet: false, ci: planEnv.ci, hookOrGate, safeMode: planEnv.safeMode, due: momentDue(nag, 'usageScreen', acctId, planEnv.now) }
      const notice = [...usageNoticeLines(plan, nc), ...updateNoticeLines(plan, nc)]
      for (const line of notice) console.error(line)
      if (notice.length > 0) markMoment(nctx, 'usageScreen', acctId)
    }
  }

  // Anonymous opt-out ping — privacy-preserving. Started here so the request overlaps with the
  // exit-code work below, and AWAITED (bounded, <= 1.5 s, never rejects) right before any explicit
  // process.exit so a --strict exit cannot drop it.
  // Payload (schema v4): version, verdict, duration bucket, ci flag, provenance, coding-agent label, stdout-is-a-terminal flag, output kind, random install id (null in CI) ONLY.
  // Never: paths, file content, hostnames, user identity, finding details.
  // Opt out: SHIPGUARD_TELEMETRY=0, DO_NOT_TRACK=1, `shipguard telemetry disable`, or
  // `telemetry.enabled: false` in shipguard.policy.yml / .shipguard.yml. See src/core/telemetry.ts.
  let telemetryDone: Promise<void> | void = undefined
  try {
    const elapsedMs = Date.now() - startTime
    // Telemetry verdict bucket reflects the ACTUAL scan outcome (recommendation +
    // degraded), independent of exit code — the two are decoupled under the A1
    // contract (exit code is verdict-neutral by default; verdict lives in JSON).
    // 'review' means "a human should look at this before trusting the verdict":
    // either a degraded/partial scan, or a REVIEW_BEFORE_SHIP recommendation.
    const verdictBucket: TelemetryVerdict = result.degraded
      ? 'review'
      : result.riskScore.blockingCount > 0
        ? 'blocked'
        : result.riskScore.recommendation === 'REVIEW_BEFORE_SHIP'
          ? 'review'
          : 'safe'
    telemetryDone = sendTelemetry(
      {
        cliVersion: CLI_VERSION,
        verdict: verdictBucket,
        durationMs: elapsedMs,
        output: outputKind(opts),
      },
      { policy, projectDir: cwd },
    )
  } catch (err) {
    // Telemetry must never affect the scan result or the exit code; log under SHIPGUARD_DEBUG only.
    logger.debug(`telemetry: skipped (ignored): ${err instanceof Error ? err.message : String(err)}`)
  }

  // Exit code resolution (A1 contract) — verdict-neutral by default. --strict
  // + (blocking findings OR an unfinished scan OR a DO_NOT_SHIP verdict) is the
  // ONLY thing that moves the exit code off 0. Degradation is surfaced in JSON
  // (`degraded`/`degradedReasons`), never by reusing a different exit code —
  // see resolveExitCode() doc comment above.

  if (strictBlocked && !machineOutput && !quiet) {
    if (result.degraded === true) {
      logger.warn(
        `Strict mode: this scan did not finish — ${(result.degradedReasons ?? []).map((r) => r.code).join(', ') || 'reason not recorded'} ` +
        `— exiting with code 1. Fix the cause or drop --strict to get a report without a hard stop.`
      )
    } else if (result.riskScore.blockingCount > 0) {
      logger.warn(`Strict mode: ${result.riskScore.blockingCount} blocking finding(s) — exiting with code 1`)
    } else {
      logger.warn(
        `Strict mode: verdict is DO_NOT_SHIP (risk score ${result.riskScore.score}/100) — exiting with code 1. ` +
        `No individual finding is policy-blocking, but the combined risk score of the active findings ` +
        `crossed the DO_NOT_SHIP threshold. Fix or drop --strict to get a report without a hard stop.`
      )
    }
  }

  // --check-regressions (opt-in ONLY) — a real regression is informational-only in
  // JSON by default (result.regressions), same as any other finding. Passing this flag
  // opts into using the EXISTING BLOCKED exit code (never a new one) when at least one
  // regression fired. This does NOT touch resolveExitCode()'s A1 contract above — it is
  // a separate, additive override, and only ever raises the exit code, never lowers it.
  if (regressionBlocks && !machineOutput && !quiet) {
    logger.warn(`--check-regressions: ${result.regressions?.length} previously-passing rule(s) now fail — exiting with code 1`)
  }

  // Let the (bounded) ping finish before we may hard-exit. sendTelemetry never rejects.
  await telemetryDone

  if (exitCode !== EXIT_CODES.SAFE) {
    setExitCode(exitCode)
  }
}
