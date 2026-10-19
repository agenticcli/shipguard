import { Command } from 'commander'
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
  verdictPanel,
  renderFindingsSummary,
  findingsByCategoryTable,
  coverageLine,
  welcomeBanner,
  shouldShowProgress,
  renderProgressBar,
  quietVerdict,
  actionFooter,
} from '../core/render.js'
import { EXIT_CODES, DEFAULT_REPORT_FILE } from '@agenticcli/shared'
import type { ScanOptions, QualityGateRule, DegradeReason, Recommendation } from '@agenticcli/shared'
import { recordScanHistory, resolveScanId } from '../core/history/index.js'
import { applyVerdict, effectiveRecommendation } from '../core/verdict.js'
import type { FrameworkEntry } from '../core/framework.js'
import { sendTelemetry } from '../core/telemetry.js'
import type { TelemetryVerdict } from '../core/telemetry.js'
// Type-only import — deliberately NOT a value import. pro-scanner.ts (re2js, matcher-contract,
// coderef-dispatch, etc.) is dynamically imported ONLY inside the `if (opts.pro)` branch below to
// keep non-pro scans fast; a value import here would force it to load eagerly on every scan.
import type { ProFetchErrorCode } from '../core/pro-scanner.js'

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
 *   1 — BLOCKED. Opt-in hard gate: only when --strict is passed AND at least
 *       one blocking finding exists. This is the only condition that changes
 *       the exit code from the default 0 — everything else is informational.
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
      return `Buy more credits at ${goLink('billing')}, or pass --allow-degraded to run local rules only.`
    case 'RATE_LIMITED':
      return retryAfterSeconds !== undefined
        ? `Rate limited — retry after ${retryAfterSeconds}s, or pass --allow-degraded to run local rules only.`
        : 'Rate limited — wait and retry, or pass --allow-degraded to run local rules only.'
    case 'SERVER_ERROR':
      return 'This looks like a transient server/network issue — retry the scan, or pass --allow-degraded to run local rules only.'
    case 'PLATFORM_UNAVAILABLE':
      return platformUnavailableMessage(retryAfterSeconds)
    case 'BUNDLE_INVALID':
      return 'The pro rule bundle failed validation (server-side issue) — retry, or pass --allow-degraded to run local rules only. If this persists, contact support.'
    case 'NO_ACTIVE_RELEASE':
      return 'The Pro rule server has no active rule release yet — this is a server-side configuration gap, not something a retry or re-login will fix. Check ' + goLink('docs') + ' or contact support, or pass --allow-degraded to run local rules only in the meantime.'
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
    .description('Scan your project for high-risk issues (verbose by default; use --quiet for one-line verdict)')
    .argument('[path]', 'Path to project root to scan (defaults to current directory)')
    .option('--changed', 'Only scan changed files from git diff')
    .option('--report', 'Generate a detailed Markdown report')
    .option('--strict', 'Opt-in hard gate: exit 1 if blocking findings exist, the scan did not finish, OR the verdict is DO_NOT_SHIP (default exit is 0 — verdict is informational, read the JSON `recommendation`)')
    .option('--json', 'Output results as JSON (machine-readable; suppresses all decoration)')
    .option('--sarif', 'Output results as SARIF 2.1.0 (for GitHub Code Scanning)')
    .option('-q, --quiet', 'One-line verdict only (suppresses progress, panel, and tips)')
    .option('--pro', 'Include pro quality gate rules (requires authentication)')
    .option('--api-url <url>', 'API server URL', 'https://agenticcli.dev')
    .option('--category <categories>', 'Comma-separated category filter for pro rules')
    .option('--beta', 'Include beta-stage rules')
    .option('--all', 'Scan any directory, even without package.json or .git')
    .option('--allow-degraded', 'With --pro: fall back to local-only rules if the pro rule fetch fails, instead of failing loud (opt-in; restores the pre-2026-07-14 fallback behavior — see exit code 3 below)')
    .option('--check-regressions', 'Opt-in hard gate: exit 1 if a previously-passing blocking rule now fails under the same scan scope + corpus release (informational-only in --json unless this flag is set)')
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
  shipguard scan --pro            Include pro quality gate rules (requires login)
  shipguard scan --pro --allow-degraded  Fall back to local rules if the pro fetch fails (opt-in)
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
     a hard gate), or an effective \`recommendation\` of DO_NOT_SHIP (suppressed
     findings still count toward the risk score, so a scan can cross the
     DO_NOT_SHIP threshold with zero blocking findings — the exit code always
     agrees with the printed verdict). OR with --check-regressions AND at
     least one regression (see \`regressions\` in --json output —
     informational-only unless this flag is set).
  2  Config error (bad policy file, bad flags, non-project directory, scan path
     that does not exist or is not a directory).
  3  Runtime error — the scan could not meaningfully run at all. This
     INCLUDES an explicit --pro request whose rule fetch failed (auth,
     credits, rate limit, server, an invalid bundle, no active rule
     release on the server, or the platform being temporarily unavailable —
     --json code PLATFORM_UNAVAILABLE, with retryAfterSeconds when known) — the requested gate did not run, so
     ShipGuard fails loud instead of silently falling back to a free
     scan. Pass --allow-degraded to opt back into the free-scan
     fallback (degraded:true, exit code unaffected).

Local history: every scan is recorded to a local SQLite store
(\`.shipguard/history.db\` by default; override via \`history.path\` in
shipguard.policy.yml or SHIPGUARD_HISTORY_PATH). \`stateStatus\` in --json
reports whether that recording succeeded (complete/unavailable/corrupt) —
a regression is only ever claimed when it's \`complete\` for both runs
being compared. A corpus/rule update is reported as \`coverageChanged\`,
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
          logger.error(pathProblem.message)
          if (machineOutput) {
            console.log(JSON.stringify({ error: pathProblem.message, code: pathProblem.code }))
          }
          await exitWithError(EXIT_CODES.CONFIG_ERROR, startTime, process.cwd())
        }
      }

      // ---------------------------------------------------------------------------
      // A6: Scope guard — refuse to scan a non-project directory unless --all or path given
      // A true heap-OOM is prevented by Part A bounds (size/binary/total caps in readFiles),
      // but scanning an arbitrary filesystem root (e.g. /home or /tmp) is still dangerous
      // and almost certainly unintentional. Require either a project root or --all.
      // ---------------------------------------------------------------------------
      if (!scanPath && !opts.all && !isProjectRoot(cwd)) {
        logger.error(
          `Refusing to scan a non-project directory ${cwd}. ` +
          `Pass a path (\`shipguard scan ./my-app\`) or \`--all\` to override.`
        )
        if (!machineOutput) {
          console.log(`\n${LEARN_MORE}`)
        }
        await exitWithError(EXIT_CODES.CONFIG_ERROR, startTime, process.cwd())
      }

      // Change working directory to the resolved scan root so scanner uses it as cwd
      const originalCwd = process.cwd()
      if (scanPath) {
        process.chdir(cwd)
      }

      try {
        await runScan({ cwd, opts, machineOutput, quiet, startTime })
      } finally {
        if (scanPath) {
          process.chdir(originalCwd)
        }
      }
    })
}

/**
 * The ONE exit path for every scan error (config 2 / runtime 3): sends a single telemetry ping with
 * verdict "error" (all opt-outs honoured inside sendTelemetry; it never rejects), awaited so the hard
 * exit cannot drop it, then exits. Keep every error exit going through here - a source-guard test
 * fails on a bare process.exit(CONFIG_ERROR|RUNTIME_ERROR) in this file.
 */
async function exitWithError(
  exitCode: number,
  startTime: number,
  projectDir: string,
  policy?: unknown,
): Promise<never> {
  try {
    await sendTelemetry(
      { cliVersion: CLI_VERSION, verdict: 'error', durationMs: Date.now() - startTime },
      { policy, projectDir },
    )
  } catch (err) {
    // sendTelemetry never rejects; belt and braces so telemetry can never change the exit code.
    logger.debug(`telemetry: error ping skipped (ignored): ${err instanceof Error ? err.message : String(err)}`)
  }
  return process.exit(exitCode)
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
  opts: Record<string, unknown>
  machineOutput: boolean
  quiet: boolean
  startTime: number
}) {
  const { cwd, opts, machineOutput, quiet, startTime } = ctx

  // Load policy for header info and report path resolution
  let policy
  try {
    policy = await loadPolicy(cwd)
  } catch (error) {
    logger.error(`Config error: ${error instanceof Error ? error.message : error}`)
    await exitWithError(EXIT_CODES.CONFIG_ERROR, startTime, cwd)
    return  // Unreachable in production; guards against mocked process.exit in tests
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

  const { scanId, scanIdReused } = await resolveScanId({
    cwd,
    policy,
    cliVersion: CLI_VERSION,
    changedOnly,
    categories,
    proRequested: Boolean(opts.pro),
    frameworks: frameworkNames,
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

  let proRules: QualityGateRule[] | undefined
  let creditsRemaining: number | undefined
  let rulesVersion: string | undefined
  let degraded = false
  // Machine-readable reason for the pro-fetch failure — added to result.degradedReasons
  // after the scan completes, alongside any scanner-layer reasons (FILE_TOO_LARGE, etc.)
  let proFetchDegradeReason: DegradeReason | undefined

  // `changedOnly`/`categories` were hoisted above (scanId reuse) so resolveScanId can compute its
  // pre-scan reuse key before this point — the scope fingerprint (§2.2) below reuses the same
  // values regardless of whether the pro fetch runs/succeeds.

  if (opts.pro) {
    if (!machineOutput && !quiet) {
      logger.info('Detecting stack...')
    }
    try {
      const { fetchProRules } = await import('../core/pro-scanner.js')
      const { hasConfig, generateConfig } = await import('../core/config-generator.js')
      // Reuse the framework set already detected above for the scanId reuse key — do NOT
      // re-detect (a second read could disagree with the set that keyed the scanId).
      const frameworks = detectedFrameworks

      // Auto-generate .shipguard.yml on first scan
      if (!hasConfig(cwd)) {
        const configPath = generateConfig(cwd, frameworks)
        if (!machineOutput && !quiet) {
          logger.success(`Config saved to ${configPath}`)
        }
      }

      if (!machineOutput && !quiet) {
        for (const fw of frameworks) {
          logger.info(`  + ${fw.name}${fw.version ? ` ${fw.version}` : ''}`)
        }
        logger.info('Fetching pro rules...')
      }

      // ScanId idempotency (scanId idempotency): pass the per-scan stable scanId (minted once in
      // scanCommand) down to fetchProRules so it rides in the request body AND the
      // Idempotency-Key header. The server's (userId, scanId) reservation then makes a
      // dropped-response retry re-deliver the already-paid bundle instead of charging a
      // second credit. Omitting it here forced the server to mint a fresh UUID per
      // request, defeating the entire server-side idempotency machinery (money bug).
      const fetched = await fetchProRules(
        frameworks.map((f) => f.name),
        categories.length > 0 ? categories : undefined,
        opts.apiUrl as string,
        scanId,
      )
      proRules = fetched.rules
      creditsRemaining = fetched.creditsRemaining
      rulesVersion = fetched.rulesVersion

      if (!machineOutput && !quiet && proRules.length > 0) {
        // Build category breakdown for display
        const breakdown: Record<string, number> = {}
        for (const r of proRules) {
          breakdown[r.category] = (breakdown[r.category] ?? 0) + 1
        }
        const breakdownStr = Object.entries(breakdown)
          .map(([cat, count]) => `${cat}: ${count}`)
          .join(', ')
        logger.info(`  + ${proRules.length} rules loaded (${breakdownStr})`)
        logger.info('  + Encrypted | Signed | Memory-only')
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err)
      // a NO_RULES_APPLIED (server fail-closed on an empty bundle) is an UNCHECKABLE scan,
      // NOT a transient outage. We must NOT degrade to a free scan and report green (§11.1). Exit
      // 3 (RUNTIME_ERROR) loudly and suppress the free-rule fallback — a scan that checked nothing
      // can never be SAFE_TO_SHIP.
      const isNoRulesApplied =
        (err instanceof Error && err.name === 'NoRulesAppliedError') ||
        (err as { code?: string })?.code === 'NO_RULES_APPLIED'
      if (isNoRulesApplied) {
        if (!machineOutput) {
          logger.error(`Pro rules unavailable (fail-closed): ${errMsg}`)
          logger.error('This scan applied ZERO rules — it checked nothing. Refusing to report a clean pass.')
        } else {
          console.log(JSON.stringify({ error: errMsg, code: 'NO_RULES_APPLIED' }))
        }
        await exitWithError(EXIT_CODES.RUNTIME_ERROR, startTime, cwd, policy)
      }

      // ---------------------------------------------------------------------
      // every OTHER Pro-fetch failure class (auth, credits,
      // rate limit, server/network, invalid bundle). Classify by duck-typing the
      // `code` field pro-scanner.ts's ProFetchError carries (see the type-only
      // import at the top of this file — we deliberately do NOT value-import
      // pro-scanner.js here, to keep it lazy-loaded for non-pro scans).
      // Unrecognized/untyped errors default to SERVER_ERROR: fail loud is the
      // SAFE default (never silently reclassify an unknown error as a clean
      // free-scan fallback).
      // ---------------------------------------------------------------------
      const rawErrCode = (err as { code?: unknown })?.code
      const KNOWN_PRO_FETCH_ERROR_CODES: readonly ProFetchErrorCode[] = [
        'AUTH_FAILED', 'INSUFFICIENT_CREDITS', 'RATE_LIMITED', 'SERVER_ERROR', 'BUNDLE_INVALID', 'NO_ACTIVE_RELEASE', 'PLATFORM_UNAVAILABLE',
      ]
      const proErrorCode: ProFetchErrorCode =
        typeof rawErrCode === 'string' && (KNOWN_PRO_FETCH_ERROR_CODES as string[]).includes(rawErrCode)
          ? (rawErrCode as ProFetchErrorCode)
          : 'SERVER_ERROR'
      const retryAfterSeconds = (err as { retryAfterSeconds?: number })?.retryAfterSeconds

      if (opts.allowDegraded) {
        // Opt-in: restores the pre-2026-07-14 fallback — free scan, degraded:true,
        // verdict-neutral exit (resolveExitCode is unaffected by this branch).
        logger.warn('--allow-degraded set — degrading to free scan; pro rules will not be applied')
        degraded = true
        proFetchDegradeReason = {
          code: 'PRO_RULES_UNAVAILABLE',
          detail: `[${proErrorCode}] Pro rules could not be fetched: ${errMsg}`,
        }
      } else {
        // Default (amended A1, explicit-Pro-failure path only — see the
        // resolveExitCode doc comment above for the governance note): the
        // caller explicitly asked for the pro gate and it did NOT run. Fail
        // loud, exit 3 — never silently degrade to a free scan and report
        // green. Structured, machine-readable, and includes what the caller
        // can do next.
        const action = proFetchActionHint(proErrorCode, retryAfterSeconds)
        if (proErrorCode === 'PLATFORM_UNAVAILABLE') {
          // The action text IS the calm message (it already carries the --allow-degraded hint) —
          // don't prefix it with the raw server string.
          logger.error(action)
        } else {
          logger.error(`Pro rules request failed [${proErrorCode}]: ${errMsg}`)
          logger.error(action)
          logger.error('Pass --allow-degraded to fall back to a free (local-rules-only) scan instead.')
        }
        if (machineOutput) {
          console.log(JSON.stringify({
            error: errMsg,
            code: proErrorCode,
            degraded: false,
            action,
            ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
          }))
        }
        await exitWithError(EXIT_CODES.RUNTIME_ERROR, startTime, cwd, policy)
      }
    }
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
    if (!machineOutput) {
      logger.error(`Scan failed: ${error instanceof Error ? error.message : error}`)
    } else {
      console.log(JSON.stringify({ error: String(error) }))
    }
    return exitWithError(EXIT_CODES.RUNTIME_ERROR, startTime, cwd, policy)
  }

  // Clear progress line before printing results
  if (showProgress) {
    process.stderr.write('\r\x1b[K')  // Clear the progress bar line
  }

  // Extract internal metadata (human output only) before building the public result
  const skippedTooLarge = result._skippedTooLarge ?? 0
  const skippedTooLargeFiles = result._skippedTooLargeFiles ?? []
  const skippedBinary = result._skippedBinary ?? 0
  const skippedBinaryFiles = result._skippedBinaryFiles ?? []
  const skippedSymlinks = result._skippedSymlinks ?? 0
  const skippedSymlinkFiles = result._skippedSymlinkFiles ?? []
  const truncatedByBounds = result._truncated ?? false

  // Populate new ScanResult fields
  // Bumped 4 → 5 (recommendations #1/#2/#8): the verdict is now fail-closed and the
  // duplicate `riskScore.recommendation` is a deprecated mirror; receipt fields
  // (`runId`, `treeDigest`, `cliVersion`) are additive — see the schema-freeze test's
  // own documented evolution procedure (tests/commands/scan-json-schema-freeze.test.ts).
  result.schemaVersion = '5'
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
  result.creditsWarning = creditsRemaining !== undefined && creditsRemaining < 10
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

  // Build the public JSON-safe result (strip internal _ fields from the frozen schema)
  // The --json schema is a frozen contract — internal metadata must not appear in it.
  const publicResult = { ...result }
  delete (publicResult as Record<string, unknown>)._skippedTooLarge
  delete (publicResult as Record<string, unknown>)._skippedTooLargeFiles
  delete (publicResult as Record<string, unknown>)._skippedBinary
  delete (publicResult as Record<string, unknown>)._skippedBinaryFiles
  delete (publicResult as Record<string, unknown>)._skippedSymlinks
  delete (publicResult as Record<string, unknown>)._skippedSymlinkFiles
  delete (publicResult as Record<string, unknown>)._truncated

  // -----------------------------------------------------------------------
  // Write the report BEFORE rendering (rec #4): the human panel embeds the report
  // path, so the path has to exist by the time the panel is built. The write is
  // unconditional-on-request and independent of output mode, exactly as before.
  // -----------------------------------------------------------------------
  const shouldReport = scanOptions.generateReport || policy.scan.generate_report
  let reportPaths: Awaited<ReturnType<typeof generateReport>> | undefined
  if (shouldReport) {
    const reportElapsedMs = Date.now() - startTime
    try {
      reportPaths = await generateReport(result, scanOptions.reportPath, reportElapsedMs)
    } catch (error) {
      // Loud. A failed report write never changes the verdict or the exit
      // code, but it is never swallowed either.
      logger.error(`Report generation failed: ${error instanceof Error ? error.message : error}`)
    }
  }

  // Machine-readable output — exactly one format emitted to stdout
  if (opts.sarif) {
    console.log(JSON.stringify(toSarif(publicResult), null, 2))
  } else if (scanOptions.json) {
    console.log(JSON.stringify(publicResult, null, 2))
  } else if (quiet) {
    // --quiet mode: one-line verdict only
    console.log(quietVerdict(result, scanOptions.strict))
  } else {
    // -----------------------------------------------------------------------
    // Verbose human output (default) — rich, gamified, full scan experience
    // -----------------------------------------------------------------------
    const elapsedMs = Date.now() - startTime

    // First-run welcome banner (TTY only, not in --json/--sarif/--quiet)
    const isTTY = Boolean(process.stdout.isTTY)
    if (isTTY) {
      const banner = welcomeBanner()
      if (banner) console.log(banner)
    }

    // Findings summary — categorized by severity + confidence/FP labels
    console.log(renderFindingsSummary(result.findings))

    // Category breakdown table
    if (result.findings.length > 0) {
      console.log(findingsByCategoryTable(result.findings))
      console.log('')
    }

    // Oversized-file skip is a DEGRADED condition — LOUD warning that NAMES the
    // file(s) so the user knows exactly what was NOT scanned (oversized-file skip). A 180 MB generated/minified bundle hiding a secret
    // must never be silently dropped into a SAFE verdict.
    if (skippedTooLarge > 0) {
      const named = skippedTooLargeFiles.slice(0, 10).join(', ')
      const more = skippedTooLarge > skippedTooLargeFiles.length || skippedTooLargeFiles.length > 10
        ? ` (and others)`
        : ''
      logger.warn(
        `Scan INCOMPLETE: ${skippedTooLarge} file(s) skipped for exceeding the size limit — NOT scanned: ${named}${more}`
      )
      logger.warn(
        `These files were not checked. Split/minify-exclude them, or raise \`limits.maxFileSizeBytes\` in shipguard.policy.yml. Verdict is degraded — see \`degraded\`/\`degradedReasons\` in --json output (does not change the exit code).`
      )
    }

    // Symlink skip is a DEGRADED condition — LOUD warning that NAMES the symlink(s)
    // so the user knows exactly what subtree was NOT scanned (symlink reporting). A
    // symlinked `src/` (or any symlinked file/dir) can hide an entire project's real
    // source from the scan with no other signal; followSymbolicLinks:false itself is
    // correct and unchanged  — what changed is that
    // this is no longer silent.
    if (skippedSymlinks > 0) {
      const named = skippedSymlinkFiles.slice(0, 10).join(', ')
      const more = skippedSymlinks > skippedSymlinkFiles.length || skippedSymlinkFiles.length > 10
        ? ` (and others)`
        : ''
      logger.warn(
        `Scan INCOMPLETE: ${skippedSymlinks} symlink(s) not followed — NOT scanned: ${named}${more}`
      )
      logger.warn(
        `ShipGuard never follows symlinks (privacy moat — a symlink could point outside your project). If this path holds real source, replace the symlink with the real directory/file to have it scanned. Verdict is degraded — see \`degraded\`/\`degradedReasons\` in --json output (does not change the exit code).`
      )
    }

    // Binary skips are NORMAL (no source to scan) — informational only, but named
    // (symlink reporting: this file's own docs already admitted binary skips happen,
    // never named which files, unlike every other skip category).
    if (skippedBinary > 0) {
      const named = skippedBinaryFiles.slice(0, 10).join(', ')
      const more = skippedBinary > skippedBinaryFiles.length || skippedBinaryFiles.length > 10
        ? ` (and others)`
        : ''
      logger.info(`Files skipped (binary, normal): ${skippedBinary} — ${named}${more}`)
    }

    if (creditsRemaining !== undefined) {
      logger.info(`Credits remaining: ${creditsRemaining}`)
    }

    if (scanIdReused) {
      logger.info('Retry detected — reused the prior scanId (no double charge for this retry)')
    }

    if (degraded) {
      logger.warn('Scan ran in degraded mode — pro rules were unavailable')
    }

    // Truncation warning — loud, actionable
    if (truncatedByBounds) {
      logger.warn(
        `Scan was truncated: file count or total size limit was reached. ` +
        `Results are INCOMPLETE — add a \`.shipguardignore\` or edit \`shipguard.policy.yml\` limits.`
      )
      logger.warn(`Docs: ${goLink('docs')}`)
    }

    // Coverage line — honest statement of what was checked
    console.log(coverageLine())
    console.log('')

    // End-of-scan action footer — copy-paste commands, zero learning curve.
    // Rec #4: tips print BEFORE the panel. They used to sit after it, so the last
    // thing on screen was a list of suggestions and the verdict was ~70 lines up.
    const topRuleId = result.findings.length > 0 ? result.findings[0].id : undefined
    // isLoggedIn: heuristic — if pro rules loaded successfully we are authenticated
    const isLoggedIn = Boolean(opts.pro && !degraded)
    console.log(actionFooter({
      hasFindings: result.findings.length > 0,
      topRuleId,
      isLoggedIn,
    }))

    // Gamified verdict panel — LAST (rec #4). Carries the verdict, and now the report
    // path too, so nothing prints after it that could contradict its glyph.
    console.log(verdictPanel(
      result,
      elapsedMs,
      skippedTooLarge + skippedBinary + skippedSymlinks,
      result.findings,
      scanOptions.strict,
      reportPaths,
    ))
  }

  // Anonymous opt-out ping — privacy-preserving. Started here so the request overlaps with the
  // exit-code work below, and AWAITED (bounded, <= 1.5 s, never rejects) right before any explicit
  // process.exit so a --strict exit cannot drop it.
  // Payload (schema v2): version, verdict, duration bucket, ci flag, provenance, random install id (null in CI) ONLY.
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

  if (exitCode === EXIT_CODES.BLOCKED && !machineOutput && !quiet) {
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
  if (opts.checkRegressions && exitCode === EXIT_CODES.SAFE && (result.regressions?.length ?? 0) > 0) {
    exitCode = EXIT_CODES.BLOCKED
    if (!machineOutput && !quiet) {
      logger.warn(`--check-regressions: ${result.regressions?.length} previously-passing rule(s) now fail — exiting with code 1`)
    }
  }

  // Let the (bounded) ping finish before we may hard-exit. sendTelemetry never rejects.
  await telemetryDone

  if (exitCode !== EXIT_CODES.SAFE) {
    process.exit(exitCode)
  }
}
