import { Command } from 'commander'
import { EXIT_CODES } from '@agenticcli/shared'
import { loadPolicy } from '../core/policy.js'
import { logger } from '../utils/logger.js'
import { emitError } from '../utils/exit.js'
import { ERROR_CODES, OUTCOMES, NEXT_STEP_KINDS, WARNING_CODES, SCHEMA_VERSION, buildErrorEnvelope } from '../core/outcome.js'
import {
  DEFAULT_MAX_FILE_SIZE_BYTES,
  DEFAULT_MAX_FILES,
  DEFAULT_MAX_TOTAL_BYTES,
} from '../utils/fs.js'

/**
 * `shipguard schema --json`.
 *
 * Specification:
 *   "`shipguard schema --json`: machine-readable contract — schemaVersion, enum values,
 *    exit-code meanings, and the **limits block** (maxFiles, maxFileSize, unanalyzable
 *    types)"
 *
 * WHY: agents read local contracts, not doc sites. Today an agent has to hard-code what
 * `recommendation` can be, what exit 1 means, and where the file cap sits — every one of
 * those is a guess that silently rots. This is the surface where the constraints live, and
 * it is where the boundary round  writes its measured numbers.
 *
 * DELIBERATELY SMALL: this is the "small schema --json", NOT a capabilities
 * discovery surface. No negotiation, no registry, no feature flags.
 *
 * HONESTY RULE: every limit says where its value came from and whether it has been VERIFIED
 * by a real run. Until the boundary round runs, `verifiedBy` is null and `verified` is
 * false — publishing an unmeasured number as fact is exactly what this field exists to stop.
 */

declare const __SHIPGUARD_VERSION__: string | undefined

const CLI_VERSION =
  typeof __SHIPGUARD_VERSION__ !== 'undefined'
    ? __SHIPGUARD_VERSION__
    : (process.env.npm_package_version ?? '0.0.0-dev')

/** The schemaVersion the `scan --json` payload currently reports. */
export const CURRENT_SCHEMA_VERSION = SCHEMA_VERSION

export interface LimitEntry {
  /** Effective value for THIS project (policy-merged), or null when not a number. */
  value: number | null
  unit?: string
  /** 'default' or 'policy' — where the effective value came from. */
  source: 'default' | 'policy'
  /** What ShipGuard does when the limit is reached. */
  behaviorAtLimit: string
  /** How a machine detects it happened. null means there is no machine signal (by design). */
  machineSignal: string | null
  /**
   * Run id of the measurement that PROVED this row, or null when it has only been read out
   * of the code. Filled by the boundary/scale round.
   */
  verifiedBy: string | null
}

export interface SchemaContract {
  schemaVersion: string
  cliVersion: string
  contract: 'shipguard-scan-result'
  recommendation: {
    field: string
    values: string[]
    failClosed: string
    deprecatedMirrors: string[]
  }
  exitCodes: Array<{ code: number; name: string; meaning: string }>
  /** Exit-2 errors in machine mode: stdout holds exactly one object of this shape. */
  configError: { shape: string; when: string; codes: Array<{ code: string; meaning: string }> }
  degradeCodes: Array<{ code: string; meaning: string }>
  /** Verdict values of `verdict.value` (the deprecated top-level `recommendation` carries the same). */
  verdictValues: string[]
  /** Every error code of every command: exit code, cause, fix and what an agent does next. */
  errorCodes: Record<string, { exit: number; hostExit?: { claude: number; git: number }; cause: string; fix: string; agentAction: string }>
  /** The one decision table that picks `agentAction`; modifier rows have `precedence: null`. */
  outcomes: Array<{ precedence: number | null; outcome: string; exit: string; agentAction: string; nextStep: string }>
  degradedReasonCodes: Record<string, string>
  nextStepKinds: string[]
  warningCodes: Record<string, string>
  agentActions: string[]
  /** JSON Schema 2020-12 for the `scan --json` result (schemaVersion 7). */
  jsonSchema: Record<string, unknown>
  limits: {
    maxFiles: LimitEntry
    maxFileSizeBytes: LimitEntry
    maxTotalBytes: LimitEntry
    unanalyzableTypes: Array<{ type: string; behavior: string; machineSignal: string | null; verifiedBy: string | null }>
    /** Overall statement about whether these numbers have been measured. */
    verificationStatus: string
  }
}

/** JSON Schema (draft 2020-12) of the `scan --json` result: required keys and closed enums, not every leaf. */
export function buildScanJsonSchema(): Record<string, unknown> {
  const finding = {
    type: 'object',
    required: ['id', 'occurrence', 'title', 'severity', 'confidence', 'category', 'blocking', 'file', 'line', 'endLine', 'column', 'evidence', 'why', 'fix', 'notAVulnerabilityIf', 'suppressed', 'suppressionState', 'origin', 'matcherType', 'aiCodeTarget', 'cwe', 'recommendation'],
    properties: {
      occurrence: { type: 'string', pattern: '^[0-9a-f]{12}$' },
      severity: { enum: ['critical', 'high', 'medium', 'low', 'info'] },
      origin: { enum: ['general', 'rulebook'] },
      evidence: { oneOf: [{ type: 'null' }, { type: 'object', required: ['kind'], properties: { kind: { enum: ['secret', 'text'] } } }] },
      fix: { type: 'object', required: ['summary', 'certainty', 'code', 'steps', 'verify', 'effort'], properties: { certainty: { enum: ['stack-specific', 'generic'] } } },
    },
  }
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: 'shipguard scan --json (schemaVersion 7)',
    type: 'object',
    required: ['schemaVersion', 'cliVersion', 'runId', 'ok', 'verdict', 'exit', 'agentAction', 'rules', 'plan', 'findings', 'coverage', 'degraded', 'degradedReasons', 'warnings', 'nextSteps'],
    properties: {
      schemaVersion: { const: SCHEMA_VERSION },
      ok: { type: 'boolean' },
      verdict: {
        type: 'object',
        required: ['value', 'reason', 'blockingCount', 'findingCount', 'complete', 'summary', 'meaning'],
        properties: { value: { enum: ['SAFE_TO_SHIP', 'REVIEW_BEFORE_SHIP', 'DO_NOT_SHIP'] } },
      },
      exit: { type: 'object', required: ['code', 'strict', 'strictWouldExit'] },
      agentAction: { enum: ['proceed', 'fix_and_rerun', 'retry', 'ask_human', 'stop'] },
      findings: { type: 'array', items: finding },
      nextSteps: {
        type: 'array',
        items: { type: 'object', required: ['order', 'kind', 'label', 'command', 'safe', 'blocking'], properties: { kind: { enum: [...NEXT_STEP_KINDS] } } },
      },
      plan: {
        type: 'object',
        required: ['status', 'reason', 'command', 'link', 'server', 'recommendation', 'usageNote', 'receiptNote'],
        properties: { recommendation: { type: 'object', required: ['eligible', 'relay', 'kind', 'reason', 'sentence', 'next', 'mute'] } },
      },
    },
  }
}

export function buildSchemaContract(limits: {
  maxFiles: number
  maxFileSizeBytes: number
  maxTotalBytes: number
}): SchemaContract {
  // Per-limit provenance, decided by comparing the effective value to the shipped default.
  // `policy.limits` is always populated (loadPolicy merges defaults in), so testing it for
  // presence would label every value "policy" — a small lie in a document whose whole job
  // is to be trustworthy about where its numbers came from.
  const src = (value: number, fallback: number): LimitEntry['source'] =>
    value === fallback ? 'default' : 'policy'
  return {
    schemaVersion: CURRENT_SCHEMA_VERSION,
    cliVersion: CLI_VERSION,
    contract: 'shipguard-scan-result',
    verdictValues: ['SAFE_TO_SHIP', 'REVIEW_BEFORE_SHIP', 'DO_NOT_SHIP'],
    agentActions: ['proceed', 'fix_and_rerun', 'retry', 'ask_human', 'stop'],
    errorCodes: Object.fromEntries(
      Object.entries(ERROR_CODES as Record<string, (typeof ERROR_CODES)[keyof typeof ERROR_CODES]>).map(([code, e]) => [
        code,
        {
          exit: e.exit,
          ...('exitGit' in e ? { hostExit: { claude: e.exit, git: e.exitGit } } : {}),
          cause: e.cause,
          fix: e.fix,
          agentAction: e.agentAction,
        },
      ]),
    ),
    outcomes: OUTCOMES.map((o) => ({ ...o })),
    degradedReasonCodes: Object.fromEntries(
      [
        ['FILE_TOO_LARGE', 'A file exceeded the per-file size cap and was not scanned.'],
        ['UNSCANNED_UNKNOWN_BINARY', 'A file holds NUL or control data no text reading explains, with no sign of a known binary format; not scanned.'],
        ['FILE_UNREADABLE', 'A file could not be read (permission, or removed during the scan). Printed as UNREADABLE_FILE by 0.12.'],
        ['INVALID_UTF8', 'A file was not valid UTF-8 and was skipped rather than mangled.'],
        ['OUTPUT_TRUNCATED', 'The file or byte limit was reached; the remaining files were not scanned.'],
        ['SYMLINK_SKIPPED', 'A symlink was not followed (privacy) and was not scanned.'],
        ['CODEREF_SKIPPED', 'Rulebook rules that need a newer ShipGuard were skipped.'],
        ['PRO_RULES_UNAVAILABLE', 'The full rulebook could not be obtained.'],
        ['COMPILE_FAILURE', 'A rulebook bundle failed to compile and was refused.'],
        ['NO_FILES_SCANNED', 'Zero files were scanned: a scan that read nothing is never SAFE_TO_SHIP.'],
      ],
    ),
    nextStepKinds: [...NEXT_STEP_KINDS],
    warningCodes: { ...WARNING_CODES },
    jsonSchema: buildScanJsonSchema(),
    recommendation: {
      field: 'recommendation',
      // Closed set. Deliberately NOT extended for degraded scans — a new value would be a
      // fail-open trap for the very common `recommendation !== 'DO_NOT_SHIP'` parser.
      values: ['SAFE_TO_SHIP', 'REVIEW_BEFORE_SHIP', 'DO_NOT_SHIP'],
      failClosed:
        'When `degraded` is true the recommendation is ALWAYS DO_NOT_SHIP — a scan that ' +
        'did not read everything it was asked to read cannot report that shipping is safe. ' +
        'The exit code is unaffected: ShipGuard is passive by default and still exits 0 ' +
        'while saying this. Only --strict turns it into a hard stop.',
      deprecatedMirrors: ['riskScore.recommendation'],
    },
    configError: {
      shape: '{ "schemaVersion": "7", "ok": false, "error": { "code", "message", "cause", "fix", "command" }, "agentAction": string, "exit": { "code": number } }',
      when: 'every error of every command with --json or --sarif (exit 2, 3 or 130): stdout is exactly this one JSON object; the same error is on stderr as the one error template.',
      codes: Object.entries(ERROR_CODES as Record<string, (typeof ERROR_CODES)[keyof typeof ERROR_CODES]>)
        .filter(([, e]) => e.exit === 2)
        .map(([code, e]) => ({ code, meaning: e.cause })),
    },
    exitCodes: [
      {
        code: EXIT_CODES.SAFE,
        name: 'COMPLETED',
        meaning:
          'The scan ran. The verdict is in the `recommendation` field — NOT in this exit ' +
          'code. Returned even when findings are blocking and even when `degraded` is true.',
      },
      {
        code: EXIT_CODES.BLOCKED,
        name: 'BLOCKED',
        meaning:
          'Opt-in hard stop. Returned only with --strict, when there is at least one ' +
          'blocking finding OR the scan did not finish (`degraded: true`); or with ' +
          '--check-regressions when a previously-passing rule now fails.',
      },
      {
        code: EXIT_CODES.CONFIG_ERROR,
        name: 'CONFIG_ERROR',
        meaning:
          'Bad policy file, unknown flag, or a non-project directory without --all. Never ' +
          'used for a degraded-but-completed scan.',
      },
      {
        code: EXIT_CODES.RUNTIME_ERROR,
        name: 'RUNTIME_ERROR',
        meaning:
          'The scan could not meaningfully run at all — zero rules applied, or an explicit ' +
          '--pro request whose rulebook could not be obtained (pass --allow-degraded to opt into a ' +
          'general-rules fallback instead), or an environment, network, sign-in or internal error.',
      },
    ],
    degradeCodes: [
      { code: 'FILE_TOO_LARGE', meaning: 'One or more files exceeded the per-file size cap and were not scanned.' },
      { code: 'OUTPUT_TRUNCATED', meaning: 'The file-count or total-bytes ceiling was reached; collection stopped early.' },
      { code: 'CODEREF_SKIPPED', meaning: 'One or more rulebook coderef rules need a newer CLI and were skipped.' },
      { code: 'PRO_RULES_UNAVAILABLE', meaning: 'The full rulebook could not be obtained (sign-in, rate limit, network or server).' },
      { code: 'INVALID_UTF8', meaning: 'One or more files were not valid UTF-8 and were skipped rather than mangled.' },
      { code: 'UNREADABLE_FILE', meaning: 'One or more files could not be read from disk.' },
      { code: 'COMPILE_FAILURE', meaning: 'A rulebook bundle failed to compile; the whole bundle was refused rather than partly run.' },
      { code: 'SYMLINK_SKIPPED', meaning: 'One or more symlinks were not followed (privacy) and were not scanned.' },
      { code: 'UNSCANNED_UNKNOWN_BINARY', meaning: 'One or more files hold NUL or control data that no text reading explains and show no sign of a known binary format; they were not scanned. Add their paths to ignore.paths if they are safe.' },
      { code: 'NO_FILES_SCANNED', meaning: 'Zero files were scanned (empty tree, everything ignored or binary, or --changed where every changed file was ignored or unreadable). A scan that read nothing is never SAFE_TO_SHIP. --changed when git reports no changed files is the same code and also sets coverage.changed.nothingToCheck: true (nothing was scanned: not safe, --strict exits 1).' },
    ],
    limits: {
      maxFiles: {
        value: limits.maxFiles,
        unit: 'files',
        source: src(limits.maxFiles, DEFAULT_MAX_FILES),
        behaviorAtLimit: 'Collection stops; the remaining files are NOT scanned.',
        machineSignal: 'degraded:true + degradedReasons[].code === "OUTPUT_TRUNCATED"',
        verifiedBy: null,
      },
      maxFileSizeBytes: {
        value: limits.maxFileSizeBytes,
        unit: 'bytes',
        source: src(limits.maxFileSizeBytes, DEFAULT_MAX_FILE_SIZE_BYTES),
        behaviorAtLimit: 'The individual file is skipped unread; the rest of the scan continues.',
        machineSignal: 'degraded:true + degradedReasons[].code === "FILE_TOO_LARGE" (detail names the files)',
        verifiedBy: null,
      },
      maxTotalBytes: {
        value: limits.maxTotalBytes,
        unit: 'bytes',
        source: src(limits.maxTotalBytes, DEFAULT_MAX_TOTAL_BYTES),
        behaviorAtLimit: 'Collection stops; the remaining files are NOT scanned.',
        machineSignal: 'degraded:true + degradedReasons[].code === "OUTPUT_TRUNCATED"',
        verifiedBy: null,
      },
      unanalyzableTypes: [
        {
          type: 'binary',
          behavior: 'Real binaries (known format AND mostly non-printable content) are skipped and counted. The file name and extension are never used. SQLite and TAR files are scanned through their ASCII strings.',
          // Counted, not degraded, except when nothing at all was scanned (NO_FILES_SCANNED).
          machineSignal: 'coverage.skipped.binary (no degrade); degradedReasons[].code === "NO_FILES_SCANNED" when nothing was scanned',
          verifiedBy: null,
        },
        {
          type: 'utf16',
          behavior: 'Decoded and scanned (BOM, and BOM-less when the bytes fit UTF-16). Findings use code-unit columns of the decoded text.',
          machineSignal: 'coverage.decoded.utf16',
          verifiedBy: null,
        },
        {
          type: 'nul-in-text',
          behavior: 'A text file with a few stray NUL bytes is scanned with each NUL read as one space (lines and columns unchanged). A key split by a NUL byte is not matched.',
          machineSignal: 'coverage.decoded.nulSubstituted',
          verifiedBy: null,
        },
        {
          type: 'unknown-binary',
          behavior: 'NUL or control data that no reading explains and with no real-binary evidence: skipped and the scan is degraded.',
          machineSignal: 'degradedReasons[].code === "UNSCANNED_UNKNOWN_BINARY"',
          verifiedBy: null,
        },
        {
          type: 'special',
          behavior: 'FIFO, socket and device nodes hold no stored content: counted, not read, not degraded.',
          machineSignal: 'coverage.skipped.special',
          verifiedBy: null,
        },
        {
          type: 'invalid-utf8',
          behavior: 'Skipped unread — decoding with replacement characters can destroy a secret that straddles the bad bytes.',
          machineSignal: 'degradedReasons[].code === "INVALID_UTF8"',
          verifiedBy: null,
        },
        {
          type: 'symlink',
          behavior: 'Never followed. A symlink pointing out of the project root is refused.',
          machineSignal: 'degradedReasons[].code === "SYMLINK_SKIPPED" (full scan); "UNREADABLE_FILE" when a changed path resolves outside the root',
          verifiedBy: null,
        },
        {
          type: 'unreadable',
          behavior: 'Skipped — permission error, deleted mid-scan, dangling symlink.',
          machineSignal: 'degradedReasons[].code === "UNREADABLE_FILE"',
          verifiedBy: null,
        },
        {
          type: 'ignored-by-default',
          behavior: 'Not collected: node_modules, dist, build, .next, coverage, .git, vendor, tmp, out, lockfiles, *.log, *.min.js, *.map and ShipGuard’s own artifacts. Images and other media are NOT ignored: they are classified by content.',
          machineSignal: 'coverage.ignoredByDefault (counts per rule); coverage.ignoredByUser',
          verifiedBy: null,
        },
      ],
      verificationStatus:
        'UNVERIFIED — these values are read from configuration, not measured. The ' +
        'boundary/scale round fills every verifiedBy with the run id that proved it. ' +
        'Until then, treat them as declared limits, not observed ones.',
    },
  }
}

export function schemaCommand(): Command {
  return new Command('schema')
    .description('Print the machine-readable scan contract: verdict values, exit codes, and scan limits')
    .option('--json', 'Output the contract as JSON (the machine-readable form)')
    .addHelpText('after', `
Run this inside a project to see the limits THAT project actually uses (its
shipguard.policy.yml is merged in); run it anywhere else for the defaults.

Examples:
  shipguard schema --json            The contract, for an agent or a script
  shipguard schema                   The same thing, readable

Exit codes:
  0  Printed.
  2  Config error — the project's policy file could not be read.`)
    .action(async (opts: { json?: boolean }) => {
      const cwd = process.cwd()

      let contract: SchemaContract
      try {
        const policy = await loadPolicy(cwd)
        contract = buildSchemaContract({
          maxFiles: policy.limits?.maxFiles ?? DEFAULT_MAX_FILES,
          maxFileSizeBytes: policy.limits?.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES,
          maxTotalBytes: policy.limits?.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        emitError(
          buildErrorEnvelope({
            code: 'INVALID_POLICY',
            message: 'shipguard.policy.yml could not be read.',
            cliVersion: CLI_VERSION,
            cause: message,
            extra: { file: 'shipguard.policy.yml' },
          }),
          { machine: Boolean(opts.json) },
        )
        return
      }

      if (opts.json) {
        console.log(JSON.stringify(contract, null, 2))
        return
      }

      console.log(renderSchemaHuman(contract))
    })
}

/** Readable rendering of the same contract — same facts, no second source of truth. */
export function renderSchemaHuman(c: SchemaContract): string {
  const lines: string[] = []
  lines.push(`ShipGuard scan contract — schemaVersion ${c.schemaVersion} (CLI ${c.cliVersion})`)
  lines.push('')
  lines.push(`Verdict field: ${c.recommendation.field}`)
  lines.push(`  Values: ${c.recommendation.values.join(', ')}`)
  lines.push(`  Fail-closed: ${c.recommendation.failClosed}`)
  lines.push(`  Deprecated copies: ${c.recommendation.deprecatedMirrors.join(', ')}`)
  lines.push('')
  lines.push('Exit codes:')
  for (const e of c.exitCodes) lines.push(`  ${e.code}  ${e.name} — ${e.meaning}`)
  lines.push('')
  lines.push(`Errors with --json/--sarif: stdout is ${c.configError.shape}`)
  lines.push('Every error code (exit, what an agent does next):')
  for (const [code, e] of Object.entries(c.errorCodes)) lines.push(`  ${code} [exit ${e.exit}, ${e.agentAction}] — ${e.cause}. Fix: ${e.fix}`)
  lines.push('')
  lines.push('Limits:')
  for (const [name, entry] of Object.entries(c.limits)) {
    if (name === 'unanalyzableTypes' || name === 'verificationStatus') continue
    const l = entry as LimitEntry
    lines.push(`  ${name}: ${l.value} ${l.unit ?? ''} (${l.source})`)
    lines.push(`    at the limit: ${l.behaviorAtLimit}`)
    lines.push(`    machine signal: ${l.machineSignal ?? 'none'}`)
  }
  lines.push('')
  lines.push('File types that are not analyzed:')
  for (const t of c.limits.unanalyzableTypes) lines.push(`  ${t.type} — ${t.behavior}`)
  lines.push('')
  lines.push(c.limits.verificationStatus)
  return lines.join('\n')
}
