import { Command } from 'commander'
import { EXIT_CODES } from '@agenticcli/shared'
import { loadPolicy } from '../core/policy.js'
import { logger } from '../utils/logger.js'
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

/** The schemaVersion the `scan --json` payload currently reports. Keep in sync with scan.ts. */
export const CURRENT_SCHEMA_VERSION = '5'

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
  degradeCodes: Array<{ code: string; meaning: string }>
  limits: {
    maxFiles: LimitEntry
    maxFileSizeBytes: LimitEntry
    maxTotalBytes: LimitEntry
    unanalyzableTypes: Array<{ type: string; behavior: string; machineSignal: string | null; verifiedBy: string | null }>
    /** Overall statement about whether these numbers have been measured. */
    verificationStatus: string
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
          '--pro request whose rule fetch failed (pass --allow-degraded to opt into a free ' +
          'scan fallback instead).',
      },
    ],
    degradeCodes: [
      { code: 'FILE_TOO_LARGE', meaning: 'One or more files exceeded the per-file size cap and were not scanned.' },
      { code: 'OUTPUT_TRUNCATED', meaning: 'The file-count or total-bytes ceiling was reached; collection stopped early.' },
      { code: 'CODEREF_SKIPPED', meaning: 'One or more Pro coderef rules need a newer CLI and were skipped.' },
      { code: 'PRO_RULES_UNAVAILABLE', meaning: 'Pro rules could not be fetched (auth, credits, rate limit, network).' },
      { code: 'INVALID_UTF8', meaning: 'One or more files were not valid UTF-8 and were skipped rather than mangled.' },
      { code: 'UNREADABLE_FILE', meaning: 'One or more files could not be read from disk.' },
      { code: 'COMPILE_FAILURE', meaning: 'A Pro rule bundle failed to compile; the whole bundle was refused rather than partly run.' },
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
          behavior: 'Skipped. A binary file has no source to scan.',
          // Deliberately no degrade signal: a binary skip is normal, not incomplete coverage.
          machineSignal: null,
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
          machineSignal: 'degradedReasons[].code === "UNREADABLE_FILE" when the path was reported as changed',
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
          behavior: 'Not collected: node_modules, dist, build, .next, coverage, .git, lockfiles, images/archives/media, and ShipGuard’s own artifacts.',
          machineSignal: null,
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
        logger.error(`Config error: ${error instanceof Error ? error.message : error}`)
        process.exit(EXIT_CODES.CONFIG_ERROR)
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
