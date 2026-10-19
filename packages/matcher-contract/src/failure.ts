// Task A.8 — Failure policy: DegradedReason enum, ScanOutcome type, resolveExitCode.
//
// DESIGN DECISIONS
// ================
// 1. DegradedReason is an object literal used as a const enum (not a TS enum)
//    so that values are plain strings that survive tsup tree-shaking and are
//    directly serializable to JSON without special transforms.  Each key equals
//    its value — the object IS the lookup table.
//
// 2. Exit code semantics mirror constants.ts:9-14 + scan.ts:54-67 exactly:
//      0 = clean (no degradation, no blocking findings, or blocking not --strict)
//      1 = blocked under --strict (hasBlockingFindings && strict)
//      2 = config-degraded (bundle compile issues, cap, attestation config errors)
//      3 = runtime error (engine exception, unreadable file, invalid UTF-8,
//              coderef mismatch, missing attestation at runtime, manifest mismatch)
//   Priority: exit 1 wins over exit 2 (blocking+strict is the highest signal
//   a scan can return — it means "definitely blocked, run was incomplete too").
//   Exit 1 also wins over exit 3 (blocking finding is actionable for the user).
//
// 3. Degraded reasons split into two exit-code classes:
//      CONFIG-DEGRADED (exit 2): compile-failure, cap-exceeded
//        — problems that prevent the scan from running the full rule set
//          but are not I/O or runtime crashes.
//      RUNTIME-ERROR (exit 3): engine-exception, unreadable-file, invalid-utf8,
//          coderef-mismatch, missing-attestation, bundle-or-manifest-mismatch
//        — problems that indicate a runtime failure or security concern.
//
// 4. ANY degraded reason → exit code ≠ 0.  NEVER exit 0 on a degraded scan.
//    This is the primary contract: false-negative risk is the worst outcome.
//
// 5. Zero new runtime deps: pure TS, no imports from outside this package.

// ---------------------------------------------------------------------------
// DegradedReason — canonical string enum (object-as-enum pattern)
// ---------------------------------------------------------------------------

/**
 * Canonical degraded-reason identifiers.
 *
 * These strings appear in scan results, log lines, and exit-code mappings.
 * They are kept as plain string values (not numeric enum members) so they
 * serialise directly to JSON without transforms.
 *
 * Key = value by convention so that code can write `DegradedReason['cap-exceeded']`
 * and get the string `"cap-exceeded"` back — no translation table needed.
 */
export const DegradedReason = {
  /**
   * A rule or anti-pattern failed to compile (e.g. invalid regex syntax
   * that slipped past Gate B/C validation, or a flag rejected at runtime).
   * Config-degraded class → exit 2.
   */
  'compile-failure': 'compile-failure',

  /**
   * The delivered rule bundle or manifest does not match the attested corpus
   * (completeness check, hash mismatch, or multiset inequality).
   * Runtime-error class → exit 3.
   */
  'bundle-or-manifest-mismatch': 'bundle-or-manifest-mismatch',

  /**
   * The bundle response is missing a required corpusAttestation, or the
   * attestation is invalid / signed by the wrong key.
   * Runtime-error class → exit 3.
   */
  'missing-attestation': 'missing-attestation',

  /**
   * An uncaught exception occurred inside the matching engine during a scan.
   * Runtime-error class → exit 3.
   */
  'engine-exception': 'engine-exception',

  /**
   * A file could not be read from disk (permission error, deleted during scan,
   * I/O error).  The file is skipped but the scan is marked degraded.
   * Runtime-error class → exit 3.
   */
  'unreadable-file': 'unreadable-file',

  /**
   * A file contained invalid UTF-8 byte sequences.  TextDecoder(fatal:true)
   * threw; the file is skipped but the scan is marked degraded to prevent
   * silent false-negatives (secrets straddling an invalid boundary).
   * Runtime-error class → exit 3.
   */
  'invalid-utf8': 'invalid-utf8',

  /**
   * A scan-time cap was exceeded (maxFiles, maxTotalBytes, maxRules,
   * maxPatternsPerRule, maxTotalPatternBytes, or maxFindings).
   * Config-degraded class → exit 2.
   */
  'cap-exceeded': 'cap-exceeded',

  /**
   * A coderef module's checksum does not match the expected value in the
   * checksum manifest.  The module is considered tampered and the scan is
   * aborted.  Runtime-error class → exit 3.
   */
  'coderef-mismatch': 'coderef-mismatch',
} as const

/** Union type of all valid degraded reason strings. */
export type DegradedReasonValue = (typeof DegradedReason)[keyof typeof DegradedReason]

// ---------------------------------------------------------------------------
// Exit-code classification helpers (internal)
// ---------------------------------------------------------------------------

/**
 * Reasons that map to exit code 2 (config-degraded).
 * Problems that prevent a full scan but are not runtime crashes.
 */
const CONFIG_DEGRADED_REASONS: ReadonlySet<string> = new Set<DegradedReasonValue>([
  DegradedReason['compile-failure'],
  DegradedReason['cap-exceeded'],
])

/**
 * Resolve the exit-code class for a given degraded reason.
 *
 * - Config-degraded reasons → 2
 * - All other degraded reasons → 3 (runtime error)
 *
 * This function is INTERNAL; use resolveExitCode for the full decision.
 */
function degradedExitCode(reason: string): 2 | 3 {
  return CONFIG_DEGRADED_REASONS.has(reason) ? 2 : 3
}

// ---------------------------------------------------------------------------
// ScanOutcome — the input to resolveExitCode
// ---------------------------------------------------------------------------

/**
 * Summary of a completed (or aborted) scan run.
 *
 * `resolveExitCode` maps this to the CLI exit code.
 */
export interface ScanOutcome {
  /**
   * Whether the scan was degraded (i.e. did not complete a full clean run).
   * MUST be true whenever any DegradedReason was encountered.
   */
  degraded: boolean

  /**
   * The canonical reason for the degradation.
   * Required when `degraded === true`; must be undefined when `degraded === false`.
   */
  degradedReason?: DegradedReasonValue

  /**
   * Whether any blocking finding (severity=error with blocking=true) was
   * produced during the scan.
   */
  hasBlockingFindings: boolean
}

// ---------------------------------------------------------------------------
// resolveExitCode — the canonical exit-code mapping
// ---------------------------------------------------------------------------

/**
 * Determine the CLI process exit code for a completed scan.
 *
 * ## Exit code semantics (matches constants.ts:9-14 / scan.ts:54-67)
 *
 * | Code | Meaning                                              |
 * |------|------------------------------------------------------|
 * | 0    | Clean scan — no degradation, no blocking findings    |
 * | 1    | Blocked — `--strict` mode + hasBlockingFindings      |
 * | 2    | Config-degraded — compile failure, cap exceeded      |
 * | 3    | Runtime error — engine exception, bad bytes, tamper  |
 *
 * ## Priority rule (from scan.ts:54-67)
 * Exit 1 WINS over exit 2 and exit 3 when all three conditions hold:
 * blocking findings present AND strict mode AND any degradation.
 *
 * Rationale: a blocked finding is the most actionable signal for the user.
 * A degraded scan that still produced a blocking finding must be reported
 * as blocked (exit 1) so that CI gates trigger.  The degradation is still
 * visible in the scan output.
 *
 * ## INVARIANT
 * A degraded scan NEVER produces exit 0.  ANY `degraded === true` → exit ≥ 2
 * (unless exit 1 applies first).
 *
 * @param outcome - The scan outcome to map.
 * @param strict  - Whether the CLI was invoked with `--strict`.
 * @returns The exit code: 0, 1, 2, or 3.
 */
export function resolveExitCode(outcome: ScanOutcome, strict: boolean): 0 | 1 | 2 | 3 {
  // Exit 1 wins: blocking + --strict → highest-priority signal
  if (strict && outcome.hasBlockingFindings) {
    return 1
  }

  // Degraded scan → NEVER 0; resolve to 2 or 3 by reason class
  if (outcome.degraded) {
    if (outcome.degradedReason !== undefined) {
      return degradedExitCode(outcome.degradedReason)
    }
    // Degraded but no specific reason provided — default to runtime error (3)
    // This should not happen in practice; fail loud as exit 3 rather than 0.
    return 3
  }

  // Clean scan
  return 0
}
