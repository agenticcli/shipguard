export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type CheckCategory = 'secrets' | 'auth' | 'payments' | 'database' | 'deployment' | 'injection' | 'supply-chain' | 'crypto' | 'config'
export type Recommendation = 'SAFE_TO_SHIP' | 'REVIEW_BEFORE_SHIP' | 'DO_NOT_SHIP'
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW'

export interface Finding {
  id: string
  title: string
  severity: Severity
  category: CheckCategory
  file: string
  line?: number
  /**
   * 1-based column of the match start on its line (UTF-16 code units from the
   * start of the line after the preceding '\n').  Populated by the pro-scanner
   * via the matcher-contract adapter.
   *
   * Since 2026-08-04 this is populated for the BUNDLED CORPUS rules too — they run through
   * the same adapter on every offline scan. Still absent on findings from the hand-written
   * check modules, which have no per-match position data.
   */
  column?: number
  evidence?: string
  explanation: string
  recommendation: string
  blocking: boolean
  fix?: string
  confidence?: Confidence
  aiCodeTarget?: boolean
  suppressed?: boolean
  cwe?: string[]
  /**
   * Per-occurrence suppression state from the contract's CanonicalFinding.
   * - "active"    — a real finding; anti-pattern did NOT match this occurrence's line.
   * - "suppressed" — anti-pattern matched the occurrence's line; retained but non-blocking.
   * Populated for pro findings and, since 2026-08-04, for the bundled corpus rules that
   * run on every offline scan. Absent on findings from the hand-written check modules,
   * which use the shipguard-ignore comment mechanism instead.
   */
  suppressionState?: 'active' | 'suppressed'
  /**
   * The releaseId of the attested rule bundle that produced this finding.
   * Populated by the pro-scanner once Layer-1 attestation is active (Phase C).
   * Absent on free-tier findings and on pre-Phase-C pro findings.
   */
  releaseId?: string
  /**
   * Discriminant of the rule's Matcher type: "pattern" | "file-presence" | "file-relationship".
   * Populated by the pro-scanner via the matcher-contract adapter, and
   * since 2026-08-04 by the bundled corpus rules that run on every offline scan. Absent on
   * findings from the hand-written check modules.
   */
  matcherType?: string
}

export interface FileInfo {
  path: string
  content: string
  relativePath: string
}

export interface PolicyLimits {
  /** Max size in bytes for a single file (default 512 KB). Files over this are skipped. */
  maxFileSizeBytes: number
  /** Max total bytes accumulated across all files (default 256 MB). Stops collection if exceeded. */
  maxTotalBytes: number
  /** Max file count before stopping collection (default 5000). */
  maxFiles: number
}

export interface Policy {
  version: number
  project: {
    name: string
    framework: string
    risk_profile: string
  }
  scan: {
    changed_files_only: boolean
    generate_report: boolean
  }
  block: string[]
  warn: string[]
  ignore: {
    paths: string[]
  }
  report: {
    output: string
    format: string
  }
  /** Optional file-read limits to prevent OOM on large codebases. Merged with defaults if absent. */
  limits?: PolicyLimits
  /**
   * observability/audit-trail store config.
   * Optional — a scan with no `history` block uses the default path and unlimited retention.
   */
  history?: {
    /** Override for the local history store path. `SHIPGUARD_HISTORY_PATH` env wins over this. */
    path?: string
    /** Optional retention window in days. Unset = keep forever (§1.7). */
    retention_days?: number
    /**
     * ScanId reuse — override for the scanId retry-idempotency reuse window, in
     * minutes. `SHIPGUARD_SCAN_ID_REUSE_WINDOW_MINUTES` env wins over this; unset uses
     * `DEFAULT_SCAN_ID_REUSE_WINDOW_MINUTES` (constants.ts).
     */
    scan_id_reuse_window_minutes?: number
  }
}

/**
 * The local audit-trail/history store's persistence outcome for THIS scan.
 * The hard rule this type exists to enforce:
 * a scan may only claim a regression verdict when `stateStatus` is `complete` for both the
 * current run and whatever it was compared against.
 *
 *   complete    — history was read (for comparison) and written (for this scan) successfully.
 *   unavailable — history could not be read/written this run (lock timeout, disk full,
 *                 permission error, unsupported Node runtime). NOT set on a normal first-ever
 *                 write (a brand-new file being created is the ordinary case, not a failure).
 *   corrupt     — the file opened but failed `PRAGMA integrity_check`, or a migration
 *                 failed partway (forward-only; the original file is left untouched).
 */
export type StateStatus = 'complete' | 'unavailable' | 'corrupt'

/** How a repo's identity was resolved for the history store (§2.1). */
export type RepoIdKind = 'root-commit' | 'remote-url' | 'fallback-uuid'

/**
 * One instance of the ONE regression claim this schema exists to serve (§4):
 * "a previously-passing blocking rule now fails, under the same scope fingerprint,
 * within the same corpus release family."
 */
export interface RegressionEntry {
  ruleId: string
  baselineScanId: string
  baselineTimestamp: string
  currentScanId: string
  corpusVersion: { baseline: string; current: string }
  scopeFingerprint: string
}

/**
 * A rule that CANNOT be safely compared pass→fail across the two scans because the rule
 * itself (not the user's code) changed between them — new since baseline, withdrawn since
 * baseline, or its own `ruleVersion` changed. Reported separately from `regressions` so a
 * corpus/rule update is never misread as "you regressed" .
 */
export interface CoverageChangedEntry {
  ruleId: string
  reason: 'new-since-baseline' | 'withdrawn-since-baseline' | 'rule-version-changed'
  baselineRuleVersion?: string
  currentRuleVersion?: string
}

/** Why the regression comparison did not run at all for this scan. */
export type RegressionCheckSkippedReason =
  | 'no-baseline'
  | 'state-unavailable'
  | 'scope-mismatch'

export interface CheckModule {
  id: string
  name: string
  run(files: FileInfo[], policy: Policy): Finding[]
}

export interface RiskScore {
  score: number
  /**
   * @deprecated MIRROR of the top-level `ScanResult.recommendation` — read that instead.
   *
   * Note: the verdict existed in two
   * places, so patching one desynchronized the other for whichever field a consumer
   * happened to parse. Since schemaVersion 5 this copy is written ONLY by
   * `applyVerdict()` (packages/cli/src/core/verdict.ts) as an exact mirror, never
   * computed independently. It is kept for one minor version so existing parsers do
   * not break, and is scheduled for removal at the next schemaVersion bump.
   */
  recommendation: Recommendation
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  infoCount: number
  blockingCount: number
}

/**
 * Stable codes for each degrade source.
 * Additive — new codes may be added in future minor versions.
 * Consumers MUST handle unknown codes gracefully (treat as opaque string).
 *
 *   FILE_TOO_LARGE        — one or more files exceeded the per-file size cap and were not scanned.
 *   OUTPUT_TRUNCATED      — total file count or byte ceiling was reached; collection stopped early.
 *   CODEREF_SKIPPED       — one or more pro coderef rules were skipped (minCliVersion > installed).
 *   PRO_RULES_UNAVAILABLE — pro rules could not be fetched (auth failure, network error, etc.).
 *   INVALID_UTF8          — one or more files contained invalid UTF-8 and were skipped
 *                           (scanning with replacement chars risks false-negative secret detection).
 *   UNREADABLE_FILE       — one or more files could not be read from disk (permission error,
 *                           deleted during scan, dangling symlink, etc.).
 *   COMPILE_FAILURE       — one or more pro rule bundles failed to compile (invalid regex /
 *                           invalid anti-pattern / invalid flags) — the whole bundle is degraded
 *                           rather than running a partially-compiled rule (fail-open fix).
 *   SYMLINK_SKIPPED       — one or more symlinks were discovered but not followed
 *                            and were
 *                           therefore NOT scanned. A skipped symlink can hide an entire subtree
 *                           (e.g. a symlinked `src/`) from the scan with no other signal.
 */
export type DegradeCode =
  | 'FILE_TOO_LARGE'
  | 'OUTPUT_TRUNCATED'
  | 'CODEREF_SKIPPED'
  | 'PRO_RULES_UNAVAILABLE'
  | 'INVALID_UTF8'
  | 'UNREADABLE_FILE'
  | 'COMPILE_FAILURE'
  | 'SYMLINK_SKIPPED'

/** A single reason contributing to a degraded scan. */
export interface DegradeReason {
  /** Stable machine-readable code — safe to switch/if-chain in agent logic. */
  code: DegradeCode
  /** Human-readable detail. Content may change across releases; key on `code`, not `detail`. */
  detail?: string
}

export interface ScanResult {
  findings: Finding[]
  riskScore: RiskScore
  filesScanned: number
  timestamp: string
  policyUsed: string
  /**
   * THE verdict. Always present on a real scan (stamped by `applyVerdict()`); optional
   * only so hand-built fixtures/tests can omit it.
   *
   * Fail-closed since schemaVersion 5 : when `degraded` is true this
   * is ALWAYS `DO_NOT_SHIP`, because a scan that did not read everything it was asked to
   * read cannot report that shipping is safe. The exit code is unaffected — ShipGuard is
   * passive by default and still exits 0 while saying this; only `--strict` blocks.
   */
  recommendation?: Recommendation
  rulesApplied?: number
  rulesBreakdown?: Record<string, number>
  schemaVersion?: string
  degraded?: boolean
  /**
   * Machine-readable reasons for degradation — present when `degraded` is true.
   * Each entry carries a stable `code` (safe to key on) and an optional human `detail`.
   * Empty array means the boolean was set for an unknown/legacy reason (defensive).
   * Consumers SHOULD check `degraded` first; `degradedReasons` provides the WHY.
   */
  degradedReasons?: DegradeReason[]
  creditsWarning?: boolean
  rulesVersion?: string
  /**
   * RECEIPT FIELDS (schemaVersion 5). Together they let anyone re-derive
   * what this verdict was about, without ShipGuard's cooperation and without a signing
   * pipeline. Field-mappable onto an in-toto verification predicate / SLSA VSA when
   * verifiers exist in the wild — being attestation-READY is the deliberate stopping point
   *.
   */
  /** Stable id for THIS run — the same id used for retry idempotency and the report filename. */
  runId?: string
  /**
   * SHA-256 over every file this scan actually read: `sha256(path + NUL + sha256(content))`
   * folded in sorted path order. Two scans with the same treeDigest looked at exactly the
   * same bytes, so a differing verdict is a ShipGuard change, not a code change. Absent when
   * no files were read.
   */
  treeDigest?: string
  /** The CLI build that produced this verdict. */
  cliVersion?: string
  aiCodeIssues?: number
  /**
   * Observability store fields — additive, non-breaking to the frozen --json contract.
   */
  /** Persistence outcome of the local history store for this scan. Absent on very old CLI builds. */
  stateStatus?: StateStatus
  /** true when the regression comparison did not run (no baseline, DB unavailable/corrupt, or scope mismatch). */
  regressionCheckSkipped?: boolean
  /** Machine-readable reason, present only when `regressionCheckSkipped` is true. */
  regressionCheckSkippedReason?: RegressionCheckSkippedReason
  /** Present (possibly empty) only when the comparison actually ran (`regressionCheckSkipped` is false). */
  regressions?: RegressionEntry[]
  /** Present (possibly empty) only when the comparison actually ran (`regressionCheckSkipped` is false). */
  coverageChanged?: CoverageChangedEntry[]
  /**
   * ScanId reuse — true when THIS scan's scanId was reused from a prior local
   * reservation (same repo + requested scope + working-tree content, within the reuse
   * window) rather than freshly minted. Lets a retrying agent confirm the retry idempotency
   * guarantee actually engaged. Absent on CLI builds predating this field — always populated
   * (true/false) on builds that have it. See history/scan-id.ts.
   */
  scanIdReused?: boolean
}

export interface ScanOptions {
  changedOnly: boolean
  generateReport: boolean
  strict: boolean
  json: boolean
  reportPath: string
}

export interface QualityGateRule {
  id: string
  framework: string[]
  frameworkVersion?: string
  category: CheckCategory
  tier: 'free' | 'pro' | 'enterprise'
  severity: Severity
  subcategory?: 'vuln' | 'audit' | 'secure-default'
  confidence?: Confidence
  action?: 'block' | 'warn' | 'monitor'
  findingType?: 'vulnerability' | 'hotspot'
  version?: string
  stage?: 'draft' | 'beta' | 'canary' | 'ga' | 'deprecated' | 'archived'
  fix?: string
  cwe?: string[]
  owasp?: string[]
  compliance?: string[]
  aiCodeTarget?: boolean
  source?: string
  sourceLicense?: 'MIT' | 'Apache-2.0' | 'original' | 'proprietary'
  url?: string
  matcher: {
    type: 'pattern' | 'file-presence' | 'file-relationship' | 'config-value'
    fileGlob: string
    patterns: string[]
    antiPatterns: string[]
    flags?: string
    context?: { requiresFile?: string; requiresPattern?: string }
  }
  explanation: string
  recommendation: string
  references?: string[]
}

export interface AuthCredentials {
  accessToken: string
  refreshToken: string
  expiresAt: number
  apiUrl: string
}

export interface RuleBundlePayload {
  rules: QualityGateRule[]
  watermark: {
    userId: string
    scanId: string
    issuedAt: number
    rulesVersion?: string
  }
  expiresAt?: number
}

export interface ProScanResult extends ScanResult {
  proRulesUsed: boolean
  creditsRemaining: number
  encryptionVerified?: boolean
}
