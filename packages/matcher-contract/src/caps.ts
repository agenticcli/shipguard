// Caps profile + CapTracker
//
// Published capability caps for @agenticcli/matcher-contract v1.
// These values appear in the FullManifest.capProfile field (matcher spec §3.2)
// and are signed by the Release-Attestation key.  A cap hit MUST mark the
// scan result INCOMPLETE and map to a non-safe exit (exit code 2 or 3 —
// never exit 0).  There is NO silent truncation: the caller receives a
// CapHitResult with incomplete=true and a canonical degraded reason.
//
// DESIGN DECISIONS
// ================
// 1. CapsProfile is a plain record type (no class) so it can be serialized
//    directly as a JSON-signable object (cf. FullManifest.capProfile §3.2).
//    Field names match matcher spec §3.2 exactly (camelCase).
//
// 2. CapTracker is a stateful accumulator — callers call addFile/addRule/
//    addFindings as they process input.  capHit() returns the FIRST cap
//    violation observed (deterministic: checked in a fixed priority order).
//
// 3. Priority order for multiple simultaneous cap hits: files → bytes →
//    rules → patternsPerRule → totalPatternBytes → findings.  The first hit
//    wins; subsequent ones are not surfaced in the same result.  This is
//    intentional — the caller must abort on the first INCOMPLETE signal.
//
// 4. DEFAULT_CAPS values are deliberately generous for pre-MVP single-tenant
//    use.  They will be tightened for production as corpus size and scan
//    performance data become available.
//
// 5. Zero new runtime deps: pure TS, no imports from outside this package.

// ---------------------------------------------------------------------------
// CapsProfile — the published cap schema (matches FullManifest.capProfile §3.2)
// ---------------------------------------------------------------------------

/**
 * Capability caps published in the signed FullManifest.
 *
 * A scan that would exceed any of these caps MUST be marked INCOMPLETE
 * with a canonical degraded reason ("cap-exceeded") and exit non-safe.
 *
 * Field names are camelCase to match the matcher spec §3.2 JSON schema.
 */
export interface CapsProfile {
  /** Maximum number of files the scanner will process per scan. */
  maxFiles: number
  /** Maximum total decoded bytes across all files in the scan. */
  maxTotalBytes: number
  /** Maximum number of rules that can be active in a single bundle. */
  maxRules: number
  /** Maximum number of patterns within a single rule. */
  maxPatternsPerRule: number
  /** Maximum total byte-length of all pattern strings across all rules. */
  maxTotalPatternBytes: number
  /** Maximum number of findings emitted before the scan is capped. */
  maxFindings: number
}

/**
 * Default caps for @agenticcli/matcher-contract v1.
 *
 * These are the values embedded in the first attested release manifest.
 * They are intentionally generous for pre-MVP single-tenant CLI use.
 *
 * All values are safe integers (well within 2^53−1).
 */
export const DEFAULT_CAPS: CapsProfile = {
  maxFiles: 50_000,
  maxTotalBytes: 512 * 1024 * 1024, // 512 MiB
  maxRules: 1_000,
  maxPatternsPerRule: 20,
  maxTotalPatternBytes: 10 * 1024 * 1024, // 10 MiB total pattern content
  maxFindings: 100_000,
}

// ---------------------------------------------------------------------------
// CapHitResult — returned by CapTracker.capHit() on a violation
// ---------------------------------------------------------------------------

/**
 * Describes the first cap that was exceeded during a scan.
 *
 * `reason` is the canonical DegradedReason string for this class of failure.
 * `detail` is a human-readable string identifying which specific cap was hit.
 * `incomplete` is always true — a cap hit ALWAYS marks the scan INCOMPLETE.
 */
export interface CapHitResult {
  /** Canonical degraded reason (§ failure.ts DegradedReason). */
  reason: 'cap-exceeded'
  /** Human-readable detail: which cap was exceeded and by how much. */
  detail: string
  /**
   * Always true: a cap hit marks the scan INCOMPLETE.
   * The result MUST NOT be treated as a complete/authoritative scan.
   * Exit code MUST be non-zero (2 or 3, never 0).
   */
  incomplete: true
}

// ---------------------------------------------------------------------------
// CapTracker — stateful accumulator
// ---------------------------------------------------------------------------

/**
 * Tracks scan progress against a CapsProfile.
 *
 * Callers call addFile/addRule/addFindings as they process files and rules.
 * After each addition (or at any checkpoint), call capHit() to check whether
 * a cap has been exceeded.
 *
 * ## Usage contract
 *
 * ```ts
 * const tracker = new CapTracker(profile)
 * for (const file of files) {
 *   tracker.addFile(file.byteLength)
 *   const hit = tracker.capHit()
 *   if (hit) { markIncomplete(hit); break }
 *   // ... process file ...
 * }
 * ```
 *
 * ## Non-safe exit
 *
 * A non-null capHit() result MUST cause the caller to mark the scan
 * INCOMPLETE and exit non-safe (exit code 2 or 3).  NEVER truncate silently.
 */
export class CapTracker {
  private readonly caps: Readonly<CapsProfile>

  private _fileCount = 0
  private _totalBytes = 0
  private _ruleCount = 0
  private _maxPatternsSeenPerRule = 0
  private _totalPatternBytes = 0
  private _findingCount = 0

  constructor(caps: CapsProfile) {
    this.caps = { ...caps }
  }

  /**
   * Record that one file has been added to the scan.
   *
   * @param byteLength - The decoded byte length of the file's content
   *   (UTF-16 code units × 2, or the raw buffer size — whichever the
   *   caller uses consistently).
   */
  addFile(byteLength: number): void {
    this._fileCount++
    this._totalBytes += byteLength
  }

  /**
   * Record that one rule has been added to the active bundle.
   *
   * @param patternCount - The number of patterns in this rule.
   * @param patternBytes - The total byte-length of all pattern strings in this rule.
   */
  addRule(patternCount: number, patternBytes: number): void {
    this._ruleCount++
    if (patternCount > this._maxPatternsSeenPerRule) {
      this._maxPatternsSeenPerRule = patternCount
    }
    this._totalPatternBytes += patternBytes
  }

  /**
   * Record that `count` findings have been emitted.
   *
   * @param count - Number of new findings to add to the running total.
   */
  addFindings(count: number): void {
    this._findingCount += count
  }

  /**
   * Check whether any cap has been exceeded.
   *
   * Returns the FIRST cap violation found (priority: files → bytes → rules
   * → patternsPerRule → totalPatternBytes → findings), or null if all
   * counts are within limits.
   *
   * This method is pure and side-effect-free (read-only on internal state).
   */
  capHit(): CapHitResult | null {
    if (this._fileCount > this.caps.maxFiles) {
      return {
        reason: 'cap-exceeded',
        detail: `maxFiles exceeded: ${this._fileCount} > ${this.caps.maxFiles}`,
        incomplete: true,
      }
    }

    if (this._totalBytes > this.caps.maxTotalBytes) {
      return {
        reason: 'cap-exceeded',
        detail: `maxTotalBytes exceeded: ${this._totalBytes} > ${this.caps.maxTotalBytes}`,
        incomplete: true,
      }
    }

    if (this._ruleCount > this.caps.maxRules) {
      return {
        reason: 'cap-exceeded',
        detail: `maxRules exceeded: ${this._ruleCount} > ${this.caps.maxRules}`,
        incomplete: true,
      }
    }

    if (this._maxPatternsSeenPerRule > this.caps.maxPatternsPerRule) {
      return {
        reason: 'cap-exceeded',
        detail: `maxPatternsPerRule exceeded: ${this._maxPatternsSeenPerRule} > ${this.caps.maxPatternsPerRule}`,
        incomplete: true,
      }
    }

    if (this._totalPatternBytes > this.caps.maxTotalPatternBytes) {
      return {
        reason: 'cap-exceeded',
        detail: `maxTotalPatternBytes exceeded: ${this._totalPatternBytes} > ${this.caps.maxTotalPatternBytes}`,
        incomplete: true,
      }
    }

    if (this._findingCount > this.caps.maxFindings) {
      return {
        reason: 'cap-exceeded',
        detail: `maxFindings exceeded: ${this._findingCount} > ${this.caps.maxFindings}`,
        incomplete: true,
      }
    }

    return null
  }

  // ---------------------------------------------------------------------------
  // Read-only counters (for diagnostics / logging — NOT for control flow)
  // ---------------------------------------------------------------------------

  get fileCount(): number { return this._fileCount }
  get totalBytes(): number { return this._totalBytes }
  get ruleCount(): number { return this._ruleCount }
  get maxPatternsSeenPerRule(): number { return this._maxPatternsSeenPerRule }
  get totalPatternBytes(): number { return this._totalPatternBytes }
  get findingCount(): number { return this._findingCount }
}
