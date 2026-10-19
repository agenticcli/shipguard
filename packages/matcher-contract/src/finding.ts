// Canonical finding DTO — the normalized, signable representation of a
// single finding emitted by the ShipGuard scanner.
//
// RELATIONSHIP TO @agenticcli/shared Finding
// ==========================================
// `shared/src/types.ts:6-22` defines the `Finding` type used by the CLI
// today. Key differences vs. this CanonicalFinding:
//   - `Finding.id` (not `ruleId`) → CanonicalFinding.id mirrors this
//   - `Finding` has NO `column` → CanonicalFinding adds it (UTF-16, 1-based)
//   - `Finding.evidence` is optional, not populated for pro findings →
//     CanonicalFinding makes it mandatory (null for redacted/unavailable)
//   - CanonicalFinding adds: severity, blocking, suppressionState, releaseId,
//     matcherType — fields the CLI will wire in via Task A-CLI-INT.2
//
// WHAT IS EXCLUDED FROM THE CANONICAL FORM
// =========================================
// - Timestamps (createdAt, scannedAt, …): non-deterministic across runs;
//   excluded so that two scans of the same content produce the same hash.
// - Absolute paths: `file` is root-relative with forward-slash separators.
//   Absolute paths are a contract violation; validate at call sites.
//
// CANONICAL SERIALIZATION
// =======================
// Call `canonicalizeFinding(f)` (src/canonical.ts) to produce a plain object
// with exactly the 10 mandatory fields, then `canonicalJson(...)` to get the
// RFC 8785 byte string used as the hash preimage for Phase C signing.

import type { SuppressionState } from './matcher.js'

/**
 * Severity level of a finding, as declared in the rule corpus.
 * Mirrors the authoring schema severity values.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'

/**
 * The canonical, signable DTO for a single finding.
 *
 * All 10 fields are MANDATORY in the canonical form (no optional/undefined).
 * Use `null` for fields that are intentionally absent (e.g. redacted evidence).
 *
 * ## Field contract
 *
 * | Field | Source | Notes |
 * |---|---|---|
 * | `id` | Rule corpus `id` | NOT `ruleId` — mirrors `Finding.id` in @agenticcli/shared |
 * | `file` | Scan root-relative | Forward-slash separators; no leading slash |
 * | `line` | MatchResultOccurrence.line | 1-based; UTF-16 code units |
 * | `column` | MatchResultOccurrence.column | 1-based; UTF-16 code units from line start |
 * | `evidence` | MatchResultOccurrence.evidence | Matched text; null = redacted/unavailable |
 * | `severity` | Rule corpus `severity` | Declared severity; not computed at runtime |
 * | `blocking` | Rule corpus `blocking` | Whether the finding blocks CI in `--strict` mode |
 * | `suppressionState` | MatchResultOccurrence.suppressionState | Per-occurrence; NOT file-wide |
 * | `releaseId` | ExecCtx.releaseId | Ties the finding to a specific attested rule release |
 * | `matcherType` | Matcher.type | Discriminant: `"pattern"` | `"file-presence"` | `"file-relationship"` |
 *
 * ## Excluded from canonical form
 * Timestamps, absolute paths, and any extension fields are excluded by
 * `canonicalizeFinding` (src/canonical.ts) — they MUST NOT appear in the
 * hash preimage used for Phase C signing.
 */
export interface CanonicalFinding {
  /** Rule `id` from the corpus (NOT `ruleId`). Mirrors `Finding.id` in @agenticcli/shared. */
  id: string

  /**
   * File path relative to the scan root, with forward-slash separators,
   * no leading slash (e.g. `"src/config/database.ts"`).
   */
  file: string

  /** 1-based line number of the match start (UTF-16 code units). */
  line: number

  /**
   * 1-based column of the match start on its line (UTF-16 code units from
   * the first code unit after the preceding `\n`, or from string start for
   * line 1).
   */
  column: number

  /**
   * The matched text (the full evidence string from `MatchResultOccurrence.evidence`).
   * `null` when evidence is redacted or unavailable (e.g. binary file scan,
   * content-redaction policy).  NOT optional — must be explicitly `null`.
   */
  evidence: string | null

  /** Declared severity from the rule corpus. */
  severity: Severity

  /**
   * Whether this finding blocks CI in `--strict` mode.
   * Derived from the rule's `blocking` field in the corpus.
   */
  blocking: boolean

  /**
   * Per-occurrence suppression state (NOT file-wide).
   * `"active"` = a real finding; `"suppressed"` = anti-pattern matched the
   * occurrence's context window.
   */
  suppressionState: SuppressionState

  /**
   * The `releaseId` from `ExecCtx` — ties this finding to a specific
   * atomically-published, attested rule release.  Required for Phase C
   * audit provenance.
   */
  releaseId: string

  /**
   * The `Matcher.type` discriminant of the rule that produced this finding.
   * One of `"pattern"`, `"file-presence"`, `"file-relationship"`.
   */
  matcherType: string
}
