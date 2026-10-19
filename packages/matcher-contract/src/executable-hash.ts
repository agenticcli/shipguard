// Shared per-rule executableHash computation — matcher spec §3.1 (updated 0.5.0).
//
// This module is the SINGLE source of truth for the per-rule executableHash used
// by BOTH the server (build-manifest.ts) and the CLI (release-verify.ts).
//
// DESIGN (0.5.0 — integrity closure):
//   ALL fields the executor reads to MATCH or decides BLOCK/WARN are now in the
//   hash preimage.  There are no hash-excluded "extension fields" — every field
//   delivered in the wire ExecutableRule is hashed so a MITM cannot tamper
//   any field (fileGlob→match-nothing, blocking→false, antiPatternScope→'file')
//   without causing the CLI's recomputed hash to disagree with the manifest entry.
//
//   Fields added vs 0.4.1:
//     antiPatternScope — controls the context window for anti-pattern suppression
//     boundary         — post-match boundary mode ('none'|'word'|'token')
//     action           — CI blocking disposition ('block'|'warn'|'monitor')
//     blocking         — boolean shorthand for action === 'block'
//     fileGlob         — file glob scoping which files this rule applies to
//     presenceRule     — file-presence semantics ('must-exist'|'must-not-exist')
//
//   antiPatternScope has a union shape: 'statement'|'block'|'function'|'file'|{lines:N}.
//   The object form {lines:N} is canonicalized by canonicalJson (RFC 8785 JCS) — it
//   serializes deterministically as {"lines":N} regardless of insertion order.
//
// Hash algorithm (matcher spec §3.1 — normative):
//   executableHash = SHA-256("shipguard-rule-v1\x00" + JCS(canonicalRuleObject))
//
//   canonicalRuleObject contains ALL known fields when present/non-undefined.
//   Genuinely-unknown fields are REJECTED.

import { createHash } from 'node:crypto'
import { canonicalJson } from './canonical.js'

// ---------------------------------------------------------------------------
// Complete field set (20 fields — ALL enter the hash preimage in 0.5.0)
// ---------------------------------------------------------------------------

/**
 * All matcher spec §3.1 fields that constitute the per-rule executableHash preimage.
 * This includes the former "extension fields" (action, blocking, fileGlob,
 * presenceRule) and the newly-added behavior fields (antiPatternScope, boundary).
 *
 * Order of declaration here is irrelevant — canonicalJson sorts keys by UTF-16 code unit.
 * Optional fields are included ONLY when present and non-undefined.
 *
 * Count: 21 fields (14 original + 6 added in 0.5.0 + confidence added in 0.5.1).
 *
 * 0.5.1 — `confidence` added (per-rule confidence): the corpus governance model
 * (rule-corpus/rule-logic.md §4) calibrates action to per-rule confidence (HIGH/MEDIUM/LOW),
 * but the wire ExecutableRule had no confidence field, so the CLI hardcoded every delivered
 * rule to HIGH. confidence is now a first-class hashed field: tampering it (e.g. demoting a
 * HIGH rule to LOW to soften output) changes the recomputed hash and the bundle is rejected.
 * Rules WITHOUT confidence hash identically to 0.5.0 (present-fields-only preimage), so
 * existing pinned hashes stay valid; the CLI separately REQUIRES confidence (fail-closed).
 */
export const EXEC_RULE_FIELDS = [
  'action',
  'antiBoundary',
  'antiPattern',
  'antiPatternScope',
  'blocking',
  'boundary',
  'categories',
  'confidence',
  'enabled',
  'fileGlob',
  'flags',
  'framework',
  'id',
  'matcherType',
  'pattern',
  'presenceRule',
  'requiresFile',
  'requiresPattern',
  'severity',
  'tier',
  'title',
] as const

export type ExecRuleField = (typeof EXEC_RULE_FIELDS)[number]

// ---------------------------------------------------------------------------
// No hash-excluded extension fields in 0.5.0
// ---------------------------------------------------------------------------

/**
 * In contract 0.5.0, there are NO hash-excluded extension fields.
 * Every field in the delivered ExecutableRule is part of the hash preimage.
 * This set is kept as an empty sentinel so callers that reference it continue
 * to compile without changes (the set is empty — nothing is excluded).
 *
 * @deprecated All fields are now hashed. This constant will be removed in 0.6.0.
 */
export const EXEC_RULE_EXTENSION_FIELDS = new Set<string>([])

// ---------------------------------------------------------------------------
// Domain-separation prefix (matcher spec §3.1 + §2.3)
// ---------------------------------------------------------------------------

const RULE_DOMAIN_PREFIX = 'shipguard-rule-v1\x00'

// ---------------------------------------------------------------------------
// Internal: build the canonical preimage object
// ---------------------------------------------------------------------------

/**
 * Build the canonical rule object for hashing (matcher spec §3.1, 0.5.0).
 *
 * ALL known fields present on `raw` are included (undefined/absent omitted).
 * Genuinely-unknown fields are REJECTED.
 *
 * Special canonicalization:
 *   - `categories`: sorted lexicographically (stable sort, callers must NOT pre-sort).
 *   - `antiPatternScope`: the union shape 'statement'|'block'|'function'|'file'|{lines:N}
 *     is serialized by canonicalJson (RFC 8785 JCS). The object form {lines:N} serializes
 *     as {"lines":N} — deterministic because JCS sorts keys. No special handling needed
 *     beyond passing the value through; canonicalJson handles it recursively.
 *
 * @param raw - The delivered rule object (all known fields).
 * @returns A plain object containing only the known fields that are present.
 * @throws Error if `raw` contains genuinely-unknown fields.
 */
function buildCanonicalRuleObject(raw: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {}

  // Populate all known fields that are present and non-undefined.
  for (const field of EXEC_RULE_FIELDS) {
    if (field in raw && raw[field] !== undefined) {
      // `categories` is canonicalized here (stable lexicographic sort) so that
      // any caller passing unsorted categories yields the SAME hash.
      // This is the single source of truth for categories ordering — callers
      // MUST NOT pre-sort before passing to computeExecutableHash.
      if (field === 'categories' && Array.isArray(raw[field])) {
        result[field] = [...(raw[field] as string[])].sort()
      } else {
        result[field] = raw[field]
      }
    }
  }

  // Strict schema: reject genuinely-unknown fields.
  // In 0.5.0, EXEC_RULE_EXTENSION_FIELDS is empty — every known field is in EXEC_RULE_FIELDS.
  const knownFields = new Set(EXEC_RULE_FIELDS as readonly string[])
  for (const key of Object.keys(raw)) {
    if (!knownFields.has(key)) {
      throw new Error(
        `Delivered rule has extra field "${key}" not in ExecutableRule canonical schema — rejected`,
      )
    }
  }

  return result
}

// ---------------------------------------------------------------------------
// Public: computeExecutableHash
// ---------------------------------------------------------------------------

/**
 * Compute the per-rule executableHash per matcher spec §3.1 (0.5.0).
 *
 * Algorithm:
 *   preimage = "shipguard-rule-v1\x00" + JCS(canonicalRuleObject)
 *   executableHash = SHA-256(preimage) as lowercase hex
 *
 * In 0.5.0, the canonicalRuleObject includes ALL fields the executor reads at runtime:
 *   - Matching fields: pattern, antiPattern, flags, boundary, antiPatternScope,
 *     requiresFile, requiresPattern, presenceRule, fileGlob
 *   - Policy fields: action, blocking
 *   - Metadata fields: id, title, severity, tier, framework, matcherType, enabled,
 *     antiBoundary, categories
 *
 * Tampering ANY field on a delivered rule now changes the recomputed hash, causing
 * the CLI to reject the bundle (hash mismatch vs manifest entry).
 *
 * This is the SINGLE shared implementation used by BOTH the server (build-manifest.ts)
 * and the CLI (release-verify.ts).  Any divergence in hash preimage = a bug.
 *
 * @param raw - The delivered rule object (all known fields).
 * @returns 64-character lowercase hex SHA-256 digest.
 * @throws Error if `raw` contains genuinely-unknown fields.
 */
export function computeExecutableHash(raw: Record<string, unknown>): string {
  const canonical = buildCanonicalRuleObject(raw)
  const preimage = RULE_DOMAIN_PREFIX + canonicalJson(canonical)
  return createHash('sha256').update(preimage, 'utf8').digest('hex')
}
