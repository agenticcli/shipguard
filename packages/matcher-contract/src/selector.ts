// Task A.11 — Selector + Exact-Set Completeness Algorithm
//
// Implements matcher spec §4 (normative).
//
// Two public exports:
//   selectExpected(manifest, request) → ExpectedSet
//   verifyExactSet(delivered, expected) → {ok:true} | {ok:false, violations}
//
// DESIGN DECISIONS
// ================
// 1. selectExpected is a PURE function — no I/O, no side effects. Given the
//    same manifest + request it ALWAYS produces the same output. This is the
//    correctness guarantee that lets the CLI recompute the expected set
//    independently of Convex. (matcher spec §4.1 "deterministic")
//
// 2. verifyExactSet performs O(n) MULTISET equality using Maps. The five
//    distinct violation types are REJECT-missing, REJECT-extra,
//    REJECT-hash-mismatch, REJECT-duplicate-id, REJECT-unknown.
//    Note: REJECT-extra and REJECT-unknown are the same physical event (a rule
//    in delivered but not in expected); both are surfaced as "extra-rule"
//    violation. matcher spec §4.2 calls it "unexpected rule" — we map that
//    to violation type "extra-rule" with a clear ruleId.
//
// 3. Policy cap (step 7): if candidates.length > manifest.capProfile.maxRules
//    we THROW with a canonical "FAIL_INCOMPLETE(rule-count-cap-exceeded)"
//    message. Callers that want soft handling should catch this. The spec says
//    "FAIL_INCOMPLETE + non-safe exit" — in the contract layer, throwing is the
//    correct representation (callers map it to a DegradedReason + exit code).
//
// 4. Framework deduplication (step 3): when a generic rule and a framework-
//    specific rule share the same id, the framework-specific one wins. If two
//    framework-specific rules from DIFFERENT frameworks share the same id and
//    both frameworks are requested, the spec does not define a tiebreak order —
//    we pick the first one encountered in the rules array (stable sort order
//    from the manifest). This is a conservative choice; the expected invariant
//    in practice is that a given id appears at most once per (framework OR
//    generic) with no cross-framework id collision.
//
// 5. "local" tier: matcher spec §4.1 step 6 notes that "local" is aliased to
//    "free" at publish time (publish-rules.ts:242). A properly-formed manifest
//    will never contain tier="local". We check tier === "free" exactly; a
//    "local" tier in a manifest is treated as unknown and excluded from non-pro
//    requests (same behaviour as an unknown tier). No aliasing is applied here.
//
// 6. Zero new runtime deps: pure TS, no imports from outside this package.

// ---------------------------------------------------------------------------
// Types (also exported for callers and tests)
// ---------------------------------------------------------------------------

/**
 * A single entry in the FullManifest.rules array.
 *
 * Field names mirror matcher spec §3.1 ManifestRuleEntry exactly.
 * All optional fields (antiBoundary, categories) may be absent.
 */
export interface ManifestRuleEntry {
  id: string
  executableHash: string
  enabled: boolean
  framework: string
  tier: string
  severity: string
  matcherType: string
  title: string
  flags: string
  categories?: string[]
  antiBoundary?: string
  sourceYamlDigest?: string
}

/**
 * The signed FullManifest delivered in the BundleResponse.
 *
 * Only the fields consumed by selectExpected are declared here; the full
 * schema (with cryptographic signing fields) is in matcher spec §3.2 and will
 * be declared in the Phase-C crypto layer. This subset is sufficient for the
 * contract package's selector.
 */
export interface FullManifest {
  protocolVersion: '1'
  releaseId: string
  releaseSequence: number
  corpusRuleCount: number
  rules: ManifestRuleEntry[]
  capProfile: {
    maxFileBytes: number
    maxFiles: number
    maxFindings: number
    maxPatternBytes: number
    maxPatternsPerRule: number
    maxRules: number
  }
  matcherEngineVersion: string
  matcherEngineOptions: { LOOKBEHINDS: boolean }
  matcherRuntimeId: string
  contractVersion: string
  gateBVersion: string
  gateCVersion: string
}

/**
 * The scan request parameters used to select rules from the manifest.
 *
 * - `frameworks`: list of framework tags (e.g. ["nextjs", "react"]).
 *   "generic" rules always apply regardless of this list.
 * - `categories`: optional category filter. When non-empty, only rules
 *   whose categories list intersects with this set are included (plus rules
 *   with no categories, which pass unconditionally).
 * - `isPro`: when true, pro-tier rules are included. When false or absent,
 *   only free-tier rules are included.
 */
export interface ScanRequest {
  frameworks: string[]
  categories?: string[]
  isPro?: boolean
}

/**
 * One entry in the expected rule-ID/hash MULTISET.
 *
 * Mirrors BundleEnvelope.expectedRuleSet (matcher spec §3.5).
 */
export interface ExpectedEntry {
  id: string
  executableHash: string
}

/**
 * The expected rule-ID/hash MULTISET — the output of selectExpected.
 * Sorted by `id` ascending (deterministic).
 */
export type ExpectedSet = ExpectedEntry[]

// ---------------------------------------------------------------------------
// Violation types for verifyExactSet
// ---------------------------------------------------------------------------

/**
 * A single violation found during exact-multiset equality verification.
 *
 * Five distinct violation types per matcher spec §4.2:
 * - "missing-rule": expected rule was not delivered
 * - "extra-rule": delivered rule was not in the expected set (also "unknown")
 * - "hash-mismatch": rule id matches but executableHash differs
 * - "duplicate-id": same rule id appears more than once in delivered
 * - "count-mismatch": cardinality differs (caught before per-rule checks)
 */
export type ViolationType =
  | 'missing-rule'
  | 'extra-rule'
  | 'hash-mismatch'
  | 'duplicate-id'
  | 'count-mismatch'

export interface SetViolation {
  type: ViolationType
  ruleId: string
  detail: string
}

/** The failure result from verifyExactSet. */
export interface SetMismatch {
  ok: false
  violations: SetViolation[]
}

/** The success result from verifyExactSet. */
export interface SetMatch {
  ok: true
}

// ---------------------------------------------------------------------------
// selectExpected — the canonical selection algorithm (matcher spec §4.1)
// ---------------------------------------------------------------------------

/**
 * Compute the expected rule-ID/hash MULTISET for a given manifest + request.
 *
 * ## Algorithm (matcher spec §4.1 — normative, 8 steps)
 *
 * 1. Filter to enabled rules only.
 * 2. Generic-rule merge: include "generic" framework always; include
 *    framework-specific rules only when their framework is in request.frameworks.
 * 3. Framework deduplication: when a generic and a framework-specific rule
 *    share the same id, the framework-specific one wins.
 * 4. Category filter: when request.categories is non-empty, include only rules
 *    whose categories intersect the requested set, PLUS rules with no categories
 *    (which pass unconditionally).
 * 5. Status/beta filter: only enabled=true rules (already filtered in step 1).
 *    No separate "beta" field in v1 corpus.
 * 6. Tier filter: free-tier always included; pro-tier only when request.isPro.
 *    "local" tier has been aliased to "free" at publish time — no aliasing here.
 * 7. Policy caps: if candidates.length > manifest.capProfile.maxRules, THROW
 *    with "FAIL_INCOMPLETE(rule-count-cap-exceeded)".
 * 8. Build expected MULTISET: sort by id ascending.
 *
 * @param manifest - A verified FullManifest (must satisfy corpusRuleCount === rules.length).
 * @param request  - The scan request parameters.
 * @returns The expected rule-ID/hash MULTISET, sorted by id ascending.
 * @throws Error with "rule-count-cap-exceeded" if candidates exceed maxRules.
 */
export function selectExpected(manifest: FullManifest, request: ScanRequest): ExpectedSet {
  const requestedFrameworks = new Set(request.frameworks)

  // ── Step 1: enabled-only filter ──────────────────────────────────────────
  let candidates = manifest.rules.filter((r) => r.enabled)

  // ── Step 2: generic-rule merge ───────────────────────────────────────────
  // Generic rules apply to ALL requests; framework-specific only when their
  // framework tag is present in request.frameworks.
  candidates = candidates.filter(
    (r) => r.framework === 'generic' || requestedFrameworks.has(r.framework),
  )

  // ── Step 3: framework deduplication ──────────────────────────────────────
  // When a generic rule and a framework-specific rule share the same id,
  // the framework-specific one wins (more specific overrides generic).
  // We process in manifest order; the last write per id wins. To implement
  // "specific > generic" we do two passes:
  //   pass A: collect all framework-specific entries for requested frameworks
  //   pass B: for each id, if a framework-specific entry exists use it,
  //           otherwise fall back to the generic entry.
  const genericById = new Map<string, ManifestRuleEntry>()
  const specificById = new Map<string, ManifestRuleEntry>()

  for (const r of candidates) {
    if (r.framework === 'generic') {
      // Collect generic; only keep first occurrence per id (manifest order)
      if (!genericById.has(r.id)) {
        genericById.set(r.id, r)
      }
    } else {
      // Framework-specific: keep first occurrence per id among requested frameworks
      if (!specificById.has(r.id)) {
        specificById.set(r.id, r)
      }
    }
  }

  // Merge: specific wins over generic for the same id
  const dedupedById = new Map<string, ManifestRuleEntry>()
  for (const [id, r] of genericById) {
    dedupedById.set(id, r)
  }
  for (const [id, r] of specificById) {
    // Overwrite generic entry (if any) with the framework-specific one
    dedupedById.set(id, r)
  }

  candidates = Array.from(dedupedById.values())

  // ── Step 4: category filter ───────────────────────────────────────────────
  // When request.categories is non-empty, include only rules whose categories
  // list intersects the requested set. Rules with no/empty categories pass
  // unconditionally.
  if (request.categories !== undefined && request.categories.length > 0) {
    const requestedCategories = new Set(request.categories)
    candidates = candidates.filter((r) => {
      if (!r.categories || r.categories.length === 0) {
        return true // no categories → pass unconditionally
      }
      return r.categories.some((c) => requestedCategories.has(c))
    })
  }

  // ── Step 5: status/beta filter ────────────────────────────────────────────
  // Already handled: step 1 filtered to enabled=true only.
  // No separate "beta" field in v1 corpus (per matcher spec §4.1 step 5).

  // ── Step 6: tier filter ───────────────────────────────────────────────────
  // "free" always included. "pro" only when isPro. "local" has been aliased to
  // "free" at publish time — a "local" tier in a manifest is non-conforming.
  if (!request.isPro) {
    candidates = candidates.filter((r) => r.tier === 'free')
  }

  // ── Step 7: policy cap ────────────────────────────────────────────────────
  if (candidates.length > manifest.capProfile.maxRules) {
    throw new Error(
      `FAIL_INCOMPLETE(rule-count-cap-exceeded): ` +
        `${candidates.length} candidates exceed maxRules=${manifest.capProfile.maxRules}`,
    )
  }

  // ── Step 8: build expected MULTISET, sorted by id ascending ───────────────
  const sorted = [...candidates].sort((a, b) => {
    if (a.id < b.id) return -1
    if (a.id > b.id) return 1
    return 0
  })

  return sorted.map((r) => ({ id: r.id, executableHash: r.executableHash }))
}

// ---------------------------------------------------------------------------
// verifyExactSet — EXACT multiset equality (matcher spec §4.2)
// ---------------------------------------------------------------------------

/**
 * Verify that `delivered` is byte-identical to `expected` as a MULTISET.
 *
 * ## Checks performed (matcher spec §4.2 — normative)
 *
 * 1. Duplicate-ID check: if any id appears more than once in `delivered`,
 *    REJECT with violation type "duplicate-id".
 * 2. Cardinality check: if |delivered| ≠ |expected|, REJECT with
 *    violations identifying the specific missing / extra rules.
 * 3. Missing rules: every id in `expected` must appear in `delivered`.
 * 4. Extra rules: every id in `delivered` must appear in `expected`.
 * 5. Hash check: for each matched id, executableHash must be identical.
 *
 * All violations are collected and returned together (not just the first).
 * A delivered set that has both missing and extra rules will report both.
 *
 * ## No Merkle proofs
 * Per matcher spec §4.2: "No Merkle proofs. Inclusion proofs (Merkle) prove
 * membership in a set but do NOT prove that no rule was omitted from the full
 * corpus." This function implements the full-manifest exact-multiset approach.
 *
 * @param delivered - The selectedRules delivered in the BundleResponse,
 *   expressed as {id, executableHash} pairs (the hash to verify against).
 * @param expected  - The ExpectedSet from selectExpected.
 * @returns SetMatch ({ok:true}) or SetMismatch ({ok:false, violations}).
 */
export function verifyExactSet(
  delivered: ReadonlyArray<{ id: string; executableHash: string }>,
  expected: ExpectedSet,
): SetMatch | SetMismatch {
  const violations: SetViolation[] = []

  // ── 1. Duplicate-ID check ─────────────────────────────────────────────────
  const deliveredMap = new Map<string, string>() // id → executableHash
  const seenIds = new Set<string>()

  for (const entry of delivered) {
    if (seenIds.has(entry.id)) {
      violations.push({
        type: 'duplicate-id',
        ruleId: entry.id,
        detail: `Rule id "${entry.id}" appears more than once in the delivered set`,
      })
    }
    seenIds.add(entry.id)
    deliveredMap.set(entry.id, entry.executableHash)
  }

  // If duplicates are found, we cannot reliably perform further checks
  // (the Map already holds last-write-wins). We report duplicates plus any
  // other structural issues discovered via the de-duplicated map.

  // ── 2. Build expected map ─────────────────────────────────────────────────
  const expectedMap = new Map<string, string>() // id → executableHash
  for (const e of expected) {
    expectedMap.set(e.id, e.executableHash)
  }

  // ── 3. Missing rules (in expected but not in delivered) ───────────────────
  for (const [id, _hash] of expectedMap) {
    if (!deliveredMap.has(id)) {
      violations.push({
        type: 'missing-rule',
        ruleId: id,
        detail: `Expected rule "${id}" was not found in the delivered set`,
      })
    }
  }

  // ── 4. Extra rules (in delivered but not in expected) ─────────────────────
  for (const [id, _hash] of deliveredMap) {
    if (!expectedMap.has(id)) {
      violations.push({
        type: 'extra-rule',
        ruleId: id,
        detail: `Delivered rule "${id}" was not in the expected set (unknown rule)`,
      })
    }
  }

  // ── 5. Hash mismatch (id in both, but hash differs) ───────────────────────
  for (const [id, deliveredHash] of deliveredMap) {
    const expectedHash = expectedMap.get(id)
    if (expectedHash !== undefined && deliveredHash !== expectedHash) {
      violations.push({
        type: 'hash-mismatch',
        ruleId: id,
        detail:
          `executableHash mismatch for rule "${id}": ` +
          `expected "${expectedHash}", got "${deliveredHash}"`,
      })
    }
  }

  if (violations.length > 0) {
    return { ok: false, violations }
  }

  return { ok: true }
}
