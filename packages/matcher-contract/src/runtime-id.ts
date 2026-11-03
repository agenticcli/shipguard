// matcherRuntimeId ALGORITHM (algorithm only — no frozen value).
//
// Implements the function `computeMatcherRuntimeId` that produces the
// `matcherRuntimeId` hash from matcher spec §9.1.  The result is:
//
//   SHA-256(
//     "shipguard-runtime-v1\x00" +
//     JCS({
//       adapterImplHash: string,
//       buildLock: string,
//       contractPkgVersion: string,
//       engineOptions: object,
//       engineVersion: string,
//     })
//   )
//
// encoded as a 64-character lowercase hex string.
//
// ## No frozen values here
//
// This module exposes ONLY the algorithm.  The frozen concrete values are:
//   - NATIVE_V1_RUNTIME_ID: frozen in Phase B.1 (uses native-RegExp adapter)
//   - RE2JS_V1_RUNTIME_ID: frozen in Phase D.1 (uses re2js@2.8.3 adapter)
//
// Phase B.1 imports this function, computes the hash with the real
// adapterImplHash and buildLock, and records the frozen constant.  Phase C.2
// imports NATIVE_V1_RUNTIME_ID from Phase B.1.
//
// ## Preimage construction (matcher spec §9.1 — normative)
//
// The input struct is mapped to the canonical preimage object:
//   contractVersion → contractPkgVersion  (field name from matcher spec §9.1)
//   engineMeta.version → engineVersion
//   engineMeta.options → engineOptions
//
// The preimage object is sorted by JCS (RFC 8785) key order before hashing.
// A domain-separation prefix "shipguard-runtime-v1\x00" is prepended before
// the canonical JSON bytes.  This prevents a valid signature for a different
// object type from being replayed as a runtimeId.
//
// ## Implementation: Node built-in crypto
//
// SHA-256 uses Node.js `crypto.createHash` (available since Node 0.x; no
// external deps needed — we are a Node CLI, constraint §Global Constraints).
// The @noble/hashes package exists in the CLI's direct deps but we do NOT
// pull it into the contract package to keep the dependency surface minimal.
//
// DESIGN DECISIONS
// ================
// 1. No frozen values exported — they belong to Phase B.1 / D.1.
// 2. Domain prefix = "shipguard-runtime-v1\x00" (matches matcher spec §9.1).
// 3. Preimage field names are the matcher spec §9.1 names (contractPkgVersion,
//    engineVersion, engineOptions) — NOT the input parameter names.
// 4. canonicalJson from src/canonical.ts is used for the JCS serialization,
//    ensuring key-sort invariance (same logical content → same bytes).
// 5. Zero new runtime deps: uses Node built-in `crypto` module only.

import { createHash } from 'node:crypto'
import { canonicalJson } from './canonical.js'
import type { EngineMeta } from './engine-meta.js'

// ---------------------------------------------------------------------------
// Domain-separation prefix (matcher spec §9.1)
// ---------------------------------------------------------------------------

const RUNTIME_ID_DOMAIN_PREFIX = 'shipguard-runtime-v1\x00'

// ---------------------------------------------------------------------------
// computeMatcherRuntimeId input type
// ---------------------------------------------------------------------------

/**
 * Input to `computeMatcherRuntimeId`.
 *
 * Field names match the function signature in matcher spec §9.1 and
 * the matcher spec.
 *
 * The function maps these to the canonical preimage key names:
 *   contractVersion   → "contractPkgVersion" (preimage key)
 *   engineMeta.version  → "engineVersion" (preimage key)
 *   engineMeta.options  → "engineOptions" (preimage key)
 */
export interface MatcherRuntimeIdInput {
  /**
   * The exact semver string of `@agenticcli/matcher-contract` at build time.
   * (e.g. "0.1.0")
   *
   * Maps to `contractPkgVersion` in the JCS preimage (matcher spec §9.1).
   */
  contractVersion: string

  /**
   * SHA-256 hex digest of the compiled adapter implementation bytes.
   *
   * Phase B.1 computes this over the native-v1 adapter's compiled output.
   * Phase D.1 computes this over the re2js-v1 adapter's compiled output.
   *
   * Maps to `adapterImplHash` in the JCS preimage (same key name).
   */
  adapterImplHash: string

  /**
   * `EngineMeta` describing the engine used by this adapter.
   *
   * `engineMeta.version` maps to `engineVersion` in the preimage.
   * `engineMeta.options` maps to `engineOptions` in the preimage.
   * `engineMeta.engine` is intentionally NOT in the preimage — it is
   * implied by `engineVersion` (e.g. a native version is a Node version
   * string; a re2js version is the npm package version "2.8.3").
   *
   * Note: this differs from the matcher spec preimage in that the matcher spec
   * shows `engineVersion` and `engineOptions` as top-level fields.  This
   * function unpacks them from `engineMeta` to produce the correct preimage.
   */
  engineMeta: EngineMeta

  /**
   * A hash of the build lockfile (e.g. SHA-256 of `pnpm-lock.yaml`).
   *
   * Binds the runtimeId to a specific set of transitive dependency versions,
   * so that a build with different deps produces a different runtimeId.
   *
   * Maps to `buildLock` in the JCS preimage (same key name).
   */
  buildLock: string
}

// ---------------------------------------------------------------------------
// The canonical preimage object shape (matcher spec §9.1)
// ---------------------------------------------------------------------------

/**
 * The object that is JCS-serialized and hashed.
 *
 * Field names are the matcher spec §9.1 canonical names.
 * This object is NOT exported — it is constructed internally.
 */
interface RuntimeIdPreimage {
  adapterImplHash: string
  buildLock: string
  contractPkgVersion: string
  engineOptions: Record<string, unknown>
  engineVersion: string
}

// ---------------------------------------------------------------------------
// computeMatcherRuntimeId — the algorithm
// ---------------------------------------------------------------------------

/**
 * Compute the `matcherRuntimeId` for a given adapter + engine configuration.
 *
 * ## Algorithm (matcher spec §9.1 — normative)
 *
 * ```
 * preimage = "shipguard-runtime-v1\x00"
 *          + JCS({
 *              adapterImplHash: input.adapterImplHash,
 *              buildLock:       input.buildLock,
 *              contractPkgVersion: input.contractVersion,
 *              engineOptions:   input.engineMeta.options,
 *              engineVersion:   input.engineMeta.version,
 *            })
 * return SHA-256(preimage).hex()
 * ```
 *
 * The JCS step (canonicalJson) sorts keys by UTF-16 code unit, removes
 * whitespace, and serialises numbers per RFC 8785 §3.2.2.  This ensures
 * the hash is invariant to JS object key insertion order.
 *
 * ## What this does NOT contain
 *
 * - `engineMeta.engine` is NOT in the preimage.  The engine discriminant is
 *   implied by the version string (a Node version vs. "2.8.3") — including it
 *   would double-count the engine information.
 *
 * - No timestamp, no nonce.  The runtimeId must be REPRODUCIBLE across
 *   builds with the same inputs (Phase B.1 / D.1 freeze it as a constant).
 *
 * ## IMPORTANT: no frozen constants here
 *
 * This function returns the algorithm result for arbitrary inputs.
 * Callers that need the frozen constants must do so in their own module:
 *   - Phase B.1 calls this with the native-v1 adapter hash and records the result.
 *   - Phase D.1 calls this with the re2js-v1 adapter hash and records the result.
 *
 * @param input - The runtimeId input fields.
 * @returns A 64-character lowercase hex SHA-256 digest.
 */
export function computeMatcherRuntimeId(input: MatcherRuntimeIdInput): string {
  // 1. Build the canonical preimage object (matcher spec §9.1 field names).
  const preimageObj: RuntimeIdPreimage = {
    adapterImplHash: input.adapterImplHash,
    buildLock: input.buildLock,
    contractPkgVersion: input.contractVersion,
    // Cast options to Record<string, unknown> for JSON serialisation.
    // EngineOptions only contains JSON-representable boolean fields.
    // Double-cast through unknown to satisfy tsc strict assignment check. (as any WHY: EngineOptions lacks an index signature)
    engineOptions: input.engineMeta.options as unknown as Record<string, unknown>,
    engineVersion: input.engineMeta.version,
  }

  // 2. Serialise with RFC 8785 (JCS) — key-sorted, no whitespace.
  const jcsBytes = canonicalJson(preimageObj)

  // 3. Prepend domain-separation prefix (matcher spec §9.1 + §2.3 pattern).
  const preimage = RUNTIME_ID_DOMAIN_PREFIX + jcsBytes

  // 4. SHA-256 using Node built-in crypto (no external deps — constraint §GC).
  const digest = createHash('sha256').update(preimage, 'utf8').digest('hex')

  // 5. Return lowercase hex (digest() with 'hex' is already lowercase).
  return digest
}
