// Task A.9 — Engine metadata schema + pinned constants.
//
// DESIGN DECISIONS
// ================
// 1. EngineMeta is a plain interface (no class, no enum) so it serialises
//    directly as a JSON-signable object.  It appears in the FullManifest
//    (via matcherEngineVersion + matcherEngineOptions fields — matcher spec §3.2)
//    and in the matcherRuntimeId preimage (Task A.10).
//
// 2. Engine OPTIONS are kept SEPARATE from author FLAGS.  Author flags
//    ("i"/"m"/"s") live on individual PatternMatcher objects (src/flags.ts).
//    Engine options (e.g. RE2JS.LOOKBEHINDS) are adapter-level knobs that
//    affect the matching engine's behaviour globally — they must not leak
//    into per-rule flag fields.  Mixing them would make the runtimeId
//    algorithm ambiguous.
//
// 3. RE2JS_VERSION = "2.8.3" (exact, not a semver range).
//    Ground truth: npm registry + GitHub tags verified 2026-06-25.
//    1.4.0 is deprecated ("Accidental publish of breaking changes").
//    Do NOT loosen to "^2.8.3" — the runtimeId algorithm requires
//    an exact version to produce a stable frozen hash (Task A.10 / B.1 / D.1).
//
// 4. SUPPORTED_NODE_VERSIONS = ["20", "22"] — explicit list of tested versions.
//    NOT ">=20" (an open semver range is not pinnable and could mask
//    incompatibilities introduced by a new Node major).  Sources:
//      - shipguard `engines node>=20` → 20 is the minimum tested floor
//      - agenticcli CI Node 22 → 22 is the upper bound tested in CI
//      - tsup `target node20` → 20 is the compile target
//      - GROUND-TRUTH.md §Build / test / CI / signing: "Node 22" for agenticcli CI
//    If new Node versions are tested, add them to this list and update tests.
//
// 5. LOOKBEHINDS default is false for v1 (confirmed by matcher spec §3.2 and
//    IMPLEMENTATION-PLAN Task A.9 / Codex I3).  The re2js lookbehind feature
//    (RE2JS.LOOKBEHINDS, captureless-only) is disabled in v1 to avoid the
//    partially-verified semantics flagged in GROUND-TRUTH §External facts.
//
// 6. This module does NOT import re2js or any Phase-D dependency.
//    re2js is NOT added as a runtime dep until Phase D.1 (Task D.1).
//    This module only defines the METADATA SCHEMA and PINNED CONSTANTS.
//
// 7. Zero new runtime deps: pure TS, no imports from outside this package.

// ---------------------------------------------------------------------------
// Pinned constants
// ---------------------------------------------------------------------------

/**
 * The exact pinned version of re2js used by the re2js-v1 adapter (Phase D).
 *
 * Pinned at the specific verified-stable release (2026-06-25: npm latest).
 * 1.4.0 is deprecated; ^2.x is NOT used — exact pinning is required for
 * the stable `RE2JS_V1_RUNTIME_ID` frozen in Task D.1.
 *
 * Do NOT add re2js as a package dependency here (Phase D only).
 * This constant is metadata only.
 */
export const RE2JS_VERSION = '2.8.3' as const

/**
 * Explicit list of Node.js major versions tested against this package.
 *
 * This is NOT a semver range. Each entry is a major version string.
 * Adding "18" or "24" requires testing + updating this list.
 *
 * Sources (verified 2026-06-25):
 * - shipguard monorepo `engines node>=20` → 20 is the minimum floor
 * - agenticcli CI uses Node 22 → 22 is CI-tested
 * - tsup `target node20` → compiled for 20 compatibility
 */
export const SUPPORTED_NODE_VERSIONS: readonly string[] = ['20', '22'] as const

// ---------------------------------------------------------------------------
// EngineOptions — engine-level knobs (SEPARATE from author flags)
// ---------------------------------------------------------------------------

/**
 * Engine-level options that affect the matching engine globally.
 *
 * These are SEPARATE from per-rule author flags ("i"/"m"/"s") defined in
 * `src/flags.ts`.  Author flags are per-rule; engine options are per-adapter.
 *
 * Field names match the re2js option names (e.g. `RE2JS.LOOKBEHINDS`) so that
 * the Phase-D adapter can pass them directly to `RE2JS.compile(pattern, flags, options)`.
 * For the native-v1 adapter (Phase B), all options are false/off (native RegExp
 * does not have these feature flags).
 */
export interface EngineOptions {
  /**
   * Whether lookbehind assertions are enabled in re2js.
   *
   * Default: `false` for v1 (I3 confirmed in matcher spec / IMPLEMENTATION-PLAN).
   *
   * re2js lookbehind (RE2JS.LOOKBEHINDS, v2.7.0+) supports variable-width
   * lookbehinds but ONLY without capture groups (captureless).  The semantics
   * are only PARTIALLY VERIFIED for v1 corpus (GROUND-TRUTH §External facts).
   * Keeping this off eliminates uncertainty about v1 correctness.
   *
   * When enabled in a future version, the runtimeId must be re-frozen
   * (the options object is part of the hash preimage — Task A.10).
   */
  LOOKBEHINDS: boolean
}

// ---------------------------------------------------------------------------
// EngineMeta — the engine descriptor that travels in the manifest + runtimeId
// ---------------------------------------------------------------------------

/**
 * Engine metadata describing the matching engine used to compile and run
 * the active rule bundle.
 *
 * ## Where this appears
 * - `FullManifest.matcherEngineVersion` (§3.2) — the `version` field.
 * - `FullManifest.matcherEngineOptions` (§3.2) — the `options` field.
 * - `computeMatcherRuntimeId` preimage (Task A.10 / §9.1).
 *
 * ## Important: engine vs. author flags
 * `options` contains ENGINE-LEVEL knobs only.  Per-rule author flags
 * ("i"/"m"/"s") live on `PatternMatcher.flags` (src/flags.ts), not here.
 * A bundle signed with `LOOKBEHINDS:false` cannot be executed by an adapter
 * that enables lookbehinds — the runtimeId mismatch catches this.
 *
 * ## Stability requirement
 * For a given adapter + build lock, EngineMeta must be DETERMINISTIC.
 * Two builds that use the same engine version and options must produce
 * byte-identical EngineMeta JSON (for stable runtimeId hashing — §9.1).
 */
export interface EngineMeta {
  /**
   * Discriminant for the matching engine.
   *
   * - `"native"`: Node.js built-in `RegExp` (Phase B native-v1 adapter).
   * - `"re2js"`: the pure-JS RE2 engine (Phase D re2js-v1 adapter).
   */
  engine: 'native' | 're2js'

  /**
   * The exact version string of the engine.
   *
   * - For `"native"`: the Node.js version string (e.g. `"v20.11.0"`) from
   *   `process.version` at the time the runtimeId was frozen (Task B.1).
   * - For `"re2js"`: `RE2JS_VERSION` (`"2.8.3"`) — pinned exact npm version.
   */
  version: string

  /**
   * Engine-level options (SEPARATE from per-rule author flags).
   *
   * See `EngineOptions` for the full description of each field.
   */
  options: EngineOptions
}

// ---------------------------------------------------------------------------
// Factory functions (for tests + Phase B/D adapters)
// ---------------------------------------------------------------------------

/**
 * Produce an `EngineMeta` for the native-v1 adapter (Phase B).
 *
 * The native adapter uses Node.js built-in RegExp.  All engine options are
 * off (native RegExp has no re2js-specific knobs).
 *
 * @param nodeVersion - The Node.js version string (e.g. `process.version`).
 *   Must be the version string at the time the runtimeId is FROZEN (B.1),
 *   not a range or "latest".
 */
export function makeNativeEngineMeta(nodeVersion: string): EngineMeta {
  return {
    engine: 'native',
    version: nodeVersion,
    options: {
      LOOKBEHINDS: false,
    },
  }
}

/**
 * Produce an `EngineMeta` for the re2js-v1 adapter (Phase D).
 *
 * Uses `RE2JS_VERSION` ("2.8.3") as the exact pinned version.
 * LOOKBEHINDS defaults to false for v1 (I3 — confirmed off).
 *
 * @param lookbehinds - Whether to enable lookbehind support (default: false).
 *   Pass `true` only in a future version after thorough testing.
 *   Changing this value changes the runtimeId — a new freeze point is required.
 */
export function makeRe2jsEngineMeta(lookbehinds = false): EngineMeta {
  return {
    engine: 're2js',
    version: RE2JS_VERSION,
    options: {
      LOOKBEHINDS: lookbehinds,
    },
  }
}
