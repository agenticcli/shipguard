import * as path from 'node:path'
import * as os from 'node:os'

import { getAuthToken } from './auth.js'
import { goLink } from './links.js'
// The verifyAndDecryptBundle and verifyRuleBundle imports were removed (retired paths).
// Both functions are permanently disabled tombstones. Any call to them throws
// 'legacy-bundle-rejected: attestation required'. The import is removed so any
// accidental re-introduction fails at compile time.
import { verifyBundleResponse } from './release-verify.js'
import type { QualityGateRule, FileInfo, Policy, Finding, Confidence } from '@agenticcli/shared'
import { minimatch } from 'minimatch'
import { runCoderefRules, type CoderefRule, type DispatchTable, type ChecksumManifest } from './coderef-dispatch.js'
// Shared suppression helper  — the SUPPRESS_RE / isLineSuppressed
// logic now lives in suppression.ts so free-tier checks honor it too. Behavior here
// is byte-identical to the inlined version it replaces.
import { isLineSuppressed } from './suppression.js'
import { assertTrustedApiUrl } from '../utils/trust.js'
// Phase D.1 — re2js-v1 adapter (ReDoS-immune linear-time engine) replaces native-v1 as default.
// native-v1 is retained as a fallback export but no longer the active executor.
// parseFlags is still imported for atomic bundle compile validation (Phase B.3).
import { re2jsV1Executor, nativeV1Executor, parseFlags } from '@agenticcli/matcher-contract'
import { installRe2jsCompileCache, compileCached } from './re2js-compile-cache.js'
import type { PatternMatcher, FilePresenceMatcher, FileRelationshipMatcher, ExecCtx, AntiPatternScope } from '@agenticcli/matcher-contract'
import { RE2JS } from 're2js'

// The active executor for pro-rule evaluation. re2js-v1 provides linear-time
// ReDoS-immune matching on all RE2-compatible patterns (222/222 corpus rules pass
// Gate B RE2-compatibility check). native-v1 is available as a fallback.
// Perf wrapper OUTSIDE the frozen re2js-v1 adapter (which must stay byte-identical so
// RE2JS_V1_RUNTIME_ID and published Pro bundles remain valid). See re2js-compile-cache.ts.
installRe2jsCompileCache()
const activeExecutor = re2jsV1Executor

// Default floor file path — persisted in the user's home directory.
// Callers may override via the floorPath parameter (for tests and custom installs).
const DEFAULT_FLOOR_PATH = path.join(os.homedir(), '.shipguard', 'release-floor.json')

/**
 * P0-5 — a HARD, NON-DEGRADABLE uncheckable-scan error. The server fail-closed because it would
 * have signed an EMPTY rule bundle (NO_RULES_APPLIED, HTTP 422). A scan that applied ZERO rules
 * checked nothing and MUST NOT be reported green: the CLI surfaces this as exit 3 (RUNTIME_ERROR),
 * NOT a degraded free scan (which, under the A1 contract, completes with exit 0 +
 * `degraded`/`degradedReasons` in the JSON output). This is the §11.1 contract — "Pro-fetch
 * failure → loud error + exit 3; do NOT degrade to a free scan and report green". Distinct from
 * a transient outage (network/503), which legitimately degrades.
 *
 * UNCHANGED by the fix below: NoRulesAppliedError already always fails loud
 * (exit 3) regardless of --allow-degraded — that invariant predates this change and is out of
 * scope for it.
 */
export class NoRulesAppliedError extends Error {
  readonly code = 'NO_RULES_APPLIED' as const
  constructor(message: string) {
    super(message)
    this.name = 'NoRulesAppliedError'
  }
}

/**
 * Stable, distinct-per-failure-class codes for every OTHER way an explicit `--pro` rule fetch
 * can fail (auth, credits, rate limit, server/network, a structurally-invalid bundle, or the
 * server having no rule release to serve at all).
 *
 * prior to this change, every one of these classes was caught by scan.ts,
 * collapsed into a single generic message, and silently degraded to a free scan with exit 0 —
 * an agent that explicitly requested the pro gate saw exit 0 exactly when that gate did NOT run.
 * ProFetchError gives the caller (scan.ts) enough structure to fail loud (exit 3) by default,
 * with distinct machine-readable `code`s, while `--allow-degraded` remains available to opt back
 * into the old free-scan fallback.
 *
 * NO_ACTIVE_RELEASE added. Root cause: the rules backend throws a structured `NO_ACTIVE_RELEASE` ConvexError when no rule
 * release has ever been activated. Before this fix that code was NOT in this list, so it fell
 * through to the generic `SERVER_ERROR` bucket below — indistinguishable from a transient
 * outage, and silently degradable to a green free scan via `--allow-degraded`. This is exactly
 * why a real launch-day server-wide outage (no release ever activated since 2026-07-19) was
 * invisible: the CLI could not tell "retry me" apart from "nobody can get Pro rules right now."
 *
 * platform-unavailable-20261018: PLATFORM_UNAVAILABLE added. The hosted backend answers HTTP 503
 * `{"error": "...", "code": "PLATFORM_UNAVAILABLE"}` (+ `Retry-After`, `X-Platform-Status:
 * unavailable`, and NO `X-Credits-Remaining`) when it is over its plan limits or its deployment is
 * disabled. That is temporary and entirely on the server's side. Unmapped it fell into the generic
 * SERVER_ERROR bucket, so the user saw "Pro rules request failed [SERVER_ERROR]" and could not
 * tell it from their own network trouble.
 */
export type ProFetchErrorCode =
  | 'AUTH_FAILED'
  | 'INSUFFICIENT_CREDITS'
  | 'RATE_LIMITED'
  | 'SERVER_ERROR'
  | 'BUNDLE_INVALID'
  | 'NO_ACTIVE_RELEASE'
  | 'PLATFORM_UNAVAILABLE'

export class ProFetchError extends Error {
  readonly code: ProFetchErrorCode
  /** Only populated for RATE_LIMITED and PLATFORM_UNAVAILABLE, when the server sends a usable `Retry-After` header. */
  readonly retryAfterSeconds?: number
  constructor(code: ProFetchErrorCode, message: string, opts?: { retryAfterSeconds?: number }) {
    super(message)
    this.name = 'ProFetchError'
    this.code = code
    this.retryAfterSeconds = opts?.retryAfterSeconds
  }
}

import {
  PlatformUnavailableError,
  isPlatformUnavailable,
  parseRetryAfterSeconds,
  PLATFORM_UNAVAILABLE_DEFAULT_MESSAGE,
} from './platform-status.js'

/**
 * Reads `X-Credits-Remaining`. A missing, empty or non-numeric header means "balance unknown"
 * (e.g. the platform-unavailable response never carries it) — return undefined, never NaN and
 * never a made-up 0.
 */
function parseCreditsRemaining(headers: Headers): number | undefined {
  const raw = headers.get('X-Credits-Remaining')
  if (raw === null || raw.trim() === '') return undefined
  const credits = Number(raw.trim())
  return Number.isFinite(credits) ? credits : undefined
}

export async function fetchProRules(
  frameworks: string[],
  categories: string[] | undefined,
  apiUrl: string,
  scanId?: string,
  floorPath?: string,
): Promise<{ rules: QualityGateRule[]; creditsRemaining: number | undefined; rulesVersion?: string }> {
  assertTrustedApiUrl(apiUrl)
  // pass apiUrl through so a raw SHIPGUARD_API_KEY is exchanged for an
  // access token against the SAME configured API base this call targets.
  // The token refresh and the API-key exchange can ALSO receive the platform-unavailable 503
  // (review 2026-10-18, finding 1): that is not an auth problem, so it must not become
  // "Run `shipguard login`". The auth layer throws PlatformUnavailableError; re-wrap it here.
  let token: string | null
  try {
    token = await getAuthToken(apiUrl)
  } catch (err) {
    if (err instanceof PlatformUnavailableError) {
      throw new ProFetchError('PLATFORM_UNAVAILABLE', err.message, { retryAfterSeconds: err.retryAfterSeconds })
    }
    throw err
  }
  if (!token) throw new ProFetchError('AUTH_FAILED', 'Not authenticated. Run `shipguard login` first.')

  // ScanId idempotency (scanId idempotency): send the CLI's stable scanId BOTH in the body AND as the
  // HTTP-idiomatic Idempotency-Key header, on EVERY attempt (a retry of the same scan reuses
  // the same scanId — runScan mints it once per logical scan). The server keys its credit
  // reservation on (userId, scanId), so a dropped-response retry re-fetches the already-paid
  // bundle instead of consuming a SECOND credit. Without this the server minted a fresh UUID
  // per request and every retry double-charged (money bug).
  let res: Response
  try {
    res = await fetch(`${apiUrl}/api/rules/fetch`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(scanId ? { 'Idempotency-Key': scanId } : {}),
      },
      body: JSON.stringify({ frameworks, categories, ...(scanId ? { scanId } : {}) }),
    })
  } catch (networkErr: unknown) {
    // fetch() itself threw (DNS failure, connection refused, timeout, TLS error, etc.) —
    // this is a SERVER_ERROR-class failure from the caller's perspective (transient,
    // worth a retry), not a distinct code of its own.
    const msg = networkErr instanceof Error ? networkErr.message : String(networkErr)
    throw new ProFetchError('SERVER_ERROR', `Network error contacting pro rules API: ${msg}`)
  }

  if (!res.ok) {
    // Read the JSON body ONCE, defensively, BEFORE any of the
    // status-specific branches below. A structured `code` field (e.g. NO_ACTIVE_RELEASE) can
    // legitimately arrive on ANY non-2xx status — the platform team, not this file, owns which
    // HTTP status a given ConvexError code gets mapped to (see the platform's
    // error-status mapping) — so we classify by CODE first and fall back to STATUS only when no
    // recognized code is present. A non-JSON/unparsable body is a normal case for some failure
    // classes (e.g. a bare 5xx from an upstream proxy) — errorBody stays undefined and
    // status-based classification below proceeds exactly as before.
    let errorBody: { code?: string; error?: string } | undefined
    try {
      errorBody = await res.json() as { code?: string; error?: string }
    } catch (parseErr: unknown) {
      const msg = parseErr instanceof Error ? parseErr.message : String(parseErr)
      console.error(
        `[shipguard] Pro-fetch error response body was not parsable JSON — falling back to ` +
        `HTTP-status classification: ${msg}`,
      )
    }

    // NO_ACTIVE_RELEASE — thrown by the rules backend when no rule
    // release has EVER been activated. This is a server-wide configuration gap (nobody's Pro scan
    // can get real rules right now), not a transient per-request blip, so it is classified by its
    // own distinct code ahead of every status-based branch below — see the ProFetchErrorCode
    // doc comment above for the full RCA.
    if (errorBody?.code === 'NO_ACTIVE_RELEASE') {
      throw new ProFetchError(
        'NO_ACTIVE_RELEASE',
        errorBody.error ?? 'No rule release has ever been activated on the server — Pro rules ' +
        'genuinely cannot be served right now (a server-side activation gap, not a transient outage).',
      )
    }

    // PLATFORM_UNAVAILABLE — the hosted backend is over its plan limits or its deployment is
    // disabled (temporary, server-side). Detected by the body `code` on any status, or by the
    // `X-Platform-Status: unavailable` header on a 503 when the body is unreadable. Checked
    // before the status branches so it never falls into the generic 5xx SERVER_ERROR bucket.
    if (isPlatformUnavailable(res, errorBody)) {
      throw new ProFetchError(
        'PLATFORM_UNAVAILABLE',
        errorBody?.error ?? PLATFORM_UNAVAILABLE_DEFAULT_MESSAGE,
        { retryAfterSeconds: parseRetryAfterSeconds(res.headers) },
      )
    }

    if (res.status === 401) throw new ProFetchError('AUTH_FAILED', 'Auth expired. Run `shipguard login` again.')
    if (res.status === 402) throw new ProFetchError('INSUFFICIENT_CREDITS', `No credits. Buy at ${goLink('billing')}`)
    if (res.status === 429) {
      throw new ProFetchError(
        'RATE_LIMITED',
        `Rate limited (429): too many pro rule fetches.`,
        { retryAfterSeconds: parseRetryAfterSeconds(res.headers) },
      )
    }
    // 409 — scanId conflict/idempotency clash at the server. Not one of the named classes;
    // treated as SERVER_ERROR (transient — a fresh scanId/retry resolves it).
    if (res.status === 409) throw new ProFetchError('SERVER_ERROR', `Rule fetch conflict (409): ${res.statusText}`)
    // P0-5 — a 422 with code NO_RULES_APPLIED is the server's fail-closed "I refused to sign an
    // empty bundle" signal. This is NOT a transient failure to degrade past — throw a HARD error
    // that the scan command maps to exit 3 and that SUPPRESSES the free-rule fallback.
    if (res.status === 422) {
      if (errorBody?.code === 'NO_RULES_APPLIED') {
        throw new NoRulesAppliedError(
          errorBody.error ?? 'Pro rule fetch resolved zero rules — the scan checked nothing (fail-closed). This is NOT a clean pass.',
        )
      }
      const detail = errorBody?.error ?? res.statusText
      throw new ProFetchError('BUNDLE_INVALID', `Rule fetch failed (422): ${detail}`)
    }
    if (res.status >= 500) throw new ProFetchError('SERVER_ERROR', `Rule fetch failed (${res.status}): ${res.statusText}`)
    throw new ProFetchError('SERVER_ERROR', `Rule fetch failed: ${res.statusText}`)
  }

  const credits = parseCreditsRemaining(res.headers)
  const rulesVersion = res.headers.get('X-Rules-Version') ?? undefined

  // Finding 8 (GC.9b): read the raw response text FIRST, then run duplicate-key
  // detection via parseStrictNoDup before any JSON.parse. Using res.json() directly
  // silently deduplicates keys before any detection can occur, making GC.9b illusory.
  // We must use the CONTRACT'S parseStrictNoDup (from canonical.ts) on the COMPLETE
  // raw response string so that duplicate-key injection is rejected before crypto.
  const rawText = await res.text()
  let responseJson: unknown
  try {
    const { parseStrictNoDup: parseStrict } = await import('@agenticcli/matcher-contract')
    responseJson = parseStrict(rawText)
  } catch (parseErr: unknown) {
    const msg = parseErr instanceof Error ? parseErr.message : String(parseErr)
    throw new ProFetchError(
      'BUNDLE_INVALID',
      `Rule fetch response rejected — duplicate-key or malformed JSON detected: ${msg}`,
    )
  }

  // Phase C: attested format detection.
  // If the response contains a 'fullManifest' key, it is the new attested format.
  // Route through verifyBundleResponse for full cryptographic verification.
  if (responseJson && typeof responseJson === 'object' && 'fullManifest' in responseJson) {
    const bundleResponse = responseJson as {
      fullManifest: unknown
      corpusAttestation: unknown
      freshnessTok: unknown
      selectedRules: unknown
      bundleEnvelope: unknown
    }

    const effectiveFloorPath = floorPath ?? DEFAULT_FLOOR_PATH
    const effectiveScanId = scanId ?? ''

    const verifyResult = await verifyBundleResponse(
      bundleResponse,
      {
        scanId: effectiveScanId,
        frameworks,
        options: {},
        isPro: true,
      },
      effectiveFloorPath,
    )

    if (!verifyResult.ok) {
      throw new ProFetchError(
        'BUNDLE_INVALID',
        `Attested bundle verification failed: ${verifyResult.reason}` +
        (verifyResult.nonSafe ? ' [non-safe exit]' : ''),
      )
    }

    // Map ExecutableRule[] → QualityGateRule[] for the existing scan pipeline.
    // Fix 1: use r.blocking for the blocking decision (not r.severity === 'error').
    //   The old code coerced blocking from the 3-value severity enum; that caused
    //   every signed rule to map to action='warn' since 'error' is not in the new
    //   5-value enum (critical|high|medium|low|info) and the condition was never true.
    // Fix 3: propagate ALL matcher fields from the ExecutableRule to QualityGateRule.
    //   The old code hardcoded fileGlob:'**/*' and dropped presenceRule/requiresFile/
    //   requiresPattern, causing file-presence and file-relationship rules to behave
    //   as if they had no targeting or context.
    // WHY 'as unknown as Record': ExecutableRule from the contract has no index signature —
    // it is a strict typed interface and does not allow arbitrary field access.
    // The delivered wire object carries all fields from the 20-field 0.5.0 schema
    // (including fileGlob, presenceRule, antiPatternScope, boundary) but the TypeScript
    // type only exposes the 14 originally typed fields. Going through unknown is the
    // safe, intentional approach for dynamic field access on a validated contract object.
    const rules = verifyResult.selectedRules.map(r => {
      const rAny = r as unknown as Record<string, unknown>

      // FIX 2: use r.action directly (the author's signed intent) rather than
      // reconstructing action from r.blocking. The prior code:
      //   action: (r.blocking === true ? 'block' : 'warn')
      // was wrong for medium-severity rules with action:block (e.g. flask.redirect.open-redirect:
      // severity:medium → blocking:false at build time (old severity-based derivation) →
      // reconstructed as action:'warn' here → production silently downgrades a BLOCK rule).
      // With FIX 2 in build-manifest.ts, blocking = (action === 'block'), so both fields
      // are consistent. Using r.action directly is the correct single source of truth.
      const action = (rAny['action'] as string | undefined) ?? (r.blocking ? 'block' : 'warn')

      return {
        id: r.id,
        title: r.title,
        severity: r.severity as 'critical' | 'high' | 'medium' | 'low' | 'info',
        category: (r.categories?.[0] ?? 'security') as QualityGateRule['category'],
        explanation: r.title,
        recommendation: '',
        action: action as QualityGateRule['action'],
        // Per-rule confidence (hardcoded-confidence fix): carry the rule's REAL signed confidence.
        // verifyBundleResponse has already fail-closed if any rule lacks confidence, so
        // r.confidence is guaranteed present here — never a silent HIGH default. Corpus
        // governance (rule-corpus/rule-logic.md §4) calibrates action to this value, and
        // deriveBlocking() + CLI output/JSON depend on it being the author's signed intent.
        confidence: r.confidence,
        matcher: {
          type: r.matcherType === 'pattern' ? 'pattern' : r.matcherType,
          // fileGlob: all 20 fields are hashed in 0.5.0 and delivered on the wire.
          fileGlob: (rAny['fileGlob'] as string | undefined) ?? '**/*',
          patterns: r.pattern ? [r.pattern] : [],
          antiPatterns: r.antiPattern ? [r.antiPattern] : [],
          flags: r.flags,
          // FIX 1 (CRITICAL): antiPatternScope and boundary are now part of the 20-field
          // hash preimage (contract 0.5.0) and ARE delivered on the wire ExecutableRule.
          // They were missing from this mapping, causing runProRules to always default to
          // antiPatternScope:'statement' / boundary:'none' — ignoring the corpus values.
          // 55 corpus rules set non-default scope/boundary; this was a gate-C ≠ production
          // divergence. Copy them into matcher so runProRules picks them up correctly.
          ...(rAny['antiPatternScope'] !== undefined && { antiPatternScope: rAny['antiPatternScope'] }),
          ...(rAny['boundary'] !== undefined && { boundary: rAny['boundary'] }),
          // Preserve presenceRule for file-presence matchers.
          ...(r.matcherType === 'file-presence' && {
            presenceRule: ((rAny['presenceRule'] as string | undefined) ?? 'must-not-exist'),
          }),
          // Preserve context for file-relationship matchers.
          ...(r.matcherType === 'file-relationship' && {
            context: {
              requiresFile: r.requiresFile,
              requiresPattern: r.requiresPattern,
            },
          }),
        },
        // Propagate the framework for routing
        framework: r.framework,
      }
    }) as unknown as QualityGateRule[]

    return { rules, creditsRemaining: credits, rulesVersion }
  }

  // If we reach here, the response lacked 'fullManifest'.
  // Legacy bundles (AES-GCM encrypted or JWT) are PERMANENTLY REFUSED. Non-safe exit.
  // The server MUST deliver a BundleResponse with fullManifest + corpusAttestation
  // (attested-release protocol).
  throw new ProFetchError(
    'BUNDLE_INVALID',
    'legacy-bundle-rejected: attestation required — server response lacks fullManifest. ' +
    'The server must deliver a BundleResponse with fullManifest + corpusAttestation ' +
    '(attested-release protocol). Exit non-safe.',
  )
}

// ---------------------------------------------------------------------------
// Atomic bundle compile validation (Phase B.3 fail-open fix)
//
// DESIGN: Before running ANY rule, validate that EVERY pattern, anti-pattern,
// and flag in the ENTIRE rule set compiles successfully. If ANY compile fails,
// the WHOLE bundle is degraded and we REFUSE to run a partially-compiled rule.
//
// This kills the fail-open bug at compileRules:62-85 where a dropped anti-pattern
// let the rule still fire — a rule running without its anti-pattern guard is
// silently weakened (false-negative risk).
//
// Returns: { ok: true } if all rules compile; { ok: false, reason } if any fail.
// ---------------------------------------------------------------------------

function toRe2jsFlags(flags: Set<'i' | 'm' | 's'>): number {
  // Import RE2JS flag constants at runtime — same as the re2js-v1 adapter.
  let bits = 0
  if (flags.has('i')) bits |= RE2JS.CASE_INSENSITIVE
  if (flags.has('m')) bits |= RE2JS.MULTILINE
  if (flags.has('s')) bits |= RE2JS.DOTALL
  return bits
}

/**
 * Exported (2026-08-04) so the OFFLINE bundle path can fail loud instead of quiet.
 *
 * `runProRules` reacts to a compile failure by logging and returning `[]`. For the pro path
 * that is fine — `runProRulesWithDispatch` turns it into a `degraded` scan. The bundled-corpus
 * path calls `runProRules` directly, where an empty result is indistinguishable from "the code
 * was clean", so a bundle that failed to compile would produce a confident all-clear over zero
 * corpus rules. That is precisely the failure this bundle exists to remove, so `bundled-rules.ts`
 * calls this once at load and throws rather than letting it happen.
 */
function validateBundleCompile(
  rules: QualityGateRule[],
): { ok: true } | { ok: false; reason: string } {
  for (const rule of rules) {
    const rawFlags = rule.matcher.flags ?? ''

    // 1. Validate the flag string via the contract's strict enum validator.
    //    This catches 'g', 'y', 'u', 'x', duplicates, and unknown chars.
    const flagsResult = parseFlags(rawFlags)
    if (!flagsResult.ok) {
      return {
        ok: false,
        reason: `Rule ${rule.id}: invalid flags "${rawFlags}" — ${flagsResult.reason}`,
      }
    }

    // Compute the re2js flag bitmask (same as re2js-v1 adapter).
    const re2jsFlags = toRe2jsFlags(flagsResult.flags)

    // 2. Try to compile every primary pattern with re2js (EXACT same engine as the
    //    executor). FIX 5: use re2js, not native RegExp — a pattern that passes
    //    native compilation but fails re2js would previously pass preflight then be
    //    silently skipped at runtime (zero findings). Now we catch it here.
    for (const p of rule.matcher.patterns) {
      try {
        // compileCached, not RE2JS.compile: this validation pass and the executor's own
        // compilation now share one cache, so a bundle is compiled once per process rather
        // than twice. Behaviour is identical — a compile failure still throws here, every
        // time, because failures are deliberately not cached.
        compileCached(p, re2jsFlags)
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        return {
          ok: false,
          reason: `Rule ${rule.id}: primary pattern "${p}" fails re2js compilation — ${msg}`,
        }
      }
    }

    // 3. Try to compile every anti-pattern with re2js (FIX 3 + FIX 5).
    //    An invalid anti-pattern is NOT silently dropped — it degrades the bundle.
    //    Using re2js here ensures preflight is consistent with runtime execution.
    for (const ap of rule.matcher.antiPatterns) {
      try {
        compileCached(ap, re2jsFlags)
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        return {
          ok: false,
          reason:
            `Rule ${rule.id}: anti-pattern "${ap}" fails re2js compilation — ${msg}. ` +
            `The entire bundle is degraded rather than running the rule without its ` +
            `anti-pattern guard (atomic compile, FIX 5 fail-closed).`,
        }
      }
    }
  }

  return { ok: true }
}

/**
 * Exported (E5) so the history store's ruleOutcomes can compute "is this rule blocking in
 * the CURRENT scan's corpus" using the exact same rule → blocking derivation the scanner
 * itself uses to set Finding.blocking — keeping the two in lockstep without duplicating the
 * precedence logic (action field wins; falls back to confidence/severity heuristics).
 */
export function deriveBlocking(rule: QualityGateRule): boolean {
  if (rule.action === 'block') return true
  if (rule.action === 'warn' || rule.action === 'monitor') return false
  if (rule.confidence === 'HIGH') return true
  return rule.severity === 'critical' || rule.severity === 'high'
}

// ---------------------------------------------------------------------------
// runProRules — declarative regex engine using re2js-v1 adapter (Phase D.1)
//
// CHANGED from Phase B.2 baseline:
//   - compileRules() removed; replaced by validateBundleCompile() + re2js-v1 executor
//   - Atomic compile: any invalid pattern/anti-pattern/flag → returns empty findings
//     + logs an error (callers detect via runProRulesWithDispatch's degraded flag)
//   - Per-occurrence line-level anti-pattern suppression via the adapter (fixes
//     file-wide anti-pattern bug)
//   - evidence is now populated from CanonicalFinding.evidence (was not populated
//     for pro findings previously — Task A-CLI-INT.2)
//   - column is populated from CanonicalFinding.column
//   - suppressionState and matcherType are populated (new Finding fields)
//
// PHASE D.1 CHANGES (re2js engine swap):
//   - Active executor switched from native-v1 to re2js-v1 (linear-time, ReDoS-immune)
//   - All 222 corpus rules are RE2-compatible (Gate B pre-validates this)
//   - native-v1 remains importable as a fallback but is no longer the default
//
// PHASE C.3 CHANGES (crypto-fix):
//   - Finding 3: ALL matcher types (pattern, file-presence, file-relationship) are
//     now dispatched to the re2js-v1 executor. Previously file-presence and
//     file-relationship rules were silently skipped (continue), producing false
//     negatives on a cryptographically-verified bundle. A fully unsupported matcher
//     type now throws a sentinel error that causes the caller to mark the scan
//     non-safe rather than returning partial findings.
//   - Finding 4: Engine execution exceptions are no longer swallowed with continue.
//     Any exception during matcher.evaluate() throws a sentinel error so the caller
//     (runProRulesWithDispatch) marks the complete scan non-safe/degraded.
//
// UNCHANGED:
//   - Public signature: (rules, files, _policy) => Finding[]
//   - Glob pre-filter via minimatch
//   - deriveBlocking logic
//   - shipguard-ignore comment suppression (isLineSuppressed)
//   - All 13 existing test assertions (except the one that tested the OLD
//     fail-open behavior: "does not throw on invalid patterns" — updated to
//     assert the CORRECT atomic-compile degradation behavior)
// ---------------------------------------------------------------------------

/**
 * Sentinel error thrown by runProRules when execution must fail closed:
 *   - An unsupported matcher type exists in the verified bundle (F3).
 *   - A matcher/engine execution exception occurs (F4).
 * Caught by runProRulesWithDispatch, which then marks the scan degraded+non-safe.
 */
export class RunProRulesFatalError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RunProRulesFatalError'
  }
}

export function runProRules(
  rules: QualityGateRule[],
  files: FileInfo[],
  _policy: Policy,
): Finding[] {
  // Atomic compile gate: validate the entire bundle before executing any rule.
  // Any compile failure degrades the whole bundle — NEVER run a partially-compiled rule.
  const compileCheck = validateBundleCompile(rules)
  if (!compileCheck.ok) {
    // Log loudly (no silent failures).
    console.error(
      `[shipguard] Pro rule bundle failed atomic compile — refusing to run degraded bundle.\n` +
      `  Reason: ${compileCheck.reason}\n` +
      `  Action: The caller must mark the scan result DEGRADED + non-safe.`,
    )
    // Return empty findings with a special sentinel rule entry so the caller
    // (runProRulesWithDispatch) can detect compile failure via the degraded flag.
    // The sentinel is NOT emitted as a Finding — it is only used to communicate
    // the compile failure reason via the warnings array.
    return []
  }

  // Finding 3 pre-check: all matcher types in this verified bundle must be supported.
  // native-v1 implements: 'pattern', 'file-presence', 'file-relationship'.
  // Any other type in a signed bundle is a fatal bundle error → reject non-safe.
  const SUPPORTED_TYPES = new Set(['pattern', 'file-presence', 'file-relationship'])
  for (const rule of rules) {
    if (!SUPPORTED_TYPES.has(rule.matcher.type)) {
      throw new RunProRulesFatalError(
        `Bundle contains unsupported matcher type "${rule.matcher.type}" ` +
        `on rule "${rule.id}" — whole bundle rejected (non-safe). ` +
        `Only pattern/file-presence/file-relationship are supported by re2js-v1.`,
      )
    }
  }

  const findings: Finding[] = []
  const allRelativePaths = files.map((f) => f.relativePath)

  // Pre-attestation releaseId placeholder — replaced by Phase C with the real
  // attested bundle releaseId once Layer-1 is active.
  const ctx: ExecCtx = {
    allRelativePaths,
    releaseId: 'pre-attestation',
  }

  for (const rule of rules) {
    // Build the correct Matcher shape for the native-v1 executor based on type.
    // Finding 3: ALL signed matcher types are dispatched — no silent skips.
    let matcherForExecutor: PatternMatcher | FilePresenceMatcher | FileRelationshipMatcher

    if (rule.matcher.type === 'pattern') {
      // FIX 1+2: read antiPatternScope and boundary from the delivered rule.
      // In contract 0.5.0, these fields are part of the hash preimage and
      // delivered in the wire ExecutableRule. Read them dynamically — QualityGateRule
      // doesn't have typed accessors for these contract-level fields.
      const ruleAny = rule.matcher as unknown as Record<string, unknown>
      const antiPatternScope = ruleAny['antiPatternScope'] as AntiPatternScope | undefined
      const boundary = ruleAny['boundary'] as 'none' | 'word' | 'token' | undefined
      matcherForExecutor = {
        type: 'pattern',
        fileGlob: rule.matcher.fileGlob,
        patterns: rule.matcher.patterns,
        antiPatterns: rule.matcher.antiPatterns,
        flags: rule.matcher.flags ?? '',
        // FIX 1+2: pass through delivered values; executor defaults to 'none'/'statement'.
        ...(boundary !== undefined && { boundary }),
        ...(antiPatternScope !== undefined && { antiPatternScope }),
      } satisfies PatternMatcher
    } else if (rule.matcher.type === 'file-presence') {
      // file-presence: the fileGlob is the dangerous-file glob; presenceRule defaults
      // to 'must-not-exist' (standard corpus semantic: "this file must not be committed").
      // WHY 'as any': QualityGateRule.matcher does not carry presenceRule (it is an
      // ExecutableRule field); we default to must-not-exist which is the only corpus use.
      const presenceRule = (rule.matcher as unknown as { presenceRule?: string }).presenceRule
        ?? 'must-not-exist'
      matcherForExecutor = {
        type: 'file-presence',
        fileGlob: rule.matcher.fileGlob,
        presenceRule: presenceRule as 'must-exist' | 'must-not-exist',
      } satisfies FilePresenceMatcher
    } else if (rule.matcher.type === 'file-relationship') {
      // For requiresPattern-only (no requiresFile) rules, the executor evaluates
      // requiresPattern as a self-referential prerequisite on the primary file, then
      // runs primary patterns + antiPatterns. Forward those fields so the executor
      // can perform the content-based evaluation (FIX: requiresPattern self-referential).
      const frAny = rule.matcher as unknown as Record<string, unknown>
      const frFlags = (frAny['flags'] as string | undefined) ?? ''
      const frPatterns = (rule.matcher.patterns as string[] | undefined) ?? []
      const frAntiPatterns = (rule.matcher.antiPatterns as string[] | undefined) ?? []
      // Build the matcher with extended optional fields (read by evaluateFileRelationship
      // when performing the self-referential pattern evaluation).
      // WHY 'as unknown as FileRelationshipMatcher': FileRelationshipMatcher contract type
      // does not carry patterns/antiPatterns/flags — these are extra fields the executor
      // reads dynamically via Record cast to implement the self-referential semantics.
      matcherForExecutor = {
        type: 'file-relationship',
        fileGlob: rule.matcher.fileGlob,
        context: {
          requiresFile: rule.matcher.context?.requiresFile,
          requiresPattern: rule.matcher.context?.requiresPattern,
        },
        // Extended fields for self-referential requiresPattern evaluation:
        patterns: frPatterns,
        antiPatterns: frAntiPatterns,
        flags: frFlags,
      } as unknown as FileRelationshipMatcher
    } else {
      // Should be unreachable — pre-check above guards this.
      throw new RunProRulesFatalError(
        `Unreachable: unsupported matcher type "${(rule.matcher as { type: string }).type}" ` +
        `on rule "${rule.id}"`,
      )
    }

    // Glob pre-filter: skip files that don't match the rule's fileGlob
    const matched = files.filter((f) => minimatch(f.relativePath, rule.matcher.fileGlob))

    for (const file of matched) {
      // Run the re2js-v1 executor against this file (linear-time, ReDoS-immune).
      // The executor returns CanonicalFinding[] — one entry per match occurrence.
      let canonicalFindings
      try {
        canonicalFindings = activeExecutor.evaluate(
          matcherForExecutor,
          { relativePath: file.relativePath, content: file.content },
          ctx,
        )
      } catch (execErr: unknown) {
        // Finding 4: Engine exception → fail closed. Any execution exception on a
        // signed rule must make the COMPLETE scan non-safe (not just skip the rule).
        // Partial findings from remaining rules CANNOT be returned as a clean scan.
        const msg = execErr instanceof Error ? execErr.message : String(execErr)
        console.error(
          `[shipguard] Engine exception evaluating rule ${rule.id} against ` +
          `${file.relativePath}: ${msg} — scan non-safe (Finding 4 fail-closed)`,
        )
        throw new RunProRulesFatalError(
          `Engine exception evaluating rule "${rule.id}" against "${file.relativePath}": ${msg}`,
        )
      }

      // Map CanonicalFinding → Finding, injecting the real rule-level fields
      // (id, severity, blocking, category, title, explanation, recommendation)
      // that the stub values in the adapter don't know about.
      for (const cf of canonicalFindings) {
        // Per-occurrence suppression: check the shipguard-ignore comment mechanism
        // (isLineSuppressed) on top of the adapter's per-line anti-pattern suppression.
        const lines = file.content.split('\n')
        const lineIndex = cf.line - 1
        const commentSuppressed = lineIndex >= 0
          ? isLineSuppressed(lines, lineIndex, rule.id)
          : false

        // The adapter returns suppressionState 'suppressed' when an anti-pattern
        // matched the occurrence's line. We also check the comment suppression.
        const isSuppressed = cf.suppressionState === 'suppressed' || commentSuppressed

        findings.push({
          id: rule.id,
          title: rule.explanation.split('.')[0],
          severity: rule.severity,
          category: rule.category,
          file: file.relativePath,
          line: cf.line,
          column: cf.column,
          evidence: cf.evidence ?? undefined,
          explanation: rule.explanation,
          recommendation: rule.recommendation,
          blocking: isSuppressed ? false : deriveBlocking(rule),
          suppressed: isSuppressed,
          // New fields from contract integration (Task A-CLI-INT.2)
          suppressionState: isSuppressed ? 'suppressed' : 'active',
          matcherType: cf.matcherType,
          // releaseId: 'pre-attestation' — not set on Finding until Phase C wires
          // the real attested releaseId into the bundle response.
          // New fields from QualityGateRule
          fix: rule.fix,
          confidence: rule.confidence as Confidence | undefined,
          aiCodeTarget: rule.aiCodeTarget,
          cwe: rule.cwe,
        })
      }
    }
  }

  return findings
}

// ---------------------------------------------------------------------------
// runProRulesWithDispatch — Suricata-model orchestrator (Phase 1 registry engine)
//
// Partitions rules by implType:
//   - "coderef" (or implType present and === "coderef") → coderef-dispatch
//   - anything else (undefined, "declarative", legacy) → runProRules
//
// The existing runProRules signature and test assertions are UNCHANGED.
// ---------------------------------------------------------------------------

export interface ProRulesDispatchResult {
  findings: Finding[]
  /** True when ≥1 coderef rule was skipped due to minCliVersion > installed. */
  degraded: boolean
  /** Human-readable warning messages for skip events. */
  warnings: string[]
}

/**
 * Orchestrator that routes coderef rules to bundled CheckModule functions and
 * declarative rules to the existing regex engine (runProRules).
 *
 * @param rules      All pro rules from the registry.
 * @param files      Scanned files.
 * @param policy     Active policy.
 * @param cliVersion Installed CLI version (injectable for tests).
 * @param table      Coderef dispatch table (injectable for tests).
 * @param manifest   Optional checksum manifest (injectable for tests).
 */
export function runProRulesWithDispatch(
  rules: QualityGateRule[],
  files: FileInfo[],
  policy: Policy,
  cliVersion?: string,
  table?: DispatchTable,
  manifest?: ChecksumManifest,
): ProRulesDispatchResult {
  // Cast to CLI-local augmented type — WHY: implType/codeRef are Phase-1 fields
  // not yet in @agenticcli/shared (the concurrent Convex schema agent owns that).
  const augmented = rules as CoderefRule[]

  // Partition: coderef rules → dispatch; everything else → declarative regex engine.
  const coderefs = augmented.filter(r => r.implType === 'coderef')
  const declaratives = augmented.filter(r => r.implType !== 'coderef') as QualityGateRule[]

  // Declarative path — atomic compile validated inside runProRules.
  // runProRules may throw RunProRulesFatalError (Finding 3: unsupported type;
  // Finding 4: engine execution exception). Catch those and propagate as degraded.
  let declarativeFindings: Finding[] = []
  let fatalErrorReason: string | undefined

  if (declaratives.length > 0) {
    try {
      declarativeFindings = runProRules(declaratives, files, policy)
    } catch (err: unknown) {
      if (err instanceof RunProRulesFatalError) {
        // Fatal error: unsupported matcher type or engine execution exception.
        // The scan is non-safe — propagate as degraded with the reason.
        fatalErrorReason = err.message
        console.error(
          `[shipguard] runProRules fatal error — scan non-safe: ${err.message}`,
        )
      } else {
        // Unexpected error: re-throw (not a controlled degradation)
        throw err
      }
    }
  }

  // Detect whether the declarative path degraded.
  // Priority: fatal errors (Finding 3/4) > compile failures (Finding B.3).
  const compileResult = fatalErrorReason === undefined && declaratives.length > 0
    ? validateBundleCompile(declaratives)
    : { ok: true as const }
  const compileDegraded = !compileResult.ok
  const fatalDegraded = fatalErrorReason !== undefined

  const compileWarnings: string[] = compileDegraded
    ? [`Pro rule bundle compile failure: ${(compileResult as { ok: false; reason: string }).reason}`]
    : fatalDegraded
    ? [`Pro rule bundle fatal execution error: ${fatalErrorReason}`]
    : []

  // Coderef dispatch path
  const dispatchArgs: Parameters<typeof runCoderefRules> = [
    coderefs as QualityGateRule[],
    files,
    policy,
  ]
  if (cliVersion !== undefined) dispatchArgs.push(cliVersion)
  if (table !== undefined) dispatchArgs.push(table)
  if (manifest !== undefined) dispatchArgs.push(manifest)

  const { findings: coderefFindings, degraded: coderefDegraded, warnings: coderefWarnings } = runCoderefRules(...dispatchArgs)

  return {
    findings: [...declarativeFindings, ...coderefFindings],
    degraded: compileDegraded || fatalDegraded || coderefDegraded,
    warnings: [...compileWarnings, ...coderefWarnings],
  }
}

// ---------------------------------------------------------------------------
// Internal export for testing atomic compile validation
// (allows tests to verify the fail-open fix without going through the full scan)
// ---------------------------------------------------------------------------
export { validateBundleCompile }
