// CLI-side cryptographic verification for the attested-release protocol.
// Implements matcher spec §7.2 (normative verification order) — all 7 steps.
//
// Security model:
//   - All 5 bundle components are parsed with parseStrictNoDup before any crypto.
//   - Attestation → freshness → envelope → completeness → runtimeId → floor.
//   - Any step failure → { ok: false, reason, nonSafe: true }.
//   - Floor durability: write-temp → fsync(temp) → rename → fsync(dir).
//
// Attacks blocked:
//   tampered manifest: attestation sig rejects
//   dropped rule: verifyExactSet missing-rule violation
//   extra/duplicate rule: verifyExactSet extra-rule/duplicate-id violation
//   sequence floor: incoming < floor.sequence → REJECT
//   idempotent re-fetch: same tuple accepted, floor not updated
//   expired freshness: clock check rejects
//   wrong-role freshness key: verifyFreshness role check rejects
//   freshness bound to different manifest: manifestDigest cross-check rejects
//   gap in sequence (floor+3): accepted (gap-tolerant)
//   replay with different scanId: requestDigest cross-check rejects
//   bundle key used for attestation: resolveAndImportKey role check rejects
//   duplicate JSON key: parseStrictNoDup rejects before any crypto
//   bundle key for attestation: role check on kid rejects
//   floor write failure: scan completes non-safe
//   runtimeId-mismatch — manifest.matcherRuntimeId !== RE2JS_V1_RUNTIME_ID: REJECT

import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { ensureSecureDir, writeSecureFileSync, SECURE_FILE_MODE } from '../utils/secure-fs.js'

import { sha256 } from '@noble/hashes/sha2.js'

import {
  canonicalJson,
  parseStrictNoDup,
  selectExpected,
  verifyExactSet,
  RE2JS_V1_RUNTIME_ID,
  computeExecutableHash,
  EXEC_RULE_FIELDS,
  EXEC_RULE_EXTENSION_FIELDS,
} from '@agenticcli/matcher-contract'

import {
  verifyAttestation,
  verifyFreshness,
  verifyBundleEnvelopeSignature,
  KEYRING,
} from './crypto.js'

// ---------------------------------------------------------------------------
// Compile-time constants (anti-downgrade lower bounds)
// ---------------------------------------------------------------------------

const MIN_ACCEPTABLE_SEQUENCE = 1

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Raw bundle response — all 5 components as opaque unknowns for strict parsing. */
export interface BundleResponseRaw {
  fullManifest: unknown
  corpusAttestation: unknown
  freshnessTok: unknown
  selectedRules: unknown
  bundleEnvelope: unknown
}

/** Successful verification result. */
export interface VerifyOk {
  ok: true
  selectedRules: ExecutableRule[]
}

/** Failure verification result. */
export interface VerifyFail {
  ok: false
  reason: string
  /** true = scan result cannot be trusted; false = structural protocol error. */
  nonSafe: boolean
}

export type VerifyResult = VerifyOk | VerifyFail

/** Canonical executable-rule form (matcher spec §3.1, contract 0.5.1). */
export interface ExecutableRule {
  // 0.5.0: action and blocking are now in the hash preimage.
  action?: 'block' | 'warn' | 'monitor'
  antiBoundary?: 'none' | 'word' | 'token'
  antiPattern?: string
  // 0.5.0: antiPatternScope and boundary are now in the hash preimage.
  // Tampering these fields now causes the recomputed hash to disagree with the manifest.
  antiPatternScope?: 'statement' | 'block' | 'function' | 'file' | { lines: number }
  blocking?: boolean
  boundary?: 'none' | 'word' | 'token'
  categories?: string[]
  /**
   * 0.5.1 (per-rule confidence — hardcoded-confidence fix): per-rule detection confidence from the
   * corpus governance model. REQUIRED and hashed — a bundle
   * whose rules lack confidence FAILS validation (fail-closed); the CLI never defaults to HIGH.
   */
  confidence: 'HIGH' | 'MEDIUM' | 'LOW'
  enabled: boolean
  fileGlob?: string
  flags: '' | 'i' | 'm' | 's' | 'im' | 'is' | 'ms' | 'ims'
  framework: string
  id: string
  matcherType: 'pattern' | 'file-presence' | 'file-relationship'
  pattern?: string
  presenceRule?: 'must-exist' | 'must-not-exist'
  requiresFile?: string
  requiresPattern?: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  tier: 'free' | 'pro'
  title: string
}

/** Persisted anti-downgrade floor tuple (matcher spec §5.4). */
export interface CliFloorTuple {
  keyringEpoch: number
  manifestDigest: string
  releaseId: string
  sequence: number
}

// ---------------------------------------------------------------------------
// Internal: SHA-256 helper
// ---------------------------------------------------------------------------

/**
 * Compute SHA-256 of input (string or bytes) and return lowercase hex.
 * Uses @noble/hashes/sha2 (sync, no WebCrypto async).
 */
function sha256hex(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  return Buffer.from(sha256(bytes)).toString('hex')
}

// ---------------------------------------------------------------------------
// Note: per-rule executableHash computation is provided by @agenticcli/matcher-contract
// (computeExecutableHash, EXEC_RULE_FIELDS, EXEC_RULE_EXTENSION_FIELDS).
// These are imported above and used in Steps 0b-5 and 4 below.
// The local implementations have been removed to eliminate server/CLI divergence.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Internal: floor file locking + durable write
// ---------------------------------------------------------------------------

/**
 * Acquire an advisory file lock using O_EXCL exclusive creation.
 * Returns a cleanup function to release the lock.
 * Retries up to timeoutMs with 10ms intervals.
 */
function acquireFloorLock(lockPath: string, timeoutMs = 5000): () => void {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const fd = fs.openSync(lockPath, 'wx', SECURE_FILE_MODE)
      fs.closeSync(fd)
      return () => {
        try { fs.unlinkSync(lockPath) } catch { /* ignore */ }
      }
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code
      if (code !== 'EEXIST') throw err
      // Lock exists — spin wait briefly
      const waitUntil = Date.now() + 10
      while (Date.now() < waitUntil) { /* spin */ }
    }
  }
  throw new Error(`floor lock timeout after ${timeoutMs}ms — concurrent CLI writer?`)
}

/**
 * Result of the atomic floor acceptance + conditional write operation.
 *
 * Finding 1 fix: the read → compare → accept-decision → write MUST all occur
 * under a single advisory lock. The pre-lock loadFloor + post-lock write pattern
 * had a TOCTOU: seq-3 writes first, seq-2 still passes the pre-lock comparison
 * (saw old floor) and is returned ACCEPTED from durableWriteFloor even though the
 * real floor under the lock is now higher.
 *
 * Finding 2 fix: ENOENT = genuine first-use (allowed). Present-but-invalid floor
 * = corruption (non-safe failure). Corruption must not be silently treated as first-use.
 */
type FloorAcceptResult =
  | { accepted: true; wrote: boolean }
  | { accepted: false; reason: string }
  | { corrupt: true; reason: string }

/** Outcome of comparing an incoming release tuple against the persisted floor. */
export type FloorDecision =
  | { decision: 'advance' }
  | { decision: 'idempotent' }
  | { decision: 'reject'; reason: string }

/**
 * The exact anti-downgrade contract, ordered lexicographically by (keyringEpoch, sequence):
 *   1. incoming.keyringEpoch > floor.keyringEpoch → ADVANCE, whatever the sequence. A key rotation
 *      resets the floor, so a poisoned epoch-1 floor (e.g. sequence 2^53-1 signed with a revoked
 *      key) cannot pin out the first epoch-2 release.
 *   2. incoming.keyringEpoch < floor.keyringEpoch → REJECT, whatever the sequence.
 *   3. same epoch, incoming.sequence < floor.sequence → REJECT (rollback).
 *   4. same epoch, same sequence: identical (releaseId, manifestDigest) → IDEMPOTENT;
 *      anything different → REJECT (substitution).
 *   5. same epoch, incoming.sequence > floor.sequence → ADVANCE (gap-tolerant).
 * Pure function; exported for the comparator-matrix tests.
 */
export function compareFloorTuples(floor: CliFloorTuple, incoming: CliFloorTuple): FloorDecision {
  if (incoming.keyringEpoch > floor.keyringEpoch) return { decision: 'advance' }
  if (incoming.keyringEpoch < floor.keyringEpoch) {
    return {
      decision: 'reject',
      reason: `keyring epoch rollback rejected: incoming epoch=${incoming.keyringEpoch}, floor epoch=${floor.keyringEpoch}`,
    }
  }
  if (incoming.sequence < floor.sequence) {
    return {
      decision: 'reject',
      reason: `sequence rollback rejected: incoming=${incoming.sequence}, floor=${floor.sequence} (epoch ${floor.keyringEpoch})`,
    }
  }
  if (incoming.sequence === floor.sequence) {
    if (incoming.releaseId === floor.releaseId && incoming.manifestDigest === floor.manifestDigest) {
      return { decision: 'idempotent' }
    }
    return {
      decision: 'reject',
      reason: `same-sequence/different-tuple rejected: sequence=${incoming.sequence} (epoch ${floor.keyringEpoch})`,
    }
  }
  return { decision: 'advance' }
}

/**
 * Attempt to accept a new floor tuple and durably write it, ALL under one advisory lock.
 *
 * Under the lock:
 *   1. Read and parse the current floor (if it exists).
 *   2. Distinguish ENOENT (first-use → allowed) from parse error (corruption → reject).
 *   3. Compare the locked current floor against the incoming tuple:
 *      - incoming.sequence < locked.sequence → reject (stale, do NOT accept)
 *      - incoming.sequence === locked.sequence && tuple differs → reject (substitution)
 *      - incoming.sequence === locked.sequence && tuple same → idempotent accept (no write)
 *      - incoming.sequence > locked.sequence → accept + write
 *   4. Write durably (write-temp → fsync → rename → fsync-dir) BEFORE returning accepted.
 *
 * @throws if the lock cannot be acquired (timeout) or if a durability write step fails.
 *         Callers should translate those throws into non-safe scan results.
 */
function atomicAcceptFloor(floorPath: string, incoming: CliFloorTuple): FloorAcceptResult {
  const lockPath = `${floorPath}.lock`
  const dir = path.dirname(floorPath)
  const tmpPath = path.join(dir, `.floor-tmp-${process.pid}-${Date.now()}.json`)

  // Fresh machine: ~/.shipguard does not exist on a fresh machine. The lock (O_EXCL create)
  // and temp file below both live in it, so create it (0700) BEFORE taking the lock.
  ensureSecureDir(dir)

  const releaseLock = acquireFloorLock(lockPath)
  try {
    // ── Under-lock: read current floor ────────────────────────────────────────
    // read-first approach — distinguish ENOENT (genuine first-use) from
    // other I/O errors (corruption/permission problem → fail closed).
    // The existsSync() approach had a TOCTOU and conflated ENOENT with other errors.
    let lockedFloor: CliFloorTuple | null = null

    let rawFloor: string | null = null
    try {
      rawFloor = fs.readFileSync(floorPath, 'utf-8')
    } catch (readErr: unknown) {
      const code = (readErr as NodeJS.ErrnoException).code
      if (code === 'ENOENT') {
        // Genuine first-use — floor file does not exist yet.
        rawFloor = null
      } else {
        // I/O error on file that may exist → corruption/permission problem.
        const msg = readErr instanceof Error ? readErr.message : String(readErr)
        return { corrupt: true, reason: `floor read I/O error (${code ?? 'unknown'}): ${msg}` }
      }
    }

    if (rawFloor !== null) {
      // Finding 2: parse with the duplicate-detecting parser. Any parse error on a
      // PRESENT floor = corruption — NOT first-use. Do NOT overwrite a corrupt floor;
      // do NOT accept the scan as if it were first-use. Fail closed.
      try {
        lockedFloor = parseStrictNoDup(rawFloor) as CliFloorTuple
        // Validate the parsed floor has the required fields AND safe-integer values.
        // Number.isSafeInteger() guards against float/NaN/Infinity injection.
        if (
          typeof lockedFloor.sequence !== 'number' ||
          !Number.isSafeInteger(lockedFloor.sequence) ||
          typeof lockedFloor.releaseId !== 'string' ||
          typeof lockedFloor.manifestDigest !== 'string' ||
          typeof lockedFloor.keyringEpoch !== 'number' ||
          !Number.isSafeInteger(lockedFloor.keyringEpoch)
        ) {
          return {
            corrupt: true,
            reason: 'floor file present but missing required fields or non-safe-integer values — treating as corruption (Finding 2)',
          }
        }
      } catch (parseErr: unknown) {
        const msg = parseErr instanceof Error ? parseErr.message : String(parseErr)
        return {
          corrupt: true,
          reason: `floor file present but not valid JSON (duplicate key or malformed): ${msg} — treating as corruption (Finding 2)`,
        }
      }
    }
    // rawFloor === null → lockedFloor === null → genuine first-use (ENOENT)

    // ── Under-lock: acceptance decision (exact lexicographic epoch floor) ──
    if (lockedFloor !== null) {
      const decision = compareFloorTuples(lockedFloor, incoming)
      if (decision.decision === 'reject') {
        return { accepted: false, reason: `${decision.reason} (under-lock)` }
      }
      if (decision.decision === 'idempotent') {
        // Byte-identical tuple — idempotent re-fetch, no write needed.
        return { accepted: true, wrote: false }
      }
      // decision === 'advance' → fall through to write
    }

    // ── Under-lock: durable write ──────────────────────────────────────────────
    // Step 1: write to temp file
    writeSecureFileSync(tmpPath, JSON.stringify(incoming))

    // Step 2: fsync(temp file)
    const tmpFd = fs.openSync(tmpPath, 'r+')
    try {
      fs.fsyncSync(tmpFd)
    } finally {
      fs.closeSync(tmpFd)
    }

    // Step 3: atomic rename(temp → floor)
    fs.renameSync(tmpPath, floorPath)

    // Step 4: fsync(parent directory) — ensures directory entry is durable
    const dirFd = fs.openSync(dir, 'r')
    try {
      fs.fsyncSync(dirFd)
    } finally {
      fs.closeSync(dirFd)
    }

    return { accepted: true, wrote: true }
  } finally {
    // Clean up temp file if rename failed
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath) } catch { /* ignore */ }
    releaseLock()
  }
}

// ---------------------------------------------------------------------------
// Public: verifyBundleResponse
// ---------------------------------------------------------------------------

/**
 * Verify a complete BundleResponse from the server.
 *
 * Implements matcher spec §7.2 verification order (all 7 steps):
 *  0. Parse all 5 components with duplicate-detecting parser
 *  1. Verify corpusAttestation
 *  2. Verify bundleEnvelope
 *  3. Verify freshnessTok
 *  4. Verify completeness — exact multiset
 *  5. Verify matcherRuntimeId === RE2JS_V1_RUNTIME_ID (runtimeId-mismatch)
 *  6. Sequence floor anti-downgrade
 *  7. Return selectedRules (plaintext in attested format)
 */
export async function verifyBundleResponse(
  response: BundleResponseRaw,
  request: {
    scanId: string
    frameworks: string[]
    options: Record<string, unknown>
    isPro?: boolean
  },
  floorPath: string,
): Promise<VerifyResult> {
  // ── Step 0: Parse all 5 components with duplicate-detecting parser ─────────
  let manifest: Record<string, unknown>
  let attestation: Record<string, unknown>
  let freshnessTok: Record<string, unknown>
  let deliveredRulesRaw: unknown[]
  let envelope: Record<string, unknown>

  try {
    // Re-serialize then parse so we reject objects with duplicate keys
    // (the response fields may already be parsed objects; re-serialize for parseStrictNoDup)
    const toStrictParsed = (v: unknown): Record<string, unknown> => {
      const json = typeof v === 'string' ? v : JSON.stringify(v)
      return parseStrictNoDup(json) as Record<string, unknown>
    }

    manifest = toStrictParsed(response.fullManifest)
    attestation = toStrictParsed(response.corpusAttestation)
    freshnessTok = toStrictParsed(response.freshnessTok)
    envelope = toStrictParsed(response.bundleEnvelope)

    const rulesJson = typeof response.selectedRules === 'string'
      ? response.selectedRules
      : JSON.stringify(response.selectedRules)
    const parsedRules = parseStrictNoDup(rulesJson)
    if (!Array.isArray(parsedRules)) {
      return { ok: false, reason: 'selectedRules is not an array', nonSafe: true }
    }
    deliveredRulesRaw = parsedRules as unknown[]
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { ok: false, reason: `parse-failure: ${msg}`, nonSafe: true }
  }

  // ── Step 0b: Strict schema validation (Finding 9) ─────────────────────────
  // Validate all 5 signed components against exact closed schemas BEFORE hashing
  // or field comparison. This catches unchecked casts, JS coercion, missing/extra
  // fields, wrong protocolVersion values, and malformed enums/integers.
  //
  // Rule: fail closed on ANY malformed signed object — do not proceed to crypto.

  // Helper: check that every listed required key is present and non-undefined.
  function requireFields(
    obj: Record<string, unknown>,
    fields: string[],
    label: string,
  ): VerifyFail | null {
    for (const f of fields) {
      if (!(f in obj) || obj[f] === undefined) {
        return { ok: false, reason: `${label}: missing required field "${f}"`, nonSafe: true }
      }
    }
    return null
  }

  // Helper: check that ONLY the listed keys are present (closed schema).
  function rejectExtraFields(
    obj: Record<string, unknown>,
    allowed: string[],
    label: string,
  ): VerifyFail | null {
    const allowedSet = new Set(allowed)
    for (const key of Object.keys(obj)) {
      if (!allowedSet.has(key)) {
        return { ok: false, reason: `${label}: unexpected field "${key}"`, nonSafe: true }
      }
    }
    return null
  }

  // Helper: check that a value is a safe integer (finite, no fractional part, within ±2^53).
  function isSafeInteger(v: unknown): v is number {
    return typeof v === 'number' && Number.isSafeInteger(v)
  }

  // 0b-1: Manifest schema
  {
    const MANIFEST_REQUIRED = [
      'protocolVersion', 'releaseId', 'releaseSequence', 'corpusRuleCount',
      'rules', 'capProfile', 'matcherEngineVersion', 'matcherEngineOptions',
      'matcherRuntimeId', 'contractVersion', 'gateBVersion', 'gateCVersion',
    ]
    const MANIFEST_ALLOWED = [...MANIFEST_REQUIRED, 'sourceYamlDigest']
    const f = requireFields(manifest, MANIFEST_REQUIRED, 'manifest')
    if (f) return f
    const x = rejectExtraFields(manifest, MANIFEST_ALLOWED, 'manifest')
    if (x) return x
    if (manifest['protocolVersion'] !== '1') {
      return { ok: false, reason: `manifest.protocolVersion must be "1", got "${manifest['protocolVersion']}"`, nonSafe: true }
    }
    if (!isSafeInteger(manifest['releaseSequence'])) {
      return { ok: false, reason: 'manifest.releaseSequence must be a safe integer', nonSafe: true }
    }
    if (!isSafeInteger(manifest['corpusRuleCount']) || (manifest['corpusRuleCount'] as number) < 0) {
      return { ok: false, reason: 'manifest.corpusRuleCount must be a non-negative safe integer', nonSafe: true }
    }
    if (typeof manifest['releaseId'] !== 'string' || manifest['releaseId'] === '') {
      return { ok: false, reason: 'manifest.releaseId must be a non-empty string', nonSafe: true }
    }
    if (!Array.isArray(manifest['rules'])) {
      return { ok: false, reason: 'manifest.rules must be an array', nonSafe: true }
    }
  }

  // 0b-2: Attestation schema
  {
    const ATT_REQUIRED = ['issuedAt', 'kid', 'manifestDigest', 'protocolVersion', 'releaseId', 'releaseSequence', 'signature']
    const f = requireFields(attestation, ATT_REQUIRED, 'attestation')
    if (f) return f
    const x = rejectExtraFields(attestation, ATT_REQUIRED, 'attestation')
    if (x) return x
    if (attestation['protocolVersion'] !== '1') {
      return { ok: false, reason: `attestation.protocolVersion must be "1", got "${attestation['protocolVersion']}"`, nonSafe: true }
    }
    if (!isSafeInteger(attestation['issuedAt'])) {
      return { ok: false, reason: 'attestation.issuedAt must be a safe integer', nonSafe: true }
    }
    if (!isSafeInteger(attestation['releaseSequence'])) {
      return { ok: false, reason: 'attestation.releaseSequence must be a safe integer', nonSafe: true }
    }
    if (typeof attestation['kid'] !== 'string' || attestation['kid'] === '') {
      return { ok: false, reason: 'attestation.kid must be a non-empty string', nonSafe: true }
    }
    if (typeof attestation['signature'] !== 'string' || attestation['signature'] === '') {
      return { ok: false, reason: 'attestation.signature must be a non-empty string', nonSafe: true }
    }
  }

  // 0b-3: Freshness token schema
  {
    const FRESH_REQUIRED = ['expiresAt', 'issuedAt', 'kid', 'manifestDigest', 'protocolVersion', 'releaseId', 'sequence', 'signature']
    const f = requireFields(freshnessTok, FRESH_REQUIRED, 'freshnessTok')
    if (f) return f
    const x = rejectExtraFields(freshnessTok, FRESH_REQUIRED, 'freshnessTok')
    if (x) return x
    if (freshnessTok['protocolVersion'] !== '1') {
      return { ok: false, reason: `freshnessTok.protocolVersion must be "1", got "${freshnessTok['protocolVersion']}"`, nonSafe: true }
    }
    if (!isSafeInteger(freshnessTok['issuedAt'])) {
      return { ok: false, reason: 'freshnessTok.issuedAt must be a safe integer', nonSafe: true }
    }
    if (!isSafeInteger(freshnessTok['expiresAt'])) {
      return { ok: false, reason: 'freshnessTok.expiresAt must be a safe integer', nonSafe: true }
    }
    if (!isSafeInteger(freshnessTok['sequence'])) {
      return { ok: false, reason: 'freshnessTok.sequence must be a safe integer', nonSafe: true }
    }
    if (typeof freshnessTok['kid'] !== 'string' || freshnessTok['kid'] === '') {
      return { ok: false, reason: 'freshnessTok.kid must be a non-empty string', nonSafe: true }
    }
    if (typeof freshnessTok['signature'] !== 'string' || freshnessTok['signature'] === '') {
      return { ok: false, reason: 'freshnessTok.signature must be a non-empty string', nonSafe: true }
    }
  }

  // 0b-4: Bundle envelope schema
  {
    const ENV_REQUIRED = [
      'exp', 'expectedRuleSet', 'frameworks', 'iat', 'kid', 'manifestDigest',
      'options', 'protocolVersion', 'releaseId', 'requestDigest', 'scanId',
      'sequence', 'signature',
    ]
    const f = requireFields(envelope, ENV_REQUIRED, 'bundleEnvelope')
    if (f) return f
    const x = rejectExtraFields(envelope, ENV_REQUIRED, 'bundleEnvelope')
    if (x) return x
    if (envelope['protocolVersion'] !== '1') {
      return { ok: false, reason: `bundleEnvelope.protocolVersion must be "1", got "${envelope['protocolVersion']}"`, nonSafe: true }
    }
    if (!isSafeInteger(envelope['exp'])) {
      return { ok: false, reason: 'bundleEnvelope.exp must be a safe integer', nonSafe: true }
    }
    if (!isSafeInteger(envelope['iat'])) {
      return { ok: false, reason: 'bundleEnvelope.iat must be a safe integer', nonSafe: true }
    }
    if (!isSafeInteger(envelope['sequence'])) {
      return { ok: false, reason: 'bundleEnvelope.sequence must be a safe integer', nonSafe: true }
    }
    if (!Array.isArray(envelope['expectedRuleSet'])) {
      return { ok: false, reason: 'bundleEnvelope.expectedRuleSet must be an array', nonSafe: true }
    }
    if (typeof envelope['kid'] !== 'string' || envelope['kid'] === '') {
      return { ok: false, reason: 'bundleEnvelope.kid must be a non-empty string', nonSafe: true }
    }
    if (typeof envelope['signature'] !== 'string' || envelope['signature'] === '') {
      return { ok: false, reason: 'bundleEnvelope.signature must be a non-empty string', nonSafe: true }
    }
  }

  // 0b-1b: Validate manifest.rules[] entries (recursive schema)
  {
    const manifestRulesArr = manifest['rules'] as unknown[]
    const MANIFEST_RULE_REQUIRED = ['id', 'executableHash', 'enabled', 'framework', 'tier', 'severity', 'matcherType', 'title', 'flags', 'sourceYamlDigest']
    // Severity in manifest entries may include the old 3-value set or the new 5-value set —
    // accept a broad union here (the signed ExecutableRule validation (0b-5) enforces the 5-value enum).
    const VALID_MANIFEST_SEVERITY = new Set(['error', 'warning', 'info', 'critical', 'high', 'medium', 'low'])
    const VALID_MANIFEST_MATCHER_TYPES = new Set(['pattern', 'file-presence', 'file-relationship'])
    for (let i = 0; i < manifestRulesArr.length; i++) {
      const r = manifestRulesArr[i]
      if (r === null || typeof r !== 'object' || Array.isArray(r)) {
        return { ok: false, reason: `manifest.rules[${i}] is not an object`, nonSafe: true }
      }
      const rEntry = r as Record<string, unknown>
      for (const field of MANIFEST_RULE_REQUIRED) {
        if (!(field in rEntry) || rEntry[field] === undefined) {
          return { ok: false, reason: `manifest.rules[${i}]: missing required field "${field}"`, nonSafe: true }
        }
      }
      if (typeof rEntry['id'] !== 'string' || rEntry['id'] === '') {
        return { ok: false, reason: `manifest.rules[${i}].id must be a non-empty string`, nonSafe: true }
      }
      if (typeof rEntry['executableHash'] !== 'string' || rEntry['executableHash'].length !== 64) {
        return { ok: false, reason: `manifest.rules[${i}].executableHash must be a 64-char hex string`, nonSafe: true }
      }
      if (typeof rEntry['enabled'] !== 'boolean') {
        return { ok: false, reason: `manifest.rules[${i}].enabled must be a boolean`, nonSafe: true }
      }
      if (typeof rEntry['severity'] !== 'string' || !VALID_MANIFEST_SEVERITY.has(rEntry['severity'] as string)) {
        return { ok: false, reason: `manifest.rules[${i}].severity must be a valid severity enum value, got "${rEntry['severity']}"`, nonSafe: true }
      }
      if (typeof rEntry['matcherType'] !== 'string' || !VALID_MANIFEST_MATCHER_TYPES.has(rEntry['matcherType'] as string)) {
        return { ok: false, reason: `manifest.rules[${i}].matcherType must be pattern|file-presence|file-relationship`, nonSafe: true }
      }
    }
  }

  // 0b-1c: Validate manifest.capProfile fields (recursive schema)
  {
    const cap = manifest['capProfile']
    if (cap === null || typeof cap !== 'object' || Array.isArray(cap)) {
      return { ok: false, reason: 'manifest.capProfile must be an object', nonSafe: true }
    }
    const capObj = cap as Record<string, unknown>
    const CAP_FIELDS = ['maxFileBytes', 'maxFiles', 'maxFindings', 'maxPatternBytes', 'maxPatternsPerRule', 'maxRules']
    for (const field of CAP_FIELDS) {
      if (!(field in capObj) || !Number.isSafeInteger(capObj[field]) || (capObj[field] as number) < 0) {
        return { ok: false, reason: `manifest.capProfile.${field} must be a non-negative safe integer`, nonSafe: true }
      }
    }
    // Reject extra fields in capProfile (closed schema)
    for (const key of Object.keys(capObj)) {
      if (!CAP_FIELDS.includes(key)) {
        return { ok: false, reason: `manifest.capProfile: unexpected field "${key}"`, nonSafe: true }
      }
    }
  }

  // 0b-1d: Validate manifest.matcherEngineOptions (recursive schema)
  {
    const opts = manifest['matcherEngineOptions']
    if (opts === null || typeof opts !== 'object' || Array.isArray(opts)) {
      return { ok: false, reason: 'manifest.matcherEngineOptions must be an object', nonSafe: true }
    }
    const optsObj = opts as Record<string, unknown>
    if (typeof optsObj['LOOKBEHINDS'] !== 'boolean') {
      return { ok: false, reason: 'manifest.matcherEngineOptions.LOOKBEHINDS must be a boolean', nonSafe: true }
    }
    // Strict: only LOOKBEHINDS allowed
    for (const key of Object.keys(optsObj)) {
      if (key !== 'LOOKBEHINDS') {
        return { ok: false, reason: `manifest.matcherEngineOptions: unexpected field "${key}"`, nonSafe: true }
      }
    }
  }

  // 0b-4b: Validate envelope.expectedRuleSet entries (recursive schema)
  {
    const expectedSet = envelope['expectedRuleSet'] as unknown[]
    for (let i = 0; i < expectedSet.length; i++) {
      const e = expectedSet[i]
      if (e === null || typeof e !== 'object' || Array.isArray(e)) {
        return { ok: false, reason: `bundleEnvelope.expectedRuleSet[${i}] is not an object`, nonSafe: true }
      }
      const eObj = e as Record<string, unknown>
      if (typeof eObj['id'] !== 'string' || eObj['id'] === '') {
        return { ok: false, reason: `bundleEnvelope.expectedRuleSet[${i}].id must be a non-empty string`, nonSafe: true }
      }
      if (typeof eObj['executableHash'] !== 'string' || eObj['executableHash'].length !== 64) {
        return { ok: false, reason: `bundleEnvelope.expectedRuleSet[${i}].executableHash must be a 64-char hex string`, nonSafe: true }
      }
      // Strict: only id and executableHash
      for (const key of Object.keys(eObj)) {
        if (key !== 'id' && key !== 'executableHash') {
          return { ok: false, reason: `bundleEnvelope.expectedRuleSet[${i}]: unexpected field "${key}"`, nonSafe: true }
        }
      }
    }
  }

  // 0b-4c: Validate envelope.frameworks entries (recursive schema)
  {
    const frameworks = envelope['frameworks']
    if (!Array.isArray(frameworks)) {
      return { ok: false, reason: 'bundleEnvelope.frameworks must be an array', nonSafe: true }
    }
    for (let i = 0; i < frameworks.length; i++) {
      if (typeof frameworks[i] !== 'string') {
        return { ok: false, reason: `bundleEnvelope.frameworks[${i}] must be a string`, nonSafe: true }
      }
    }
  }

  // 0b-5: Validate each delivered ExecutableRule schema (0.5.0 — complete field set)
  // This runs BEFORE hashing (step 4) so that schema violations are caught before crypto.
  // In 0.5.0, ALL fields are part of the hash preimage — no "extension fields" exclusion.
  {
    const VALID_FLAGS = new Set(['', 'i', 'm', 's', 'im', 'is', 'ms', 'ims'])
    const VALID_SEVERITY_5 = new Set(['critical', 'high', 'medium', 'low', 'info'])
    const VALID_MATCHER_TYPES = new Set(['pattern', 'file-presence', 'file-relationship'])
    const VALID_BOUNDARY = new Set(['none', 'word', 'token'])
    // In 0.5.0, EXEC_RULE_FIELDS contains ALL known fields (including former extension fields).
    // EXEC_RULE_EXTENSION_FIELDS is empty. Use the imported set directly.
    const EXEC_RULE_ALLOWED = new Set([...EXEC_RULE_FIELDS])
    // 0.5.1 (per-rule confidence): 'confidence' is REQUIRED on every delivered rule. A bundle missing it is
    // an OLD (pre-0.5.1) release — rejected fail-closed with a clear reason (attested bundles are
    // versioned; the server must re-publish with confidence). The CLI NEVER defaults to HIGH.
    const EXEC_RULE_REQUIRED = ['confidence', 'enabled', 'flags', 'framework', 'id', 'matcherType', 'severity', 'tier', 'title']
    const VALID_CONFIDENCE = new Set(['HIGH', 'MEDIUM', 'LOW'])

    for (let i = 0; i < deliveredRulesRaw.length; i++) {
      const r = deliveredRulesRaw[i]
      if (r === null || typeof r !== 'object' || Array.isArray(r)) {
        return { ok: false, reason: `selectedRules[${i}] is not an object`, nonSafe: true }
      }
      const rObj = r as Record<string, unknown>

      // Required fields
      for (const field of EXEC_RULE_REQUIRED) {
        if (!(field in rObj) || rObj[field] === undefined) {
          if (field === 'confidence') {
            // 0.5.1 fail-closed: a rule without confidence means a pre-0.5.1 (legacy) release.
            // Attested bundles are versioned — the server must re-publish the corpus with
            // per-rule confidence. Rejecting is the designed behavior, never defaulting to HIGH.
            return {
              ok: false,
              reason:
                `selectedRules[${i}]: missing required field "confidence" — this is a pre-0.5.1 ` +
                `release without per-rule confidence. The CLI refuses to guess (no HIGH default); ` +
                `the server must serve a re-published release that includes confidence.`,
              nonSafe: true,
            }
          }
          return { ok: false, reason: `selectedRules[${i}]: missing required field "${field}"`, nonSafe: true }
        }
      }

      // Extra fields (closed schema — only EXEC_RULE_FIELDS allowed)
      for (const key of Object.keys(rObj)) {
        if (!EXEC_RULE_ALLOWED.has(key as never)) {
          return { ok: false, reason: `selectedRules[${i}]: unexpected field "${key}"`, nonSafe: true }
        }
      }

      // Type/enum validation
      // 0.5.1 (per-rule confidence): confidence must be exactly HIGH|MEDIUM|LOW (corpus governance enum).
      // Any other value is a schema violation → reject nonSafe.
      if (typeof rObj['confidence'] !== 'string' || !VALID_CONFIDENCE.has(rObj['confidence'] as string)) {
        return { ok: false, reason: `selectedRules[${i}].confidence must be "HIGH"|"MEDIUM"|"LOW", got "${String(rObj['confidence'])}"`, nonSafe: true }
      }
      if (typeof rObj['enabled'] !== 'boolean') {
        return { ok: false, reason: `selectedRules[${i}].enabled must be a boolean`, nonSafe: true }
      }
      if (typeof rObj['flags'] !== 'string' || !VALID_FLAGS.has(rObj['flags'] as string)) {
        return { ok: false, reason: `selectedRules[${i}].flags must be a valid flags enum (""|"i"|"m"|"s"|"im"|"is"|"ms"|"ims"), got "${rObj['flags']}"`, nonSafe: true }
      }
      if (typeof rObj['id'] !== 'string' || rObj['id'] === '') {
        return { ok: false, reason: `selectedRules[${i}].id must be a non-empty string`, nonSafe: true }
      }
      if (typeof rObj['matcherType'] !== 'string' || !VALID_MATCHER_TYPES.has(rObj['matcherType'] as string)) {
        return { ok: false, reason: `selectedRules[${i}].matcherType must be pattern|file-presence|file-relationship`, nonSafe: true }
      }
      if (typeof rObj['severity'] !== 'string' || !VALID_SEVERITY_5.has(rObj['severity'] as string)) {
        return { ok: false, reason: `selectedRules[${i}].severity must be critical|high|medium|low|info, got "${rObj['severity']}"`, nonSafe: true }
      }
      if (typeof rObj['tier'] !== 'string' || (rObj['tier'] !== 'free' && rObj['tier'] !== 'pro')) {
        return { ok: false, reason: `selectedRules[${i}].tier must be "free"|"pro"`, nonSafe: true }
      }
      if (typeof rObj['title'] !== 'string') {
        return { ok: false, reason: `selectedRules[${i}].title must be a string`, nonSafe: true }
      }
      if (typeof rObj['framework'] !== 'string') {
        return { ok: false, reason: `selectedRules[${i}].framework must be a string`, nonSafe: true }
      }

      // Optional fields validation (all now part of the hash preimage in 0.5.0)
      if ('action' in rObj && rObj['action'] !== undefined) {
        if (typeof rObj['action'] !== 'string' || !['block', 'warn', 'monitor'].includes(rObj['action'] as string)) {
          return { ok: false, reason: `selectedRules[${i}].action must be "block"|"warn"|"monitor"`, nonSafe: true }
        }
      }
      if ('antiBoundary' in rObj && rObj['antiBoundary'] !== undefined) {
        if (typeof rObj['antiBoundary'] !== 'string' || !VALID_BOUNDARY.has(rObj['antiBoundary'] as string)) {
          return { ok: false, reason: `selectedRules[${i}].antiBoundary must be none|word|token`, nonSafe: true }
        }
      }
      // validate antiPatternScope — string enum OR {lines:N} object
      if ('antiPatternScope' in rObj && rObj['antiPatternScope'] !== undefined) {
        const scope = rObj['antiPatternScope']
        const VALID_SCOPE_STRINGS = new Set(['statement', 'block', 'function', 'file'])
        const isValidScopeString = typeof scope === 'string' && VALID_SCOPE_STRINGS.has(scope)
        const isValidScopeObject = (
          scope !== null &&
          typeof scope === 'object' &&
          !Array.isArray(scope) &&
          'lines' in (scope as object) &&
          Number.isSafeInteger((scope as Record<string, unknown>)['lines']) &&
          ((scope as Record<string, unknown>)['lines'] as number) >= 0 &&
          Object.keys(scope as object).length === 1
        )
        if (!isValidScopeString && !isValidScopeObject) {
          return { ok: false, reason: `selectedRules[${i}].antiPatternScope must be "statement"|"block"|"function"|"file" or {lines:N}`, nonSafe: true }
        }
      }
      if ('blocking' in rObj && rObj['blocking'] !== undefined) {
        if (typeof rObj['blocking'] !== 'boolean') {
          return { ok: false, reason: `selectedRules[${i}].blocking must be a boolean`, nonSafe: true }
        }
      }
      // validate boundary — now part of hash preimage
      if ('boundary' in rObj && rObj['boundary'] !== undefined) {
        if (typeof rObj['boundary'] !== 'string' || !VALID_BOUNDARY.has(rObj['boundary'] as string)) {
          return { ok: false, reason: `selectedRules[${i}].boundary must be "none"|"word"|"token"`, nonSafe: true }
        }
      }
      if ('categories' in rObj && rObj['categories'] !== undefined) {
        if (!Array.isArray(rObj['categories'])) {
          return { ok: false, reason: `selectedRules[${i}].categories must be an array`, nonSafe: true }
        }
      }
      if ('fileGlob' in rObj && rObj['fileGlob'] !== undefined) {
        if (typeof rObj['fileGlob'] !== 'string') {
          return { ok: false, reason: `selectedRules[${i}].fileGlob must be a string`, nonSafe: true }
        }
      }
      if ('presenceRule' in rObj && rObj['presenceRule'] !== undefined) {
        if (typeof rObj['presenceRule'] !== 'string' || !['must-exist', 'must-not-exist'].includes(rObj['presenceRule'] as string)) {
          return { ok: false, reason: `selectedRules[${i}].presenceRule must be "must-exist"|"must-not-exist"`, nonSafe: true }
        }
      }
    }
  }

  // ── Step 1: Verify corpusAttestation ─────────────────
  // 1a. Recompute manifestDigest = SHA-256("shipguard-manifest-v1\x00" + JCS(manifest))
  const manifestDigest = sha256hex('shipguard-manifest-v1\x00' + canonicalJson(manifest))

  // 1b. Verify manifest.protocolVersion === "1" (already done in schema check above)
  if (manifest['protocolVersion'] !== '1') {
    return { ok: false, reason: `unknown protocolVersion "${manifest['protocolVersion']}"`, nonSafe: true }
  }

  // 1c. Verify corpusRuleCount === rules.length
  const manifestRules = manifest['rules']
  if (!Array.isArray(manifestRules)) {
    return { ok: false, reason: 'manifest.rules is not an array', nonSafe: true }
  }
  if (manifest['corpusRuleCount'] !== manifestRules.length) {
    return {
      ok: false,
      reason: `manifest.corpusRuleCount (${manifest['corpusRuleCount']}) !== manifest.rules.length (${manifestRules.length})`,
      nonSafe: true,
    }
  }

  // 1d. Cross-checks on attestation fields
  if (attestation['releaseId'] !== manifest['releaseId']) {
    return {
      ok: false,
      reason: `attestation.releaseId mismatch: "${attestation['releaseId']}" !== "${manifest['releaseId']}"`,
      nonSafe: true,
    }
  }
  if (attestation['releaseSequence'] !== manifest['releaseSequence']) {
    return {
      ok: false,
      reason: `attestation.releaseSequence mismatch`,
      nonSafe: true,
    }
  }
  if (attestation['manifestDigest'] !== manifestDigest) {
    return {
      ok: false,
      reason: `attestation.manifestDigest does not match recomputed manifest digest`,
      nonSafe: true,
    }
  }

  // 1e. Verify attestation signature (rejects wrong role)
  try {
    // Build attestation-without-signature
    const { signature: _sig, ...attestationWithoutSig } = attestation as Record<string, unknown> & { signature: string }
    const attPreimage = new TextEncoder().encode(
      'shipguard-attestation-v1\x00' + canonicalJson(attestationWithoutSig)
    )
    await verifyAttestation(attPreimage, attestation['signature'] as string, attestation['kid'] as string)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { ok: false, reason: `attestation-verify-failed: ${msg}`, nonSafe: true }
  }

  // ── Step 2: Verify bundleEnvelope ──────────────────────────────────
  // 2a. Compute requestDigest = SHA-256(JCS({frameworks, options, scanId}))
  // matcher spec §3.5: "SHA-256 of the canonical request object (frameworks + options + scanId)"
  // No domain prefix defined for the request object — use plain canonicalJson
  const requestObj = {
    frameworks: request.frameworks,
    options: request.options,
    scanId: request.scanId,
  }
  const requestDigest = sha256hex(canonicalJson(requestObj))

  // 2b. Cross-checks
  if (envelope['releaseId'] !== manifest['releaseId']) {
    return { ok: false, reason: `envelope.releaseId mismatch`, nonSafe: true }
  }
  if (envelope['sequence'] !== manifest['releaseSequence']) {
    return { ok: false, reason: `envelope.sequence mismatch`, nonSafe: true }
  }
  if (envelope['manifestDigest'] !== manifestDigest) {
    return { ok: false, reason: `envelope.manifestDigest does not match manifest digest`, nonSafe: true }
  }
  const now = Math.floor(Date.now() / 1000)
  if (typeof envelope['exp'] !== 'number' || envelope['exp'] <= now) {
    return { ok: false, reason: `bundle envelope expired (exp=${envelope['exp']}, now=${now})`, nonSafe: true }
  }
  if (envelope['requestDigest'] !== requestDigest) {
    return {
      ok: false,
      reason: `envelope.requestDigest mismatch — possible replay for a different scanId/request`,
      nonSafe: true,
    }
  }

  // 2c. Verify envelope signature (replay for different scanId blocked by requestDigest)
  try {
    const { signature: _eSig, ...envelopeWithoutSig } = envelope as Record<string, unknown> & { signature: string }
    const envPreimage = new TextEncoder().encode(
      'shipguard-bundle-v1\x00' + canonicalJson(envelopeWithoutSig)
    )
    await verifyBundleEnvelopeSignature(envPreimage, envelope['signature'] as string, envelope['kid'] as string)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { ok: false, reason: `envelope-verify-failed: ${msg}`, nonSafe: true }
  }

  // ── Step 3: Verify freshnessTok ───────────────────
  // 3a. Freshness clock checks
  const nowFresh = Math.floor(Date.now() / 1000)
  const issuedAt = freshnessTok['issuedAt'] as number
  const expiresAt = freshnessTok['expiresAt'] as number
  const CLOCK_SKEW = 300 // ±5 minutes

  if (nowFresh > expiresAt + CLOCK_SKEW) {
    return {
      ok: false,
      reason: `freshness token expired (expiresAt=${expiresAt}, now=${nowFresh})`,
      nonSafe: true,
    }
  }
  if (nowFresh < issuedAt - CLOCK_SKEW) {
    return {
      ok: false,
      reason: `freshness token issued in the future (issuedAt=${issuedAt}, now=${nowFresh})`,
      nonSafe: true,
    }
  }
  // Max TTL check (matcher spec §3.4: max 25 hours = 90000 seconds)
  if (expiresAt - issuedAt > 90000) {
    return {
      ok: false,
      reason: `freshness token TTL exceeds maximum 25 hours (${expiresAt - issuedAt}s)`,
      nonSafe: true,
    }
  }

  // 3b. Cross-checks on freshness fields
  if (freshnessTok['releaseId'] !== manifest['releaseId']) {
    return { ok: false, reason: `freshnessTok.releaseId mismatch`, nonSafe: true }
  }
  if (freshnessTok['sequence'] !== manifest['releaseSequence']) {
    return { ok: false, reason: `freshnessTok.sequence mismatch`, nonSafe: true }
  }
  if (freshnessTok['manifestDigest'] !== manifestDigest) {
    return {
      ok: false,
      reason: `freshnessTok.manifestDigest mismatch — token bound to a different manifest`,
      nonSafe: true,
    }
  }

  // 3c. Verify freshness signature (wrong-role key rejects via resolveAndImportKey)
  try {
    const { signature: _fSig, ...freshnessWithoutSig } = freshnessTok as Record<string, unknown> & { signature: string }
    const freshPreimage = new TextEncoder().encode(
      'shipguard-freshness-v1\x00' + canonicalJson(freshnessWithoutSig)
    )
    await verifyFreshness(freshPreimage, freshnessTok['signature'] as string, freshnessTok['kid'] as string)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { ok: false, reason: `freshness-verify-failed: ${msg}`, nonSafe: true }
  }

  // ── Step 4: Completeness — exact multiset ───────────────────
  // 4a. Compute per-rule hashes and verify against manifest entries
  // Build a map of manifest entries for O(1) lookup
  const manifestRuleMap = new Map<string, Record<string, unknown>>()
  for (const r of manifestRules) {
    const rEntry = r as Record<string, unknown>
    manifestRuleMap.set(rEntry['id'] as string, rEntry)
  }

  const deliveredWithHashes: Array<{ id: string; executableHash: string; rule: ExecutableRule }> = []
  for (const rawRule of deliveredRulesRaw) {
    const ruleObj = rawRule as Record<string, unknown>
    const ruleId = ruleObj['id'] as string

    // Recompute hash and verify against manifest entry.
    // Uses the shared computeExecutableHash from @agenticcli/matcher-contract (matcher spec §3.1)
    // to ensure server (build-manifest.ts) and CLI produce identical hashes.
    let recomputedHash: string
    try {
      recomputedHash = computeExecutableHash(ruleObj)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      return { ok: false, reason: `rule-hash-compute-failed for "${ruleId}": ${msg}`, nonSafe: true }
    }

    const manifestEntry = manifestRuleMap.get(ruleId)
    if (!manifestEntry) {
      return {
        ok: false,
        reason: `delivered rule "${ruleId}" not found in manifest`,
        nonSafe: true,
      }
    }
    if (manifestEntry['executableHash'] !== recomputedHash) {
      return {
        ok: false,
        reason: `rule "${ruleId}" hash mismatch: manifest="${manifestEntry['executableHash']}", recomputed="${recomputedHash}"`,
        nonSafe: true,
      }
    }

    deliveredWithHashes.push({
      id: ruleId,
      executableHash: recomputedHash,
      rule: ruleObj as unknown as ExecutableRule,
    })
  }

  // 4b. Compute expected set from manifest
  // WHY: manifest is typed Record<string, unknown> at this scope, but its shape has been
  // guaranteed by the recursive strict-schema validation above (lines 702–784) which
  // checks every required FullManifest field (protocolVersion, releaseId, releaseSequence,
  // corpusRuleCount, rules[], capProfile, matcherEngineVersion, matcherEngineOptions,
  // matcherRuntimeId (must equal RE2JS_V1_RUNTIME_ID), contractVersion, gateBVersion, gateCVersion) and rejects on any
  // mismatch. Direct cast fails due to insufficient overlap; unknown intermediate is correct.
  const manifestForSelector = manifest as unknown as import('@agenticcli/matcher-contract').FullManifest
  let expectedSet: import('@agenticcli/matcher-contract').ExpectedSet
  try {
    expectedSet = selectExpected(manifestForSelector, {
      frameworks: request.frameworks,
      isPro: request.isPro ?? false,
    })
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { ok: false, reason: `select-expected-failed: ${msg}`, nonSafe: true }
  }

  // 4c. Verify exact multiset against expected
  const deliveredPairs = deliveredWithHashes.map(d => ({ id: d.id, executableHash: d.executableHash }))
  const exactSetResult = verifyExactSet(deliveredPairs, expectedSet)
  if (!exactSetResult.ok) {
    const violations = exactSetResult.violations.map(v => `${v.type}:${v.ruleId}`).join(', ')
    return {
      ok: false,
      reason: `completeness-mismatch: ${violations}`,
      nonSafe: true,
    }
  }

  // 4d. Also verify bundleEnvelope.expectedRuleSet matches the computed expectedSet
  const envelopeExpected = envelope['expectedRuleSet'] as Array<{ id: string; executableHash: string }>
  if (!Array.isArray(envelopeExpected)) {
    return { ok: false, reason: 'bundleEnvelope.expectedRuleSet is not an array', nonSafe: true }
  }
  const envelopeSetResult = verifyExactSet(envelopeExpected, expectedSet)
  if (!envelopeSetResult.ok) {
    const violations = envelopeSetResult.violations.map(v => `${v.type}:${v.ruleId}`).join(', ')
    return {
      ok: false,
      reason: `envelope.expectedRuleSet mismatch: ${violations}`,
      nonSafe: true,
    }
  }

  // ── Step 5: Runtime identity check ────────────────────────────────────────
  if (manifest['matcherRuntimeId'] !== RE2JS_V1_RUNTIME_ID) {
    return {
      ok: false,
      reason: `matcherRuntimeId mismatch: manifest="${manifest['matcherRuntimeId']}", CLI="${RE2JS_V1_RUNTIME_ID}"`,
      nonSafe: true,
    }
  }

  // ── Step 6: Sequence floor anti-downgrade ─────────────────
  // Finding 1 fix: ALL of read → compare → accept-decision → write happen under
  // ONE advisory lock via atomicAcceptFloor(). The pre-lock loadFloor + post-lock
  // write pattern was a TOCTOU: a concurrent seq-3 could write first while seq-2
  // was doing the pre-lock comparison, leaving seq-2 "accepted" but stale.
  const incomingSequence = manifest['releaseSequence'] as number
  const incomingReleaseId = manifest['releaseId'] as string

  // MIN_ACCEPTABLE_SEQUENCE check
  if (incomingSequence < MIN_ACCEPTABLE_SEQUENCE) {
    return {
      ok: false,
      reason: `sequence ${incomingSequence} is below MIN_ACCEPTABLE_SEQUENCE ${MIN_ACCEPTABLE_SEQUENCE}`,
      nonSafe: true,
    }
  }

  // Determine keyringEpoch from the attestation kid
  // The attestation signature was already verified against this kid, so the entry exists; a
  // missing entry here is an internal inconsistency and must fail closed, never default.
  const attestationEntry = KEYRING.find(e => e.kid === (attestation['kid'] as string))
  if (!attestationEntry) {
    return {
      ok: false,
      reason: `attestation kid "${String(attestation['kid'])}" vanished from KEYRING after verification`,
      nonSafe: true,
    }
  }
  const incomingKeyringEpoch = attestationEntry.epoch

  const incomingTuple: CliFloorTuple = {
    sequence: incomingSequence,
    releaseId: incomingReleaseId,
    manifestDigest,
    keyringEpoch: incomingKeyringEpoch,
  }

  // Atomic floor accept + conditional write (Finding 1 + 2 combined fix).
  let floorResult: FloorAcceptResult
  try {
    floorResult = atomicAcceptFloor(floorPath, incomingTuple)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    // Lock timeout or durable-write I/O failure → non-safe
    return {
      ok: false,
      reason: `floor-write-failure: ${msg}`,
      nonSafe: true,
    }
  }

  // Finding 2: corrupt floor → non-safe (not first-use)
  if ('corrupt' in floorResult) {
    return {
      ok: false,
      reason: `floor-corruption: ${floorResult.reason}`,
      nonSafe: true,
    }
  }

  // Finding 1: stale sequence or same-seq/different-tuple rejected under lock
  if (!floorResult.accepted) {
    return {
      ok: false,
      reason: floorResult.reason,
      nonSafe: true,
    }
  }

  // ── Step 7: Return selectedRules ──────────────────────────────────────────
  // In the attested format, selectedRules are plaintext ExecutableRule[] —
  // verification is by attestation + envelope + completeness checks above.
  const selectedRules = deliveredWithHashes.map(d => d.rule)

  return { ok: true, selectedRules }
}
