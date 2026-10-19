/**
 * TDD suite for verifyBundleResponse — CLI-side attested-release verification.
 *
 * Each test is named after the GC attack it covers (per matcher spec §7.2 +
 * VERIFICATION-PLAN). Tests sign real fixtures with ephemeral Ed25519 keypairs
 * injected via _testInjectKeyringEntry.
 *
 * GC attacks covered:
 *   tampered manifest byte
 *   missing rule in selectedRules (completeness)
 *   extra rule in selectedRules
 *   duplicate rule id in selectedRules
 *   sequence below floor (replay)
 *   idempotent re-fetch (same tuple accepted)
 *   gap-tolerant sequence (floor+3 accepted)
 *   expired freshness token
 *   freshness signed by bundle key (wrong role)
 *   freshnessTok.manifestDigest mismatch
 *   valid bundle replayed with different scanId
 *   bundle-key signature used for attestation
 *   duplicate JSON field
 *   forged attestation signed with bundle key
 *   floor write fails
 *   runtimeId-mismatch — manifest.matcherRuntimeId wrong
 *   valid-full-flow — complete valid bundle
 */

import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'

// ---------------------------------------------------------------------------
// Dynamic imports (ESM modules with top-level await patterns)
// ---------------------------------------------------------------------------

const { verifyBundleResponse } = await import('../../src/core/release-verify.js')
const { _testInjectKeyringEntry, computeSpkiFingerprint } = await import('../../src/core/crypto.js')
const { canonicalJson, NATIVE_V1_RUNTIME_ID, RE2JS_V1_RUNTIME_ID } = await import('@agenticcli/matcher-contract')
const { sha256 } = await import('@noble/hashes/sha2.js')

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type KeyRole = 'release-attestation' | 'ci-freshness' | 'bundle' | 'auth'

interface TestKeypair {
  privateKey: CryptoKey
  publicKey: CryptoKey
  pem: string
  kid: string
  role: KeyRole
  cleanup: () => void
}

async function generateAndInjectKeypair(
  kid: string,
  role: KeyRole,
  overrides?: { expiry?: number; epoch?: number },
): Promise<TestKeypair> {
  const { privateKey, publicKey } = await globalThis.crypto.subtle.generateKey(
    'Ed25519', true, ['sign', 'verify'],
  )
  const spkiDer = await globalThis.crypto.subtle.exportKey('spki', publicKey)
  const b64 = Buffer.from(spkiDer).toString('base64')
  const lines = b64.match(/.{1,64}/g)!.join('\n')
  const pem = `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`

  const cleanup = _testInjectKeyringEntry({
    kid,
    role,
    epoch: overrides?.epoch ?? 2, // MIN_ACCEPTABLE_EPOCH is 2
    expiry: overrides?.expiry ?? Math.floor(Date.now() / 1000) + 3600,
    fingerprint: computeSpkiFingerprint(pem), // computed-fingerprint guard
    publicKey: pem,
  })

  return { privateKey, publicKey, pem, kid, role, cleanup }
}

function sha256hex(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  return Buffer.from(sha256(bytes)).toString('hex')
}

async function sign(preimageBytes: Uint8Array, privateKey: CryptoKey): Promise<string> {
  const sigBytes = await globalThis.crypto.subtle.sign('Ed25519', privateKey, preimageBytes)
  return Buffer.from(sigBytes).toString('base64url')
}

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

interface FixtureManifest {
  protocolVersion: '1'
  releaseId: string
  releaseSequence: number
  corpusRuleCount: number
  rules: Array<{
    id: string
    executableHash: string
    enabled: boolean
    framework: string
    tier: string
    severity: string
    matcherType: string
    title: string
    flags: string
    sourceYamlDigest: string
  }>
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

/** Build a canonical ExecutableRule for a test rule, then hash it */
function buildTestRuleHash(
  ruleId: string,
  framework: string,
  tier: 'free' | 'pro',
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'medium',
  // 0.5.1 (per-rule confidence): confidence is REQUIRED on the wire. Fixtures default to HIGH;
  // pass null to build a legacy (pre-0.5.1) rule object for the fail-closed tests.
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | null = 'HIGH',
): {
  executableHash: string
  ruleObj: Record<string, unknown>
} {
  const ruleObj: Record<string, unknown> = {
    ...(confidence !== null ? { confidence } : {}),
    enabled: true,
    flags: '',
    framework,
    id: ruleId,
    matcherType: 'pattern' as const,
    pattern: 'TODO',
    // Fix 1/5: use 5-value severity enum (critical|high|medium|low|info).
    // The old 'warning' value is no longer valid after Fix 5 schema validation.
    severity,
    tier,
    title: `Test Rule ${ruleId}`,
  }
  const preimage = 'shipguard-rule-v1\x00' + canonicalJson(ruleObj)
  const executableHash = sha256hex(preimage)
  return { executableHash, ruleObj }
}

async function buildValidFixtures(overrides?: {
  sequence?: number
  releaseId?: string
  runtimeId?: string
  rulesTier?: 'free' | 'pro'
  extraRuleIds?: string[]
  missingRuleId?: string
  freshnessTtl?: number
  freshnessIssuedAt?: number
  freshnessManifestDigest?: string
  /** 0.5.1 (per-rule confidence): null builds a legacy rule WITHOUT confidence (hash-consistent). */
  ruleConfidence?: 'HIGH' | 'MEDIUM' | 'LOW' | null
  /** inject the three keys under these exact kids (e.g. the retired ra-k1-2026 set). */
  kids?: { ra: string; cf: string; bundle: string }
  /** keyring epoch of the injected keys (default 2). */
  keyEpoch?: number
}): Promise<{
  manifest: FixtureManifest
  manifestDigest: string
  attestation: Record<string, unknown>
  freshnessTok: Record<string, unknown>
  bundleEnvelope: Record<string, unknown>
  selectedRules: Record<string, unknown>[]
  request: { scanId: string; frameworks: string[]; options: Record<string, unknown>; isPro?: boolean }
  raKeypair: TestKeypair
  cfKeypair: TestKeypair
  bundleKeypair: TestKeypair
  cleanupAll: () => void
}> {
  const sequence = overrides?.sequence ?? 100
  const releaseId = overrides?.releaseId ?? 'test-release-' + Math.random().toString(36).slice(2)
  const tier = overrides?.rulesTier ?? 'free'

  // Generate keypairs
  const epochOverride = overrides?.keyEpoch !== undefined ? { epoch: overrides.keyEpoch } : undefined
  const raKeypair = await generateAndInjectKeypair(overrides?.kids?.ra ?? 'test-ra-' + sequence, 'release-attestation', epochOverride)
  const cfKeypair = await generateAndInjectKeypair(overrides?.kids?.cf ?? 'test-cf-' + sequence, 'ci-freshness', epochOverride)
  const bundleKeypair = await generateAndInjectKeypair(overrides?.kids?.bundle ?? 'test-bk-' + sequence, 'bundle', epochOverride)

  // Build rules
  const { executableHash: ruleHash, ruleObj } = buildTestRuleHash(
    'rule-001', 'generic', tier, 'medium',
    overrides?.ruleConfidence === undefined ? 'HIGH' : overrides.ruleConfidence,
  )

  const manifestRules = [
    {
      id: 'rule-001',
      executableHash: ruleHash,
      enabled: true,
      framework: 'generic',
      tier,
      // Fix 1/5: use 5-value severity enum. 'warning' is no longer accepted.
      severity: 'medium',
      matcherType: 'pattern',
      title: 'Test Rule rule-001',
      flags: '',
      sourceYamlDigest: sha256hex('yaml-content-001'),
    },
  ]

  const manifest: FixtureManifest = {
    protocolVersion: '1',
    releaseId,
    releaseSequence: sequence,
    corpusRuleCount: manifestRules.length,
    rules: manifestRules,
    capProfile: {
      maxFileBytes: 1048576,
      maxFiles: 1000,
      maxFindings: 500,
      maxPatternBytes: 4096,
      maxPatternsPerRule: 50,
      maxRules: 500,
    },
    matcherEngineVersion: 'native-v1',
    matcherEngineOptions: { LOOKBEHINDS: false },
    matcherRuntimeId: overrides?.runtimeId ?? RE2JS_V1_RUNTIME_ID,
    contractVersion: '1.0.0',
    gateBVersion: '1.0.0',
    gateCVersion: '1.0.0',
  }

  // Compute manifestDigest
  const manifestDigest = sha256hex('shipguard-manifest-v1\x00' + canonicalJson(manifest))

  // Build attestation (without signature)
  const attBase: Record<string, unknown> = {
    issuedAt: Math.floor(Date.now() / 1000),
    kid: raKeypair.kid,
    manifestDigest,
    protocolVersion: '1',
    releaseId,
    releaseSequence: sequence,
  }
  const attPreimage = new TextEncoder().encode('shipguard-attestation-v1\x00' + canonicalJson(attBase))
  const attSig = await sign(attPreimage, raKeypair.privateKey)
  const attestation = { ...attBase, signature: attSig }

  // Build freshness token (without signature)
  const nowSec = Math.floor(Date.now() / 1000)
  const freshTtl = overrides?.freshnessTtl ?? 86400
  const freshIssuedAt = overrides?.freshnessIssuedAt ?? nowSec
  const freshBase: Record<string, unknown> = {
    expiresAt: freshIssuedAt + freshTtl,
    issuedAt: freshIssuedAt,
    kid: cfKeypair.kid,
    manifestDigest: overrides?.freshnessManifestDigest ?? manifestDigest,
    protocolVersion: '1',
    releaseId,
    sequence,
  }
  const freshPreimage = new TextEncoder().encode('shipguard-freshness-v1\x00' + canonicalJson(freshBase))
  const freshSig = await sign(freshPreimage, cfKeypair.privateKey)
  const freshnessTok = { ...freshBase, signature: freshSig }

  // Build request
  const request = {
    scanId: 'scan-' + Math.random().toString(36).slice(2),
    frameworks: ['generic'],
    options: {} as Record<string, unknown>,
    isPro: false,
  }

  // Compute requestDigest
  const requestDigest = sha256hex(canonicalJson({
    frameworks: request.frameworks,
    options: request.options,
    scanId: request.scanId,
  }))

  // Build expectedRuleSet
  const expectedRuleSet = [{ id: 'rule-001', executableHash: ruleHash }]

  // Build envelope (without signature)
  const envBase: Record<string, unknown> = {
    exp: nowSec + 600,
    expectedRuleSet,
    frameworks: request.frameworks,
    iat: nowSec,
    kid: bundleKeypair.kid,
    manifestDigest,
    options: request.options,
    protocolVersion: '1',
    releaseId,
    requestDigest,
    scanId: request.scanId,
    sequence,
  }
  const envPreimage = new TextEncoder().encode('shipguard-bundle-v1\x00' + canonicalJson(envBase))
  const envSig = await sign(envPreimage, bundleKeypair.privateKey)
  const bundleEnvelope = { ...envBase, signature: envSig }

  // selectedRules = the executable rule objects
  const selectedRules = [ruleObj]

  const cleanupAll = () => {
    raKeypair.cleanup()
    cfKeypair.cleanup()
    bundleKeypair.cleanup()
  }

  return {
    manifest,
    manifestDigest,
    attestation,
    freshnessTok,
    bundleEnvelope,
    selectedRules,
    request,
    raKeypair,
    cfKeypair,
    bundleKeypair,
    cleanupAll,
  }
}

// ---------------------------------------------------------------------------
// Temp floor file helper
// ---------------------------------------------------------------------------

function makeTempFloorPath(): string {
  return path.join(os.tmpdir(), `sg-test-floor-${Date.now()}-${Math.random().toString(36).slice(2)}.json`)
}

function makeInvalidFloorPath(): string {
  // A path whose parent "directory" is a regular FILE → the parent can never be created
  // (ENOTDIR) → the lock/write genuinely fails. (A merely MISSING parent is NOT a failure:
  // that is the fresh-machine case, fixed in 0.7.1 — see the fresh-home tests below.)
  const blocker = path.join(os.tmpdir(), `sg-test-notadir-${Date.now()}-${Math.random().toString(36).slice(2)}`)
  fs.writeFileSync(blocker, 'x')
  return path.join(blocker, 'floor.json')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('verifyBundleResponse', () => {
  const cleanupFns: Array<() => void> = []

  afterEach(() => {
    for (const fn of cleanupFns.splice(0)) fn()
  })

  // ── valid-full-flow ────────────────────────────────────────────────────────
  it('valid-full-flow: complete valid bundle returns ok with selectedRules', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.selectedRules).toHaveLength(1)
      expect(result.selectedRules[0].id).toBe('rule-001')
    }

    // Floor file should have been written
    expect(fs.existsSync(floorPath)).toBe(true)

    // Cleanup
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── Per-rule confidence (0.5.1): per-rule confidence is REQUIRED + hashed ─────────────
  // Fail-before/pass-after: before the 0.5.1 contract change, a rule WITHOUT
  // confidence verified fine (and the CLI then hardcoded confidence:HIGH); a rule
  // WITH confidence was rejected as an unknown extra field. After: confidence is
  // required (fail-closed), enum-validated, and part of the executableHash preimage.
  it('task#16: valid bundle carries the REAL per-rule confidence through to selectedRules', async () => {
    const f = await buildValidFixtures({ ruleConfidence: 'MEDIUM' })
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.selectedRules[0].confidence).toBe('MEDIUM')
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('task#16: rule WITHOUT confidence (pre-0.5.1 legacy release) is rejected fail-closed', async () => {
    // Hash-consistent legacy fixture: the manifest hash matches the no-confidence rule
    // object, so the ONLY failure must be the missing-confidence schema gate — proving
    // the CLI refuses to default to HIGH rather than failing on a hash mismatch.
    const f = await buildValidFixtures({ ruleConfidence: null })
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toContain('missing required field "confidence"')
      expect(result.nonSafe).toBe(true)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('task#16: invalid confidence value is rejected (enum HIGH|MEDIUM|LOW only)', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Tamper the delivered rule's confidence to a non-enum value.
    const tamperedRules = [{ ...f.selectedRules[0], confidence: 'high' }]

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: tamperedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toContain('confidence must be "HIGH"|"MEDIUM"|"LOW"')
      expect(result.nonSafe).toBe(true)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('task#16: TAMPERED confidence (HIGH→LOW downgrade) is caught by the executableHash', async () => {
    // The manifest hash was computed over confidence:HIGH; delivering confidence:LOW
    // must produce a recomputed-hash mismatch — confidence is cryptographically bound,
    // not advisory metadata a MITM could soften.
    const f = await buildValidFixtures({ ruleConfidence: 'HIGH' })
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const tamperedRules = [{ ...f.selectedRules[0], confidence: 'LOW' }]

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: tamperedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toContain('hash mismatch')
      expect(result.nonSafe).toBe(true)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── tampered manifest ────────────────────────────────────────────────
  it('tampered manifest byte causes attestation verification to reject', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Tamper with the manifest: change a field
    const tamperedManifest = {
      ...f.manifest,
      corpusRuleCount: f.manifest.corpusRuleCount + 1, // tampered
      rules: [...f.manifest.rules, ...f.manifest.rules], // add extra to match count
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: tamperedManifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      // Either manifestDigest mismatch in attestation OR corpusRuleCount mismatch
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── missing rule ─────────────────────────────────────────────────────
  it('missing highest-severity rule causes completeness to reject', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: [], // no rules delivered
        bundleEnvelope: {
          ...f.bundleEnvelope,
          expectedRuleSet: [], // also empty to pass envelope check
        },
      },
      f.request,
      floorPath,
    )

    // The envelope also needs to reflect the delivered rules. Since the envelope has
    // a different expectedRuleSet (empty vs manifest-derived non-empty), it will fail
    // on either completeness or envelope expectedRuleSet mismatch.
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── extra rule ─────────────────────────────────────────────────────
  it('extra rule in selectedRules causes completeness to reject', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Add an extra rule not in the manifest
    const extraRule = {
      enabled: true,
      flags: '',
      framework: 'generic',
      id: 'rule-EXTRA',
      matcherType: 'pattern',
      pattern: 'extra',
      severity: 'error',
      tier: 'free',
      title: 'Extra Rule',
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: [...f.selectedRules, extraRule],
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      // Either rule-EXTRA not in manifest, or envelope mismatch
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── duplicate rule id ───────────────────────────────────────────────
  it('duplicate rule id in selectedRules causes completeness to reject', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: [...f.selectedRules, ...f.selectedRules], // duplicate
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── sequence below floor (replay) ────────────────────────────────────
  it('sequence below floor is rejected (anti-downgrade)', async () => {
    // First, accept a high-sequence bundle to set the floor
    const f1 = await buildValidFixtures({ sequence: 200 })
    cleanupFns.push(f1.cleanupAll)
    const floorPath = makeTempFloorPath()

    const r1 = await verifyBundleResponse(
      {
        fullManifest: f1.manifest,
        corpusAttestation: f1.attestation,
        freshnessTok: f1.freshnessTok,
        selectedRules: f1.selectedRules,
        bundleEnvelope: f1.bundleEnvelope,
      },
      f1.request,
      floorPath,
    )
    expect(r1.ok).toBe(true)

    // Now try to replay an older-sequence bundle
    const f2 = await buildValidFixtures({ sequence: 100 }) // lower sequence
    cleanupFns.push(f2.cleanupAll)

    const r2 = await verifyBundleResponse(
      {
        fullManifest: f2.manifest,
        corpusAttestation: f2.attestation,
        freshnessTok: f2.freshnessTok,
        selectedRules: f2.selectedRules,
        bundleEnvelope: f2.bundleEnvelope,
      },
      f2.request,
      floorPath,
    )

    expect(r2.ok).toBe(false)
    if (!r2.ok) {
      expect(r2.reason).toMatch(/rollback|sequence/)
      expect(r2.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── idempotent re-fetch ─────────────────────────────────────────────
  it('idempotent re-fetch of same release is accepted', async () => {
    const f = await buildValidFixtures({ sequence: 150 })
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // First fetch sets the floor
    const r1 = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )
    expect(r1.ok).toBe(true)

    // Second fetch with the SAME bundle — idempotent
    const r2 = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )
    // The second fetch has a different scanId in the envelope (envelope was built for f.request.scanId)
    // but uses the same request — HOWEVER the envelope.requestDigest was computed for f.request.scanId.
    // Since the request.scanId is the same object, this should pass.
    // Note: freshness token may have the same issuedAt, which is fine.
    expect(r2.ok).toBe(true)

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── gap-tolerant sequence ──────────────────────────────────────────
  it('gap-tolerant: sequence floor+3 (gap from failed reservation) is accepted', async () => {
    const f1 = await buildValidFixtures({ sequence: 10 })
    cleanupFns.push(f1.cleanupAll)
    const floorPath = makeTempFloorPath()

    const r1 = await verifyBundleResponse(
      {
        fullManifest: f1.manifest,
        corpusAttestation: f1.attestation,
        freshnessTok: f1.freshnessTok,
        selectedRules: f1.selectedRules,
        bundleEnvelope: f1.bundleEnvelope,
      },
      f1.request,
      floorPath,
    )
    expect(r1.ok).toBe(true)

    // New bundle with sequence 13 (gap of 3 from 10 — gaps are harmless)
    const f2 = await buildValidFixtures({ sequence: 13 })
    cleanupFns.push(f2.cleanupAll)

    const r2 = await verifyBundleResponse(
      {
        fullManifest: f2.manifest,
        corpusAttestation: f2.attestation,
        freshnessTok: f2.freshnessTok,
        selectedRules: f2.selectedRules,
        bundleEnvelope: f2.bundleEnvelope,
      },
      f2.request,
      floorPath,
    )
    expect(r2.ok).toBe(true)

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── expired freshness token ────────────────────────────────────────
  it('expired freshness token is rejected', async () => {
    // issuedAt = 2 hours ago, expiresAt = 1 hour ago (well past clock-skew tolerance)
    const nowSec = Math.floor(Date.now() / 1000)
    const f = await buildValidFixtures({
      freshnessIssuedAt: nowSec - 7200, // 2 hours ago
      freshnessTtl: 3600, // 1 hour TTL → expiresAt = 1 hour ago (expired)
    })
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/expir/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── freshness signed by bundle key (wrong role) ────────────────────
  it('freshness token signed by bundle key is rejected (wrong role)', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Re-sign the freshness token using the BUNDLE key (wrong role)
    const { signature: _fSig, ...freshBase } = f.freshnessTok as Record<string, unknown> & { signature: string }
    const badFreshBase = { ...freshBase, kid: f.bundleKeypair.kid }
    const freshPreimage = new TextEncoder().encode('shipguard-freshness-v1\x00' + canonicalJson(badFreshBase))
    const badSig = await sign(freshPreimage, f.bundleKeypair.privateKey)
    const badFreshnessTok = { ...badFreshBase, signature: badSig }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: badFreshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/freshness-verify-failed/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── freshnessTok.manifestDigest mismatch ───────────────────────────
  it('freshnessTok.manifestDigest bound to different manifest is rejected', async () => {
    // Build freshness token with a fake manifestDigest (different manifest)
    const f = await buildValidFixtures({
      freshnessManifestDigest: sha256hex('some-other-manifest-content'),
    })
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      // Either the freshness manifestDigest cross-check fails before sig verify
      // or the sig verify fails (the freshness was signed with the wrong manifestDigest)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── replay with different scanId ────────────────────────────────────
  it('valid bundle replayed with different scanId is rejected by requestDigest', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Present the bundle with a DIFFERENT scanId in the request
    const differentRequest = {
      ...f.request,
      scanId: 'different-scan-id-replay-attempt',
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope, // envelope still has old scanId's requestDigest
      },
      differentRequest,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/requestDigest|replay/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── bundle-key signature used for attestation ──────────────────────
  it('bundle-key signature presented as attestation is rejected (cross-role)', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Re-sign the attestation using the BUNDLE key (wrong role)
    const { signature: _aSig, ...attBase } = f.attestation as Record<string, unknown> & { signature: string }
    const badAttBase = { ...attBase, kid: f.bundleKeypair.kid }
    const attPreimage = new TextEncoder().encode('shipguard-attestation-v1\x00' + canonicalJson(badAttBase))
    const badSig = await sign(attPreimage, f.bundleKeypair.privateKey)
    const badAttestation = { ...badAttBase, signature: badSig }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: badAttestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/attestation-verify-failed/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── duplicate JSON field ───────────────────────────────────────────
  it('duplicate JSON field in attestation is rejected by duplicate-key parser', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Create a raw JSON string with a duplicate key for the attestation
    const dupJson = JSON.stringify(f.attestation).replace(
      '"signature"',
      '"releaseId":"INJECTED","signature"',
    )

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: dupJson, // raw JSON string with duplicate key
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/parse-failure|[Dd]uplicate/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── forged attestation with bundle key ─────────────────────────────
  it('forged manifest+attestation signed with bundle key is rejected (role check)', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Attacker re-signs attestation with bundle key, claims kid = bundle key
    const { signature: _aSig, ...attBase } = f.attestation as Record<string, unknown> & { signature: string }
    const forgedAttBase = { ...attBase, kid: f.bundleKeypair.kid }
    const attPreimage = new TextEncoder().encode('shipguard-attestation-v1\x00' + canonicalJson(forgedAttBase))
    const forgedSig = await sign(attPreimage, f.bundleKeypair.privateKey)
    const forgedAttestation = { ...forgedAttBase, signature: forgedSig }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: forgedAttestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/attestation-verify-failed/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  // ── floor write fails ─────────────────────────────────────────────
  it('floor write failure causes non-safe exit', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)

    // Use a path under a regular file — the parent dir cannot be created, write will fail
    const invalidFloorPath = makeInvalidFloorPath()

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      invalidFloorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/floor-write-failure/)
      expect(result.nonSafe).toBe(true)
    }
  })

  // ── fresh-home: the floor's parent dir does not exist yet ─────
  it('fresh-home: first verify on a machine with no ~/.shipguard creates the dir (0700) and floor (0600)', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-fresh-home-'))
    cleanupFns.push(() => fs.rmSync(fakeHome, { recursive: true, force: true }))
    const sgDir = path.join(fakeHome, '.shipguard')
    const floorPath = path.join(sgDir, 'release-floor.json')
    expect(fs.existsSync(sgDir)).toBe(false)

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result).toMatchObject({ ok: true })
    expect(fs.existsSync(floorPath)).toBe(true)
    if (process.platform !== 'win32') {
      expect(fs.statSync(sgDir).mode & 0o777).toBe(0o700)
      expect(fs.statSync(floorPath).mode & 0o777).toBe(0o600)
    }
    // no stray lock / temp files left behind
    expect(fs.readdirSync(sgDir)).toEqual(['release-floor.json'])
  })

  // ── runtimeId-mismatch ────────────────────────────────────────────────────
  it('runtimeId-mismatch: manifest.matcherRuntimeId !== RE2JS_V1_RUNTIME_ID is rejected (arbitrary wrong id)', async () => {
    const f = await buildValidFixtures({ runtimeId: 'wrong-runtime-id-0000000000000000000000000000000000000000000000' })
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/matcherRuntimeId|runtimeId/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('runtimeId-mismatch: NATIVE_V1_RUNTIME_ID-stamped manifest is now REJECTED (engine divergence)', async () => {
    // CLI executes re2js-v1; a manifest stamped native-v1 would silently under-match
    // (native has lookahead; re2js does not). The verifier must reject native-stamped
    // manifests to prevent false negatives.
    const f = await buildValidFixtures({ runtimeId: NATIVE_V1_RUNTIME_ID })
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/matcherRuntimeId|runtimeId/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })
})

// ---------------------------------------------------------------------------
// Finding 1: floor TOCTOU — concurrent writers
// ---------------------------------------------------------------------------

describe('Finding 1 — floor TOCTOU: concurrent writers, under-lock comparison', () => {
  const cleanupFns: Array<() => void> = []

  afterEach(() => {
    for (const fn of cleanupFns.splice(0)) fn()
  })

  it('Finding 1a: stale-sequence scan rejected under lock (seq-2 rejected when floor already at seq-3)', async () => {
    // Simulate: seq-3 writes first, then seq-2 tries to verify.
    // The floor TOCTOU fix ensures seq-2 is rejected under lock (not accepted).
    const floorPath = makeTempFloorPath()

    // First, establish floor at seq-3
    const f3 = await buildValidFixtures({ sequence: 300 })
    cleanupFns.push(f3.cleanupAll)
    const r3 = await verifyBundleResponse(
      {
        fullManifest: f3.manifest,
        corpusAttestation: f3.attestation,
        freshnessTok: f3.freshnessTok,
        selectedRules: f3.selectedRules,
        bundleEnvelope: f3.bundleEnvelope,
      },
      f3.request,
      floorPath,
    )
    expect(r3.ok).toBe(true)

    // Now seq-2 (lower than current floor=300) tries to verify — must be REJECTED
    const f2 = await buildValidFixtures({ sequence: 200 })
    cleanupFns.push(f2.cleanupAll)
    const r2 = await verifyBundleResponse(
      {
        fullManifest: f2.manifest,
        corpusAttestation: f2.attestation,
        freshnessTok: f2.freshnessTok,
        selectedRules: f2.selectedRules,
        bundleEnvelope: f2.bundleEnvelope,
      },
      f2.request,
      floorPath,
    )

    expect(r2.ok).toBe(false)
    if (!r2.ok) {
      // Must mention rollback/sequence — specifically from the under-lock comparison
      expect(r2.reason).toMatch(/rollback|sequence/)
      expect(r2.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Finding 1b: same-seq/different-tuple rejected under lock (substitution attack)', async () => {
    // Two bundles with the SAME sequence but different content (different releaseId).
    // The first one writes the floor. The second one must be REJECTED.
    const floorPath = makeTempFloorPath()

    const seq = 500
    const f1 = await buildValidFixtures({ sequence: seq, releaseId: 'release-A-' + Math.random().toString(36).slice(2) })
    cleanupFns.push(f1.cleanupAll)

    // First verify sets the floor
    const r1 = await verifyBundleResponse(
      {
        fullManifest: f1.manifest,
        corpusAttestation: f1.attestation,
        freshnessTok: f1.freshnessTok,
        selectedRules: f1.selectedRules,
        bundleEnvelope: f1.bundleEnvelope,
      },
      f1.request,
      floorPath,
    )
    expect(r1.ok).toBe(true)

    // Second verify: same sequence, different releaseId (tuple differs) → REJECT
    const f2 = await buildValidFixtures({ sequence: seq, releaseId: 'release-B-' + Math.random().toString(36).slice(2) })
    cleanupFns.push(f2.cleanupAll)

    const r2 = await verifyBundleResponse(
      {
        fullManifest: f2.manifest,
        corpusAttestation: f2.attestation,
        freshnessTok: f2.freshnessTok,
        selectedRules: f2.selectedRules,
        bundleEnvelope: f2.bundleEnvelope,
      },
      f2.request,
      floorPath,
    )

    expect(r2.ok).toBe(false)
    if (!r2.ok) {
      expect(r2.reason).toMatch(/same-sequence\/different-tuple|different-tuple/)
      expect(r2.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })
})

// ---------------------------------------------------------------------------
// Finding 2: corrupt floor → non-safe (not first-use)
// ---------------------------------------------------------------------------

describe('Finding 2 — corrupt floor is non-safe (not treated as first-use)', () => {
  const cleanupFns: Array<() => void> = []

  afterEach(() => {
    for (const fn of cleanupFns.splice(0)) fn()
  })

  it('Finding 2a: corrupt floor file (malformed JSON) causes non-safe failure (not first-use)', async () => {
    const floorPath = makeTempFloorPath()

    // Write a corrupt (malformed JSON) floor file
    fs.writeFileSync(floorPath, '{ "sequence": 1, INVALID JSON }', 'utf-8')

    const f = await buildValidFixtures({ sequence: 50 })
    cleanupFns.push(f.cleanupAll)

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    // A present-but-invalid floor MUST fail non-safe, not be treated as first-use
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/floor-corruption|corrupt/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Finding 2b: floor file with duplicate keys (parseStrictNoDup failure) causes non-safe', async () => {
    const floorPath = makeTempFloorPath()

    // Write a floor with a duplicate key (bypasses JSON.parse dedup)
    fs.writeFileSync(
      floorPath,
      '{"sequence":1,"sequence":999,"releaseId":"r1","manifestDigest":"d1","keyringEpoch":1}',
      'utf-8',
    )

    const f = await buildValidFixtures({ sequence: 50 })
    cleanupFns.push(f.cleanupAll)

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    // Present-but-invalid (duplicate key) floor MUST fail non-safe
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/floor-corruption|corrupt|[Dd]uplicate/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Finding 2c: missing floor (ENOENT) is genuine first-use — scan accepted', async () => {
    // ENOENT = first-use = allowed. This must still succeed.
    const floorPath = makeTempFloorPath()
    // Do NOT create the floor file — let it be absent (ENOENT)

    const f = await buildValidFixtures({ sequence: 50 })
    cleanupFns.push(f.cleanupAll)

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    // ENOENT = first-use = OK
    expect(result.ok).toBe(true)

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })
})

// ---------------------------------------------------------------------------
// Finding 9: strict schema validation of signed objects
// ---------------------------------------------------------------------------

describe('Finding 9 — strict schema validation of all 5 signed components', () => {
  const cleanupFns: Array<() => void> = []

  afterEach(() => {
    for (const fn of cleanupFns.splice(0)) fn()
  })

  it('Finding 9a: attestation with wrong protocolVersion is rejected before hashing', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const badAttestation = {
      ...f.attestation,
      protocolVersion: '99',  // wrong version
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: badAttestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/protocolVersion|schema/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Finding 9b: freshnessTok with missing required field is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Remove 'expiresAt' from freshnessTok — required field
    const { expiresAt: _exp, ...badFreshnessTok } = f.freshnessTok as Record<string, unknown> & { expiresAt: number }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: badFreshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/expiresAt|missing|schema/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Finding 9c: bundleEnvelope with wrong protocolVersion is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const badEnvelope = {
      ...f.bundleEnvelope,
      protocolVersion: '2',  // wrong version
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: badEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/protocolVersion|schema/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Finding 9d: manifest with non-integer releaseSequence is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // releaseSequence as a float (not a safe integer)
    const badManifest = {
      ...f.manifest,
      releaseSequence: 1.5,  // not a safe integer
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: badManifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/releaseSequence|safe integer|schema/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Finding 9e: attestation with unknown extra field is rejected (closed schema)', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Add an unknown field to attestation
    const badAttestation = {
      ...f.attestation,
      unknownExtraField: 'injected',
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: badAttestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/unexpected field|schema|unknownExtraField/)
      expect(result.nonSafe).toBe(true)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })
})

// ---------------------------------------------------------------------------
// Fix 2: ENOENT vs corruption in floor read
// ---------------------------------------------------------------------------

describe('Fix 2 — floor ENOENT vs read-error distinction', () => {
  const cleanupFns: Array<() => void> = []

  afterEach(() => {
    for (const fn of cleanupFns.splice(0)) fn()
  })

  it('Fix2-floor: non-safe-integer sequence in present floor fails non-safe', async () => {
    const floorPath = makeTempFloorPath()
    // Write a floor with float sequence (not a safe integer)
    fs.writeFileSync(floorPath, JSON.stringify({ sequence: 1.5, releaseId: 'x', manifestDigest: 'y', keyringEpoch: 1 }), 'utf-8')

    const f = await buildValidFixtures({ sequence: 50 })
    cleanupFns.push(f.cleanupAll)

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/floor-corruption|corrupt/)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix2-floor: non-safe-integer keyringEpoch in present floor fails non-safe', async () => {
    const floorPath = makeTempFloorPath()
    // Write a floor with float keyringEpoch
    fs.writeFileSync(floorPath, JSON.stringify({ sequence: 1, releaseId: 'x', manifestDigest: 'y', keyringEpoch: 0.5 }), 'utf-8')

    const f = await buildValidFixtures({ sequence: 50 })
    cleanupFns.push(f.cleanupAll)

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/floor-corruption|corrupt/)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix2-floor: present floor with missing keyringEpoch fails non-safe', async () => {
    const floorPath = makeTempFloorPath()
    // Write a floor missing keyringEpoch
    fs.writeFileSync(floorPath, JSON.stringify({ sequence: 1, releaseId: 'x', manifestDigest: 'y' }), 'utf-8')

    const f = await buildValidFixtures({ sequence: 50 })
    cleanupFns.push(f.cleanupAll)

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/floor-corruption|corrupt/)
    }

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })
})

// ---------------------------------------------------------------------------
// Fix 9: Recursive strict schema validation
// ---------------------------------------------------------------------------

describe('Fix 9 — recursive strict schema validation', () => {
  const cleanupFns: Array<() => void> = []

  afterEach(() => {
    for (const fn of cleanupFns.splice(0)) fn()
  })

  it('Fix9-rules: manifest.rules[] entry with missing executableHash is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const badManifest = {
      ...f.manifest,
      rules: f.manifest.rules.map((r: Record<string, unknown>) => {
        const { executableHash: _, ...rest } = r as Record<string, unknown> & { executableHash: string }
        return rest
      }),
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: badManifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/executableHash|manifest\.rules/)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix9-capProfile: manifest.capProfile with non-integer field is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const badManifest = {
      ...f.manifest,
      capProfile: { ...f.manifest.capProfile, maxFiles: 'not-a-number' },
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: badManifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/capProfile|maxFiles/)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix9-capProfile: manifest.capProfile with unknown extra field is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const badManifest = {
      ...f.manifest,
      capProfile: { ...f.manifest.capProfile, unknownCapField: 99 },
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: badManifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/unknownCapField|capProfile/)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix9-engineOpts: manifest.matcherEngineOptions with unknown field is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const badManifest = {
      ...f.manifest,
      matcherEngineOptions: { LOOKBEHINDS: false, EXTRA_FIELD: true },
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: badManifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/EXTRA_FIELD|matcherEngineOptions/)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix9-engineOpts: manifest.matcherEngineOptions.LOOKBEHINDS not boolean is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const badManifest = {
      ...f.manifest,
      matcherEngineOptions: { LOOKBEHINDS: 'yes' },
    }

    const result = await verifyBundleResponse(
      {
        fullManifest: badManifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/LOOKBEHINDS|matcherEngineOptions/)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix9-severity: selectedRule with old 3-value severity "error" is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // Inject a rule with old-style severity='error' (not in 5-value enum)
    const badRule = { ...f.selectedRules[0], severity: 'error' }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: [badRule],
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/severity/)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix9-severity: selectedRule with old 3-value severity "warning" is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const badRule = { ...f.selectedRules[0], severity: 'warning' }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: [badRule],
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/severity/)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix9-blocking: selectedRule with blocking:true injected after signing FAILS hash check (0.5.0 tamper-detection)', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    // In contract 0.5.0, 'blocking' is now IN the hash preimage (no longer an extension field).
    // Injecting blocking:true on a delivered rule whose executableHash was computed WITHOUT
    // 'blocking' causes a hash mismatch → tamper-detection → result.ok === false.
    // This is the CORRECT behavior: a MITM that upgrades blocking:false to blocking:true
    // is detectable via hash verification.
    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: [{ ...f.selectedRules[0], blocking: true }],
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    // Tamper-detection: hash mismatch due to injected 'blocking' field
    expect(result.ok).toBe(false)

    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix9-extraField: selectedRule with unknown field is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const badRule = { ...f.selectedRules[0], unknownField: 'injected' }

    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: [badRule],
        bundleEnvelope: f.bundleEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/unknownField|unexpected field/)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('Fix9-envelope: envelope.expectedRuleSet entry with extra field is rejected', async () => {
    const f = await buildValidFixtures()
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()

    const badEnvelope = {
      ...f.bundleEnvelope,
      expectedRuleSet: (f.bundleEnvelope.expectedRuleSet as Array<Record<string, unknown>>).map(e => ({ ...e, injected: 'x' })),
    }

    // Schema check (0b-4b) runs BEFORE signature verification, so rejection is at schema gate.
    const result = await verifyBundleResponse(
      {
        fullManifest: f.manifest,
        corpusAttestation: f.attestation,
        freshnessTok: f.freshnessTok,
        selectedRules: f.selectedRules,
        bundleEnvelope: badEnvelope,
      },
      f.request,
      floorPath,
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/injected|expectedRuleSet|unexpected field/)
    }
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })
})

// ---------------------------------------------------------------------------
// revoked epoch-1 keys: captured epoch-1 bundles are rejected, epoch 2 resets the floor
// ---------------------------------------------------------------------------

describe('key rotation — captured epoch-1 bundles and the epoch floor', () => {
  const cleanupFns: Array<() => void> = []
  afterEach(() => {
    for (const fn of cleanupFns.splice(0)) fn()
  })

  const RETIRED_KIDS = { ra: 'ra-k1-2026', cf: 'cf-k1-2026', bundle: 'k1-2026' }

  function asResponse(f: Awaited<ReturnType<typeof buildValidFixtures>>) {
    return {
      fullManifest: f.manifest,
      corpusAttestation: f.attestation,
      freshnessTok: f.freshnessTok,
      selectedRules: f.selectedRules,
      bundleEnvelope: f.bundleEnvelope,
    }
  }

  it('a captured epoch-1 bundle (signed under the retired kids, keys no longer in KEYRING) is rejected non-safe', async () => {
    // Build a fully-signed bundle exactly as the revoked epoch-1 keys would have produced it,
    // then remove the keys from KEYRING — the shipped 0.8.0 keyring does not contain them.
    const f = await buildValidFixtures({ sequence: 3, kids: RETIRED_KIDS })
    f.cleanupAll()
    const floorPath = makeTempFloorPath()
    const result = await verifyBundleResponse(asResponse(f), f.request, floorPath)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/Unknown key "ra-k1-2026"/)
    }
    expect(fs.existsSync(floorPath)).toBe(false) // nothing persisted
  })

  it('an epoch-1 bundle is rejected even if its keys were re-added to KEYRING at epoch 1', async () => {
    const f = await buildValidFixtures({ sequence: 3, kids: RETIRED_KIDS, keyEpoch: 1 })
    cleanupFns.push(f.cleanupAll)
    const floorPath = makeTempFloorPath()
    const result = await verifyBundleResponse(asResponse(f), f.request, floorPath)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.nonSafe).toBe(true)
      expect(result.reason).toMatch(/below the minimum acceptable epoch 2/)
    }
    expect(fs.existsSync(floorPath)).toBe(false)
  })

  it('a poisoned epoch-1 floor (sequence 2^53-1) does NOT block the first epoch-2 release; floor is rewritten at epoch 2', async () => {
    const floorPath = makeTempFloorPath()
    fs.writeFileSync(floorPath, JSON.stringify({
      sequence: Number.MAX_SAFE_INTEGER,
      releaseId: 'attacker-forged-release',
      manifestDigest: 'f'.repeat(64),
      keyringEpoch: 1,
    }))
    const f = await buildValidFixtures({ sequence: 4 })
    cleanupFns.push(f.cleanupAll)
    const result = await verifyBundleResponse(asResponse(f), f.request, floorPath)
    expect(result.ok).toBe(true)
    const floor = JSON.parse(fs.readFileSync(floorPath, 'utf-8'))
    expect(floor).toMatchObject({ sequence: 4, keyringEpoch: 2, releaseId: f.manifest.releaseId })
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })

  it('once the floor is at epoch 2, a higher-sequence release at a LOWER epoch is rejected', async () => {
    const floorPath = makeTempFloorPath()
    fs.writeFileSync(floorPath, JSON.stringify({
      sequence: 4, releaseId: 'r4', manifestDigest: 'a'.repeat(64), keyringEpoch: 3,
    }))
    // Fixture keys are epoch 2 (the minimum); the floor claims epoch 3 → epoch 2 is a rollback.
    const f = await buildValidFixtures({ sequence: 900 })
    cleanupFns.push(f.cleanupAll)
    const result = await verifyBundleResponse(asResponse(f), f.request, floorPath)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toMatch(/keyring epoch rollback rejected/)
    try { fs.unlinkSync(floorPath) } catch { /* ignore */ }
  })
})
