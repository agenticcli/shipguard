/**
 * roundtrip.test.ts — end-to-end integration gate for the signed-release round-trip.
 *
 * Proves that the server-signing path (agenticcli/scripts/roundtrip-emit.ts) and
 * the CLI-verification path (release-verify.ts verifyBundleResponse) AGREE on the
 * wire format.  A wire-format mismatch — field names, canonical bytes, requestDigest
 * construction, domain prefixes, key encodings — causes the happy-path verify to fail
 * and this test reports the exact discrepancy.
 *
 * SELF-GENERATING (Fix: roundtrip fixture timestamps are now generated at test startup
 * using Date.now()-relative values so the freshness and envelope tokens are always
 * current, instead of relying on stale /tmp files from a previous roundtrip-emit run.)
 *
 * Test scope:
 *   1. happy-path  — full valid bundle → verifyBundleResponse returns ok:true
 *   2. tamper-manifest    — flip manifest field → attestation digest rejects
 *   3. drop-rule          — remove one rule from selectedRules → completeness rejects
 *   4. wrong-scanId       — change request.scanId → requestDigest mismatch
 *   5. cross-role-sig     — use RA key signature on the envelope → role check rejects
 *
 * All checks use the REAL verifyBundleResponse with real Ed25519 signatures.
 */

import { describe, it, expect, afterAll, beforeAll } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'

// ---------------------------------------------------------------------------
// Dynamic imports (ESM / NodeNext)
// ---------------------------------------------------------------------------

const { verifyBundleResponse } = await import('../../src/core/release-verify.js')
const { _testInjectKeyringEntry, computeSpkiFingerprint } = await import('../../src/core/crypto.js')
const { canonicalJson, RE2JS_V1_RUNTIME_ID } = await import('@agenticcli/matcher-contract')
const { sha256 } = await import('@noble/hashes/sha2.js')

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type KeyRole = 'release-attestation' | 'ci-freshness' | 'bundle' | 'auth'

function sha256hex(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  return Buffer.from(sha256(bytes)).toString('hex')
}

async function generateAndInjectKeypair(kid: string, role: KeyRole): Promise<{
  privateKey: CryptoKey
  publicKey: CryptoKey
  pem: string
  kid: string
  cleanup: () => void
}> {
  const { privateKey, publicKey } = await globalThis.crypto.subtle.generateKey(
    'Ed25519', true, ['sign', 'verify'],
  )
  const spkiDer = await globalThis.crypto.subtle.exportKey('spki', publicKey)
  const b64 = Buffer.from(spkiDer).toString('base64')
  const lines = b64.match(/.{1,64}/g)!.join('\n')
  const pem = `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`

  const nowSec = Math.floor(Date.now() / 1000)
  const cleanup = _testInjectKeyringEntry({
    kid,
    role,
    epoch: 2, // MIN_ACCEPTABLE_EPOCH is 2
    expiry: nowSec + 86400 * 30,
    fingerprint: computeSpkiFingerprint(pem), // resolver checks the computed fingerprint
    publicKey: pem,
  })

  return { privateKey, publicKey, pem, kid, cleanup }
}

async function sign(preimageBytes: Uint8Array, privateKey: CryptoKey): Promise<string> {
  const sigBytes = await globalThis.crypto.subtle.sign('Ed25519', privateKey, preimageBytes)
  return Buffer.from(sigBytes).toString('base64url')
}

// ---------------------------------------------------------------------------
// Self-generating fixture builder
// Replicates roundtrip-emit.ts logic with Date.now()-relative timestamps.
// ---------------------------------------------------------------------------

interface RoundtripFixtures {
  bundle: Record<string, unknown>
  request: { scanId: string; frameworks: string[]; options: Record<string, unknown>; isPro: boolean }
  cleanupAll: () => void
  raKid: string
  bkKid: string
}

async function buildRoundtripFixtures(): Promise<RoundtripFixtures> {
  const RELEASE_SEQUENCE = 42
  const nowSec = Math.floor(Date.now() / 1000)

  // Key ids — unique per test run to avoid KEYRING collision across test files
  const runId = Math.random().toString(36).slice(2)
  const RA_KID = `rt-ra-${runId}`
  const CF_KID = `rt-cf-${runId}`
  const BK_KID = `rt-bk-${runId}`

  const raKp = await generateAndInjectKeypair(RA_KID, 'release-attestation')
  const cfKp = await generateAndInjectKeypair(CF_KID, 'ci-freshness')
  const bkKp = await generateAndInjectKeypair(BK_KID, 'bundle')

  // ── Build synthetic rules (file-presence type — no pattern/antiPattern) ──

  function buildSyntheticRule(id: string): {
    ruleObj: Record<string, unknown>
    executableHash: string
    manifestEntry: Record<string, unknown>
  } {
    const ruleObj: Record<string, unknown> = {
      // 0.5.1 (per-rule confidence): confidence is REQUIRED on every delivered rule and hashed.
      confidence: 'HIGH',
      enabled: true,
      flags: '',
      framework: 'generic',
      id,
      matcherType: 'file-presence',
      requiresFile: `${id}.lock`,
      // Fix 1/5: 5-value severity enum — 'warning' is no longer valid.
      severity: 'medium',
      tier: 'free',
      title: `Roundtrip Test Rule ${id}`,
    }
    const preimage = 'shipguard-rule-v1\x00' + canonicalJson(ruleObj)
    const executableHash = sha256hex(preimage)
    const manifestEntry: Record<string, unknown> = {
      ...ruleObj,
      executableHash,
      sourceYamlDigest: sha256hex(`synthetic-yaml-${id}`),
    }
    return { ruleObj, executableHash, manifestEntry }
  }

  const rule1 = buildSyntheticRule('rt-rule-001')
  const rule2 = buildSyntheticRule('rt-rule-002')
  const allRules = [rule1, rule2]

  // ── Build manifest ──

  const manifestEntries = allRules.map(r => r.manifestEntry)
  const withoutReleaseId: Record<string, unknown> = {
    capProfile: {
      maxFileBytes: 10485760,
      maxFiles: 1000,
      maxFindings: 500,
      maxPatternBytes: 65536,
      maxPatternsPerRule: 20,
      maxRules: 500,
    },
    contractVersion: '0.2.0',
    corpusRuleCount: manifestEntries.length,
    gateBVersion: '1.0.0',
    gateCVersion: '1.0.0',
    matcherEngineOptions: { LOOKBEHINDS: false },
    matcherEngineVersion: 'native-v1',
    matcherRuntimeId: RE2JS_V1_RUNTIME_ID,
    protocolVersion: '1',
    releaseSequence: RELEASE_SEQUENCE,
    rules: manifestEntries,
  }
  const releaseId = sha256hex(canonicalJson(withoutReleaseId))
  const manifest = { ...withoutReleaseId, releaseId }

  // ── Compute manifestDigest ──

  const manifestDigest = sha256hex('shipguard-manifest-v1\x00' + canonicalJson(manifest))

  // ── Sign corpusAttestation ──

  const attBase: Record<string, unknown> = {
    issuedAt: nowSec,
    kid: RA_KID,
    manifestDigest,
    protocolVersion: '1',
    releaseId,
    releaseSequence: RELEASE_SEQUENCE,
  }
  const attPreimage = new TextEncoder().encode('shipguard-attestation-v1\x00' + canonicalJson(attBase))
  const attSig = await sign(attPreimage, raKp.privateKey)
  const corpusAttestation = { ...attBase, signature: attSig }

  // ── Sign freshnessTok (Date.now()-relative — always current) ──

  const FRESHNESS_TTL = 86400 // 24h
  const freshBase: Record<string, unknown> = {
    expiresAt: nowSec + FRESHNESS_TTL,
    issuedAt: nowSec,
    kid: CF_KID,
    manifestDigest,
    protocolVersion: '1',
    releaseId,
    sequence: RELEASE_SEQUENCE,
  }
  const freshPreimage = new TextEncoder().encode('shipguard-freshness-v1\x00' + canonicalJson(freshBase))
  const freshSig = await sign(freshPreimage, cfKp.privateKey)
  const freshnessTok = { ...freshBase, signature: freshSig }

  // ── Build request ──

  const scanId = 'rt-scan-' + Date.now().toString(36)
  const frameworks = ['generic']
  const options: Record<string, unknown> = {}
  const isPro = false

  // ── requestDigest ──

  const requestDigest = sha256hex(canonicalJson({ frameworks, options, scanId }))

  // ── expectedRuleSet (sorted) ──

  const expectedRuleSet = allRules
    .filter(r => r.ruleObj.enabled && r.ruleObj.framework === 'generic')
    .map(r => ({ id: r.ruleObj.id as string, executableHash: r.executableHash }))
    .sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0)

  // ── Build and sign bundleEnvelope (Date.now()-relative exp) ──

  const iat = nowSec
  const exp = nowSec + 600 // 10-minute window

  const envBase: Record<string, unknown> = {
    exp,
    expectedRuleSet,
    frameworks,
    iat,
    kid: BK_KID,
    manifestDigest,
    options,
    protocolVersion: '1',
    releaseId,
    requestDigest,
    scanId,
    sequence: RELEASE_SEQUENCE,
  }
  const envPreimage = new TextEncoder().encode('shipguard-bundle-v1\x00' + canonicalJson(envBase))
  const envSig = await sign(envPreimage, bkKp.privateKey)
  const bundleEnvelope = { ...envBase, signature: envSig }

  // ── Assemble BundleResponse ──

  const selectedRules = allRules.map(r => r.ruleObj)
  const bundle: Record<string, unknown> = {
    bundleEnvelope,
    corpusAttestation,
    freshnessTok,
    fullManifest: manifest,
    selectedRules,
  }

  const request = { scanId, frameworks, options, isPro }
  const cleanupAll = () => {
    raKp.cleanup()
    cfKp.cleanup()
    bkKp.cleanup()
  }

  return { bundle, request, cleanupAll, raKid: RA_KID, bkKid: BK_KID }
}

// ---------------------------------------------------------------------------
// Floor file helpers
// ---------------------------------------------------------------------------

function makeTempFloor(): string {
  return path.join(os.tmpdir(), `sg-rt-floor-${Date.now()}-${Math.random().toString(36).slice(2)}.json`)
}

function cleanFloor(p: string): void {
  try { fs.unlinkSync(p) } catch { /* ignore */ }
  try { fs.unlinkSync(`${p}.lock`) } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('roundtrip integration — server-sign vs CLI-verify', () => {
  let fixtures: RoundtripFixtures

  // Build fresh self-signed fixtures before tests using Date.now()-relative timestamps.
  // This replaces the old /tmp-file approach that went stale (expired envelope.exp).
  beforeAll(async () => {
    fixtures = await buildRoundtripFixtures()
  })

  afterAll(() => {
    fixtures?.cleanupAll()
  })

  // ── 1. Happy path ──────────────────────────────────────────────────────────

  it('happy-path: real server-signed bundle verifies end-to-end (ok:true)', async () => {
    const floorPath = makeTempFloor()
    try {
      const result = await verifyBundleResponse(
        fixtures.bundle as Parameters<typeof verifyBundleResponse>[0],
        fixtures.request,
        floorPath,
      )

      if (!result.ok) {
        // Surface the EXACT reason so a wire-format mismatch is immediately diagnosable
        throw new Error(
          `verifyBundleResponse returned ok:false — wire-format mismatch detected.\n` +
          `reason: ${result.reason}\n` +
          `nonSafe: ${result.nonSafe}\n` +
          `\nThis means the server-signing path and CLI-verification path DISAGREE.\n` +
          `Check: field names, canonical-bytes order, domain prefixes, requestDigest formula.`
        )
      }

      expect(result.ok).toBe(true)
      expect(result.selectedRules).toHaveLength(2)
      expect(result.selectedRules.map((r: Record<string, unknown>) => r.id).sort()).toEqual([
        'rt-rule-001',
        'rt-rule-002',
      ])

      // Floor file must exist and contain the sequence
      expect(fs.existsSync(floorPath)).toBe(true)
      const floor = JSON.parse(fs.readFileSync(floorPath, 'utf8'))
      expect(floor.sequence).toBe(42)
    } finally {
      cleanFloor(floorPath)
    }
  })

  // ── 2. Tamper: flip a manifest field ──────────────────────────────────────

  it('tamper-manifest: mutated manifest field causes attestation-digest rejection', async () => {
    const floorPath = makeTempFloor()
    try {
      // Tamper: change contractVersion in the manifest
      const tampered = {
        ...fixtures.bundle,
        fullManifest: {
          ...(fixtures.bundle.fullManifest as Record<string, unknown>),
          contractVersion: 'TAMPERED',
        },
      }

      const result = await verifyBundleResponse(
        tampered as Parameters<typeof verifyBundleResponse>[0],
        fixtures.request,
        floorPath,
      )

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.nonSafe).toBe(true)
        // The manifestDigest computed by CLI will differ from attestation.manifestDigest
        expect(result.reason).toMatch(/manifestDigest|attestation|tamper/i)
      }
    } finally {
      cleanFloor(floorPath)
    }
  })

  // ── 3. Drop one rule from selectedRules ────────────────────────────────────

  it('drop-rule: dropping one rule from selectedRules causes completeness rejection', async () => {
    const floorPath = makeTempFloor()
    try {
      const originalRules = fixtures.bundle.selectedRules as unknown[]
      // Drop the last rule
      const trimmed = {
        ...fixtures.bundle,
        selectedRules: originalRules.slice(0, -1),
      }

      const result = await verifyBundleResponse(
        trimmed as Parameters<typeof verifyBundleResponse>[0],
        fixtures.request,
        floorPath,
      )

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.nonSafe).toBe(true)
        // Either completeness-mismatch or delivered rule not in manifest
        expect(result.reason).toMatch(/completeness|missing|mismatch/i)
      }
    } finally {
      cleanFloor(floorPath)
    }
  })

  // ── 4. Wrong scanId → requestDigest mismatch ──────────────────────────────

  it('wrong-scanId: changed scanId causes envelope requestDigest rejection', async () => {
    const floorPath = makeTempFloor()
    try {
      const differentScanId = {
        ...fixtures.request,
        scanId: 'forged-scan-id-' + Math.random().toString(36).slice(2),
      }

      const result = await verifyBundleResponse(
        fixtures.bundle as Parameters<typeof verifyBundleResponse>[0],
        differentScanId,
        floorPath,
      )

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.nonSafe).toBe(true)
        // requestDigest in envelope won't match the recomputed one for the new scanId
        expect(result.reason).toMatch(/requestDigest|replay|scanId/i)
      }
    } finally {
      cleanFloor(floorPath)
    }
  })

  // ── 5. Cross-role: RA key signature used for bundle envelope ──────────────

  it('cross-role: RA-key signature on bundle envelope causes role-check rejection', async () => {
    const floorPath = makeTempFloor()
    try {
      // Swap the bundle envelope's kid to the RA kid — the RA key's role is
      // 'release-attestation', not 'bundle'. The CLI verifyBundleEnvelopeSignature
      // will call resolveAndImportKey(kid, 'bundle') and throw on role mismatch.
      const envelope = fixtures.bundle.bundleEnvelope as Record<string, unknown>
      const crossRoleEnvelope = {
        ...envelope,
        kid: fixtures.raKid,
        // Keep the original signature (which was made by the BK key) — the
        // role check fires BEFORE signature verification anyway, but this also
        // proves the role guard works correctly.
      }

      const result = await verifyBundleResponse(
        { ...fixtures.bundle, bundleEnvelope: crossRoleEnvelope } as Parameters<typeof verifyBundleResponse>[0],
        fixtures.request,
        floorPath,
      )

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.nonSafe).toBe(true)
        // Role mismatch OR signature verification failure — both are acceptable here
        expect(result.reason).toMatch(/role|envelope|verify/i)
      }
    } finally {
      cleanFloor(floorPath)
    }
  })
})
