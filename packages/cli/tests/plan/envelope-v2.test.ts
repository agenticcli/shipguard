/**
 * Envelope v2 (bundle-protocol=2): the signed `selection` {tiers, categories} inside the existing signed bundle
 * envelope. Tiers are open tokens; the completeness check takes them from `selection`; categories must equal what
 * THIS CLI asked for; a made-up tier is a forgery; a narrower selection than the rulebook the request should get
 * is RULEBOOK_PARTIAL (verified, runnable, but never passed off as a full rulebook).
 */
import { afterEach, describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { canonicalJson, RE2JS_V1_RUNTIME_ID } from '@agenticcli/matcher-contract'
import { sha256 } from '@noble/hashes/sha2.js'
import { _testInjectKeyringEntry, computeSpkiFingerprint } from '../../src/core/crypto.js'
import { verifyBundleResponse } from '../../src/core/release-verify.js'

const hex = (s: string) => Buffer.from(sha256(new TextEncoder().encode(s))).toString('hex')

async function keypair(kid: string, role: 'release-attestation' | 'ci-freshness' | 'bundle') {
  const { privateKey, publicKey } = await globalThis.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const der = Buffer.from(await globalThis.crypto.subtle.exportKey('spki', publicKey)).toString('base64').match(/.{1,64}/g)!.join('\n')
  const pem = `-----BEGIN PUBLIC KEY-----\n${der}\n-----END PUBLIC KEY-----`
  const cleanup = _testInjectKeyringEntry({ kid, role, epoch: 2, expiry: Math.floor(Date.now() / 1000) + 3600, fingerprint: computeSpkiFingerprint(pem), publicKey: pem })
  const sign = async (preimage: string) => Buffer.from(await globalThis.crypto.subtle.sign('Ed25519', privateKey, new TextEncoder().encode(preimage))).toString('base64url')
  return { kid, sign, cleanup }
}

interface Build {
  protocolVersion?: '1' | '2'
  manifestTiers?: string[]            // one rule per tier, in the manifest
  selection?: Record<string, unknown> | undefined
  deliverTiers?: string[]             // tiers the server actually delivers (default = selection tiers)
  requestCategories?: string[] | null
  requestIsPro?: boolean
  verifiedRulebookTiers?: string[] | null
}

const cleanups: Array<() => void> = []
afterEach(() => { for (const c of cleanups.splice(0)) c() })

async function run(b: Build) {
  const seq = Math.floor(Math.random() * 1e6) + 100
  const ra = await keypair(`t-ra-${seq}`, 'release-attestation'), cf = await keypair(`t-cf-${seq}`, 'ci-freshness'), bk = await keypair(`t-bk-${seq}`, 'bundle')
  cleanups.push(ra.cleanup, cf.cleanup, bk.cleanup)
  const manifestTiers = b.manifestTiers ?? ['free', 'pro']
  const ruleFor = (tier: string) => {
    const obj = { confidence: 'HIGH', enabled: true, flags: '', framework: 'generic', id: `rule-${tier}`, matcherType: 'pattern', pattern: 'TODO', severity: 'medium', tier, title: `Rule ${tier}` }
    return { obj, hash: hex('shipguard-rule-v1\x00' + canonicalJson(obj)) }
  }
  const rules = manifestTiers.map((t) => ({ t, ...ruleFor(t) }))
  const manifest = {
    protocolVersion: '1', releaseId: `rel-${seq}`, releaseSequence: seq, corpusRuleCount: rules.length,
    rules: rules.map((r) => ({ id: r.obj.id, executableHash: r.hash, enabled: true, framework: 'generic', tier: r.t, severity: 'medium', matcherType: 'pattern', title: r.obj.title, flags: '', sourceYamlDigest: hex('y' + r.t) })),
    capProfile: { maxFileBytes: 1048576, maxFiles: 1000, maxFindings: 500, maxPatternBytes: 4096, maxPatternsPerRule: 50, maxRules: 500 },
    matcherEngineVersion: 'native-v1', matcherEngineOptions: { LOOKBEHINDS: false }, matcherRuntimeId: RE2JS_V1_RUNTIME_ID,
    contractVersion: '1.0.0', gateBVersion: '1.0.0', gateCVersion: '1.0.0',
  }
  const manifestDigest = hex('shipguard-manifest-v1\x00' + canonicalJson(manifest))
  const now = Math.floor(Date.now() / 1000)
  const attBase = { issuedAt: now, kid: ra.kid, manifestDigest, protocolVersion: '1', releaseId: manifest.releaseId, releaseSequence: seq }
  const attestation = { ...attBase, signature: await ra.sign('shipguard-attestation-v1\x00' + canonicalJson(attBase)) }
  const freshBase = { expiresAt: now + 86400, issuedAt: now, kid: cf.kid, manifestDigest, protocolVersion: '1', releaseId: manifest.releaseId, sequence: seq }
  const freshnessTok = { ...freshBase, signature: await cf.sign('shipguard-freshness-v1\x00' + canonicalJson(freshBase)) }

  const protocolVersion = b.protocolVersion ?? '2'
  const selection = 'selection' in b ? b.selection : { tiers: manifestTiers, categories: b.requestCategories ?? null }
  const deliverTiers = b.deliverTiers ?? ((selection?.['tiers'] as string[] | undefined) ?? manifestTiers)
  const delivered = rules.filter((r) => deliverTiers.includes(r.t))
  const request = { scanId: `scan-${seq}`, frameworks: ['generic'], options: {} as Record<string, unknown>, isPro: b.requestIsPro ?? true, categories: b.requestCategories ?? null, verifiedRulebookTiers: b.verifiedRulebookTiers ?? null }
  const requestDigest = hex(canonicalJson({ frameworks: request.frameworks, options: request.options, scanId: request.scanId }))
  const envBase: Record<string, unknown> = {
    exp: now + 600, expectedRuleSet: delivered.map((r) => ({ id: r.obj.id, executableHash: r.hash })), frameworks: request.frameworks, iat: now, kid: bk.kid,
    manifestDigest, options: request.options, protocolVersion, releaseId: manifest.releaseId, requestDigest, scanId: request.scanId, sequence: seq,
    ...(selection !== undefined ? { selection } : {}),
  }
  const bundleEnvelope = { ...envBase, signature: await bk.sign('shipguard-bundle-v1\x00' + canonicalJson(envBase)) }
  const floor = path.join(os.tmpdir(), `sg-w1a-floor-${seq}.json`)
  try {
    return await verifyBundleResponse({ fullManifest: manifest, corpusAttestation: attestation, freshnessTok, selectedRules: delivered.map((r) => r.obj), bundleEnvelope }, request, floor)
  } finally { fs.rmSync(floor, { force: true }) }
}

describe('envelope v2', () => {
  it('a full v2 selection verifies and returns the selection, not partial', async () => {
    const r = await run({})
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.selection).toEqual({ tiers: ['free', 'pro'], categories: null })
      expect(r.partial).toBe(false)
      expect(r.selectedRules.map((x) => x.id).sort()).toEqual(['rule-free', 'rule-pro'])
    }
  })
  it('protocol 1 (a server that ignores the hello) still verifies exactly as before: no selection, no partial flag', async () => {
    const r = await run({ protocolVersion: '1', selection: undefined })
    expect(r.ok).toBe(true)
    if (r.ok) { expect(r.selection).toBeUndefined(); expect(r.partial).toBeUndefined() }
  })
  it('open tier tokens: a manifest with a third tier verifies when the selection serves it', async () => {
    const r = await run({ manifestTiers: ['free', 'pro', 'team'] })
    expect(r.ok && r.selection?.tiers).toEqual(['free', 'pro', 'team'])
  })
  it('a rulebook request whose selection is narrower than the manifest = verified but PARTIAL (never passed off as full)', async () => {
    const r = await run({ manifestTiers: ['free', 'pro'], selection: { tiers: ['free'], categories: null } })
    expect(r.ok).toBe(true)
    if (r.ok) { expect(r.partial).toBe(true); expect(r.selectedRules.map((x) => x.id)).toEqual(['rule-free']) }
  })
  it('a verified live descriptor is the reference when there is one: narrower than ITS tiers is partial, equal is not', async () => {
    const narrower = await run({ manifestTiers: ['free', 'pro', 'team'], selection: { tiers: ['free', 'pro'], categories: null }, verifiedRulebookTiers: ['free', 'pro', 'team'] })
    expect(narrower.ok && narrower.partial).toBe(true)
    const equal = await run({ manifestTiers: ['free', 'pro', 'team'], selection: { tiers: ['free', 'pro'], categories: null }, verifiedRulebookTiers: ['free', 'pro'] })
    expect(equal.ok && equal.partial).toBe(false)
  })
  it('a plain Free request (not a rulebook request) is never flagged partial', async () => {
    const r = await run({ requestIsPro: false, selection: { tiers: ['free'], categories: null } })
    expect(r.ok && r.partial).toBe(false)
  })
  it('a tier the attested manifest does not have is a forgery, not a partial rulebook', async () => {
    const r = await run({ selection: { tiers: ['free', 'pro', 'gold'], categories: null } })
    expect(r.ok).toBe(false)
    if (!r.ok) { expect(r.reason).toMatch(/does not have/); expect(r.nonSafe).toBe(true) }
  })
  it('the free tier must be in the selection', async () => {
    const r = await run({ selection: { tiers: ['pro'], categories: null } })
    expect(r.ok).toBe(false)
  })
  it('selection.categories must EQUAL the CLI request (order and null/[] aside)', async () => {
    expect((await run({ selection: { tiers: ['free', 'pro'], categories: ['payments', 'auth'] }, requestCategories: ['auth', 'payments'] })).ok).toBe(true)
    expect((await run({ selection: { tiers: ['free', 'pro'], categories: [] }, requestCategories: null })).ok).toBe(true)
    const widened = await run({ selection: { tiers: ['free', 'pro'], categories: null }, requestCategories: ['auth'] })
    expect(widened.ok).toBe(false)
    const swapped = await run({ selection: { tiers: ['free', 'pro'], categories: ['database'] }, requestCategories: ['auth'] })
    expect(swapped.ok).toBe(false)
    if (!swapped.ok) expect(swapped.reason).toMatch(/categories/)
  })
  it('malformed selections are rejected fail-closed', async () => {
    const bad: unknown[] = [null, 'x', [], {}, { tiers: [] }, { tiers: ['Free'] }, { tiers: ['free', 'free'] }, { tiers: ['free'], categories: 'auth' }, { tiers: ['free'], extra: 1 }, { tiers: Array.from({ length: 17 }, (_, i) => `t${i}`) }, { tiers: ['free'], categories: ['bad cat!'] }]
    for (const selection of bad) {
      const r = await run({ selection: selection as Record<string, unknown> })
      expect(r.ok, JSON.stringify(selection)).toBe(false)
    }
  })
  it('a v2 envelope with no selection, or a selection on a v1 envelope, is rejected', async () => {
    expect((await run({ selection: undefined })).ok).toBe(false)
    expect((await run({ protocolVersion: '1', selection: { tiers: ['free'], categories: null } })).ok).toBe(false)
  })
  it('the server cannot serve fewer rules than the selection claims (completeness still exact)', async () => {
    const r = await run({ selection: { tiers: ['free', 'pro'], categories: null }, deliverTiers: ['free'] })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toMatch(/completeness|expectedRuleSet/)
  })
  it('an unknown envelope protocol version is rejected', async () => {
    expect((await run({ protocolVersion: '3' as '2' })).ok).toBe(false)
  })
})
