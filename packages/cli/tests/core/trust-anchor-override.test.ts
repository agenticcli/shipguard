/**
 * Trust-anchor override: there is none.
 *
 * A `NODE_ENV !== 'production'` guard on an env-var key override would FAIL OPEN for end-user
 * CLI runs (NODE_ENV is unset in a real shell). The override was removed entirely, not re-guarded.
 *
 * This file proves, in both directions:
 *   1. verifyBundleEnvelopeSignature, the live bundle verification path, has zero override surface:
 *      an attacker key never verifies.
 *   2. A legitimate bundle signed by a real pinned key still verifies, so the fix did not
 *      overcorrect into breaking real Pro scans.
 */

import { describe, it, expect, afterEach } from 'vitest'

const {
  verifyBundleEnvelopeSignature,
  _testInjectKeyringEntry,
  computeSpkiFingerprint,
} = await import('../../src/core/crypto.js')

async function generateTestKeypair(): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  const { privateKey, publicKey } = await globalThis.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  return { privateKey, publicKey }
}

async function exportPublicKeyAsPem(publicKey: CryptoKey): Promise<string> {
  const spkiDer = await globalThis.crypto.subtle.exportKey('spki', publicKey)
  const b64 = Buffer.from(spkiDer).toString('base64')
  const lines = b64.match(/.{1,64}/g)!.join('\n')
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`
}

async function signPreimage(preimage: Uint8Array, privateKey: CryptoKey): Promise<string> {
  const sigBytes = await globalThis.crypto.subtle.sign('Ed25519', privateKey, preimage)
  return Buffer.from(sigBytes).toString('base64url')
}

describe('trust anchor — DIRECTION 1: fail CLOSED (attacker override never verifies)', () => {
  let cleanup: (() => void) | undefined
  afterEach(() => {
    cleanup?.()
    cleanup = undefined
    delete process.env.SHIPGUARD_PUBLIC_KEY
    delete process.env.NODE_ENV
  })

  it('setting SHIPGUARD_PUBLIC_KEY (any value, any NODE_ENV) has ZERO effect on ' +
     'verifyBundleEnvelopeSignature — verification resolves only from the ' +
     'compiled-in KEYRING by kid, never an env var', async () => {
    // Simulate the exact attack: attacker sets an env override to their own key.
    const attacker = await generateTestKeypair()
    const attackerPem = await exportPublicKeyAsPem(attacker.publicKey)
    delete process.env.NODE_ENV  // the exact "fails open" condition from the original bug
    process.env.SHIPGUARD_PUBLIC_KEY = attackerPem

    const preimage = new TextEncoder().encode('shipguard-bundle-v1\x00{"malicious":true}')
    const attackerSig = await signPreimage(preimage, attacker.privateKey)

    // Attacker signs with their own key, under a kid that does NOT exist in
    // KEYRING. If the (removed) env override were still honoured, this would
    // resolve via SHIPGUARD_PUBLIC_KEY and verify successfully — attack
    // succeeds. Post-fix: unknown kid → hard rejection, env var ignored.
    await expect(
      verifyBundleEnvelopeSignature(preimage, attackerSig, 'attacker-controlled-kid'),
    ).rejects.toThrow(/unknown key/i)
  })

  it('an attacker cannot even shadow a REAL kid (e.g. "k3-2026") via the env var — ' +
     'the KEYRING entry for that kid still resolves to the PINNED key, not the env value', async () => {
    const attacker = await generateTestKeypair()
    const attackerPem = await exportPublicKeyAsPem(attacker.publicKey)
    process.env.NODE_ENV = 'production'  // even the "safe" branch of the old buggy guard
    process.env.SHIPGUARD_PUBLIC_KEY = attackerPem

    const preimage = new TextEncoder().encode('shipguard-bundle-v1\x00{"malicious":true}')
    const attackerSig = await signPreimage(preimage, attacker.privateKey)

    // 'k3-2026' is the REAL pinned bundle-role kid (k1-2026 and k2-2026 are gone). Until the
    // key ceremony fills it in, the repo holds a stand-in, so pin a throwaway key under that kid. The
    // attacker's signature (made with their own key) must NOT verify against the pinned k3-2026
    // public key — proves resolution is entirely from KEYRING/PINNED_KEYS,
    // never from process.env, regardless of kid or NODE_ENV.
    const pinned = await generateTestKeypair()
    const restore = _testInjectKeyringEntry({
      kid: 'k3-2026',
      role: 'bundle',
      epoch: 3,
      expiry: Math.floor(Date.now() / 1000) + 3600,
      fingerprint: computeSpkiFingerprint(await exportPublicKeyAsPem(pinned.publicKey)),
      publicKey: await exportPublicKeyAsPem(pinned.publicKey),
    })
    try {
      await expect(
        verifyBundleEnvelopeSignature(preimage, attackerSig, 'k3-2026'),
      ).rejects.toThrow(/verification failed/i)
    } finally {
      restore()
    }
  })
})

describe('trust anchor — DIRECTION 2: fail OPEN check — legitimate bundle still verifies', () => {
  let cleanup: (() => void) | undefined
  afterEach(() => {
    cleanup?.()
    cleanup = undefined
  })

  it('a bundle legitimately signed by a real pinned "bundle"-role key STILL ' +
     'verifies successfully — the fix removed the override without breaking ' +
     'the real verification path (the fix is not an overcorrection)', async () => {
    const { privateKey, publicKey } = await generateTestKeypair()
    const pem = await exportPublicKeyAsPem(publicKey)
    cleanup = _testInjectKeyringEntry({
      kid: 'trust-anchor-test-key',
      role: 'bundle',
      epoch: 2, // MIN_ACCEPTABLE_EPOCH is 2
      expiry: Math.floor(Date.now() / 1000) + 3600,
      fingerprint: computeSpkiFingerprint(pem), // computed-fingerprint guard
      publicKey: pem,
    })

    const preimage = new TextEncoder().encode('shipguard-bundle-v1\x00{"rules":[]}')
    const sig = await signPreimage(preimage, privateKey)

    await expect(
      verifyBundleEnvelopeSignature(preimage, sig, 'trust-anchor-test-key'),
    ).resolves.toBeUndefined()
  })
})
