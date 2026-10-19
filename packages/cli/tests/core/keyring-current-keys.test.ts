/**
 * Current keys and revoked keys.
 *
 * Pins the contract of this CLI:
 *   - k2-2026 is gone from KEYRING and its fingerprint is on the revocation list (a re-added K2 PEM is
 *     refused under any kid);
 *   - a bundle envelope signed under kid k2-2026 is rejected;
 *   - the three current public keys come from ONE constant file (keyring-ceremony-output.ts); while
 *     it still holds stand-ins, no new kid can verify;
 *   - once filled, k3-2026 verifies bundle envelopes and only the bundle role.
 *
 * Test keys are throwaway keys generated in-process. No real key material is used here.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'

const crypto = await import('../../src/core/crypto.js')
const {
  KEYRING,
  REVOKED_FINGERPRINTS,
  computeSpkiFingerprint,
  isKeyringPlaceholder,
  resolveAndImportKey,
  verifyBundleEnvelopeSignature,
  _testInjectKeyringEntry,
} = crypto
const { CEREMONY_OUTPUT } = await import('../../src/core/keyring-ceremony-output.js')

const K2_PEM = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1DXW6sA9dllAbfXMa/G+50Sw00svQF2X5bcU+YcP6M8=\n-----END PUBLIC KEY-----'
const K2_FP = '57873aac03421fa0740fdd9520729536223010067ea3012135db2b255a2b263c'

async function freshKey() {
  const kp = (await globalThis.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair
  const der = Buffer.from(await globalThis.crypto.subtle.exportKey('spki', kp.publicKey))
  const pem = `-----BEGIN PUBLIC KEY-----\n${der.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END PUBLIC KEY-----`
  return { ...kp, pem }
}

const inOneYear = () => Math.floor(Date.now() / 1000) + 365 * 86400
const cleanups: Array<() => void> = []
afterEach(() => { for (const c of cleanups.splice(0)) c() })

describe('the revoked K2 bundle key is retired with no overlap', () => {
  it('k2-2026 is not in KEYRING and its fingerprint is revoked', () => {
    expect(KEYRING.some(e => e.kid === 'k2-2026')).toBe(false)
    expect(computeSpkiFingerprint(K2_PEM)).toBe(K2_FP)
    expect(REVOKED_FINGERPRINTS.has(K2_FP)).toBe(true)
  })

  it('all four revoked fingerprints are on the denylist (k1, ra-k1, cf-k1, k2)', () => {
    expect(REVOKED_FINGERPRINTS.size).toBe(4)
    for (const fp of [
      '855e81b870c16d377efd8354e9761fadca2d22d16536f291fb77e690f9d65abc',
      '003837c9c656f66163a29e7b0d043a084fc83c2febc420a5e27889205a27b878',
      '87787b86689151fd9a9b763e3baa2cae884bf897d51dc02a211c70640e2c4f9d',
      K2_FP,
    ]) expect(REVOKED_FINGERPRINTS.has(fp)).toBe(true)
  })

  it('a bundle envelope naming kid k2-2026 is rejected (unknown key)', async () => {
    await expect(verifyBundleEnvelopeSignature(new Uint8Array([1]), 'AAAA', 'k2-2026')).rejects.toThrow(/Unknown key "k2-2026"/)
  })

  it('re-adding the K2 PEM under another kid is refused by the computed-fingerprint denylist', async () => {
    cleanups.push(_testInjectKeyringEntry({ kid: 'k2-readded', role: 'bundle', epoch: 3, expiry: inOneYear(), fingerprint: K2_FP, publicKey: K2_PEM }))
    await expect(resolveAndImportKey('k2-readded', 'bundle')).rejects.toThrow(/revoked/)
  })

  it('forging the declared fingerprint of a re-added K2 PEM does not help (computed value is what is denied)', async () => {
    cleanups.push(_testInjectKeyringEntry({ kid: 'k2-forged', role: 'bundle', epoch: 3, expiry: inOneYear(), fingerprint: '0'.repeat(64), publicKey: K2_PEM }))
    await expect(resolveAndImportKey('k2-forged', 'bundle')).rejects.toThrow(/fingerprint mismatch/)
  })
})

describe('the new keys come from ONE ceremony-output file', () => {
  it('the keyring has exactly ra-k2-2026, cf-k2-2026 and k3-2026, built from CEREMONY_OUTPUT', () => {
    expect(KEYRING.map(e => e.kid).sort()).toEqual(['cf-k2-2026', 'k3-2026', 'ra-k2-2026'])
    for (const [name, kid, role] of [
      ['ra', 'ra-k2-2026', 'release-attestation'],
      ['cf', 'cf-k2-2026', 'ci-freshness'],
      ['bundle', 'k3-2026', 'bundle'],
    ] as const) {
      const out = CEREMONY_OUTPUT[name]
      const e = KEYRING.find(x => x.kid === kid)!
      expect(out.kid).toBe(kid)
      expect(e.role).toBe(role)
      expect(e.publicKey).toBe(out.publicKey)
      expect(e.fingerprint).toBe(out.fingerprint)
    }
    expect(KEYRING.find(e => e.kid === 'k3-2026')!.epoch).toBeGreaterThanOrEqual(3)
  })

  it('crypto.ts holds NO key material or kid literal of its own for the new keys (single source: the constant file)', () => {
    const src = readFileSync(new URL('../../src/core/crypto.ts', import.meta.url), 'utf-8')
    expect(src).not.toMatch(/MCowBQYDK2Vw/)
    expect(src).not.toMatch(/KEYRING_PLACEHOLDER-/)
    expect(src).toMatch(/from '\.\/keyring-ceremony-output(\.js)?'/)
  })

  it('a filled-in ceremony entry is self-consistent; an unfilled one is a placeholder every path refuses', async () => {
    for (const [name, out] of Object.entries(CEREMONY_OUTPUT)) {
      if (isKeyringPlaceholder(out)) {
        await expect(resolveAndImportKey(out.kid, name === 'ra' ? 'release-attestation' : name === 'cf' ? 'ci-freshness' : 'bundle')).rejects.toThrow(/placeholder/)
      } else {
        expect(computeSpkiFingerprint(out.publicKey), name).toBe(out.fingerprint)
        expect(REVOKED_FINGERPRINTS.has(out.fingerprint), name).toBe(false)
      }
    }
  })

  it('once filled, k3-2026 verifies a bundle envelope signature, and only in the bundle role', async () => {
    const k = await freshKey()
    const fp = computeSpkiFingerprint(k.pem)
    cleanups.push(_testInjectKeyringEntry({ kid: 'k3-2026', role: 'bundle', epoch: 3, expiry: inOneYear(), fingerprint: fp, publicKey: k.pem }))
    const preimage = new Uint8Array([1, 2, 3, 4])
    const sig = Buffer.from(await globalThis.crypto.subtle.sign('Ed25519', k.privateKey, preimage)).toString('base64')
    await expect(verifyBundleEnvelopeSignature(preimage, sig, 'k3-2026')).resolves.toBeUndefined()
    await expect(resolveAndImportKey('k3-2026', 'release-attestation')).rejects.toThrow(/role mismatch/)
    const other = await freshKey()
    const badSig = Buffer.from(await globalThis.crypto.subtle.sign('Ed25519', other.privateKey, preimage)).toString('base64')
    await expect(verifyBundleEnvelopeSignature(preimage, badSig, 'k3-2026')).rejects.toThrow(/verification failed/)
  })
})
