/**
 * Keyring revocation — keys that are no longer trusted.
 *
 * Covers:
 *   - keyring shape: revoked kids are gone; the current keys are present (epoch 2 for RA/CF,
 *     present (epoch 2 for RA/CF, epoch 3 for the k3-2026 bundle key), MIN_ACCEPTABLE_EPOCH = 2
 *   - computed-vs-declared fingerprint (the resolver hashes the real SPKI DER)
 *   - forged metadata: a revoked PEM re-added with an edited fingerprint is still refused
 *   - REVOKED_FINGERPRINTS denylist applied to the COMPUTED fingerprint
 *   - unfilled placeholders are refused at runtime
 *   - the full lexicographic (epoch, sequence) floor comparator matrix
 */

import { describe, it, expect, afterEach } from 'vitest'

const crypto = await import('../../src/core/crypto.js')
const {
  KEYRING,
  MIN_ACCEPTABLE_EPOCH,
  REVOKED_FINGERPRINTS,
  computeSpkiFingerprint,
  isKeyringPlaceholder,
  resolveAndImportKey,
  verifyAttestation,
  _testInjectKeyringEntry,
} = crypto
const { compareFloorTuples } = await import('../../src/core/release-verify.js')

// The three EXPOSED public keys (public halves only — these are the keys being retired).
const EXPOSED = {
  'k1-2026': {
    role: 'bundle' as const,
    pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAkpeX0A3zIOttGn8t+jagJHLRTv5Q809vqIZU37lE6xQ=\n-----END PUBLIC KEY-----',
    fp: '855e81b870c16d377efd8354e9761fadca2d22d16536f291fb77e690f9d65abc',
  },
  'ra-k1-2026': {
    role: 'release-attestation' as const,
    pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEANcib9WOOIys1wLQW30T/RvRv+3d/+2DAWKOKwEj5sS0=\n-----END PUBLIC KEY-----',
    fp: '003837c9c656f66163a29e7b0d043a084fc83c2febc420a5e27889205a27b878',
  },
  'cf-k1-2026': {
    role: 'ci-freshness' as const,
    pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAaQ49ermPqqsENKA7fFi8K0zIEyxYEje56a34Pus6UhM=\n-----END PUBLIC KEY-----',
    fp: '87787b86689151fd9a9b763e3baa2cae884bf897d51dc02a211c70640e2c4f9d',
  },
  // the epoch-2 bundle key, also revoked.
  'k2-2026': {
    role: 'bundle' as const,
    pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1DXW6sA9dllAbfXMa/G+50Sw00svQF2X5bcU+YcP6M8=\n-----END PUBLIC KEY-----',
    fp: '57873aac03421fa0740fdd9520729536223010067ea3012135db2b255a2b263c',
  },
}

const inOneHour = () => Math.floor(Date.now() / 1000) + 3600

async function freshKey() {
  const kp = await globalThis.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair
  const der = Buffer.from(await globalThis.crypto.subtle.exportKey('spki', kp.publicKey))
  const pem = `-----BEGIN PUBLIC KEY-----\n${der.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END PUBLIC KEY-----`
  return { ...kp, pem }
}

const cleanups: Array<() => void> = []
afterEach(() => { for (const c of cleanups.splice(0)) c() })

describe('keyring shape', () => {
  it('MIN_ACCEPTABLE_EPOCH is 2', () => {
    expect(MIN_ACCEPTABLE_EPOCH).toBe(2)
  })

  it('no revoked kid remains; ra-k2-2026 / cf-k2-2026 (epoch 2) and k3-2026 (epoch 3) are present', () => {
    const kids = KEYRING.map(e => e.kid).sort()
    expect(kids).toEqual(['cf-k2-2026', 'k3-2026', 'ra-k2-2026'])
    for (const e of KEYRING) expect(e.epoch).toBe(e.kid === 'k3-2026' ? 3 : 2)
  })

  it('every revoked key fingerprint is on the denylist, and the pinned literals match the PEMs', () => {
    for (const [kid, k] of Object.entries(EXPOSED)) {
      expect(computeSpkiFingerprint(k.pem), kid).toBe(k.fp)
      expect(REVOKED_FINGERPRINTS.has(k.fp), kid).toBe(true)
    }
    expect(REVOKED_FINGERPRINTS.size).toBe(4)
  })

  it('no non-placeholder KEYRING entry is revoked, and each declares its computed fingerprint', () => {
    for (const e of KEYRING.filter(x => !isKeyringPlaceholder(x))) {
      const fp = computeSpkiFingerprint(e.publicKey)
      expect(fp, e.kid).toBe(e.fingerprint)
      expect(REVOKED_FINGERPRINTS.has(fp), e.kid).toBe(false)
    }
  })
})

describe('computed vs declared fingerprint', () => {
  it('a genuine key with its correct fingerprint resolves', async () => {
    const k = await freshKey()
    cleanups.push(_testInjectKeyringEntry({
      kid: 'fp-ok', role: 'release-attestation', epoch: 2, expiry: inOneHour(),
      fingerprint: computeSpkiFingerprint(k.pem), publicKey: k.pem,
    }))
    await expect(resolveAndImportKey('fp-ok', 'release-attestation')).resolves.toBeDefined()
  })

  it('a key whose declared fingerprint does not match its bytes is refused', async () => {
    const k = await freshKey()
    cleanups.push(_testInjectKeyringEntry({
      kid: 'fp-bad', role: 'release-attestation', epoch: 2, expiry: inOneHour(),
      fingerprint: '0'.repeat(64), publicKey: k.pem,
    }))
    await expect(resolveAndImportKey('fp-bad', 'release-attestation')).rejects.toThrow(/fingerprint mismatch/)
  })

  it('swapping the PEM under an existing declared fingerprint is refused (substituted key bytes)', async () => {
    const a = await freshKey()
    const b = await freshKey()
    cleanups.push(_testInjectKeyringEntry({
      kid: 'fp-swap', role: 'release-attestation', epoch: 2, expiry: inOneHour(),
      fingerprint: computeSpkiFingerprint(a.pem), publicKey: b.pem,
    }))
    await expect(resolveAndImportKey('fp-swap', 'release-attestation')).rejects.toThrow(/fingerprint mismatch/)
  })

  it('a malformed PEM is refused before import', async () => {
    cleanups.push(_testInjectKeyringEntry({
      kid: 'fp-junk', role: 'bundle', epoch: 2, expiry: inOneHour(),
      fingerprint: 'abc', publicKey: 'not a pem',
    }))
    await expect(resolveAndImportKey('fp-junk', 'bundle')).rejects.toThrow(/unreadable public key/)
  })
})

describe('denylist on the COMPUTED fingerprint', () => {
  for (const [kid, k] of Object.entries(EXPOSED)) {
    it(`${kid}: re-added at epoch 2 with its true fingerprint → refused as revoked`, async () => {
      cleanups.push(_testInjectKeyringEntry({
        kid: `readded-${kid}`, role: k.role, epoch: 2, expiry: inOneHour(),
        fingerprint: k.fp, publicKey: k.pem,
      }))
      await expect(resolveAndImportKey(`readded-${kid}`, k.role)).rejects.toThrow(/revoked/)
    })

    it(`${kid}: re-added with FORGED fingerprint metadata → still refused (never imported)`, async () => {
      // Attacker/accident edits the metadata to dodge a metadata-only denylist.
      cleanups.push(_testInjectKeyringEntry({
        kid: `forged-${kid}`, role: k.role, epoch: 2, expiry: inOneHour(),
        fingerprint: '1'.repeat(64), publicKey: k.pem,
      }))
      await expect(resolveAndImportKey(`forged-${kid}`, k.role)).rejects.toThrow(/fingerprint mismatch/)
    })

    it(`${kid}: re-added under a NEW kid with whitespace-reformatted PEM → still revoked`, async () => {
      const b64 = k.pem.split('\n')[1]
      const reformatted = `-----BEGIN PUBLIC KEY-----\n${b64.slice(0, 20)}\n${b64.slice(20)}\n-----END PUBLIC KEY-----\n`
      cleanups.push(_testInjectKeyringEntry({
        kid: `reformat-${kid}`, role: k.role, epoch: 2, expiry: inOneHour(),
        fingerprint: k.fp.toUpperCase(), publicKey: reformatted,
      }))
      await expect(resolveAndImportKey(`reformat-${kid}`, k.role)).rejects.toThrow(/revoked/)
    })
  }

  it('the retired kids are unknown to this CLI', async () => {
    await expect(resolveAndImportKey('ra-k1-2026', 'release-attestation')).rejects.toThrow(/Unknown key "ra-k1-2026"/)
    await expect(resolveAndImportKey('cf-k1-2026', 'ci-freshness')).rejects.toThrow(/Unknown key "cf-k1-2026"/)
    await expect(resolveAndImportKey('k1-2026', 'bundle')).rejects.toThrow(/Unknown key "k1-2026"/)
  })
})

describe('ceremony placeholders', () => {
  it('an unfilled placeholder entry is refused at runtime with a clear message', async () => {
    const placeholder = KEYRING.find(e => e.kid === 'ra-k2-2026')!
    if (!isKeyringPlaceholder(placeholder)) return // ceremony already filled it in — nothing to test
    await expect(verifyAttestation(new Uint8Array([1]), 'AAAA', 'ra-k2-2026'))
      .rejects.toThrow(/unfilled key-ceremony placeholder/)
  })
})

describe('floor comparator — exact lexicographic (epoch, sequence) matrix', () => {
  const t = (keyringEpoch: number, sequence: number, releaseId = `r${sequence}`, manifestDigest = `d${sequence}`) =>
    ({ keyringEpoch, sequence, releaseId, manifestDigest })

  const cases: Array<[string, ReturnType<typeof t>, ReturnType<typeof t>, 'advance' | 'idempotent' | 'reject']> = [
    // higher epoch replaces any lower-epoch floor, whatever the sequence
    ['higher epoch, lower seq', t(1, 3), t(2, 1), 'advance'],
    ['higher epoch, same seq, other tuple', t(1, 3), t(2, 3, 'x', 'y'), 'advance'],
    ['higher epoch, higher seq', t(1, 3), t(2, 4), 'advance'],
    ['higher epoch vs poisoned max-seq floor', t(1, Number.MAX_SAFE_INTEGER), t(2, 4), 'advance'],
    // lower epoch is always rejected
    ['lower epoch, higher seq', t(2, 4), t(1, 5), 'reject'],
    ['lower epoch, max seq', t(2, 4), t(1, Number.MAX_SAFE_INTEGER), 'reject'],
    ['lower epoch, same tuple otherwise', t(2, 4), t(1, 4, 'r4', 'd4'), 'reject'],
    ['lower epoch, lower seq', t(2, 4), t(1, 3), 'reject'],
    // same epoch: sequence monotonic
    ['same epoch, higher seq', t(2, 4), t(2, 5), 'advance'],
    ['same epoch, gap', t(2, 4), t(2, 7), 'advance'],
    ['same epoch, lower seq', t(2, 4), t(2, 3), 'reject'],
    ['same epoch, same seq, identical tuple', t(2, 4), t(2, 4), 'idempotent'],
    ['same epoch, same seq, other releaseId', t(2, 4), t(2, 4, 'other', 'd4'), 'reject'],
    ['same epoch, same seq, other manifestDigest', t(2, 4), t(2, 4, 'r4', 'other'), 'reject'],
  ]

  for (const [name, floor, incoming, expected] of cases) {
    it(`${name} → ${expected}`, () => {
      const d = compareFloorTuples(floor, incoming)
      expect(d.decision).toBe(expected)
      if (d.decision === 'reject') expect(d.reason.length).toBeGreaterThan(0)
    })
  }
})
