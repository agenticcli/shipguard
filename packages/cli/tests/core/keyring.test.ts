/**
 * TDD suite for the 4-key typed KEYRING.
 *
 * Covers: role mismatch (cross-role replay), epoch rollback protection,
 * expiry rejection, valid attestation/freshness verification, and
 * PINNED_KEYS ↔ KEYRING parity for the bundle keys.
 */

import { describe, it, expect, beforeAll, afterEach } from 'vitest';

const {
  verifyAttestation,
  verifyFreshness,
  KEYRING,
  PINNED_KEYS: _unusedPinnedKeys,
  _testInjectKeyringEntry,
} = await import('../../src/core/crypto.js');

// We also need PINNED_KEYS for the parity test. Access it via a re-import
// (the module is cached, so we get the same reference).
const cryptoModule = await import('../../src/core/crypto.js');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate a fresh Ed25519 keypair via crypto.subtle. */
async function generateTestKeypair(): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  const { privateKey, publicKey } = await globalThis.crypto.subtle.generateKey(
    'Ed25519',
    true,
    ['sign', 'verify'],
  );
  return { privateKey, publicKey };
}

/** Export a CryptoKey (public, SPKI) to PEM string. */
async function exportPublicKeyAsPem(publicKey: CryptoKey): Promise<string> {
  const spkiDer = await globalThis.crypto.subtle.exportKey('spki', publicKey);
  const b64 = Buffer.from(spkiDer).toString('base64');
  const lines = b64.match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

/** Sign preimage bytes with a CryptoKey (private Ed25519). Returns base64url string. */
async function signPreimage(preimage: Uint8Array, privateKey: CryptoKey): Promise<string> {
  const sigBytes = await globalThis.crypto.subtle.sign('Ed25519', privateKey, preimage);
  return Buffer.from(sigBytes).toString('base64url');
}

/** Build a minimal valid PinnedKeyEntry with the given overrides. */
async function makeEntry(
  overrides: Partial<import('../../src/core/crypto.js').PinnedKeyEntry> & {
    publicKey?: string;
    kid?: string;
    role?: import('../../src/core/crypto.js').KeyRole;
  },
  publicKey: CryptoKey,
): Promise<import('../../src/core/crypto.js').PinnedKeyEntry> {
  const pem = await exportPublicKeyAsPem(publicKey);
  return {
    kid: overrides.kid ?? 'test-key',
    role: overrides.role ?? 'release-attestation',
    epoch: overrides.epoch ?? 2, // MIN_ACCEPTABLE_EPOCH is 2
    expiry: overrides.expiry ?? Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
    fingerprint: cryptoModule.computeSpkiFingerprint(overrides.publicKey ?? pem),
    publicKey: overrides.publicKey ?? pem,
    ...overrides,
    // publicKey from crypto key takes precedence unless explicitly provided in overrides
    ...(overrides.publicKey ? {} : { publicKey: pem }),
  };
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('KEYRING — verifyAttestation', () => {
  let cleanup: (() => void) | undefined;

  afterEach(() => {
    cleanup?.();
    cleanup = undefined;
  });

  // -------------------------------------------------------------------------
  // Test 1: Valid attestation verifies
  // -------------------------------------------------------------------------
  it('verifies a valid attestation signature', async () => {
    const { privateKey, publicKey } = await generateTestKeypair();
    const entry = await makeEntry({ kid: 'test-ra-valid', role: 'release-attestation' }, publicKey);
    cleanup = _testInjectKeyringEntry(entry);

    const preimage = new TextEncoder().encode('shipguard-attestation-v1\x00{"rules":"hash"}');
    const sig = await signPreimage(preimage, privateKey);

    await expect(verifyAttestation(preimage, sig, 'test-ra-valid')).resolves.toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // Test 2: Tampered manifest → reject
  // -------------------------------------------------------------------------
  it('rejects a tampered preimage', async () => {
    const { privateKey, publicKey } = await generateTestKeypair();
    const entry = await makeEntry({ kid: 'test-ra-tamper', role: 'release-attestation' }, publicKey);
    cleanup = _testInjectKeyringEntry(entry);

    const preimage = new TextEncoder().encode('shipguard-attestation-v1\x00{"rules":"hash"}');
    const sig = await signPreimage(preimage, privateKey);

    // Flip a byte in the preimage
    const tampered = new Uint8Array(preimage);
    tampered[5] ^= 0xff;

    await expect(verifyAttestation(tampered, sig, 'test-ra-tamper')).rejects.toThrow(
      /signature verification failed/,
    );
  });

  // -------------------------------------------------------------------------
  // Test 3: Wrong-role key rejects (cross-role replay)
  // -------------------------------------------------------------------------
  it('rejects a "bundle"-role key used for attestation (cross-role replay)', async () => {
    const { privateKey, publicKey } = await generateTestKeypair();
    const entry = await makeEntry({ kid: 'test-bundle-as-ra', role: 'bundle' }, publicKey);
    cleanup = _testInjectKeyringEntry(entry);

    const preimage = new TextEncoder().encode('shipguard-attestation-v1\x00{"rules":"hash"}');
    const sig = await signPreimage(preimage, privateKey);

    await expect(verifyAttestation(preimage, sig, 'test-bundle-as-ra')).rejects.toThrow(
      /key role mismatch: expected release-attestation, got bundle — cross-role replay rejected/,
    );
  });

  // -------------------------------------------------------------------------
  // Test 6: Epoch rollback rejected
  // -------------------------------------------------------------------------
  it('rejects a key with epoch below MIN_ACCEPTABLE_EPOCH (epoch=0)', async () => {
    const { privateKey, publicKey } = await generateTestKeypair();
    const entry = await makeEntry({ kid: 'test-ra-epoch0', role: 'release-attestation', epoch: 0 }, publicKey);
    cleanup = _testInjectKeyringEntry(entry);

    const preimage = new TextEncoder().encode('test-preimage');
    const sig = await signPreimage(preimage, privateKey);

    await expect(verifyAttestation(preimage, sig, 'test-ra-epoch0')).rejects.toThrow(
      /rollback|epoch/i,
    );
  });

  // -------------------------------------------------------------------------
  // Test 7: Expired key rejected
  // -------------------------------------------------------------------------
  it('rejects a key that has expired', async () => {
    const { privateKey, publicKey } = await generateTestKeypair();
    const pastExpiry = Math.floor(Date.now() / 1000) - 60; // 1 minute ago
    const entry = await makeEntry(
      { kid: 'test-ra-expired', role: 'release-attestation', expiry: pastExpiry },
      publicKey,
    );
    cleanup = _testInjectKeyringEntry(entry);

    const preimage = new TextEncoder().encode('test-preimage');
    const sig = await signPreimage(preimage, privateKey);

    await expect(verifyAttestation(preimage, sig, 'test-ra-expired')).rejects.toThrow(
      /expired/i,
    );
  });
});

describe('KEYRING — verifyFreshness', () => {
  let cleanup: (() => void) | undefined;

  afterEach(() => {
    cleanup?.();
    cleanup = undefined;
  });

  // -------------------------------------------------------------------------
  // Test 4: Valid freshness verifies
  // -------------------------------------------------------------------------
  it('verifies a valid CI-freshness signature', async () => {
    const { privateKey, publicKey } = await generateTestKeypair();
    const entry = await makeEntry({ kid: 'test-cf-valid', role: 'ci-freshness' }, publicKey);
    cleanup = _testInjectKeyringEntry(entry);

    const preimage = new TextEncoder().encode('shipguard-ci-freshness-v1\x00{"iat":1234567890}');
    const sig = await signPreimage(preimage, privateKey);

    await expect(verifyFreshness(preimage, sig, 'test-cf-valid')).resolves.toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // Test 5: Wrong-role freshness rejects
  // -------------------------------------------------------------------------
  it('rejects a "release-attestation"-role key used for freshness (cross-role replay)', async () => {
    const { privateKey, publicKey } = await generateTestKeypair();
    const entry = await makeEntry({ kid: 'test-ra-as-cf', role: 'release-attestation' }, publicKey);
    cleanup = _testInjectKeyringEntry(entry);

    const preimage = new TextEncoder().encode('shipguard-ci-freshness-v1\x00{"iat":1234567890}');
    const sig = await signPreimage(preimage, privateKey);

    await expect(verifyFreshness(preimage, sig, 'test-ra-as-cf')).rejects.toThrow(
      /key role mismatch: expected ci-freshness, got release-attestation — cross-role replay rejected/,
    );
  });
});

// ---------------------------------------------------------------------------
// Test 8: bundle keys after revocation (k1-2026 removed)
// ---------------------------------------------------------------------------
describe('KEYRING — bundle keys after revocation', () => {
  const extractB64 = (pem: string) =>
    pem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s/g, '');

  it('k3-2026 is the only bundle key (k2-2026 retired); its PEM is the one from the ceremony-output file', async () => {
    const { CEREMONY_OUTPUT } = await import('../../src/core/keyring-ceremony-output.js');
    const bundleKeys = KEYRING.filter(e => e.role === 'bundle');
    expect(bundleKeys.map(e => e.kid)).toEqual(['k3-2026']);
    expect(extractB64(bundleKeys[0].publicKey)).toBe(extractB64(CEREMONY_OUTPUT.bundle.publicKey));
    expect(bundleKeys[0].epoch).toBe(3);
  });

  it('the revoked k2-2026 is not in KEYRING', () => {
    expect(KEYRING.find(e => e.kid === 'k2-2026')).toBeUndefined();
  });

  it('no revoked kid (k1-2026, ra-k1-2026, cf-k1-2026) remains in KEYRING', () => {
    for (const kid of ['k1-2026', 'ra-k1-2026', 'cf-k1-2026']) {
      expect(KEYRING.find(e => e.kid === kid)).toBeUndefined();
    }
  });
});
