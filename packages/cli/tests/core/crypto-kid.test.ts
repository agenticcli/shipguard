/**
 * Track 2 — Kid-based dual-pinned key tests
 * Updated for the attested-release protocol.
 *
 * verifyAndDecryptBundle is now PERMANENTLY DISABLED (tombstone). All tests that
 * previously called it with real crypto operations are REPLACED by:
 *   (a) tombstone-verification tests (function always throws legacy-bundle-rejected)
 *   (b) PINNED_KEYS / KEYRING static shape contract tests (source-code assertions)
 *   (c) _testInjectPinnedKey availability test (used by release-verify.test.ts)
 *
 * Original KID-001 through KID-010 relied on verifyAndDecryptBundle resolving bundles
 * after PINNED_KEYS injection. Those are no longer possible. The trust model for the
 * attested-release protocol is tested in release-verify.test.ts (GC.1–GC.16).
 *
 * Tests retained in new form:
 *   KID-005  PINNED_KEYS / KEYRING static shape contract (source-code assertions)
 *   KID-008  Pin-correctness — both k1-2026 and k2-2026 public key fragments
 *   NEW      Tombstone: verifyAndDecryptBundle always throws (all kid variants)
 *   NEW      _testInjectPinnedKey is still exported and callable
 *
 * The SHIPGUARD_PUBLIC_KEY env var is not read by crypto.ts.
 * verifyAndDecryptBundle is permanently disabled.
 */

import { describe, it, expect, afterEach } from 'vitest';

const { verifyAndDecryptBundle, _testInjectPinnedKey } = await import('../../src/core/crypto.js');

let cleanupInjection: (() => void) | undefined;

afterEach(() => {
  cleanupInjection?.();
  cleanupInjection = undefined;
});

// ---------------------------------------------------------------------------
// TOMBSTONE — verifyAndDecryptBundle always throws regardless of kid
// ---------------------------------------------------------------------------

describe('verifyAndDecryptBundle tombstone (all kid variants)', () => {
  it('rejects base64 bundle without kid field', async () => {
    await expect(
      verifyAndDecryptBundle(Buffer.from('{"signature":"AAAA","payload":{}}').toString('base64'), 'token'),
    ).rejects.toThrow('legacy-bundle-rejected');
  });

  it('rejects bundle with kid=k1-2026', async () => {
    const bundle = Buffer.from(
      JSON.stringify({ signature: 'AAAA', payload: { kid: 'k1-2026', ciphertext: 'AAAA', iv: 'AAAA', salt: 'AAAA' } }),
    ).toString('base64');
    await expect(verifyAndDecryptBundle(bundle, 'token')).rejects.toThrow('legacy-bundle-rejected');
  });

  it('rejects bundle with kid=k2-2026', async () => {
    const bundle = Buffer.from(
      JSON.stringify({ signature: 'AAAA', payload: { kid: 'k2-2026', ciphertext: 'AAAA', iv: 'AAAA', salt: 'AAAA' } }),
    ).toString('base64');
    await expect(verifyAndDecryptBundle(bundle, 'token')).rejects.toThrow('legacy-bundle-rejected');
  });

  it('rejects bundle with unknown kid', async () => {
    const bundle = Buffer.from(
      JSON.stringify({ signature: 'AAAA', payload: { kid: 'k99-future', ciphertext: 'AAAA' } }),
    ).toString('base64');
    await expect(verifyAndDecryptBundle(bundle, 'token')).rejects.toThrow('legacy-bundle-rejected');
  });

  it('rejects even after _testInjectPinnedKey injection (tombstone fires before key resolution)', async () => {
    cleanupInjection = _testInjectPinnedKey('k1-2026', '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----');
    await expect(
      verifyAndDecryptBundle(Buffer.from('{}').toString('base64'), 'token'),
    ).rejects.toThrow('legacy-bundle-rejected');
  });

  it('never resolves — fail-closed', async () => {
    const result = await verifyAndDecryptBundle('dGVzdA==', 'any-token')
      .then(() => 'resolved')
      .catch(() => 'rejected');
    expect(result).toBe('rejected');
  });

  it('error message cites attestation required (SEC-INV-001: no key material leaked)', async () => {
    let msg = '';
    try {
      await verifyAndDecryptBundle('dGVzdA==', 'any-token');
    } catch (err) {
      msg = err instanceof Error ? err.message : String(err);
    }
    expect(msg).toContain('attestation required');
    expect(msg).not.toContain('BEGIN PUBLIC KEY');
    expect(msg).not.toContain('BEGIN PRIVATE KEY');
  });
});

// ---------------------------------------------------------------------------
// KID-005 — PINNED_KEYS / KEYRING static shape contract
// ---------------------------------------------------------------------------

describe('KID-005: PINNED_KEYS static shape contract', () => {
  it('crypto.ts source contains PINNED_KEYS, DEFAULT_KID, and lacks deprecated symbols', async () => {
    const { readFileSync } = await import('node:fs');
    const cryptoPath = new URL('../../src/core/crypto.ts', import.meta.url).pathname;
    const source = readFileSync(cryptoPath, 'utf-8');

    expect(source).toMatch(/PINNED_KEYS/);
    // k2-2026 is retired too. The default kid is the current bundle kid (k3-2026) and, like all
    // three new public keys, comes from the single ceremony-output file - crypto.ts holds no key literal.
    expect(source).not.toMatch(/MCowBQYDK2VwAyEA/); // no Ed25519 SPKI key material in crypto.ts
    expect(source).toMatch(/DEFAULT_KID\s*=\s*CEREMONY_OUTPUT\.bundle\.kid/);
    // FALLBACK_PUBLIC_KEY must be gone (replaced by PINNED_KEYS)
    expect(source).not.toMatch(/FALLBACK_PUBLIC_KEY/);
    // SHIPGUARD_PUBLIC_KEY env override must be gone
    expect(source).not.toContain('SHIPGUARD_PUBLIC_KEY');
    // KEYRING must be present (4-key typed keyring)
    expect(source).toMatch(/KEYRING/);
  });
});

// ---------------------------------------------------------------------------
// KID-008 — Pin-correctness: both k1-2026 and k2-2026 public key fragments present
// ---------------------------------------------------------------------------

describe('KID-008: pin-correctness — no revoked key (k1-2026, k2-2026) is pinned in source', () => {
  it('crypto.ts source carries neither the k1-2026 nor the k2-2026 public key', async () => {
    const { readFileSync } = await import('node:fs');
    const cryptoPath = new URL('../../src/core/crypto.ts', import.meta.url).pathname;
    const source = readFileSync(cryptoPath, 'utf-8');

    // The revoked public keys must not be pinned any more (they live only as REVOKED fingerprints).
    expect(source).not.toContain('MCowBQYDK2VwAyEA1DXW6sA9dllAbfXMa/G+50Sw00svQF2X5bcU+YcP6M8='); // k2-2026
    expect(source).not.toContain('MCowBQYDK2VwAyEAkpeX0A3zIOttGn8t+jagJHLRTv5Q809vqIZU37lE6xQ='); // k1-2026
    expect(source).toContain('57873aac03421fa0740fdd9520729536223010067ea3012135db2b255a2b263c'); // k2-2026 fingerprint, revoked
  });
});

// ---------------------------------------------------------------------------
// _testInjectPinnedKey — still exported for release-verify.test.ts and keyring.test.ts
// ---------------------------------------------------------------------------

describe('_testInjectPinnedKey — still exported and callable', () => {
  it('is a function', () => {
    expect(typeof _testInjectPinnedKey).toBe('function');
  });

  it('returns a cleanup function', () => {
    const cleanup = _testInjectPinnedKey('test-kid-shape', '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----');
    expect(typeof cleanup).toBe('function');
    cleanup(); // restore immediately
  });
});
