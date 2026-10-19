/**
 * crypto-cross-impl.test.ts — UPDATED.
 *
 * The original cross-implementation KAT suite (CRYPTO-001 through CRYPTO-006)
 * tested verifyAndDecryptBundle with Node.js-signed fixture bundles. Those tests
 * are REPLACED by tombstone-verification tests because verifyAndDecryptBundle is
 * now permanently disabled.
 *
 * Retained: _testInjectPinnedKey usage verification (still needed by keyring tests).
 *
 * Historical note: the original suite covered:
 *   CRYPTO-001: cross-impl Ed25519 round-trip (Node sign → WebCrypto verify)
 *   CRYPTO-002: HKDF cross-implementation parity
 *   CRYPTO-003: legacy JWT fallback behavior
 *   CRYPTO-004: kid resolution / unknown-kid rejection
 *   CRYPTO-005: AES-GCM auth-tag integrity (tampered ciphertext)
 *   CRYPTO-006: defense in depth (multiple layers of protection)
 *   SEC-INV-005: no key material in error messages
 *
 * These are superseded by the attested-release path tests in release-verify.test.ts.
 * The cross-boundary cryptographic security is now enforced via:
 *   - BundleEnvelope Ed25519 signature (signBundleEnvelope, §3.5)
 *   - CorpusAttestation (CI-signed, Release-Attestation key, role 2)
 *   - FreshnessToken (CI-signed, CI-Freshness key, role 3)
 *   - verifyBundleResponse in release-verify.ts (attack coverage)
 */

import { describe, it, expect } from 'vitest'

const { verifyAndDecryptBundle, _testInjectPinnedKey } = await import('../../src/core/crypto.js')

// ---------------------------------------------------------------------------
// TOMBSTONE VERIFICATION
// ---------------------------------------------------------------------------

describe('verifyAndDecryptBundle is permanently disabled', () => {
  it('throws legacy-bundle-rejected for any base64 input', async () => {
    await expect(verifyAndDecryptBundle('dGVzdA==', 'any-token'))
      .rejects.toThrow('legacy-bundle-rejected')
  })

  it('error message cites attestation required', async () => {
    await expect(verifyAndDecryptBundle('base64==', 'token'))
      .rejects.toThrow('attestation required')
  })

  it('never resolves regardless of input format (empty, garbage, valid base64)', async () => {
    for (const input of ['', 'dGVzdA==', Buffer.from('{}').toString('base64'), 'AAAA']) {
      const result = await verifyAndDecryptBundle(input, 'token')
        .then(() => 'resolved')
        .catch(() => 'rejected')
      expect(result).toBe('rejected')
    }
  })
})

// ---------------------------------------------------------------------------
// _testInjectPinnedKey still available for release-verify.test.ts and keyring.test.ts
// ---------------------------------------------------------------------------

describe('_testInjectPinnedKey — available for other test suites', () => {
  it('is a function (release-verify.test.ts and keyring.test.ts depend on it)', () => {
    expect(typeof _testInjectPinnedKey).toBe('function')
  })
})
