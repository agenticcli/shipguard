/**
 * crypto.test.ts — updated.
 *
 * verifyAndDecryptBundle and verifyRuleBundle are PERMANENTLY DISABLED tombstones.
 * Their original behavior tests are REPLACED by tombstone-verification tests that
 * assert the functions always throw 'legacy-bundle-rejected: attestation required'.
 *
 * The keyring tests (below) are UNCHANGED — _testInjectPinnedKey is still used
 * by release-verify.test.ts and keyring.test.ts.
 */

import { describe, it, expect } from 'vitest';

const { verifyAndDecryptBundle, verifyRuleBundle, _testInjectPinnedKey } = await import('../../src/core/crypto.js');

// -------------------------------------------------------------------------
// legacy path T1 — verifyAndDecryptBundle TOMBSTONE
// -------------------------------------------------------------------------

describe('verifyAndDecryptBundle — TOMBSTONE', () => {
  it('always throws legacy-bundle-rejected for any base64 input', async () => {
    await expect(verifyAndDecryptBundle('dGVzdA==', 'any-token'))
      .rejects.toThrow('legacy-bundle-rejected')
  })

  it('error message cites attestation required', async () => {
    await expect(verifyAndDecryptBundle('base64==', 'token'))
      .rejects.toThrow('attestation required')
  })

  it('mentions non-safe exit in the error message', async () => {
    let msg = ''
    try {
      await verifyAndDecryptBundle('dGVzdA==', 'token')
    } catch (err) {
      msg = err instanceof Error ? err.message : String(err)
    }
    expect(msg).toContain('non-safe')
  })

  it('never resolves — always rejects', async () => {
    const result = await verifyAndDecryptBundle('dGVzdA==', 'token')
      .then(() => 'resolved')
      .catch(() => 'rejected')
    expect(result).toBe('rejected')
  })
})

// -------------------------------------------------------------------------
// legacy path T2 — verifyRuleBundle TOMBSTONE
// -------------------------------------------------------------------------

describe('verifyRuleBundle — TOMBSTONE', () => {
  it('always throws legacy-bundle-rejected for any JWT token', async () => {
    await expect(verifyRuleBundle('eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.sig'))
      .rejects.toThrow('legacy-bundle-rejected')
  })

  it('error message cites attestation required', async () => {
    await expect(verifyRuleBundle('any-token'))
      .rejects.toThrow('attestation required')
  })

  it('throws for empty token', async () => {
    await expect(verifyRuleBundle('')).rejects.toThrow('legacy-bundle-rejected')
  })

  it('never resolves — always rejects', async () => {
    const result = await verifyRuleBundle('any-jwt-string')
      .then(() => 'resolved')
      .catch(() => 'rejected')
    expect(result).toBe('rejected')
  })
})

// -------------------------------------------------------------------------
// Keyring injection helper — still exported, used by release-verify.test.ts
// -------------------------------------------------------------------------

describe('_testInjectPinnedKey — still available for keyring tests', () => {
  it('is exported and is a function', () => {
    expect(typeof _testInjectPinnedKey).toBe('function')
  })
})
