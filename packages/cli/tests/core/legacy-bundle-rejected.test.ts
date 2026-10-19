/**
 * Legacy bundle paths are PERMANENTLY DISABLED.
 *
 * All bundles MUST carry a valid corpusAttestation signed by the pinned
 * Release-Attestation key (fullManifest + corpusAttestation + bundleEnvelope).
 * Un-attested bundles (AES-GCM encrypted or JWT) are REJECTED with a non-safe exit.
 *
 * Tests covered:
 *   T1 — verifyRuleBundle always throws legacy-bundle-rejected
 *   T2 — verifyAndDecryptBundle always throws legacy-bundle-rejected
 *   T3 — fetchProRules: response lacking fullManifest throws legacy-bundle-rejected
 *   T4 — fetchProRules: response with old {signedBundle} shape throws legacy-bundle-rejected
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { verifyRuleBundle, verifyAndDecryptBundle } from '../../src/core/crypto.js'

// ---------------------------------------------------------------------------
// T1 — verifyRuleBundle tombstone
// ---------------------------------------------------------------------------

describe('legacy path T1 — verifyRuleBundle is permanently disabled', () => {
  it('throws legacy-bundle-rejected for any token input', async () => {
    await expect(verifyRuleBundle('any-jwt-token')).rejects.toThrow('legacy-bundle-rejected')
  })

  it('throws with attestation-required message', async () => {
    await expect(verifyRuleBundle('eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.sig'))
      .rejects.toThrow('attestation required')
  })

  it('error message mentions non-safe exit', async () => {
    let errMsg = ''
    try {
      await verifyRuleBundle('any-token')
    } catch (err) {
      errMsg = err instanceof Error ? err.message : String(err)
    }
    expect(errMsg).toContain('non-safe')
  })

  it('throws for empty token', async () => {
    await expect(verifyRuleBundle('')).rejects.toThrow('legacy-bundle-rejected')
  })
})

// ---------------------------------------------------------------------------
// T2 — verifyAndDecryptBundle tombstone
// ---------------------------------------------------------------------------

describe('legacy path T2 — verifyAndDecryptBundle is permanently disabled', () => {
  it('throws legacy-bundle-rejected for any base64 input', async () => {
    await expect(verifyAndDecryptBundle('dGVzdA==', 'any-token')).rejects.toThrow('legacy-bundle-rejected')
  })

  it('throws with attestation-required message', async () => {
    await expect(verifyAndDecryptBundle('base64bundle==', 'access-token'))
      .rejects.toThrow('attestation required')
  })

  it('error message mentions non-safe exit', async () => {
    let errMsg = ''
    try {
      await verifyAndDecryptBundle('dGVzdA==', 'token')
    } catch (err) {
      errMsg = err instanceof Error ? err.message : String(err)
    }
    expect(errMsg).toContain('non-safe')
  })
})

// ---------------------------------------------------------------------------
// T3/T4 — fetchProRules rejects un-attested server responses
// ---------------------------------------------------------------------------

describe('legacy path T3 — fetchProRules rejects response lacking fullManifest', () => {
  beforeEach(() => {
    // Mock getAuthToken so fetchProRules can be called without a real auth state
    vi.mock('../../src/core/auth.js', () => ({
      getAuthToken: () => Promise.resolve('test-token'),
    }))
  })

  it('throws legacy-bundle-rejected when response has no fullManifest key', async () => {
    // Response without fullManifest — the old format.
    // text() is required by the Finding-8 fix (res.text() + parseStrictNoDup).
    const mockResponse = {
      signedBundle: 'dGVzdA==',
      rulesVersion: 'current',
      rulesCount: 5,
    }
    const mockBody = JSON.stringify(mockResponse)
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: {
        get: (name: string) => name === 'X-Credits-Remaining' ? '10' : null,
      },
      text: () => Promise.resolve(mockBody),
      json: () => Promise.resolve(mockResponse),
    })

    const { fetchProRules } = await import('../../src/core/pro-scanner.js')
    await expect(
      fetchProRules(['generic'], undefined, 'https://agenticcli.dev', 'test-scan-id'),
    ).rejects.toThrow('legacy-bundle-rejected')
  })

  it('throws when response has signedBundle but no fullManifest (old AES-GCM format)', async () => {
    const mockResponse = {
      signedBundle: Buffer.from(JSON.stringify({
        signature: 'base64sig==',
        payload: { kid: 'k2-2026', ciphertext: 'enc==', iv: 'iv==', salt: 'salt==', watermark: {}, expiresAt: 9999999999999 },
      })).toString('base64'),
    }
    const mockBody2 = JSON.stringify(mockResponse)
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: {
        get: (_: string) => null,
      },
      text: () => Promise.resolve(mockBody2),
      json: () => Promise.resolve(mockResponse),
    })

    const { fetchProRules: fetchProRules2 } = await import('../../src/core/pro-scanner.js')
    await expect(
      fetchProRules2(['generic'], undefined, 'https://agenticcli.dev', 'test-scan-id'),
    ).rejects.toThrow('legacy-bundle-rejected')
  })
})
