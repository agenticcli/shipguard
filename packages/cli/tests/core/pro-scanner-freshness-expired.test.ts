/**
 * An expired freshness token on the Pro rules bundle gets its own failure class
 * (FRESHNESS_EXPIRED) with one plain message; every other verification failure stays BUNDLE_INVALID.
 * Harness: real fetchProRules, mocked auth, mocked fetch, mocked verifyBundleResponse.
 */

import { describe, it, expect, vi, afterEach } from 'vitest'

vi.mock('../../src/core/auth.js', () => ({
  getAuthToken: () => Promise.resolve('test-token'),
}))
vi.mock('../../src/core/release-verify.js', () => ({
  verifyBundleResponse: vi.fn(),
}))

const { verifyBundleResponse } = await import('../../src/core/release-verify.js')
const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
const { PRO_RULES_UNAVAILABLE_MESSAGE } = await import('../../src/core/platform-status.js')

const BODY = JSON.stringify({
  fullManifest: { rules: [] },
  corpusAttestation: {},
  freshnessTok: {},
  selectedRules: [],
  bundleEnvelope: {},
})

function installFetch(): void {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    headers: { get: () => null },
    text: () => Promise.resolve(BODY),
    json: () => Promise.resolve(JSON.parse(BODY)),
  }) as unknown as typeof fetch
}

const realFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = realFetch; vi.clearAllMocks() })

describe('expired freshness token → FRESHNESS_EXPIRED', () => {
  it('maps to the plain "temporarily unavailable" message', async () => {
    installFetch()
    vi.mocked(verifyBundleResponse).mockResolvedValue({
      ok: false,
      reason: 'freshness token expired (expiresAt=1, now=999999)',
      nonSafe: true,
      freshnessExpired: true,
    })
    const err = await fetchProRules(['generic'], undefined, 'https://agenticcli.dev').catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect(err.code).toBe('FRESHNESS_EXPIRED')
    expect(err.message).toContain(PRO_RULES_UNAVAILABLE_MESSAGE)
  })

  it('any other verification failure stays BUNDLE_INVALID', async () => {
    installFetch()
    vi.mocked(verifyBundleResponse).mockResolvedValue({
      ok: false,
      reason: 'freshness token TTL exceeds maximum 73 hours (999999s)',
      nonSafe: true,
    })
    const err = await fetchProRules(['generic'], undefined, 'https://agenticcli.dev').catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect(err.code).toBe('BUNDLE_INVALID')
  })
})
