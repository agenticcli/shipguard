/**
 * auth-key-exchange.test.ts — API-key exchange regression coverage.
 *
 * BUG: the CLI sent a raw SHIPGUARD_API_KEY directly as the Bearer token on Pro
 * rules/scan calls. The server's PF-D3 guard CORRECTLY rejects a raw key with
 * 401 "Auth expired" (raw keys must be exchanged first) — so a real paid user
 * with a valid API key could NEVER run a Pro scan through the CLI.
 *
 * FIX: getAuthToken() now exchanges a raw SHIPGUARD_API_KEY for a short-lived
 * access token via POST /api/agent/exchange (matching the server's expected
 * flow) and returns THAT token.
 *
 * FAIL-BEFORE: before this fix, getAuthToken() returned process.env.SHIPGUARD_API_KEY
 * immediately (auth.ts:109) — these tests would see zero fetch calls and the raw
 * key returned. Confirmed failing against pre-fix auth.ts (git stash of this diff).
 * PASS-AFTER: getAuthToken() calls POST {apiUrl}/api/agent/exchange with the raw
 * key as Bearer, and returns the server's access_token instead.
 *
 * Network is mocked; no real server.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

const API_URL = 'http://localhost:3000' // a trusted host (assertTrustedApiUrl allows localhost)

function jsonResponse(status: number, body: unknown): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: `HTTP ${status}`,
    json: async () => body,
  } as unknown as Response
}

describe('API-key exchange — CLI exchanges SHIPGUARD_API_KEY for an access token before Pro calls', () => {
  let originalFetch: typeof globalThis.fetch

  beforeEach(() => {
    originalFetch = globalThis.fetch
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    delete process.env.SHIPGUARD_API_KEY
    vi.resetModules()
  })

  it('FAIL-BEFORE/PASS-AFTER: calls POST /api/agent/exchange with the API key and returns the access_token, NOT the raw key', async () => {
    process.env.SHIPGUARD_API_KEY = 'sg_live_rawkey123'
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, { access_token: 'exchanged_access_token_abc', token_type: 'Bearer', expires_in: 900 }),
    )
    globalThis.fetch = fetchMock as unknown as typeof fetch

    const { getAuthToken } = await import('../../src/core/auth.js')
    const token = await getAuthToken(API_URL)

    // Must have called the exchange endpoint exactly once.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [calledUrl, calledInit] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(calledUrl).toBe(`${API_URL}/api/agent/exchange`)
    expect(calledInit.method).toBe('POST')
    expect((calledInit.headers as Record<string, string>).Authorization).toBe(
      'Bearer sg_live_rawkey123',
    )

    // Must return the EXCHANGED token — the raw-key-direct-send path is gone.
    expect(token).toBe('exchanged_access_token_abc')
    expect(token).not.toBe('sg_live_rawkey123')
  })

  it('reuses the cached exchanged token within the same run (does not re-exchange on every call)', async () => {
    process.env.SHIPGUARD_API_KEY = 'sg_live_cachekey'
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, { access_token: 'cached_token', expires_in: 900 }),
    )
    globalThis.fetch = fetchMock as unknown as typeof fetch

    const { getAuthToken } = await import('../../src/core/auth.js')
    const first = await getAuthToken(API_URL)
    const second = await getAuthToken(API_URL)

    expect(first).toBe('cached_token')
    expect(second).toBe('cached_token')
    expect(fetchMock).toHaveBeenCalledTimes(1) // second call reused the in-memory cache
  })

  it('a 401 from the exchange endpoint throws a clear invalid-key error, NOT the misleading "Auth expired"', async () => {
    process.env.SHIPGUARD_API_KEY = 'sg_live_badkey'
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse(401, { error: 'invalid_grant', error_description: 'invalid or revoked API key' }),
    ) as unknown as typeof fetch

    const { getAuthToken } = await import('../../src/core/auth.js')
    await expect(getAuthToken(API_URL)).rejects.toThrow(/invalid|revoked/i)

    // Reset cache-independent state and re-run to confirm the message never says
    // "Auth expired" — that wording belongs to the device-flow refresh path.
    let thrown: unknown
    try {
      await getAuthToken(API_URL)
    } catch (err) {
      thrown = err
    }
    expect(thrown).toBeInstanceOf(Error)
    expect((thrown as Error).message).not.toMatch(/auth expired/i)
  })

  it('a 402 (budget exhausted) throws a distinct budget error', async () => {
    process.env.SHIPGUARD_API_KEY = 'sg_live_nobudget'
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse(402, { error: 'budget_exceeded', error_description: 'API key monthly budget exhausted' }),
    ) as unknown as typeof fetch

    const { getAuthToken } = await import('../../src/core/auth.js')
    await expect(getAuthToken(API_URL)).rejects.toThrow(/budget/i)
  })

  it('a 500 server_error on exchange throws loudly (no silent fallback to the raw key)', async () => {
    process.env.SHIPGUARD_API_KEY = 'sg_live_servererr'
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse(500, { error: 'server_error', error_description: 'token mint failed' }),
    ) as unknown as typeof fetch

    const { getAuthToken } = await import('../../src/core/auth.js')
    const err = await getAuthToken(API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toMatch(/exchange failed/i)
  })

  it('a network error on exchange throws loudly, never returns the raw key as a fallback', async () => {
    process.env.SHIPGUARD_API_KEY = 'sg_live_networkerr'
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED')) as unknown as typeof fetch

    const { getAuthToken } = await import('../../src/core/auth.js')
    const result = await getAuthToken(API_URL).then(
      (t) => ({ ok: true as const, value: t }),
      (e) => ({ ok: false as const, value: e }),
    )
    expect(result.ok).toBe(false)
    expect(result.value).not.toBe('sg_live_networkerr')
  })

  // SECURITY REGRESSION (BL-2): the raw SHIPGUARD_API_KEY must NEVER be
  // transmitted to an untrusted host. The exchange path calls assertTrustedApiUrl()
  // BEFORE fetch(), so an untrusted --api-url (e.g. an attacker's "https://evil.com")
  // must throw and make ZERO network calls — the key never leaves the machine.
  //
  // FAIL-BEFORE: if the assertTrustedApiUrl() guard were removed from
  // exchangeApiKeyForToken() (auth.ts:143), getAuthToken('https://evil.com') would
  // POST `Authorization: Bearer <raw key>` to evil.com — fetch would be called once
  // and this test's toHaveBeenCalledTimes(0) assertion would fail, exposing the key.
  // PASS-AFTER: the guard throws first, fetch is never reached.
  it('SECURITY: an untrusted --api-url throws and makes ZERO fetch calls — the raw key is never sent', async () => {
    process.env.SHIPGUARD_API_KEY = 'sg_live_secret_never_leak'
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, { access_token: 'should_never_be_reached' }),
    )
    globalThis.fetch = fetchMock as unknown as typeof fetch

    const { getAuthToken } = await import('../../src/core/auth.js')

    // Must reject via the trust guard (its message names the untrusted URL).
    await expect(getAuthToken('https://evil.com')).rejects.toThrow(/untrusted api url/i)

    // The critical invariant: not a single network call was made, so the raw
    // SHIPGUARD_API_KEY was never transmitted to the untrusted host.
    expect(fetchMock).not.toHaveBeenCalled()
    expect(fetchMock).toHaveBeenCalledTimes(0)
  })
})
