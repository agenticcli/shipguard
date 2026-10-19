/**
 * platform-unavailable-20261018 — the platform answers a rules fetch with its "platform
 * unavailable" 503: JSON body {"error": "...", "code": "PLATFORM_UNAVAILABLE"}, a
 * `Retry-After: 300` header, `X-Platform-Status: unavailable`, and NO `X-Credits-Remaining`.
 *
 * Before: the unmapped code fell into the generic SERVER_ERROR bucket (indistinguishable from a
 * random 5xx). Now: fetchProRules throws a typed ProFetchError with the stable code
 * PLATFORM_UNAVAILABLE and the parsed retryAfterSeconds. Any OTHER 503 is unchanged.
 *
 * Network is mocked; no real server.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const mockGetAuthToken = vi.fn().mockResolvedValue('test-token')
vi.mock('../../src/core/auth.js', () => ({
  getAuthToken: mockGetAuthToken,
}))

const API_URL = 'http://localhost:3000'

const PLATFORM_BODY = {
  error: 'Service temporarily unavailable. Please try again later.',
  code: 'PLATFORM_UNAVAILABLE',
}

function response(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: `HTTP ${status}`,
    headers: { get: (name: string) => headers[name] ?? null },
    json: async () => {
      if (body === undefined) throw new SyntaxError('Unexpected end of JSON input')
      return body
    },
    text: async () => JSON.stringify(body),
  } as unknown as Response
}

async function fetchError(res: Response): Promise<InstanceType<typeof import('../../src/core/pro-scanner.js').ProFetchError>> {
  globalThis.fetch = vi.fn().mockResolvedValue(res)
  const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
  const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
  expect(err).toBeInstanceOf(ProFetchError)
  return err
}

describe('platform-unavailable-20261018 — fetchProRules maps the platform-unavailable 503', () => {
  let originalFetch: typeof globalThis.fetch
  beforeEach(() => { originalFetch = globalThis.fetch })
  afterEach(() => { globalThis.fetch = originalFetch; vi.clearAllMocks() })

  it('503 + code PLATFORM_UNAVAILABLE + Retry-After: 300 → code PLATFORM_UNAVAILABLE, retryAfterSeconds 300', async () => {
    const err = await fetchError(response(503, PLATFORM_BODY, {
      'Retry-After': '300',
      'X-Platform-Status': 'unavailable',
    }))
    expect(err.code).toBe('PLATFORM_UNAVAILABLE')
    expect(err.retryAfterSeconds).toBe(300)
    expect(err.message).toMatch(/temporarily unavailable/i)
  })

  it('PLATFORM_UNAVAILABLE without a Retry-After header → retryAfterSeconds undefined (never NaN)', async () => {
    const err = await fetchError(response(503, PLATFORM_BODY, { 'X-Platform-Status': 'unavailable' }))
    expect(err.code).toBe('PLATFORM_UNAVAILABLE')
    expect(err.retryAfterSeconds).toBeUndefined()
  })

  it('PLATFORM_UNAVAILABLE with an unparsable Retry-After → retryAfterSeconds undefined (never NaN)', async () => {
    const err = await fetchError(response(503, PLATFORM_BODY, { 'Retry-After': 'soon' }))
    expect(err.code).toBe('PLATFORM_UNAVAILABLE')
    expect(err.retryAfterSeconds).toBeUndefined()
  })

  it('is detected by the body code on any status (status-agnostic, like NO_ACTIVE_RELEASE)', async () => {
    const err = await fetchError(response(500, PLATFORM_BODY, { 'Retry-After': '60' }))
    expect(err.code).toBe('PLATFORM_UNAVAILABLE')
    expect(err.retryAfterSeconds).toBe(60)
  })

  it('503 with the X-Platform-Status: unavailable header but an unreadable body → still PLATFORM_UNAVAILABLE', async () => {
    const err = await fetchError(response(503, undefined, {
      'Retry-After': '300',
      'X-Platform-Status': 'unavailable',
    }))
    expect(err.code).toBe('PLATFORM_UNAVAILABLE')
    expect(err.retryAfterSeconds).toBe(300)
  })

  it('OTHER 503s are unchanged: a plain 503 → SERVER_ERROR', async () => {
    const err = await fetchError(response(503, { error: 'down for maintenance' }))
    expect(err.code).toBe('SERVER_ERROR')
  })

  it('OTHER 503s are unchanged: a 503 with only a Retry-After header (no code, no platform header) → SERVER_ERROR', async () => {
    const err = await fetchError(response(503, { error: 'busy' }, { 'Retry-After': '30' }))
    expect(err.code).toBe('SERVER_ERROR')
  })

  it('NO_ACTIVE_RELEASE on a 503 still wins its own code (unchanged)', async () => {
    const err = await fetchError(response(503, { error: 'none', code: 'NO_ACTIVE_RELEASE' }))
    expect(err.code).toBe('NO_ACTIVE_RELEASE')
  })

  it('429 RATE_LIMITED still parses Retry-After exactly as before', async () => {
    const err = await fetchError(response(429, { error: 'slow' }, { 'Retry-After': '42' }))
    expect(err.code).toBe('RATE_LIMITED')
    expect(err.retryAfterSeconds).toBe(42)
  })
})
