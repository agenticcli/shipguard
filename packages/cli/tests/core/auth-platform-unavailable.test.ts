/**
 * the platform-unavailable 503 can land on the
 * AUTH calls too: the token refresh (most human scans, once the 15-minute access token expired)
 * and the SHIPGUARD_API_KEY exchange (CI). Before: the refresh returned null and the exchange threw a
 * generic error, so the user saw "Run `shipguard login` first" / "exchange failed (503)" for an
 * outage on OUR side. Now both throw PlatformUnavailableError, and fetchProRules re-wraps it as the
 * same ProFetchError PLATFORM_UNAVAILABLE the rules fetch itself uses.
 *
 * Network is mocked; no real server.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const TEST_HOME = join(tmpdir(), 'shipguard-auth-platform-' + process.pid)

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>()
  return { ...actual, homedir: () => TEST_HOME }
})

const { saveCredentials, getAuthToken } = await import('../../src/core/auth.js')
const { PlatformUnavailableError } = await import('../../src/core/platform-status.js')

const API_URL = 'https://agenticcli.dev'
const EXPIRED_CREDS = {
  accessToken: 'tok_expired',
  refreshToken: 'ref_xyz',
  expiresAt: Date.now() - 3_600_000,
  apiUrl: API_URL,
}
const PLATFORM_BODY = { error: 'Service temporarily unavailable. Please try again later.', code: 'PLATFORM_UNAVAILABLE' }

function response(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  const res = {
    status,
    ok: status >= 200 && status < 300,
    statusText: `HTTP ${status}`,
    headers: { get: (name: string) => headers[name] ?? null },
    json: async () => {
      if (body === undefined) throw new SyntaxError('Unexpected end of JSON input')
      return body
    },
    text: async () => JSON.stringify(body),
    clone: () => res,
  }
  return res as unknown as Response
}

let errSpy: ReturnType<typeof vi.spyOn>
const realFetch = globalThis.fetch

beforeEach(() => {
  mkdirSync(TEST_HOME, { recursive: true })
  delete process.env.SHIPGUARD_API_KEY
  errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  rmSync(TEST_HOME, { recursive: true, force: true })
  errSpy.mockRestore()
  globalThis.fetch = realFetch
})

describe('getAuthToken — token refresh meets the platform-unavailable 503', () => {
  it('throws PlatformUnavailableError with the suggested wait instead of returning null', async () => {
    await saveCredentials(EXPIRED_CREDS)
    globalThis.fetch = vi.fn().mockResolvedValue(
      response(503, PLATFORM_BODY, { 'Retry-After': '300', 'X-Platform-Status': 'unavailable' }),
    ) as never
    const err = await getAuthToken(API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(PlatformUnavailableError)
    expect(err.code).toBe('PLATFORM_UNAVAILABLE')
    expect(err.retryAfterSeconds).toBe(300)
    expect(err.message).toBe(PLATFORM_BODY.error)
  })

  it('recognises the X-Platform-Status header on a 503 with an unreadable body', async () => {
    await saveCredentials(EXPIRED_CREDS)
    globalThis.fetch = vi.fn().mockResolvedValue(response(503, undefined, { 'X-Platform-Status': 'unavailable' })) as never
    const err = await getAuthToken(API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(PlatformUnavailableError)
    expect(err.retryAfterSeconds).toBeUndefined()
  })

  it('a plain 503 (no code, no header) still means "log in again" (returns null, unchanged)', async () => {
    await saveCredentials(EXPIRED_CREDS)
    globalThis.fetch = vi.fn().mockResolvedValue(response(503, { error: 'boom' })) as never
    expect(await getAuthToken(API_URL)).toBeNull()
  })

  it('a 401 refusal still returns null (unchanged)', async () => {
    await saveCredentials(EXPIRED_CREDS)
    globalThis.fetch = vi.fn().mockResolvedValue(response(401, { error: 'invalid_grant' })) as never
    expect(await getAuthToken(API_URL)).toBeNull()
  })
})

describe('getAuthToken — SHIPGUARD_API_KEY exchange meets the platform-unavailable 503', () => {
  it('throws PlatformUnavailableError, not the generic "exchange failed (503)"', async () => {
    process.env.SHIPGUARD_API_KEY = 'sg_live_test_key_0123456789'
    globalThis.fetch = vi.fn().mockResolvedValue(response(503, PLATFORM_BODY, { 'Retry-After': '600' })) as never
    const err = await getAuthToken(API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(PlatformUnavailableError)
    expect(err.retryAfterSeconds).toBe(600)
  })

  it('a 503 without the code or header is still the generic exchange error (unchanged)', async () => {
    process.env.SHIPGUARD_API_KEY = 'sg_live_test_key_0123456789'
    globalThis.fetch = vi.fn().mockResolvedValue(response(503, { error: 'server_error' })) as never
    const err = await getAuthToken(API_URL).catch((e) => e)
    expect(err).not.toBeInstanceOf(PlatformUnavailableError)
    expect(String(err.message)).toMatch(/exchange failed \(503\)/)
  })
})

describe('fetchProRules — a platform-unavailable auth failure is the same stable class', () => {
  it('re-wraps PlatformUnavailableError from the auth layer as ProFetchError PLATFORM_UNAVAILABLE with the wait', async () => {
    await saveCredentials(EXPIRED_CREDS)
    globalThis.fetch = vi.fn().mockResolvedValue(
      response(503, PLATFORM_BODY, { 'Retry-After': '300', 'X-Platform-Status': 'unavailable' }),
    ) as never
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect(err.code).toBe('PLATFORM_UNAVAILABLE')
    expect(err.retryAfterSeconds).toBe(300)
    expect(err.message).not.toMatch(/shipguard login/)
  })
})
