/**
 * auth-refresh-429.test.ts — issue #4: a 429 (or 5xx / network error) from the token refresh
 * must NOT mean "log in again". Retry with bounded backoff (honour Retry-After), keep the
 * stored credentials, then fail with a clear wait message (ProFetchError -> exit 3).
 * Only a 401 means the login is over. Network is mocked.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const TEST_HOME = join(tmpdir(), 'shipguard-refresh-429-' + process.pid)

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>()
  return { ...actual, homedir: () => TEST_HOME }
})

const { saveCredentials, getAuthToken, loadCredentials } = await import('../../src/core/auth.js')
const { fetchProRules } = await import('../../src/core/pro-scanner.js')

const API_URL = 'https://agenticcli.dev'
const EXPIRED = { accessToken: 'tok_expired', refreshToken: 'ref_xyz', expiresAt: Date.now() - 3_600_000, apiUrl: API_URL }

function response(status: number, body: unknown = {}, headers: Record<string, string> = {}): Response {
  const res = {
    status,
    ok: status >= 200 && status < 300,
    statusText: `HTTP ${status}`,
    headers: { get: (n: string) => headers[n] ?? null },
    json: async () => body,
    clone: () => res,
  }
  return res as unknown as Response
}
const OK = response(200, { access_token: 'tok_fresh', refresh_token: 'ref_new', expires_in: 900 })

const realFetch = globalThis.fetch
let errSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  vi.useFakeTimers()
  mkdirSync(TEST_HOME, { recursive: true })
  delete process.env.SHIPGUARD_API_KEY
  errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  vi.useRealTimers()
  rmSync(TEST_HOME, { recursive: true, force: true })
  errSpy.mockRestore()
  globalThis.fetch = realFetch
})

describe('token refresh — 429 / 5xx / network are retried, never "log in again"', () => {
  it('retries a 429 (Retry-After honoured) and then succeeds', async () => {
    await saveCredentials(EXPIRED)
    const f = vi.fn().mockResolvedValueOnce(response(429, {}, { 'Retry-After': '2' })).mockResolvedValueOnce(OK)
    globalThis.fetch = f as never
    const p = getAuthToken(API_URL)
    await vi.advanceTimersByTimeAsync(1_999)
    expect(f).toHaveBeenCalledTimes(1) // still waiting the 2 s the server asked for
    await vi.advanceTimersByTimeAsync(1)
    expect(await p).toBe('tok_fresh')
    expect(f).toHaveBeenCalledTimes(2)
  })

  it('after 3 tries of 429: fails with a wait message, keeps credentials, exit-3 class (RATE_LIMITED)', async () => {
    await saveCredentials(EXPIRED)
    const f = vi.fn().mockResolvedValue(response(429, {}, { 'Retry-After': '5' }))
    globalThis.fetch = f as never
    const p = fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    await vi.advanceTimersByTimeAsync(20_000)
    const err = await p
    expect(f).toHaveBeenCalledTimes(3)
    expect(err.name).toBe('ProFetchError')
    expect(err.code).toBe('RATE_LIMITED')
    expect(err.retryAfterSeconds).toBe(5)
    expect(err.message).toMatch(/try again in 5 s/)
    expect(err.message).not.toMatch(/shipguard login/)
    expect(loadCredentials()?.refreshToken).toBe('ref_xyz')
  })

  it('does not sleep on a Retry-After above the cap; reports it straight away', async () => {
    await saveCredentials(EXPIRED)
    const f = vi.fn().mockResolvedValue(response(429, {}, { 'Retry-After': '120' }))
    globalThis.fetch = f as never
    const err = await getAuthToken(API_URL).catch((e) => e)
    expect(f).toHaveBeenCalledTimes(1)
    expect(err.retryAfterSeconds).toBe(120)
    expect(err.message).toMatch(/try again in 120 s/)
  })

  it('retries a plain 503 and a network error the same way, never returning null', async () => {
    await saveCredentials(EXPIRED)
    const f = vi.fn().mockResolvedValueOnce(response(503)).mockRejectedValueOnce(new Error('socket hang up')).mockResolvedValueOnce(OK)
    globalThis.fetch = f as never
    const p = getAuthToken(API_URL)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(await p).toBe('tok_fresh')
    expect(f).toHaveBeenCalledTimes(3)
  })

  it('a 401 is still "log in again": no retry, returns null', async () => {
    await saveCredentials(EXPIRED)
    const f = vi.fn().mockResolvedValue(response(401, { error: 'invalid_grant' }))
    globalThis.fetch = f as never
    expect(await getAuthToken(API_URL)).toBeNull()
    expect(f).toHaveBeenCalledTimes(1)
  })
})
