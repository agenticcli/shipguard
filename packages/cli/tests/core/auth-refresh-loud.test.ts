/**
 * auth-refresh-loud.test.ts — a failed token refresh must say WHY.
 *
 *  *
 * `getAuthToken`'s refresh branch ended in a bare `} catch { }` and its `if (res.ok)` had no
 * `else`. Four completely different situations therefore produced one identical, silent
 * outcome — "please log in again":
 *   - the refresh token was revoked (server says 401)
 *   - the server was down (503)
 *   - the stored apiUrl failed the trust pin
 *   - the laptop was offline
 * A user (or an agent) had no way to tell "your session ended" from "the service is down",
 * and re-logging in only fixes the first. every catch logs.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const TEST_HOME = join(tmpdir(), 'shipguard-refresh-loud-' + process.pid)

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>()
  return { ...actual, homedir: () => TEST_HOME }
})

const { saveCredentials, getAuthToken } = await import('../../src/core/auth.js')

/** Credentials whose access token expired an hour ago — forces the refresh branch. */
const EXPIRED_CREDS = {
  accessToken: 'tok_expired',
  refreshToken: 'ref_xyz',
  expiresAt: Date.now() - 3_600_000,
  apiUrl: 'https://agenticcli.dev',
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

describe('getAuthToken — refresh failures are loud, not silent', () => {
  it('keeps the thrown reason when the refresh request itself throws (retried, then a wait message; issue #4)', async () => {
    vi.useFakeTimers()
    await saveCredentials(EXPIRED_CREDS)
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('getaddrinfo ENOTFOUND agenticcli.dev')) as never

    const p = getAuthToken('https://agenticcli.dev').catch((e) => e)
    await vi.advanceTimersByTimeAsync(10_000)
    const err = await p
    vi.useRealTimers()

    expect(err.name).toBe('RefreshUnavailableError') // not null: the caller must not prompt re-login
    expect(err.message).toMatch(/ENOTFOUND/) // the actual reason survives to the user
  })

  it('logs the status when the server REFUSES the refresh (non-2xx)', async () => {
    await saveCredentials(EXPIRED_CREDS)
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
    }) as never

    const token = await getAuthToken('https://agenticcli.dev')

    expect(token).toBeNull()
    const logged = errSpy.mock.calls.map((c) => String(c[0])).join('\n')
    expect(logged).toMatch(/Token refresh refused/)
    expect(logged).toMatch(/401/)
  })

  it('distinguishes a refusal from an outage — the two messages differ', async () => {
    await saveCredentials(EXPIRED_CREDS)
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 401, statusText: 'Unauthorized' }) as never
    await getAuthToken('https://agenticcli.dev')
    const refused = errSpy.mock.calls.map((c) => String(c[0])).join('\n')
    errSpy.mockClear()

    vi.useFakeTimers()
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('socket hang up')) as never
    const p = getAuthToken('https://agenticcli.dev').catch((e) => e)
    await vi.advanceTimersByTimeAsync(10_000)
    const threw = String((await p).message)
    vi.useRealTimers()

    expect(refused).not.toBe(threw)
    expect(refused).toMatch(/401/)
    expect(threw).toMatch(/socket hang up/)
  })

  it('logs when the stored apiUrl fails the trust pin, instead of failing silently', async () => {
    // The scheme pin (routed row 13) throws from inside the try — previously invisible.
    await saveCredentials({ ...EXPIRED_CREDS, apiUrl: 'http://agenticcli.dev' })
    globalThis.fetch = vi.fn() as never

    const token = await getAuthToken('https://agenticcli.dev')

    expect(token).toBeNull()
    const logged = errSpy.mock.calls.map((c) => String(c[0])).join('\n')
    expect(logged).toMatch(/Token refresh failed/)
    expect(logged).toMatch(/scheme/i)
    expect(globalThis.fetch).not.toHaveBeenCalled() // no token ever left the machine
  })

  it('still succeeds silently on a healthy refresh — no noise on the happy path', async () => {
    await saveCredentials(EXPIRED_CREDS)
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ access_token: 'tok_fresh', refresh_token: 'ref_new', expires_in: 900 }),
    }) as never

    const token = await getAuthToken('https://agenticcli.dev')

    expect(token).toBe('tok_fresh')
    expect(errSpy).not.toHaveBeenCalled()
  })
})
