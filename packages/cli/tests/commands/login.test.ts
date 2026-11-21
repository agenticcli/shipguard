import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('../../src/core/auth.js', () => ({
  saveCredentials: vi.fn(),
  clearCredentials: vi.fn(),
}))
const planRead = vi.hoisted(() => vi.fn())
vi.mock('../../src/core/plan-client.js', async (orig) => ({
  ...(await orig<typeof import('../../src/core/plan-client.js')>()),
  readPlanFresh: planRead,
  forgetAccountState: vi.fn(),
}))
const lifecycle = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
vi.mock('../../src/core/telemetry.js', async (orig) => ({
  ...(await orig<typeof import('../../src/core/telemetry.js')>()),
  sendLifecycleEvent: lifecycle,
}))

const { loginCommand } = await import('../../src/commands/login.js')
const { logger } = await import('../../src/utils/logger.js')

const START = { ok: true, json: async () => ({ device_code: 'dc', user_code: 'ABCD-1234', verification_uri: 'https://agenticcli.dev/activate', expires_in: 300, interval: 1 }) }
const APPROVED = { ok: true, json: async () => ({ access_token: 'tok_xyz', refresh_token: 'ref_abc', expires_in: 900 }) }
const unavailable = { signIn: 'signed-in', plan: { status: 'unavailable', reason: 'NOT_FETCHED', command: 'shipguard upgrade', link: null, server: null }, acct: null, accountStatus: null, failure: null }

let errors: string[]
beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  process.exitCode = undefined
  errors = []
  vi.spyOn(logger, 'error').mockImplementation((m: string) => void errors.push(String(m)))
  vi.spyOn(logger, 'info').mockImplementation(() => {})
  vi.spyOn(logger, 'success').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  planRead.mockResolvedValue(unavailable)
})
afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  process.exitCode = undefined
})

async function run(fetchMock: ReturnType<typeof vi.fn>): Promise<void> {
  global.fetch = fetchMock as unknown as typeof fetch
  const p = loginCommand().parseAsync(['node', 'login'])
  await vi.runAllTimersAsync()
  await p
}

describe('loginCommand', () => {
  it('saves credentials after approval and checks the account service before saying signed in', async () => {
    const { saveCredentials } = await import('../../src/core/auth.js')
    await run(vi.fn().mockResolvedValueOnce(START).mockResolvedValueOnce(APPROVED))
    expect(saveCredentials).toHaveBeenCalledOnce()
    expect(planRead).toHaveBeenCalledOnce()
    expect(lifecycle).toHaveBeenCalledOnce()
    expect(process.exitCode).toBeUndefined()
  })

  it('a refused approval is LOGIN_CONFIRM_FAILED (exit 3), never "timed out"', async () => {
    await run(vi.fn().mockResolvedValueOnce(START).mockResolvedValueOnce({ ok: false, status: 400, json: async () => ({ error: 'access_denied' }) }))
    expect(process.exitCode).toBe(3)
    expect(errors.join('\n')).toContain('LOGIN_CONFIRM_FAILED')
    expect(errors.join('\n')).not.toMatch(/timed out/i)
    expect(lifecycle).not.toHaveBeenCalled()
  })

  it('a network error while polling is LOGIN_CONFIRM_FAILED, not a timeout', async () => {
    await run(vi.fn().mockResolvedValueOnce(START).mockRejectedValue(new Error('socket hang up')))
    expect(process.exitCode).toBe(3)
    expect(errors.join('\n')).toContain('LOGIN_CONFIRM_FAILED')
  })

  it('expired_token: LOGIN_EXPIRED, exit 3, with the new-sign-in fix', async () => {
    await run(vi.fn().mockResolvedValueOnce(START).mockResolvedValueOnce({ ok: false, json: async () => ({ error: 'expired_token' }) }))
    expect(process.exitCode).toBe(3)
    expect(errors.join('\n')).toContain('LOGIN_EXPIRED')
  })

  it('never approved: one FINAL poll after the deadline, then LOGIN_EXPIRED', async () => {
    const f = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => ({ device_code: 'd', user_code: 'A', verification_uri: 'https://agenticcli.dev/activate', expires_in: 7, interval: 5 }) })
      .mockResolvedValue({ ok: false, json: async () => ({ error: 'authorization_pending' }) })
    await run(f)
    expect(process.exitCode).toBe(3)
    expect(errors.join('\n')).toContain('LOGIN_EXPIRED')
    expect(f.mock.calls.length).toBeGreaterThanOrEqual(3) // start + at least 2 polls (the last one at the deadline)
  })

  it('approval that lands on the last poll before the deadline is a success, not a timeout (fail-before/pass-after)', async () => {
    const { saveCredentials } = await import('../../src/core/auth.js')
    const f = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => ({ device_code: 'd', user_code: 'A', verification_uri: 'https://agenticcli.dev/activate', expires_in: 7, interval: 5 }) })
      .mockResolvedValueOnce({ ok: false, json: async () => ({ error: 'authorization_pending' }) })
      .mockResolvedValueOnce(APPROVED)
    await run(f)
    expect(saveCredentials).toHaveBeenCalledOnce()
    expect(errors.join('\n')).not.toMatch(/timed out|LOGIN_EXPIRED/)
  })

  it('the account service refusing the new sign-in is LOGIN_CONFIRM_FAILED', async () => {
    planRead.mockResolvedValue({ ...unavailable, signIn: 'expired', authRejected: true })
    await run(vi.fn().mockResolvedValueOnce(START).mockResolvedValueOnce(APPROVED))
    expect(process.exitCode).toBe(3)
    expect(errors.join('\n')).toContain('LOGIN_CONFIRM_FAILED')
  })

  it('cannot start: LOGIN_START_FAILED, exit 3', async () => {
    await run(vi.fn().mockRejectedValue(new Error('getaddrinfo ENOTFOUND')))
    expect(process.exitCode).toBe(3)
    expect(errors.join('\n')).toContain('LOGIN_START_FAILED')
  })
})
