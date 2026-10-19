/**
 * `shipguard login` sends the anonymous `cli_login` event only after the credentials are saved,
 * and never on a failed, denied or timed-out login. (The sender and its opt-outs: tests/core/telemetry-events.test.ts.)
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../src/core/auth.js', () => ({
  saveCredentials: vi.fn(),
  clearCredentials: vi.fn(),
}))
vi.mock('../../src/core/telemetry-events.js', () => ({
  sendLifecycleEvent: vi.fn().mockResolvedValue(undefined),
}))

const { loginCommand } = await import('../../src/commands/login.js')
const { saveCredentials } = await import('../../src/core/auth.js')
const { sendLifecycleEvent } = await import('../../src/core/telemetry-events.js')

const DEVICE = {
  ok: true,
  json: async () => ({
    device_code: 'dc_123',
    user_code: 'ABCD-1234',
    verification_uri: 'https://agenticcli.dev/activate',
    expires_in: 300,
    interval: 0,
  }),
}

describe('login -> cli_login', () => {
  beforeEach(() => vi.clearAllMocks())

  it('sends cli_login once, after saveCredentials, with no account data', async () => {
    const order: string[] = []
    vi.mocked(saveCredentials).mockImplementation(async () => {
      order.push('save')
    })
    vi.mocked(sendLifecycleEvent).mockImplementation(async () => {
      order.push('event')
    })
    global.fetch = vi
      .fn()
      .mockResolvedValueOnce(DEVICE)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'tok_SECRET', refresh_token: 'ref_SECRET', expires_in: 900 }),
      }) as unknown as typeof fetch

    await loginCommand().parseAsync(['node', 'login'])

    expect(order).toEqual(['save', 'event'])
    expect(sendLifecycleEvent).toHaveBeenCalledOnce()
    const [event, input, opts] = vi.mocked(sendLifecycleEvent).mock.calls[0]
    expect(event).toBe('cli_login')
    expect(Object.keys(input)).toEqual(['cliVersion'])
    expect(JSON.stringify([input, opts])).not.toMatch(/SECRET|agenticcli\.dev|dc_123|ABCD/)
  })

  it('sends nothing when the login is denied', async () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('exit')
    }) as never)
    global.fetch = vi
      .fn()
      .mockResolvedValueOnce(DEVICE)
      .mockResolvedValueOnce({ ok: false, json: async () => ({ error: 'access_denied' }) }) as unknown as typeof fetch
    await expect(loginCommand().parseAsync(['node', 'login'])).rejects.toThrow('exit')
    expect(saveCredentials).not.toHaveBeenCalled()
    expect(sendLifecycleEvent).not.toHaveBeenCalled()
    exit.mockRestore()
  })

  it('sends nothing when the device flow cannot start', async () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('exit')
    }) as never)
    global.fetch = vi.fn().mockResolvedValueOnce({ ok: false }) as unknown as typeof fetch
    await expect(loginCommand().parseAsync(['node', 'login'])).rejects.toThrow('exit')
    expect(sendLifecycleEvent).not.toHaveBeenCalled()
    exit.mockRestore()
  })

  it('a rejecting sender can never fail a successful login', async () => {
    vi.mocked(sendLifecycleEvent).mockRejectedValue(new Error('boom'))
    global.fetch = vi
      .fn()
      .mockResolvedValueOnce(DEVICE)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'a', refresh_token: 'r', expires_in: 900 }),
      }) as unknown as typeof fetch
    await expect(loginCommand().parseAsync(['node', 'login'])).resolves.toBeDefined()
    expect(saveCredentials).toHaveBeenCalledOnce()
  })
})
