import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/core/auth.js', () => ({
  saveCredentials: vi.fn(),
  clearCredentials: vi.fn(),
}))

const lifecycle = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
vi.mock('../../src/core/telemetry.js', async (orig) => ({
  ...(await orig<typeof import('../../src/core/telemetry.js')>()),
  sendLifecycleEvent: lifecycle,
}))

const { loginCommand } = await import('../../src/commands/login.js')

describe('loginCommand', () => {
  beforeEach(() => vi.clearAllMocks())

  it('saves credentials on successful device auth flow', async () => {
    const { saveCredentials } = await import('../../src/core/auth.js')
    global.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          device_code: 'dc_123',
          user_code: 'ABCD-1234',
          verification_uri: 'https://agenticcli.dev/activate',
          expires_in: 300,
          interval: 1,
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'tok_xyz',
          refresh_token: 'ref_abc',
          expires_in: 900,
        }),
      }) as unknown as typeof fetch

    await loginCommand().parseAsync(['node', 'login'])
    expect(saveCredentials).toHaveBeenCalledOnce()
    expect(lifecycle).toHaveBeenCalledOnce()
    expect(lifecycle.mock.calls[0][0]).toBe('cli_login')
  })

  it('does not send cli_login when auth fails', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ device_code: 'd', user_code: 'A', verification_uri: 'https://agenticcli.dev/activate', expires_in: 300, interval: 1 }) })
      .mockResolvedValueOnce({ ok: false, json: async () => ({ error: 'access_denied' }) }) as unknown as typeof fetch
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => { throw new Error('exit') }) as never)
    await expect(loginCommand().parseAsync(['node', 'login'])).rejects.toThrow('exit')
    expect(lifecycle).not.toHaveBeenCalled()
    exit.mockRestore()
  })

  it('fallback message points to /auth/device when the server URL is untrusted', async () => {
    const { logger } = await import('../../src/utils/logger.js')
    const info = vi.spyOn(logger, 'info').mockImplementation(() => {})
    vi.spyOn(logger, 'warn').mockImplementation(() => {})
    global.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          device_code: 'dc_123',
          user_code: 'ABCD-1234',
          verification_uri: 'https://evil.example/activate',
          expires_in: 300,
          interval: 1,
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 't', refresh_token: 'r', expires_in: 900 }),
      }) as unknown as typeof fetch

    await loginCommand().parseAsync(['node', 'login'])
    const msgs = info.mock.calls.map(c => String(c[0]))
    expect(msgs.some(m => m.includes('/auth/device in your browser'))).toBe(true)
    expect(msgs.some(m => m.includes('/activate'))).toBe(false)
  })
})
