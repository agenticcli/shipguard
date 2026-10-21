import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/core/auth.js', () => ({
  saveCredentials: vi.fn(),
  clearCredentials: vi.fn(),
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
