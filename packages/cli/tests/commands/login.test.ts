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
})
