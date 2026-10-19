/**
 * C2 regression: `shipguard feedback` used to POST free text to {apiUrl}/api/feedback, a route that
 * does not exist on prod (404), after a login round-trip. It is now a no-network command that
 * points at the public GitHub issues page. Fail-before: the command called getAuthToken/fetch and,
 * when logged out, printed "Not authenticated" instead of the issues URL.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const getAuthToken = vi.fn()
vi.mock('../../src/core/auth.js', () => ({
  getAuthToken: (...a: unknown[]) => getAuthToken(...a),
  loadCredentials: vi.fn(() => ({ apiUrl: 'https://agenticcli.dev' })),
}))

const { feedbackCommand } = await import('../../src/commands/feedback.js')

const ISSUES = 'https://github.com/agenticcli/shipguard/issues'
let out: string[]
let err: string[]
const realFetch = globalThis.fetch

beforeEach(() => {
  out = []
  err = []
  vi.spyOn(console, 'log').mockImplementation((...a) => void out.push(a.join(' ')))
  vi.spyOn(console, 'error').mockImplementation((...a) => void err.push(a.join(' ')))
  globalThis.fetch = vi.fn() as unknown as typeof fetch
})
afterEach(() => {
  globalThis.fetch = realFetch
  vi.restoreAllMocks()
  getAuthToken.mockReset()
})

describe('shipguard feedback makes no network call', () => {
  it('prints the GitHub issues URL, never fetches, never authenticates', async () => {
    await feedbackCommand().parseAsync(['node', 'feedback', 'the scan missed my .env'])
    expect(globalThis.fetch).not.toHaveBeenCalled()
    expect(getAuthToken).not.toHaveBeenCalled()
    expect([...out, ...err].join('\n')).toContain(ISSUES)
  })

  it('does not echo the free text anywhere it could be mistaken for being sent', async () => {
    await feedbackCommand().parseAsync(['node', 'feedback', 'secret-ish words'])
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('works with no text argument too', async () => {
    await feedbackCommand().parseAsync(['node', 'feedback'])
    expect(globalThis.fetch).not.toHaveBeenCalled()
    expect([...out, ...err].join('\n')).toContain(ISSUES)
  })
})
