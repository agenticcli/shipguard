/**
 * platform-unavailable-20261018 — a response WITHOUT a (usable) `X-Credits-Remaining` header
 * means "balance unknown". It must never become NaN, and never be shown as a fake "0".
 * fetchProRules reports `creditsRemaining: undefined` in that case; scan.ts already skips the
 * "Credits remaining" line and the low-credits warning when it is undefined.
 *
 * Harness copied from wire-scanid-confidence.test.ts: real fetchProRules, mocked auth, mocked
 * fetch, mocked verifyBundleResponse (its crypto has its own tests).
 */

import { describe, it, expect, vi, afterEach } from 'vitest'

vi.mock('../../src/core/auth.js', () => ({
  getAuthToken: () => Promise.resolve('test-token'),
}))
vi.mock('../../src/core/release-verify.js', () => ({
  verifyBundleResponse: vi.fn(),
}))

const { verifyBundleResponse } = await import('../../src/core/release-verify.js')
const { fetchProRules } = await import('../../src/core/pro-scanner.js')

const ATTESTED_BODY = JSON.stringify({
  fullManifest: { rules: [] },
  corpusAttestation: {},
  freshnessTok: {},
  selectedRules: [],
  bundleEnvelope: {},
})

function installFetch(headers: Record<string, string>): void {
  vi.mocked(verifyBundleResponse).mockResolvedValue({ ok: true, selectedRules: [] as never })
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    headers: { get: (name: string) => headers[name] ?? null },
    text: () => Promise.resolve(ATTESTED_BODY),
    json: () => Promise.resolve(JSON.parse(ATTESTED_BODY)),
  }) as unknown as typeof fetch
}

const realFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = realFetch; vi.clearAllMocks() })

describe('platform-unavailable-20261018 — X-Credits-Remaining is optional', () => {
  it('header present → the number', async () => {
    installFetch({ 'X-Credits-Remaining': '7' })
    const out = await fetchProRules(['generic'], undefined, 'https://agenticcli.dev')
    expect(out.creditsRemaining).toBe(7)
  })

  it('header absent → creditsRemaining undefined (not 0, not NaN)', async () => {
    installFetch({})
    const out = await fetchProRules(['generic'], undefined, 'https://agenticcli.dev')
    expect(out.creditsRemaining).toBeUndefined()
  })

  it('header present but not a number → creditsRemaining undefined (not NaN)', async () => {
    installFetch({ 'X-Credits-Remaining': 'unknown' })
    const out = await fetchProRules(['generic'], undefined, 'https://agenticcli.dev')
    expect(out.creditsRemaining).toBeUndefined()
  })

  it('header present but empty → creditsRemaining undefined', async () => {
    installFetch({ 'X-Credits-Remaining': '' })
    const out = await fetchProRules(['generic'], undefined, 'https://agenticcli.dev')
    expect(out.creditsRemaining).toBeUndefined()
  })
})
