/**
 * fetchProRules failure classification.
 *
 * RCA: previously EVERY pro-fetch failure (auth, 402, 409, 429, 5xx, network,
 * malformed bundle) threw a plain, undifferentiated `Error`. scan.ts's catch
 * block could not distinguish "you're not authenticated" from "the server is
 * down" from "the bundle was cryptographically invalid" — it collapsed all of
 * them into a single generic warning and silently degraded to a free scan.
 *
 * FIX: fetchProRules now throws a typed `ProFetchError` carrying a distinct,
 * stable `code` per failure class (AUTH_FAILED / INSUFFICIENT_CREDITS /
 * RATE_LIMITED / SERVER_ERROR / BUNDLE_INVALID), so scan.ts can classify the
 * failure and decide fail-loud vs (opt-in) degrade with actual information.
 *
 * Network is mocked; no real server. Pattern follows pro-scanner-no-rules.test.ts.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// Declared outside the factory so individual tests can override the resolved
// value (e.g. `mockResolvedValueOnce(null)` for the no-token case) without the
// resetModules/doMock/doUnmock dance — vi.mock factories run once per module
// graph, so a shared mock function reference lets every test control it directly.
const mockGetAuthToken = vi.fn().mockResolvedValue('test-token')
vi.mock('../../src/core/auth.js', () => ({
  getAuthToken: mockGetAuthToken,
}))

const API_URL = 'http://localhost:3000' // trusted host (assertTrustedApiUrl allows localhost)

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: `HTTP ${status}`,
    headers: { get: (name: string) => headers[name] ?? null },
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response
}

describe('fetchProRules classifies every failure class via ProFetchError', () => {
  let originalFetch: typeof globalThis.fetch
  beforeEach(() => { originalFetch = globalThis.fetch })
  afterEach(() => { globalThis.fetch = originalFetch; vi.clearAllMocks() })

  it('401 → ProFetchError AUTH_FAILED', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse(401, { error: 'expired' }))
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('AUTH_FAILED')
  })

  it('no auth token at all → ProFetchError AUTH_FAILED (never reaches the network)', async () => {
    mockGetAuthToken.mockResolvedValueOnce(null)
    globalThis.fetch = vi.fn() // must not be called
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('AUTH_FAILED')
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('402 → ProFetchError INSUFFICIENT_CREDITS', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse(402, { error: 'no credits' }))
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('INSUFFICIENT_CREDITS')
  })

  it('429 → ProFetchError RATE_LIMITED, retryAfterSeconds parsed from Retry-After header', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse(429, { error: 'slow down' }, { 'Retry-After': '42' }),
    )
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    const typed = err as InstanceType<typeof ProFetchError>
    expect(typed.code).toBe('RATE_LIMITED')
    expect(typed.retryAfterSeconds).toBe(42)
  })

  it('429 without a Retry-After header → RATE_LIMITED with retryAfterSeconds undefined', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse(429, { error: 'slow down' }))
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    const typed = err as InstanceType<typeof ProFetchError>
    expect(typed.code).toBe('RATE_LIMITED')
    expect(typed.retryAfterSeconds).toBeUndefined()
  })

  it('409 (scanId conflict) → ProFetchError SERVER_ERROR (transient, retry with a fresh scanId)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse(409, { error: 'scanId reused' }))
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('SERVER_ERROR')
  })

  it('500/503 → ProFetchError SERVER_ERROR', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse(503, { error: 'down for maintenance' }))
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('SERVER_ERROR')
  })

  it('a rejected fetch() (network/DNS/timeout failure) → ProFetchError SERVER_ERROR, never silently swallowed', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('SERVER_ERROR')
    expect((err as Error).message).toMatch(/ECONNREFUSED/)
  })

  it('422 WITHOUT NO_RULES_APPLIED code → ProFetchError BUNDLE_INVALID (distinct from the hard error)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse(422, { error: 'some other validation issue' }))
    const { fetchProRules, ProFetchError, NoRulesAppliedError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect(err).not.toBeInstanceOf(NoRulesAppliedError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('BUNDLE_INVALID')
  })

  it('422 WITH NO_RULES_APPLIED code → still NoRulesAppliedError, NOT a ProFetchError', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse(422, { error: 'empty bundle', code: 'NO_RULES_APPLIED' }),
    )
    const { fetchProRules, ProFetchError, NoRulesAppliedError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(NoRulesAppliedError)
    expect(err).not.toBeInstanceOf(ProFetchError)
  })

  it('duplicate-key/malformed JSON response → ProFetchError BUNDLE_INVALID', async () => {
    // A raw text body with a duplicate key — parseStrictNoDup rejects it.
    const dupKeyBody = '{"fullManifest": 1, "fullManifest": 2}'
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      statusText: 'OK',
      headers: { get: () => null },
      json: async () => JSON.parse(dupKeyBody),
      text: async () => dupKeyBody,
    } as unknown as Response)
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('BUNDLE_INVALID')
  })

  // NO_ACTIVE_RELEASE mapping. Root cause: the rules backend
  // throws a structured NO_ACTIVE_RELEASE error when no rule
  // release has ever been activated. Before this fix, fetchProRules only recognized 5 codes
  // (AUTH_FAILED/INSUFFICIENT_CREDITS/RATE_LIMITED/SERVER_ERROR/BUNDLE_INVALID); an unrecognized
  // code like NO_ACTIVE_RELEASE silently bucketed into SERVER_ERROR — indistinguishable from a
  // transient outage, and with --allow-degraded set, silently downgraded to a green free scan.
  // A real launch-day outage (2026-07-19+, no release ever activated) was therefore completely
  // invisible. Detection is STATUS-AGNOSTIC (keyed on the JSON body's `code` field only) because
  // the platform team owns which HTTP status this maps to; the CLI must recognize the code no
  // matter which status carries it.
  it('NO_ACTIVE_RELEASE code on a 503 → ProFetchError NO_ACTIVE_RELEASE, not SERVER_ERROR (status-agnostic detection)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse(503, { error: 'no active release', code: 'NO_ACTIVE_RELEASE' }),
    )
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('NO_ACTIVE_RELEASE')
    expect((err as Error).message).toMatch(/no active release/)
  })

  it('NO_ACTIVE_RELEASE code on a 409 → still ProFetchError NO_ACTIVE_RELEASE (not SERVER_ERROR from the 409 branch)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse(409, { error: 'no active release', code: 'NO_ACTIVE_RELEASE' }),
    )
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('NO_ACTIVE_RELEASE')
  })

  it('legacy bundle (no fullManifest) → ProFetchError BUNDLE_INVALID, message still mentions legacy-bundle-rejected', async () => {
    const legacyBody = JSON.stringify({ signedBundle: 'irrelevant-legacy-shape' })
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      statusText: 'OK',
      headers: { get: () => null },
      json: async () => JSON.parse(legacyBody),
      text: async () => legacyBody,
    } as unknown as Response)
    const { fetchProRules, ProFetchError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(ProFetchError)
    expect((err as InstanceType<typeof ProFetchError>).code).toBe('BUNDLE_INVALID')
    expect((err as Error).message).toMatch(/legacy-bundle-rejected/)
  })
})
