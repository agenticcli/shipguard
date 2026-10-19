/**
 * pro-scanner-no-rules.test.ts
 *
 * P0-5 (CLI half) — a server fail-closed empty-bundle response (HTTP 422, code NO_RULES_APPLIED)
 * must surface as a HARD, NON-DEGRADABLE error (NoRulesAppliedError), NOT a transient failure the
 * scan command degrades past into a green free scan.
 *
 * THREAT (§11.1): the server refuses to sign an empty Pro bundle (it would be a signed "clean
 * pass" over zero rules). BEFORE: the route laundered this into a generic 503, fetchProRules
 * threw a plain "Rule fetch failed", and scan.ts caught it, logged "Degrading to free scan", set
 * degraded=true → exit 2, and could still report SAFE_TO_SHIP — the precise silent false-green
 * §11.1 forbids. AFTER: the route returns 422 {code:NO_RULES_APPLIED}; fetchProRules throws a
 * typed NoRulesAppliedError; scan.ts maps it to exit 3 and suppresses the free-rule fallback.
 *
 * Fail-before/pass-after:
 *   - a 422 NO_RULES_APPLIED response → fetchProRules throws NoRulesAppliedError (typed, code-bearing).
 *   - a 503 (genuine transient outage) → a plain Error (which legitimately degrades) — distinct.
 *
 * Network is mocked; no real server.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// getAuthToken must return a token so we reach the fetch + status handling.
vi.mock('../../src/core/auth.js', () => ({
  getAuthToken: vi.fn().mockResolvedValue('test-token'),
}))

const API_URL = 'http://localhost:3000' // a trusted host (assertTrustedApiUrl allows localhost)

function jsonResponse(status: number, body: unknown): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: `HTTP ${status}`,
    headers: { get: () => null },
    json: async () => body,
  } as unknown as Response
}

describe('P0-5 (CLI) — fetchProRules surfaces NO_RULES_APPLIED as a hard, non-degradable error', () => {
  let originalFetch: typeof globalThis.fetch
  beforeEach(() => { originalFetch = globalThis.fetch })
  afterEach(() => { globalThis.fetch = originalFetch; vi.clearAllMocks() })

  it('PASS-AFTER: a 422 NO_RULES_APPLIED response throws a typed NoRulesAppliedError (code-bearing)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse(422, { error: 'NO_PRO_RULES: refusing to sign an empty bundle', code: 'NO_RULES_APPLIED' }),
    )
    const { fetchProRules, NoRulesAppliedError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(NoRulesAppliedError)
    expect((err as { code?: string }).code).toBe('NO_RULES_APPLIED')
    expect((err as Error).name).toBe('NoRulesAppliedError')
  })

  it('a 503 transient outage throws a PLAIN Error (NOT NoRulesAppliedError) — this one may degrade', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse(503, { error: 'Failed to generate rule bundle' }))
    const { fetchProRules, NoRulesAppliedError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(Error)
    expect(err).not.toBeInstanceOf(NoRulesAppliedError)
  })

  it('a 422 WITHOUT the NO_RULES_APPLIED code is a generic 422 error (not the typed hard error)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse(422, { error: 'some other validation issue' }))
    const { fetchProRules, NoRulesAppliedError } = await import('../../src/core/pro-scanner.js')
    const err = await fetchProRules(['nextjs'], undefined, API_URL).catch((e) => e)
    expect(err).toBeInstanceOf(Error)
    expect(err).not.toBeInstanceOf(NoRulesAppliedError)
  })
})
