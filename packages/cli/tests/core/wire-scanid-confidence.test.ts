/**
 * wire-scanid-confidence.test.ts — scanId idempotency + per-rule confidence
 *
 * ScanId idempotency (scanId idempotency — money bug):
 *   fetchProRules must send the CLI's stable scanId in the request BODY and as an
 *   Idempotency-Key HEADER on EVERY attempt (retries of the same scan reuse the same
 *   scanId). The server keys its credit reservation on (userId, scanId); before this
 *   fix the CLI sent no scanId from the scan command, the server minted a fresh UUID
 *   per request, and a dropped-response retry consumed a SECOND credit.
 *   FAIL-BEFORE: no Idempotency-Key header was sent (and scan.ts never passed scanId).
 *
 * Per-rule confidence (hardcoded confidence):
 *   The CLI mapped EVERY delivered pro rule to confidence: 'HIGH'
 *   (pro-scanner.ts, the ExecutableRule→QualityGateRule mapping), ignoring the
 *   per-rule confidence the corpus governance model (rule-corpus/rule-logic.md §4)
 *   calibrates action against.
 *   FAIL-BEFORE: a rule delivered with confidence MEDIUM/LOW surfaced as HIGH.
 *
 * Harness: real fetchProRules; mocked getAuthToken, mocked global fetch (captures the
 * outgoing request), mocked verifyBundleResponse (crypto verification has its own
 * suite — release-verify.test.ts — including the fail-closed missing-confidence tests).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// ---------------------------------------------------------------------------
// Mocks (hoisted)
// ---------------------------------------------------------------------------

vi.mock('../../src/core/auth.js', () => ({
  getAuthToken: () => Promise.resolve('test-token'),
}))

// verifyBundleResponse is mocked so we can hand fetchProRules a verified rule set
// with controlled confidence values. Its real behavior (including REQUIRING
// confidence on every rule, fail-closed) is covered by release-verify.test.ts.
vi.mock('../../src/core/release-verify.js', () => ({
  verifyBundleResponse: vi.fn(),
}))

const { verifyBundleResponse } = await import('../../src/core/release-verify.js')
const { fetchProRules } = await import('../../src/core/pro-scanner.js')

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal attested-shaped HTTP body — routes fetchProRules onto the attested path. */
const ATTESTED_BODY = JSON.stringify({
  fullManifest: { rules: [] },
  corpusAttestation: {},
  freshnessTok: {},
  selectedRules: [],
  bundleEnvelope: {},
})

function makeExecutableRule(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    confidence: 'HIGH',
    enabled: true,
    flags: '',
    framework: 'generic',
    id: 'test.rule.one',
    matcherType: 'pattern',
    pattern: 'x',
    severity: 'medium',
    tier: 'pro',
    title: 'Test rule',
    action: 'warn',
    blocking: false,
    fileGlob: '**/*',
    ...overrides,
  }
}

interface CapturedRequest {
  url: string
  headers: Record<string, string>
  body: Record<string, unknown>
}

const captured: CapturedRequest[] = []

function installCapturingFetch(): void {
  globalThis.fetch = vi.fn().mockImplementation(
    (url: string, init: { headers: Record<string, string>; body: string }) => {
      captured.push({
        url: String(url),
        headers: init.headers,
        body: JSON.parse(init.body) as Record<string, unknown>,
      })
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: {
          get: (name: string) =>
            name === 'X-Credits-Remaining' ? '7'
            : name === 'X-Rules-Version' ? 'test-release-1'
            : null,
        },
        text: () => Promise.resolve(ATTESTED_BODY),
        json: () => Promise.resolve(JSON.parse(ATTESTED_BODY)),
      })
    },
  ) as unknown as typeof fetch
}

const realFetch = globalThis.fetch

beforeEach(() => {
  captured.length = 0
  installCapturingFetch()
  vi.mocked(verifyBundleResponse).mockResolvedValue({
    ok: true,
    selectedRules: [makeExecutableRule()] as never,
  })
})

afterEach(() => {
  globalThis.fetch = realFetch
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// ScanId idempotency — scanId rides in body + Idempotency-Key header, stable across retries
// ---------------------------------------------------------------------------

describe('scanId idempotency — fetchProRules sends the stable scanId (body + Idempotency-Key header)', () => {
  const SCAN_ID = 'e0c9d3f2-1111-4222-8333-444455556666'

  it('sends scanId in the JSON body AND as the Idempotency-Key header', async () => {
    await fetchProRules(['generic'], undefined, 'https://agenticcli.dev', SCAN_ID)

    expect(captured).toHaveLength(1)
    // FAIL-BEFORE: the Idempotency-Key header did not exist.
    expect(captured[0].headers['Idempotency-Key']).toBe(SCAN_ID)
    expect(captured[0].body.scanId).toBe(SCAN_ID)
  })

  it('a retry of the SAME scan carries the SAME scanId in body and header (idempotent retry)', async () => {
    await fetchProRules(['generic'], undefined, 'https://agenticcli.dev', SCAN_ID)
    // Simulate the caller retrying the same logical scan (same scanId).
    await fetchProRules(['generic'], undefined, 'https://agenticcli.dev', SCAN_ID)

    expect(captured).toHaveLength(2)
    expect(captured[0].headers['Idempotency-Key']).toBe(SCAN_ID)
    expect(captured[1].headers['Idempotency-Key']).toBe(SCAN_ID)
    expect(captured[0].body.scanId).toBe(SCAN_ID)
    expect(captured[1].body.scanId).toBe(SCAN_ID)
  })

  it('omits both body.scanId and the header when no scanId is supplied (server mints its own)', async () => {
    await fetchProRules(['generic'], undefined, 'https://agenticcli.dev')

    expect(captured).toHaveLength(1)
    expect(captured[0].headers['Idempotency-Key']).toBeUndefined()
    expect('scanId' in captured[0].body).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Per-rule confidence — the delivered per-rule confidence survives the mapping (no HIGH default)
// ---------------------------------------------------------------------------

describe('per-rule confidence — pro-scanner maps the REAL delivered confidence, never a hardcoded HIGH', () => {
  it('MEDIUM and LOW confidence rules keep their values in the mapped QualityGateRule[]', async () => {
    vi.mocked(verifyBundleResponse).mockResolvedValue({
      ok: true,
      selectedRules: [
        makeExecutableRule({ id: 'r.high.rule', confidence: 'HIGH' }),
        makeExecutableRule({ id: 'r.medium.rule', confidence: 'MEDIUM' }),
        makeExecutableRule({ id: 'r.low.rule', confidence: 'LOW' }),
      ] as never,
    })

    const { rules } = await fetchProRules(['generic'], undefined, 'https://agenticcli.dev', 'scan-1')

    const byId = new Map(rules.map(r => [r.id, r]))
    expect(byId.get('r.high.rule')?.confidence).toBe('HIGH')
    // FAIL-BEFORE: both of these came back 'HIGH' (hardcoded 'HIGH' as const).
    expect(byId.get('r.medium.rule')?.confidence).toBe('MEDIUM')
    expect(byId.get('r.low.rule')?.confidence).toBe('LOW')
  })
})
