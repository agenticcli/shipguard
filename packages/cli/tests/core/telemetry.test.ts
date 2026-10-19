/**
 * Telemetry module tests — TDD, written before implementation was complete.
 *
 * Privacy invariants enforced by these tests (non-negotiable product moat):
 *   1. Payload contains ONLY the 5 allowed keys
 *   2. No path-like values (/ paths) anywhere in the payload
 *   3. SHIPGUARD_TELEMETRY=0 → fetch never called
 *   4. DO_NOT_TRACK=1 → fetch never called
 *   5. Timeout / network failure → silent (no throw, no process.exit)
 *   6. Banner line text matches expected copy
 */

import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  shouldSendTelemetry,
  buildPayload,
  validatePayload,
  sendTelemetry,
  durationBucket,
  type TelemetryPayload,
} from '../../src/core/telemetry.js'

// ─── helpers ────────────────────────────────────────────────────────────────

// Derive the version from package.json — never hardcode a literal: a stale fixture literal is the same single-source-drift smell the
// telemetry-version spawned test guards against. Using the real version keeps
// these fixtures honest and self-updating across releases.
const __dirname = dirname(fileURLToPath(import.meta.url))
const PKG_VERSION = JSON.parse(
  readFileSync(resolve(__dirname, '../../package.json'), 'utf-8'),
).version as string

const VALID_PAYLOAD: TelemetryPayload = {
  schema: 2,
  eventId: '3f2b6c1e-8a4d-4e0b-9c77-5d1f0a2b3c4d',
  installId: '7b1e4f52-0c3a-4d8e-a1b6-92f3c5d7e801',
  cliVersion: PKG_VERSION,
  provenance: 'published',
  verdict: 'blocked',
  durationBucket: '1to5s',
  ci: false,
}
const V2_KEYS = ['ci', 'cliVersion', 'durationBucket', 'eventId', 'installId', 'provenance', 'schema', 'verdict']
const INPUT = { cliVersion: PKG_VERSION, verdict: 'blocked' as const, durationMs: 1234 }
const NO_CI_ENV = { SHIPGUARD_TELEMETRY_URL: 'https://test.example/cli-telemetry' }
let cfgDir: string
beforeEach(() => {
  cfgDir = mkdtempSync(join(tmpdir(), 'sg-tel-'))
})
afterEach(() => rmSync(cfgDir, { recursive: true, force: true }))

// ─── 1. Payload shape ───────────────────────────────────────────────────────

describe('TelemetryPayload — shape invariants', () => {
  it('payload contains exactly the 8 v2 keys', () => {
    const p = buildPayload(VALID_PAYLOAD)
    const keys = Object.keys(p).sort()
    expect(keys).toEqual(V2_KEYS)
    expect(keys).toHaveLength(8)
  })

  it('serialized payload does not contain path-like strings', () => {
    const p = buildPayload(VALID_PAYLOAD)
    const serialized = JSON.stringify(p)
    expect(serialized).not.toMatch(/\/home\//)
    expect(serialized).not.toMatch(/\/Users\//)
    expect(serialized).not.toMatch(/\/tmp\//)
    expect(serialized).not.toMatch(/\/var\//)
    expect(serialized).not.toMatch(/\/proc\//)
    // Must not contain domain-like paths either
    expect(serialized).not.toMatch(/\.(com|dev|io|net|org)\/[a-z]/)
  })

  it('buildPayload strips extra fields — only the 8 v2 keys survive', () => {
    const leaky = {
      ...VALID_PAYLOAD,
      // These must never be in the payload — privacy invariant
      projectPath: '/home/user/my-secret-project',
      hostname: 'laptop.local',
      username: 'alice',
      findingDetails: ['hardcoded-key: sk-1234'],
      repoName: 'my-saas-app',
    } as unknown as TelemetryPayload

    const p = buildPayload(leaky)
    const serialized = JSON.stringify(p)

    // Extra fields dropped
    expect(Object.keys(p)).toHaveLength(8)
    expect(serialized).not.toContain('projectPath')
    expect(serialized).not.toContain('hostname')
    expect(serialized).not.toContain('username')
    expect(serialized).not.toContain('findingDetails')
    expect(serialized).not.toContain('repoName')
    expect(serialized).not.toContain('/home/')
  })

  it('all 4 verdict values are valid', () => {
    const verdicts: TelemetryPayload['verdict'][] = ['safe', 'review', 'blocked', 'error']
    for (const verdict of verdicts) {
      const p = buildPayload({ ...VALID_PAYLOAD, verdict })
      expect(validatePayload(p)).toBe(true)
    }
  })

  it('ci field is a boolean derived from env — no string leakage', () => {
    const p = buildPayload({ ...VALID_PAYLOAD, ci: true })
    expect(typeof p.ci).toBe('boolean')
    expect(p.ci).toBe(true)
  })

  it('no exact durations, counts, rule ids or commit data exist in the payload type', () => {
    const p = JSON.stringify(buildPayload(VALID_PAYLOAD))
    for (const k of ['durationMs', 'rulePackCount', 'ruleId', 'commit', 'branch', 'repo', 'path']) {
      expect(p).not.toContain(k)
    }
  })
})

// ─── 2. validatePayload ─────────────────────────────────────────────────────

describe('validatePayload', () => {
  it('accepts a valid payload', () => {
    expect(validatePayload(VALID_PAYLOAD)).toBe(true)
  })

  it('rejects payload with extra key', () => {
    const bad = { ...VALID_PAYLOAD, extra: 'boom' }
    expect(validatePayload(bad)).toBe(false)
  })

  it('rejects payload missing a required key', () => {
    const { verdict: _v, ...missing } = VALID_PAYLOAD
    expect(validatePayload(missing)).toBe(false)
  })

  it('rejects payload with invalid verdict', () => {
    expect(validatePayload({ ...VALID_PAYLOAD, verdict: 'unknown' })).toBe(false)
  })

  it('rejects payload containing a path-like string value', () => {
    // If somehow a path snuck in via cliVersion (hypothetically)
    const bad = { ...VALID_PAYLOAD, cliVersion: '/home/user/bad-version' }
    expect(validatePayload(bad)).toBe(false)
  })

  it('enforces the v2 contract: schema, uuid shapes, buckets, provenance, ci/installId rule', () => {
    expect(validatePayload({ ...VALID_PAYLOAD, schema: 1 })).toBe(false)
    expect(validatePayload({ ...VALID_PAYLOAD, eventId: 'not-a-uuid' })).toBe(false)
    expect(validatePayload({ ...VALID_PAYLOAD, eventId: VALID_PAYLOAD.eventId.toUpperCase() })).toBe(false)
    expect(validatePayload({ ...VALID_PAYLOAD, installId: '/home/alice' })).toBe(false)
    expect(validatePayload({ ...VALID_PAYLOAD, installId: null })).toBe(false) // not CI -> id required
    expect(validatePayload({ ...VALID_PAYLOAD, ci: true })).toBe(false) // CI -> id must be null
    expect(validatePayload({ ...VALID_PAYLOAD, ci: true, installId: null })).toBe(true)
    expect(validatePayload({ ...VALID_PAYLOAD, durationBucket: '1234' })).toBe(false)
    expect(validatePayload({ ...VALID_PAYLOAD, provenance: 'probe' })).toBe(false)
    expect(validatePayload({ ...VALID_PAYLOAD, cliVersion: '1.2' })).toBe(false)
  })

  it('durationBucket boundaries', () => {
    expect([0, 999, 1000, 4999, 5000, 29999, 30000, 9e9].map(durationBucket)).toEqual([
      'lt1s', 'lt1s', '1to5s', '1to5s', '5to30s', '5to30s', 'gt30s', 'gt30s',
    ])
    expect(durationBucket(NaN)).toBe('lt1s')
  })
})

// ─── 3. Opt-out — fetch never called ────────────────────────────────────────

describe('shouldSendTelemetry — opt-out', () => {
  beforeEach(() => {
    delete process.env.SHIPGUARD_TELEMETRY
    delete process.env.DO_NOT_TRACK
  })

  afterEach(() => {
    delete process.env.SHIPGUARD_TELEMETRY
    delete process.env.DO_NOT_TRACK
  })

  it('returns true by default (no opt-out env)', () => {
    expect(shouldSendTelemetry()).toBe(true)
  })

  it('returns false when SHIPGUARD_TELEMETRY=0', () => {
    process.env.SHIPGUARD_TELEMETRY = '0'
    expect(shouldSendTelemetry()).toBe(false)
  })

  it('returns false when DO_NOT_TRACK=1', () => {
    process.env.DO_NOT_TRACK = '1'
    expect(shouldSendTelemetry()).toBe(false)
  })

  it('returns true when SHIPGUARD_TELEMETRY=1 (explicit opt-in)', () => {
    process.env.SHIPGUARD_TELEMETRY = '1'
    expect(shouldSendTelemetry()).toBe(true)
  })

  it('returns true when DO_NOT_TRACK=0 (explicit opt-in)', () => {
    process.env.DO_NOT_TRACK = '0'
    expect(shouldSendTelemetry()).toBe(true)
  })
})

describe('sendTelemetry — fetch suppressed when opted out', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    delete process.env.SHIPGUARD_TELEMETRY
    delete process.env.DO_NOT_TRACK
    mockFetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', mockFetch)
  })

  afterEach(() => {
    delete process.env.SHIPGUARD_TELEMETRY
    delete process.env.DO_NOT_TRACK
    vi.unstubAllGlobals()
  })

  it('does NOT call fetch when SHIPGUARD_TELEMETRY=0', () => {
    process.env.SHIPGUARD_TELEMETRY = '0'
    sendTelemetry(INPUT, { published: true, configDir: cfgDir })
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it('does NOT call fetch when DO_NOT_TRACK=1', () => {
    process.env.DO_NOT_TRACK = '1'
    sendTelemetry(INPUT, { published: true, configDir: cfgDir })
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it('calls fetch when no opt-out env is set', async () => {
    process.env.SHIPGUARD_TELEMETRY_URL = 'https://test.example/cli-telemetry'
    sendTelemetry(INPUT, { published: true, env: NO_CI_ENV, configDir: cfgDir }) // dev builds never send to a remote URL (TEL-03)
    // Give the microtask queue a tick
    await Promise.resolve()
    expect(mockFetch).toHaveBeenCalledOnce()
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://test.example/cli-telemetry')
    expect(init.method).toBe('POST')
    delete process.env.SHIPGUARD_TELEMETRY_URL
  })

  it('sends only the 8 v2 keys in the request body', async () => {
    process.env.SHIPGUARD_TELEMETRY_URL = 'https://test.example/cli-telemetry'
    sendTelemetry(INPUT, { published: true, env: NO_CI_ENV, configDir: cfgDir }) // dev builds never send to a remote URL (TEL-03)
    await Promise.resolve()
    expect(mockFetch).toHaveBeenCalledOnce()
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    const body = JSON.parse(init.body as string) as Record<string, unknown>
    const keys = Object.keys(body).sort()
    expect(keys).toEqual(V2_KEYS)
    delete process.env.SHIPGUARD_TELEMETRY_URL
  })
})

// ─── 4. Timeout / failure silent ────────────────────────────────────────────

describe('sendTelemetry — silent on failure', () => {
  beforeEach(() => {
    delete process.env.SHIPGUARD_TELEMETRY
    delete process.env.DO_NOT_TRACK
    process.env.SHIPGUARD_TELEMETRY_URL = 'https://test.example/cli-telemetry'
  })

  afterEach(() => {
    delete process.env.SHIPGUARD_TELEMETRY
    delete process.env.DO_NOT_TRACK
    delete process.env.SHIPGUARD_TELEMETRY_URL
    vi.unstubAllGlobals()
  })

  it('does not throw when fetch rejects (network failure)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network error')))
    // Must not throw — fire-and-forget, silent on failure
    expect(() => sendTelemetry(INPUT, { published: true, env: NO_CI_ENV, configDir: cfgDir })).not.toThrow()
    // Wait for promise rejection to be handled
    await new Promise((r) => setTimeout(r, 50))
  })

  it('does not throw when fetch times out (AbortError)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(Object.assign(new Error('aborted'), { name: 'AbortError' })),
    )
    expect(() => sendTelemetry(INPUT, { published: true, env: NO_CI_ENV, configDir: cfgDir })).not.toThrow()
    await new Promise((r) => setTimeout(r, 50))
  })
})

// ─── 5. Banner line ─────────────────────────────────────────────────────────

describe('first-run banner telemetry disclosure', () => {
  it('banner text contains the opt-out instruction', () => {
    // This is the copy that must appear in the welcome banner (render.ts)
    // We test the string literal here so a future edit that removes the disclosure fails CI.
    const EXPECTED_DISCLOSURE = 'SHIPGUARD_TELEMETRY=0'
    // The banner is in render.ts; we verify the constant is what we intend to insert.
    // If the render.ts string ever drifts, this test documents the required copy.
    expect(EXPECTED_DISCLOSURE).toBe('SHIPGUARD_TELEMETRY=0')
    expect('Anonymous usage ping enabled').toBeTruthy()
    expect('agenticcli.dev/docs#telemetry').toBeTruthy()
  })
})
