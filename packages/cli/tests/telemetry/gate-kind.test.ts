/**
 * Usage ping schema 5 (plan W0, client side; the server relay is W6): the run ping carries `gateKind`,
 * which gate ran the scan. An allowlisted label only.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  TELEMETRY_GATE_KINDS,
  buildPayload,
  sendTelemetry,
  setGateKind,
  validatePayload,
  type TelemetryPayload,
} from '../../src/core/telemetry.js'

const GOOD: TelemetryPayload = {
  schema: 5,
  eventId: '3f2b6c1e-8a4d-4e0b-9c77-5d1f0a2b3c4d',
  installId: '7b1e4f52-0c3a-4d8e-a1b6-92f3c5d7e801',
  cliVersion: '0.13.0',
  provenance: 'published',
  verdict: 'safe',
  durationBucket: 'lt1s',
  ci: false,
  agent: 'none',
  interactive: false,
  output: 'json',
  gateKind: 'none',
}

describe('gateKind in the v5 payload', () => {
  it('is one of claude | git | ci | none, and required', () => {
    expect([...TELEMETRY_GATE_KINDS]).toEqual(['claude', 'git', 'ci', 'none'])
    for (const gateKind of TELEMETRY_GATE_KINDS) expect(validatePayload({ ...GOOD, gateKind })).toBe(true)
    for (const bad of ['Claude', 'hook', '', null, 1, undefined, 'git ']) expect(validatePayload({ ...GOOD, gateKind: bad })).toBe(false)
    const missing: Record<string, unknown> = { ...GOOD }
    delete missing.gateKind
    expect(validatePayload(missing)).toBe(false)
    expect(validatePayload({ ...GOOD, schema: 4 })).toBe(false)
  })
  it('buildPayload keeps it and drops anything else', () => {
    expect(buildPayload({ ...GOOD, gateKind: 'git', extra: 1 } as unknown as TelemetryPayload)).toEqual({ ...GOOD, gateKind: 'git' })
  })
})

describe('what a ping sends', () => {
  let dir: string
  let fetchMock: ReturnType<typeof vi.fn>
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sg-gk-'))
    fetchMock = vi.fn().mockResolvedValue(new Response('ok'))
    vi.stubGlobal('fetch', fetchMock)
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
  })
  afterEach(() => {
    setGateKind('none')
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
    rmSync(dir, { recursive: true, force: true })
  })
  const opts = () => ({ published: true, configDir: dir, env: { SHIPGUARD_TELEMETRY_URL: 'https://sink.example/t' } })
  const input = { cliVersion: '0.13.0', verdict: 'safe' as const, durationMs: 10, output: 'json' as const }
  const sent = (): Record<string, unknown> => JSON.parse((fetchMock.mock.calls[0][1] as { body: string }).body)

  it('a plain scan sends gateKind none', async () => {
    await sendTelemetry(input, opts())
    expect(sent()).toMatchObject({ schema: 5, gateKind: 'none' })
  })
  it('the gate command sets it once with setGateKind', async () => {
    setGateKind('claude')
    await sendTelemetry(input, opts())
    expect(sent().gateKind).toBe('claude')
  })
  it('an explicit input value wins, and an unknown kind is ignored', async () => {
    setGateKind('claude')
    setGateKind('rm -rf /')
    await sendTelemetry({ ...input, gateKind: 'ci' }, opts())
    expect(sent().gateKind).toBe('ci')
    fetchMock.mockClear()
    await sendTelemetry(input, opts())
    expect(sent().gateKind).toBe('claude')
  })
})
