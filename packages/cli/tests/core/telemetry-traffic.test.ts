/** Optional `traffic` wire key (SHIPGUARD_TRAFFIC), schema 2 and 3. */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  resolveTraffic,
  sendLifecycleEvent,
  sendTelemetry,
  validateLifecyclePayload,
  validatePayload,
} from '../../src/core/telemetry.js'

const URL_ = 'http://127.0.0.1:9/cli-telemetry'
let dir: string
let fetchMock: ReturnType<typeof vi.fn>
const env = (extra: Record<string, string> = {}): NodeJS.ProcessEnv => ({ SHIPGUARD_TELEMETRY_URL: URL_, ...extra })
const scan = (e: NodeJS.ProcessEnv, published = true) =>
  sendTelemetry({ cliVersion: '0.8.1', verdict: 'safe', durationMs: 10 }, { published, env: e, configDir: dir })
const life = (e: NodeJS.ProcessEnv, published = true) =>
  sendLifecycleEvent('cli_login', { cliVersion: '0.8.1' }, { published, env: e, configDir: dir })
const bodies = () => fetchMock.mock.calls.map((c) => JSON.parse((c[1] as { body: string }).body))

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sg-tel-traffic-'))
  fetchMock = vi.fn().mockResolvedValue({ ok: true })
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
})
afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('SHIPGUARD_TRAFFIC', () => {
  it.each(['test', 'internal'])('sends traffic=%s in schema 2 and 3', async (v) => {
    await scan(env({ SHIPGUARD_TRAFFIC: v }))
    await life(env({ SHIPGUARD_TRAFFIC: v }))
    const [a, b] = bodies()
    expect(a).toMatchObject({ schema: 2, traffic: v })
    expect(b).toMatchObject({ schema: 3, traffic: v })
    expect(validatePayload(a)).toBe(true)
    expect(validateLifecyclePayload(b)).toBe(true)
  })
  it.each(['prod', 'TEST', 'Internal', '', ' test', '1'])('omits invalid value %j', async (v) => {
    await scan(env({ SHIPGUARD_TRAFFIC: v }))
    await life(env({ SHIPGUARD_TRAFFIC: v }))
    for (const b of bodies()) expect('traffic' in b).toBe(false)
  })
  it('published build without the variable omits it', () => {
    expect(resolveTraffic({}, true)).toBeUndefined()
  })
  it('dev/probe build defaults to test', async () => {
    expect(resolveTraffic({}, false)).toBe('test')
    await scan(env(), false)
    await life(env(), false)
    for (const b of bodies()) expect(b.traffic).toBe('test')
  })
  it('opt-out still wins', async () => {
    await scan(env({ SHIPGUARD_TRAFFIC: 'test', SHIPGUARD_TELEMETRY: '0' }))
    await life(env({ SHIPGUARD_TRAFFIC: 'internal', DO_NOT_TRACK: '1' }))
    expect(fetchMock).not.toHaveBeenCalled()
  })
  it('validators reject a bad traffic value', async () => {
    await scan(env({ SHIPGUARD_TRAFFIC: 'test' }))
    expect(validatePayload({ ...bodies()[0], traffic: 'prod' })).toBe(false)
  })
})
