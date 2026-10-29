/** cli_first_run / cli_login (cli-telemetry schema 3). */
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { sendLifecycleEvent, validateLifecyclePayload } from '../../src/core/telemetry.js'

const URL_ = 'http://127.0.0.1:9/cli-telemetry'
let dir: string
let fetchMock: ReturnType<typeof vi.fn>
const env = (extra: Record<string, string> = {}): NodeJS.ProcessEnv => ({ SHIPGUARD_TELEMETRY_URL: URL_, ...extra })
const send = (event: 'cli_first_run' | 'cli_login', e = env()) =>
  sendLifecycleEvent(event, { cliVersion: '0.8.1' }, { published: true, env: e, configDir: dir })
const bodies = () => fetchMock.mock.calls.map((c) => JSON.parse((c[1] as { body: string }).body))

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sg-tel-life-'))
  fetchMock = vi.fn().mockResolvedValue({ ok: true })
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
})
afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('cli_first_run', () => {
  it('fires once per install, with the schema-3 keys only', async () => {
    await send('cli_first_run')
    await send('cli_first_run')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const b = bodies()[0]
    expect(Object.keys(b).sort()).toEqual(['ci', 'cliVersion', 'event', 'eventId', 'installId', 'provenance', 'schema'])
    expect(b).toMatchObject({ schema: 3, event: 'cli_first_run', ci: false, provenance: 'published', cliVersion: '0.8.1' })
    expect(validateLifecyclePayload(b)).toBe(true)
  })
  it('does not fire for an install that already has an id (upgrade), and stays quiet afterwards', async () => {
    writeFileSync(join(dir, 'telemetry.json'), JSON.stringify({ installId: '3f2b8c1e-5d4a-4b7e-9c10-2a6d8e0f1b34' }))
    await send('cli_first_run')
    expect(fetchMock).not.toHaveBeenCalled()
    expect(existsSync(join(dir, 'telemetry-first-run-sent'))).toBe(true)
  })
  it('is never sent from CI', async () => {
    await send('cli_first_run', env({ CI: 'true' }))
    expect(fetchMock).not.toHaveBeenCalled()
  })
  it.each([
    ['SHIPGUARD_TELEMETRY=0', { SHIPGUARD_TELEMETRY: '0' }],
    ['DO_NOT_TRACK=1', { DO_NOT_TRACK: '1' }],
  ])('opt-out %s suppresses it and leaves no marker', async (_n, extra) => {
    await send('cli_first_run', env(extra))
    expect(fetchMock).not.toHaveBeenCalled()
    expect(existsSync(join(dir, 'telemetry-first-run-sent'))).toBe(false)
  })
  it('user-config disable suppresses it', async () => {
    writeFileSync(join(dir, 'telemetry.json'), JSON.stringify({ enabled: false }))
    await send('cli_first_run')
    expect(fetchMock).not.toHaveBeenCalled()
  })
  it('a dev build sends nothing', async () => {
    await sendLifecycleEvent('cli_first_run', { cliVersion: '0.8.1' }, { published: false, env: {}, configDir: dir })
    expect(fetchMock).not.toHaveBeenCalled()
  })
  it('a network failure resolves and is not retried next run', async () => {
    fetchMock.mockRejectedValue(new Error('down'))
    await expect(send('cli_first_run')).resolves.toBeUndefined()
    await send('cli_first_run')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('cli_login', () => {
  it('fires each time it is called, with an install id outside CI', async () => {
    await send('cli_login')
    const b = bodies()[0]
    expect(b).toMatchObject({ schema: 3, event: 'cli_login', ci: false })
    expect(b.installId).toMatch(/^[0-9a-f-]{36}$/)
    expect(validateLifecyclePayload(b)).toBe(true)
  })
  it('in CI sends installId null', async () => {
    await send('cli_login', env({ CI: 'true' }))
    expect(bodies()[0]).toMatchObject({ ci: true, installId: null })
  })
  it('opt-out suppresses it', async () => {
    await send('cli_login', env({ DO_NOT_TRACK: '1' }))
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('payload contains no paths or names', () => {
  it('carries only allowlisted scalar values', async () => {
    const cwd = process.cwd()
    await send('cli_first_run')
    await send('cli_login')
    for (const b of bodies()) {
      const s = JSON.stringify(b)
      expect(s).not.toContain(cwd)
      expect(s).not.toContain(dir)
      expect(s).not.toMatch(/[\\/]/)
    }
  })
  it('validator rejects extra keys and ci first-run', () => {
    const ok = { schema: 3, event: 'cli_login', eventId: '3f2b8c1e-5d4a-4b7e-9c10-2a6d8e0f1b34', installId: null, cliVersion: '0.8.1', provenance: 'published', ci: true }
    expect(validateLifecyclePayload(ok)).toBe(true)
    expect(validateLifecyclePayload({ ...ok, path: '/home/x' })).toBe(false)
    expect(validateLifecyclePayload({ ...ok, event: 'cli_first_run' })).toBe(false)
  })
})
