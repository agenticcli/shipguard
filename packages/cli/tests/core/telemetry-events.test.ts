/**
 * Lifecycle telemetry events (schema 3): `cli_first_run` (once per install id) and `cli_login`
 * (after a successful login). Same privacy design as the scan ping (core/telemetry.ts):
 * pseudonymous install id, never linked to an account, every opt-out honoured, debug = print only.
 *
 * Invariants pinned here:
 *   1. Exact wire shape: schema 3, event, eventId, installId, cliVersion, provenance, ci. Nothing else.
 *   2. Every opt-out (env x2, `telemetry disable`, project policy x2 files) sends nothing and
 *      writes nothing (no marker, no install id).
 *   3. SHIPGUARD_TELEMETRY_DEBUG=1 prints the payload, sends nothing, writes nothing.
 *   4. First run is idempotent: marker keyed by install id, written BEFORE the send, so a failed
 *      send is never retried in a loop and an unwritable marker means no send.
 *   5. CI: no first-run event (no install id exists there); login still allowed with installId null.
 *   6. Dev builds never reach production.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  FIRST_RUN_MARKER,
  sendLifecycleEvent,
  validateLifecyclePayload,
  type LifecyclePayload,
} from '../../src/core/telemetry-events.js'
import { NOTICE_TEXT } from '../../src/core/telemetry.js'
import { readInstallId, resetInstallId, writeUserEnabled } from '../../src/core/telemetry-config.js'

const URL_ENV = { SHIPGUARD_TELEMETRY_URL: 'https://test.example/cli-telemetry' }
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const KEYS = ['ci', 'cliVersion', 'event', 'eventId', 'installId', 'provenance', 'schema']
const INPUT = { cliVersion: '0.7.1' }

let cfgDir: string
let projectDir: string
let mockFetch: ReturnType<typeof vi.fn>

beforeEach(() => {
  cfgDir = mkdtempSync(join(tmpdir(), 'sg-evt-cfg-'))
  projectDir = mkdtempSync(join(tmpdir(), 'sg-evt-proj-'))
  mockFetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))
  vi.stubGlobal('fetch', mockFetch)
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  rmSync(cfgDir, { recursive: true, force: true })
  rmSync(projectDir, { recursive: true, force: true })
})

function send(
  event: 'cli_first_run' | 'cli_login',
  extra: { env?: NodeJS.ProcessEnv; published?: boolean; projectDir?: string } = {},
) {
  return sendLifecycleEvent(event, INPUT, {
    published: extra.published ?? true,
    env: extra.env ?? URL_ENV,
    configDir: cfgDir,
    projectDir: extra.projectDir,
  })
}
function bodies(): Array<Record<string, unknown>> {
  return mockFetch.mock.calls.map((c) => JSON.parse((c[1] as RequestInit).body as string) as Record<string, unknown>)
}
function stderrSpy() {
  const writes: string[] = []
  vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
    writes.push(String(chunk))
    return true
  }) as typeof process.stderr.write)
  return writes
}

describe('wire shape', () => {
  it('cli_first_run sends exactly the 7 schema-3 keys', async () => {
    stderrSpy()
    await send('cli_first_run')
    expect(mockFetch).toHaveBeenCalledOnce()
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://test.example/cli-telemetry')
    expect(init.method).toBe('POST')
    const body = bodies()[0]
    expect(Object.keys(body).sort()).toEqual(KEYS)
    expect(body).toMatchObject({ schema: 3, event: 'cli_first_run', cliVersion: '0.7.1', provenance: 'published', ci: false })
    expect(body.eventId).toMatch(UUID_V4)
    expect(body.installId).toBe(readInstallId(cfgDir))
  })

  it('cli_login sends the same 7 keys, with the same install id (no account data)', async () => {
    stderrSpy()
    await send('cli_login')
    const body = bodies()[0]
    expect(Object.keys(body).sort()).toEqual(KEYS)
    expect(body.event).toBe('cli_login')
    expect(body.installId).toBe(readInstallId(cfgDir))
    const text = JSON.stringify(body)
    for (const k of ['email', 'token', 'user', 'account', 'accessToken', 'apiUrl', 'device']) {
      expect(text.toLowerCase()).not.toContain(k.toLowerCase())
    }
  })

  it('validateLifecyclePayload enforces the contract', () => {
    const ok: LifecyclePayload = {
      schema: 3,
      event: 'cli_first_run',
      eventId: '3f2b6c1e-8a4d-4e0b-9c77-5d1f0a2b3c4d',
      installId: '7b1e4f52-0c3a-4d8e-a1b6-92f3c5d7e801',
      cliVersion: '0.7.1',
      provenance: 'published',
      ci: false,
    }
    expect(validateLifecyclePayload(ok)).toBe(true)
    expect(validateLifecyclePayload({ ...ok, extra: 1 })).toBe(false)
    expect(validateLifecyclePayload({ ...ok, event: 'cli_run' })).toBe(false)
    expect(validateLifecyclePayload({ ...ok, schema: 2 })).toBe(false)
    expect(validateLifecyclePayload({ ...ok, installId: '/home/alice' })).toBe(false)
    expect(validateLifecyclePayload({ ...ok, installId: null })).toBe(false) // not CI -> id required
    expect(validateLifecyclePayload({ ...ok, ci: true })).toBe(false) // CI -> id must be null
    expect(validateLifecyclePayload({ ...ok, ci: true, installId: null, event: 'cli_login' })).toBe(true)
    expect(validateLifecyclePayload({ ...ok, ci: true, installId: null, event: 'cli_first_run' })).toBe(false) // no first-run in CI
    expect(validateLifecyclePayload({ ...ok, provenance: 'probe' })).toBe(false)
  })
})

describe('first run is idempotent per install id', () => {
  it('sends once, then never again for the same install id', async () => {
    stderrSpy()
    await send('cli_first_run')
    await send('cli_first_run')
    await send('cli_first_run')
    expect(mockFetch).toHaveBeenCalledOnce()
    expect(readFileSync(join(cfgDir, FIRST_RUN_MARKER), 'utf-8').trim()).toBe(readInstallId(cfgDir))
  })

  it('a failed send is NOT retried on the next run (no failure loop)', async () => {
    stderrSpy()
    mockFetch.mockRejectedValue(new Error('network down'))
    await send('cli_first_run')
    await send('cli_first_run')
    expect(mockFetch).toHaveBeenCalledOnce()
  })

  it('a non-2xx relay answer is not retried either', async () => {
    stderrSpy()
    mockFetch.mockResolvedValue(new Response('bad', { status: 400 }))
    await send('cli_first_run')
    await send('cli_first_run')
    expect(mockFetch).toHaveBeenCalledOnce()
  })

  it('does not send when the marker cannot be written (unwritable marker = no send)', async () => {
    stderrSpy()
    mkdirSync(join(cfgDir, FIRST_RUN_MARKER)) // a directory where the marker file must go
    await send('cli_first_run')
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it('does not send when the install id cannot be saved', async () => {
    stderrSpy()
    // The config dir sits below a regular file -> nothing can be persisted there.
    const blocker = join(cfgDir, 'blocker')
    writeFileSync(blocker, 'x')
    await sendLifecycleEvent('cli_first_run', INPUT, { published: true, env: URL_ENV, configDir: join(blocker, 'cfg') })
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it('a new install id (telemetry reset) is a new first run', async () => {
    stderrSpy()
    await send('cli_first_run')
    const first = readInstallId(cfgDir)
    resetInstallId(cfgDir)
    await send('cli_first_run')
    expect(mockFetch).toHaveBeenCalledTimes(2)
    expect(bodies()[1].installId).not.toBe(first)
    expect(bodies()[1].installId).toBe(readInstallId(cfgDir))
  })

  it('never throws and always resolves', async () => {
    stderrSpy()
    mockFetch.mockImplementation(() => {
      throw new Error('sync boom')
    })
    await expect(send('cli_first_run')).resolves.toBeUndefined()
    await expect(send('cli_login')).resolves.toBeUndefined()
  })
})

describe('login', () => {
  it('sends one event per successful login call (no first-run marker involved)', async () => {
    stderrSpy()
    await send('cli_login')
    await send('cli_login')
    expect(mockFetch).toHaveBeenCalledTimes(2)
    expect(existsSync(join(cfgDir, FIRST_RUN_MARKER))).toBe(false)
  })
})

describe('every existing opt-out is honoured, and nothing is written', () => {
  const optOuts: Array<[string, () => { env: NodeJS.ProcessEnv; projectDir?: string }]> = [
    ['SHIPGUARD_TELEMETRY=0', () => ({ env: { ...URL_ENV, SHIPGUARD_TELEMETRY: '0' } })],
    ['SHIPGUARD_TELEMETRY=false', () => ({ env: { ...URL_ENV, SHIPGUARD_TELEMETRY: 'false' } })],
    ['DO_NOT_TRACK=1', () => ({ env: { ...URL_ENV, DO_NOT_TRACK: '1' } })],
    ['DO_NOT_TRACK=true', () => ({ env: { ...URL_ENV, DO_NOT_TRACK: 'true' } })],
    [
      'shipguard telemetry disable',
      () => {
        writeUserEnabled(cfgDir, false)
        return { env: URL_ENV }
      },
    ],
    [
      'telemetry.enabled:false in .shipguard.yml',
      () => {
        writeFileSync(join(projectDir, '.shipguard.yml'), 'telemetry:\n  enabled: false\n')
        return { env: URL_ENV, projectDir }
      },
    ],
    [
      'telemetry.enabled:false in shipguard.policy.yml',
      () => {
        writeFileSync(join(projectDir, 'shipguard.policy.yml'), 'telemetry:\n  enabled: false\n')
        return { env: URL_ENV, projectDir }
      },
    ],
  ]
  for (const event of ['cli_first_run', 'cli_login'] as const) {
    for (const [name, setup] of optOuts) {
      it(`${event}: ${name} -> no request, no marker, no install id`, async () => {
        const out = stderrSpy()
        const { env, projectDir: pd } = setup()
        await send(event, { env, projectDir: pd })
        expect(mockFetch).not.toHaveBeenCalled()
        expect(existsSync(join(cfgDir, FIRST_RUN_MARKER))).toBe(false)
        expect(readInstallId(cfgDir)).toBeUndefined()
        expect(out.join('')).not.toContain(NOTICE_TEXT) // opted out: not even the notice
      })
    }
  }

  it('an unreadable user config fails closed (could have held enabled:false)', async () => {
    stderrSpy()
    writeFileSync(join(cfgDir, 'telemetry.json'), '{ not json')
    await send('cli_first_run')
    await send('cli_login')
    expect(mockFetch).not.toHaveBeenCalled()
  })
})

describe('SHIPGUARD_TELEMETRY_DEBUG print-only mode', () => {
  for (const event of ['cli_first_run', 'cli_login'] as const) {
    it(`${event}: prints the exact payload to stderr, sends nothing, writes nothing`, async () => {
      const out = stderrSpy()
      await send(event, { env: { ...URL_ENV, SHIPGUARD_TELEMETRY_DEBUG: '1' } })
      expect(mockFetch).not.toHaveBeenCalled()
      expect(existsSync(join(cfgDir, FIRST_RUN_MARKER))).toBe(false)
      expect(readInstallId(cfgDir)).toBeUndefined()
      const text = out.join('')
      expect(text).toContain('[shipguard:telemetry]')
      expect(text).toContain(`"event":"${event}"`)
      expect(text).toContain('"schema":3')
    })
  }
})

describe('CI', () => {
  const CI_ENV = { ...URL_ENV, CI: 'true' }
  it('cli_first_run is never sent in CI (no install id exists there)', async () => {
    stderrSpy()
    await send('cli_first_run', { env: CI_ENV })
    expect(mockFetch).not.toHaveBeenCalled()
    expect(readInstallId(cfgDir)).toBeUndefined()
    expect(existsSync(join(cfgDir, FIRST_RUN_MARKER))).toBe(false)
  })

  it('cli_login in CI is sent with installId null and creates no install id', async () => {
    stderrSpy()
    await send('cli_login', { env: CI_ENV })
    expect(mockFetch).toHaveBeenCalledOnce()
    expect(bodies()[0]).toMatchObject({ event: 'cli_login', ci: true, installId: null })
    expect(readInstallId(cfgDir)).toBeUndefined()
  })
})

describe('provenance / notice', () => {
  it('a dev build never sends to a remote URL and leaves no marker', async () => {
    stderrSpy()
    await send('cli_first_run', { published: false })
    await send('cli_login', { published: false })
    expect(mockFetch).not.toHaveBeenCalled()
    expect(existsSync(join(cfgDir, FIRST_RUN_MARKER))).toBe(false)
  })

  it('a dev build may send to a loopback capture server, with provenance "dev"', async () => {
    stderrSpy()
    await send('cli_login', { published: false, env: { SHIPGUARD_TELEMETRY_URL: 'http://127.0.0.1:4321/cli-telemetry' } })
    expect(mockFetch).toHaveBeenCalledOnce()
    expect(bodies()[0].provenance).toBe('dev')
  })

  it('the one-line notice is printed to stderr BEFORE the first request, once', async () => {
    const order: string[] = []
    vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
      order.push(`stderr:${String(chunk).trim()}`)
      return true
    }) as typeof process.stderr.write)
    mockFetch.mockImplementation(async () => {
      order.push('fetch')
      return new Response('ok')
    })
    await send('cli_first_run')
    await send('cli_login')
    expect(order).toEqual([`stderr:${NOTICE_TEXT}`, 'fetch', 'fetch'])
  })

  it('the notice mentions the first-run and login events', () => {
    expect(NOTICE_TEXT.toLowerCase()).toContain('first run')
    expect(NOTICE_TEXT.toLowerCase()).toContain('login')
  })
})
