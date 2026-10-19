/**
 * C3 unit tests: who decides whether a ping is sent.
 * Precedence: DO_NOT_TRACK=1 / SHIPGUARD_TELEMETRY=0  >  user config (`shipguard telemetry disable`)
 *             >  project policy (`telemetry.enabled: false` in shipguard.policy.yml)  >  default ON.
 */
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateConfig } from '../../src/core/config-generator.js'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  decideTelemetry,
  sendTelemetry,
  NOTICE_TEXT,
  type TelemetryInput,
} from '../../src/core/telemetry.js'
import {
  policyTelemetryEnabled,
  projectTelemetryEnabled,
  readUserConfig,
  writeUserEnabled,
  noticeShown,
  userConfigUnreadable,
} from '../../src/core/telemetry-config.js'

const PAYLOAD: TelemetryInput = { cliVersion: '9.9.9', verdict: 'safe', durationMs: 12 }
let dir: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sg-tel-cfg-'))
})
afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('policyTelemetryEnabled', () => {
  it('only an explicit false-like value disables; absent/true/garbage leave the default', () => {
    expect(policyTelemetryEnabled({ telemetry: { enabled: false } })).toBe(false)
    expect(policyTelemetryEnabled({ telemetry: { enabled: 'false' } })).toBe(false)
    expect(policyTelemetryEnabled({ telemetry: { enabled: 'off' } })).toBe(false)
    expect(policyTelemetryEnabled({ telemetry: { enabled: 0 } })).toBe(false)
    expect(policyTelemetryEnabled({ telemetry: { enabled: true } })).toBe(true)
    expect(policyTelemetryEnabled({ telemetry: {} })).toBeUndefined()
    expect(policyTelemetryEnabled({})).toBeUndefined()
    expect(policyTelemetryEnabled(null)).toBeUndefined()
    expect(policyTelemetryEnabled('x')).toBeUndefined()
  })
})

describe('project files: shipguard.policy.yml and the generated .shipguard.yml', () => {
  it('reads .shipguard.yml telemetry.enabled (the file that really carries the toggle)', () => {
    writeFileSync(join(dir, '.shipguard.yml'), 'telemetry:\n  enabled: false\n')
    expect(projectTelemetryEnabled({ projectDir: dir })).toBe(false)
    expect(decideTelemetry({ env: {}, configDir: join(dir, 'cfg'), projectDir: dir })).toMatchObject({
      enabled: false,
      source: 'project-policy',
    })
  })
  it('reads shipguard.policy.yml telemetry.enabled when no parsed policy is passed', () => {
    writeFileSync(join(dir, 'shipguard.policy.yml'), 'version: 1\ntelemetry:\n  enabled: false\n')
    expect(projectTelemetryEnabled({ projectDir: dir })).toBe(false)
  })
  it('any explicit false wins over an explicit true in the other file', () => {
    writeFileSync(join(dir, 'shipguard.policy.yml'), 'telemetry:\n  enabled: true\n')
    writeFileSync(join(dir, '.shipguard.yml'), 'telemetry:\n  enabled: false\n')
    expect(projectTelemetryEnabled({ projectDir: dir })).toBe(false)
  })
  it('malformed yaml is ignored, absent files give undefined', () => {
    writeFileSync(join(dir, '.shipguard.yml'), ': : :\n  - [')
    expect(projectTelemetryEnabled({ projectDir: dir })).toBeUndefined()
  })
  it('writer/reader contract: what generateConfig writes is what the reader understands (enabled:true), and flipping it disables', () => {
    const file = generateConfig(dir, [])
    expect(projectTelemetryEnabled({ projectDir: dir })).toBe(true)
    writeFileSync(file, readFileSync(file, 'utf-8').replace(/(telemetry:\s*\n\s*enabled:) true/, '$1 false'))
    expect(projectTelemetryEnabled({ projectDir: dir })).toBe(false)
  })
})

describe('decideTelemetry precedence', () => {
  const off = (over: object) => decideTelemetry({ env: {}, configDir: dir, ...over })

  it('default is on', () => {
    expect(off({})).toMatchObject({ enabled: true, source: 'default' })
  })
  it('project policy enabled:false turns it off (was: ignored)', () => {
    expect(off({ policy: { telemetry: { enabled: false } } })).toMatchObject({ enabled: false, source: 'project-policy' })
  })
  it('project policy enabled:true (what `shipguard init` writes) keeps the default on', () => {
    expect(off({ policy: { telemetry: { enabled: true } } })).toMatchObject({ enabled: true })
  })
  it('user config disable turns it off', () => {
    writeUserEnabled(dir, false)
    expect(off({})).toMatchObject({ enabled: false, source: 'user-config' })
  })
  it('user config enable leaves it on', () => {
    writeUserEnabled(dir, false)
    writeUserEnabled(dir, true)
    expect(off({})).toMatchObject({ enabled: true })
  })
  it('env opt-outs beat everything and are reported first', () => {
    writeUserEnabled(dir, true)
    expect(decideTelemetry({ env: { SHIPGUARD_TELEMETRY: '0' }, configDir: dir })).toMatchObject({
      enabled: false,
      source: 'env:SHIPGUARD_TELEMETRY',
    })
    expect(decideTelemetry({ env: { DO_NOT_TRACK: '1' }, configDir: dir })).toMatchObject({
      enabled: false,
      source: 'env:DO_NOT_TRACK',
    })
  })
  it('SHIPGUARD_TELEMETRY=1 does not override a config/policy opt-out', () => {
    writeUserEnabled(dir, false)
    expect(decideTelemetry({ env: { SHIPGUARD_TELEMETRY: '1' }, configDir: dir }).enabled).toBe(false)
  })
  it('a corrupt user config fails CLOSED (it may have held enabled:false) and is not fatal', () => {
    writeFileSync(join(dir, 'telemetry.json'), '{not json')
    expect(readUserConfig(dir)).toEqual({})
    expect(off({})).toMatchObject({ enabled: false, source: 'user-config' })
    expect(userConfigUnreadable(dir)).toBe(true)
  })
  it('a truncated config after `disable` never pings; `enable` repairs it', () => {
    writeUserEnabled(dir, false)
    writeFileSync(join(dir, 'telemetry.json'), '{"enabled": fal')
    expect(off({}).enabled).toBe(false)
    writeUserEnabled(dir, true)
    expect(off({}).enabled).toBe(true)
  })
  it('a missing config file is not "unreadable" (default on)', () => {
    expect(userConfigUnreadable(dir)).toBe(false)
    expect(off({}).enabled).toBe(true)
  })
  it('writeUserEnabled keeps unknown keys (the install id)', () => {
    writeFileSync(join(dir, 'telemetry.json'), JSON.stringify({ installId: 'abc' }))
    writeUserEnabled(dir, false)
    expect(JSON.parse(readFileSync(join(dir, 'telemetry.json'), 'utf-8'))).toEqual({ installId: 'abc', enabled: false })
  })
})

describe('sendTelemetry honours the decision', () => {
  it('does not fetch when the project policy says enabled:false', async () => {
    const f = vi.fn().mockResolvedValue(new Response('ok'))
    vi.stubGlobal('fetch', f)
    const err = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    await sendTelemetry(PAYLOAD, {
      published: true,
      env: { SHIPGUARD_TELEMETRY_URL: 'https://sink.example/t' },
      configDir: dir,
      policy: { telemetry: { enabled: false } },
    })
    expect(f).not.toHaveBeenCalled()
    expect(err).not.toHaveBeenCalled() // no notice either: nothing is being sent
    expect(noticeShown(dir)).toBe(false)
  })

  it('prints the notice once, before the first send, and never again', async () => {
    const order: string[] = []
    const f = vi.fn().mockImplementation(async () => {
      order.push('fetch')
      return new Response('ok')
    })
    vi.stubGlobal('fetch', f)
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      order.push(`stderr:${String(chunk).trim()}`)
      return true
    })
    const opts = { published: true, env: { SHIPGUARD_TELEMETRY_URL: 'https://sink.example/t' }, configDir: dir }
    await sendTelemetry(PAYLOAD, opts)
    await sendTelemetry(PAYLOAD, opts)
    expect(order).toEqual([`stderr:${NOTICE_TEXT}`, 'fetch', 'fetch'])
    expect(NOTICE_TEXT.split('\n')).toHaveLength(1)
    for (const s of ['SHIPGUARD_TELEMETRY=0', 'DO_NOT_TRACK=1', 'shipguard telemetry disable']) {
      expect(NOTICE_TEXT).toContain(s)
    }
    expect(existsSync(join(dir, 'telemetry-notice-shown'))).toBe(true)
  })

  it('debug mode prints the exact payload to stderr and sends nothing', async () => {
    const f = vi.fn()
    vi.stubGlobal('fetch', f)
    const lines: string[] = []
    vi.spyOn(process.stderr, 'write').mockImplementation((c: unknown) => (lines.push(String(c)), true))
    await sendTelemetry(PAYLOAD, {
      published: true,
      env: { SHIPGUARD_TELEMETRY_DEBUG: '1' },
      configDir: dir,
    })
    expect(f).not.toHaveBeenCalled()
    const text = lines.join('')
    const m = text.match(/payload=(\{.*\})/)
    expect(m, text).not.toBeNull()
    const sent = JSON.parse(m![1])
    expect(sent).toMatchObject({ schema: 2, cliVersion: '9.9.9', provenance: 'published', verdict: 'safe', durationBucket: 'lt1s', ci: false })
    expect(existsSync(join(dir, 'telemetry.json'))).toBe(false) // debug never saves an install id
    expect(noticeShown(dir)).toBe(false) // nothing was sent, so the "first ping" notice is not consumed
  })

  it('resolves within ~1.5 s even if the network hangs, and never rejects', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(() => new Promise(() => {})))
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const t0 = Date.now()
    await expect(
      sendTelemetry(PAYLOAD, { published: true, env: { SHIPGUARD_TELEMETRY_URL: 'https://sink.example/t' }, configDir: dir }),
    ).resolves.toBeUndefined()
    expect(Date.now() - t0).toBeLessThan(2000)
  })

  it('never throws even if fetch throws synchronously', async () => {
    vi.stubGlobal('fetch', () => {
      throw new Error('boom')
    })
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    await expect(
      sendTelemetry(PAYLOAD, { published: true, env: { SHIPGUARD_TELEMETRY_URL: 'https://sink.example/t' }, configDir: dir }),
    ).resolves.toBeUndefined()
  })
})
