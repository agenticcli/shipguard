/**
 * Offline mode at the call sites that talk to the network or write to the home directory.
 * With the mode on, every one of them returns before it touches fetch or the config dir.
 */
import { mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { isOffline, offlineRequestedByEnv, setOffline } from '../../src/core/offline.js'
import { sendLifecycleEvent, sendTelemetry } from '../../src/core/telemetry.js'
import { welcomeBanner } from '../../src/core/render.js'

let configDir: string
beforeEach(() => {
  configDir = mkdtempSync(join(tmpdir(), 'sg-offline-cfg-'))
})
afterEach(() => {
  setOffline(false)
  vi.unstubAllGlobals()
  rmSync(configDir, { recursive: true, force: true })
})

// Opt-in env so a request WOULD be made if offline mode did not stop it (published build + any URL).
const ENV = { SHIPGUARD_TELEMETRY: '1', SHIPGUARD_TELEMETRY_URL: 'http://127.0.0.1:1/x' } as NodeJS.ProcessEnv

describe('offline flag', () => {
  it('fails closed: any non-empty value except 0/false/no/off switches it on', () => {
    for (const v of ['1', 'true', 'TRUE', 'yes', 'on', 'enabled', 'anything', ' 1 ', '2']) {
      expect(offlineRequestedByEnv({ SHIPGUARD_OFFLINE: v }), v).toBe(true)
    }
  })
  it('0, false, no, off (any case), empty and unset leave it off', () => {
    for (const v of ['0', 'false', 'False', 'no', 'NO', 'off', 'Off', ' off ', '', '   ']) {
      expect(offlineRequestedByEnv({ SHIPGUARD_OFFLINE: v }), JSON.stringify(v)).toBe(false)
    }
    expect(offlineRequestedByEnv({})).toBe(false)
  })
  it('is off by default', () => {
    expect(isOffline()).toBe(false)
  })
})

describe('offline mode: zero network calls and no config-dir writes', () => {
  it('sendTelemetry makes no fetch call and creates nothing', async () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    setOffline(true)
    await sendTelemetry({ cliVersion: '0.12.0', verdict: 'safe', durationMs: 5, output: 'json' as const }, { env: ENV, configDir, published: true })
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(readdirSync(configDir)).toEqual([])
  })

  it('sendLifecycleEvent makes no fetch call and creates nothing', async () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    setOffline(true)
    await sendLifecycleEvent('cli_first_run', { cliVersion: '0.12.0' }, { env: ENV, configDir, published: true })
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(readdirSync(configDir)).toEqual([])
  })

  it('control: with the mode off the same call does reach fetch', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(new Response('ok'))
    vi.stubGlobal('fetch', fetchSpy)
    await sendTelemetry({ cliVersion: '0.12.0', verdict: 'safe', durationMs: 5, output: 'json' as const }, { env: ENV, configDir, published: true })
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('the first-run banner does not write its marker', () => {
    setOffline(true)
    expect(welcomeBanner(configDir)).toBe('')
    expect(readdirSync(configDir)).toEqual([])
  })
})
