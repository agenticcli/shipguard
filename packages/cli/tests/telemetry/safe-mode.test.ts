/**
 * Safe mode (spec 06, owner decision A6; plan W0): `--safe-mode` / SHIPGUARD_SAFE_MODE=1 is decided in ONE
 * place, isSafeMode() (core/telemetry-config.ts). With it on: no usage ping, no network, and nothing new
 * written to ~/.config (the sign-in token is the only allowed write outside the project, by `login`).
 * The first-line text and flag registration are wired by W2b (cli.ts); here we test the decision, the
 * writers and the real built CLI.
 */
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, afterEach, describe, expect, it, vi } from 'vitest'
import {
  SAFE_MODE_LINE,
  announceSafeMode,
  getOrCreateInstallId,
  isSafeMode,
  markFirstRunHandled,
  markNoticeShown,
} from '../../src/core/telemetry-config.js'
import { decideTelemetry, sendLifecycleEvent, sendTelemetry, telemetryState } from '../../src/core/telemetry.js'
import { buildVariant, makeRecordedCli, type RecordedCli } from '../helpers/recorded-cli.js'

vi.setConfig({ testTimeout: 60_000, hookTimeout: 120_000 })

describe('isSafeMode(): the one decision', () => {
  it.each([
    ['env 1', { SHIPGUARD_SAFE_MODE: '1' }, ['node', 'cli.js', 'scan'], true],
    ['env true', { SHIPGUARD_SAFE_MODE: 'TRUE' }, ['node', 'cli.js', 'scan'], true],
    ['flag', {}, ['node', 'cli.js', 'scan', '--safe-mode'], true],
    ['flag before the command', {}, ['node', 'cli.js', '--safe-mode', 'gate'], true],
    ['off by default', {}, ['node', 'cli.js', 'scan'], false],
    ['env 0 is off', { SHIPGUARD_SAFE_MODE: '0' }, ['node', 'cli.js', 'scan'], false],
    ['env empty is off', { SHIPGUARD_SAFE_MODE: '' }, ['node', 'cli.js', 'scan'], false],
    ['flag after -- is a path, not the flag', {}, ['node', 'cli.js', 'scan', '--', '--safe-mode'], false],
    ['similar flag is not it', {}, ['node', 'cli.js', 'scan', '--safe-mode-x'], false],
  ] as const)('%s', (_n, env, argv, expected) => {
    expect(isSafeMode(env, argv)).toBe(expected)
  })
})

describe('writers and senders in safe mode (in process)', () => {
  let dir: string
  const prev = process.env.SHIPGUARD_SAFE_MODE
  const setup = (): void => {
    dir = mkdtempSync(join(tmpdir(), 'sg-safe-'))
    process.env.SHIPGUARD_SAFE_MODE = '1'
  }
  afterEach(() => {
    if (prev === undefined) delete process.env.SHIPGUARD_SAFE_MODE
    else process.env.SHIPGUARD_SAFE_MODE = prev
    if (dir) rmSync(dir, { recursive: true, force: true })
    vi.restoreAllMocks()
  })

  it('install id, notice marker and first-run marker write nothing', () => {
    setup()
    expect(getOrCreateInstallId(dir)).toBeUndefined()
    markNoticeShown(dir)
    expect(markFirstRunHandled(dir)).toBe(false)
    expect(readdirSync(dir)).toEqual([])
  })

  it('decideTelemetry says off with source safe-mode, and the scan JSON state is off', () => {
    setup()
    expect(decideTelemetry({ configDir: dir })).toEqual({ enabled: false, source: 'safe-mode' })
    expect(telemetryState({ configDir: dir })).toBe('off')
  })

  it('sendTelemetry and sendLifecycleEvent make no request and write no file, even on a published build', async () => {
    setup()
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const opts = { published: true, configDir: dir, env: { SHIPGUARD_SAFE_MODE: '1', SHIPGUARD_TELEMETRY_URL: 'https://sink.example/t' } }
    await sendTelemetry({ cliVersion: '0.13.0', verdict: 'safe', durationMs: 5, output: 'json' }, opts)
    await sendLifecycleEvent('cli_first_run', { cliVersion: '0.13.0' }, opts)
    await sendLifecycleEvent('cli_login', { cliVersion: '0.13.0' }, opts)
    vi.unstubAllGlobals()
    expect(fetchMock).not.toHaveBeenCalled()
    expect(stderr).not.toHaveBeenCalled() // no usage notice either
    expect(readdirSync(dir)).toEqual([])
  })

  it('announceSafeMode prints the fixed line once on stderr and only when on', () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    expect(announceSafeMode({}, ['node', 'cli.js'])).toBe(false)
    expect(stderr).not.toHaveBeenCalled()
    expect(announceSafeMode({ SHIPGUARD_SAFE_MODE: '1' }, ['node', 'cli.js'])).toBe(true)
    expect(announceSafeMode({ SHIPGUARD_SAFE_MODE: '1' }, ['node', 'cli.js'])).toBe(true)
    expect(stderr).toHaveBeenCalledTimes(1)
    expect(stderr).toHaveBeenCalledWith(SAFE_MODE_LINE + '\n')
    expect(SAFE_MODE_LINE).toBe('Safe mode: no usage pings, no writes outside the project except the sign-in token.')
    expect(SAFE_MODE_LINE.toLowerCase()).not.toContain('offline')
  })
})

describe('built CLI (published build, recorder replaces fetch): no network, nothing written under HOME', () => {
  let pub: RecordedCli
  let control: RecordedCli
  const ON = { SHIPGUARD_TELEMETRY: '1', DO_NOT_TRACK: '0' }

  beforeAll(() => {
    const path = buildVariant('published', 'safemode')
    pub = makeRecordedCli(path, { freshInstall: true })
    control = makeRecordedCli(path, { freshInstall: true })
  })
  afterAll(() => {
    pub?.cleanup()
    control?.cleanup()
  })

  const homeFiles = (home: string): string[] => (existsSync(home) ? readdirSync(home, { recursive: true }).map(String) : [])

  it('control: without safe mode the same scan pings and writes ~/.config/shipguard', async () => {
    const r = await control.run(['scan', control.project, '--json'], { env: ON })
    expect(r.attempts.length).toBeGreaterThan(0)
    expect(homeFiles(control.home).some((f) => f.includes('shipguard'))).toBe(true)
  })

  it('SHIPGUARD_SAFE_MODE=1: scan makes 0 requests and leaves HOME as it was', async () => {
    const before = homeFiles(pub.home)
    const r = await pub.run(['scan', pub.project, '--json'], { env: { ...ON, SHIPGUARD_SAFE_MODE: '1' } })
    expect(r.code).toBe(0)
    expect(() => JSON.parse(r.stdout)).not.toThrow()
    expect(r.attempts).toEqual([])
    expect(homeFiles(pub.home)).toEqual(before)
    expect(r.stderr).not.toContain('usage pings on')
  })

  it('SHIPGUARD_SAFE_MODE=1: telemetry status reports it', async () => {
    const r = await pub.run(['telemetry', 'status', '--json'], { env: { ...ON, SHIPGUARD_SAFE_MODE: '1' } })
    expect(JSON.parse(r.stdout)).toMatchObject({ enabled: false, source: 'safe-mode' })
    expect(r.attempts).toEqual([])
  })
})
