/**
 * C4 unit tests: the pseudonymous install id and CI detection.
 * Contract: agenticcli docs/posthog/contracts/cli-telemetry-v2.md sections 4 and 6.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { detectCi, sendTelemetry } from '../../src/core/telemetry.js'
import { UUID_V4, getOrCreateInstallId, readInstallId, resetInstallId } from '../../src/core/telemetry-config.js'

let dir: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sg-tel-id-'))
})
afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('install id store', () => {
  it('is created lazily as a random v4 uuid, 0600, and is stable', () => {
    expect(readInstallId(dir)).toBeUndefined()
    expect(existsSync(join(dir, 'telemetry.json'))).toBe(false)
    const id = getOrCreateInstallId(dir)
    expect(id).toMatch(UUID_V4)
    expect(getOrCreateInstallId(dir)).toBe(id)
    expect(statSync(join(dir, 'telemetry.json')).mode & 0o777).toBe(0o600)
  })
  it('two installs never share an id', () => {
    const other = mkdtempSync(join(tmpdir(), 'sg-tel-id2-'))
    try {
      expect(getOrCreateInstallId(dir)).not.toBe(getOrCreateInstallId(other))
    } finally {
      rmSync(other, { recursive: true, force: true })
    }
  })
  it('keeps unknown keys and replaces a malformed stored id', () => {
    writeFileSync(join(dir, 'telemetry.json'), JSON.stringify({ enabled: true, custom: 1, installId: '/home/alice' }))
    const id = getOrCreateInstallId(dir)
    expect(id).toMatch(UUID_V4)
    expect(JSON.parse(readFileSync(join(dir, 'telemetry.json'), 'utf-8'))).toEqual({ enabled: true, custom: 1, installId: id })
  })
  it('tightens a pre-existing loose file to 0600', () => {
    writeFileSync(join(dir, 'telemetry.json'), '{}', { mode: 0o644 })
    getOrCreateInstallId(dir)
    expect(statSync(join(dir, 'telemetry.json')).mode & 0o777).toBe(0o600)
  })
  it('reset removes only the id and returns the old one', () => {
    writeFileSync(join(dir, 'telemetry.json'), JSON.stringify({ enabled: false }))
    const id = getOrCreateInstallId(dir)
    expect(resetInstallId(dir)).toEqual({ hadId: true, oldId: id })
    expect(JSON.parse(readFileSync(join(dir, 'telemetry.json'), 'utf-8'))).toEqual({ enabled: false })
    expect(resetInstallId(dir).hadId).toBe(false)
  })
  it('an unwritable config dir yields no id (never a fresh id per run)', () => {
    const blocker = join(dir, 'file')
    writeFileSync(blocker, 'x')
    expect(getOrCreateInstallId(join(blocker, 'sub'))).toBeUndefined()
  })
})

describe('detectCi', () => {
  it('is false for an empty env and for CI=false/0/empty', () => {
    expect(detectCi({})).toBe(false)
    for (const v of ['false', 'FALSE', '0', '']) expect(detectCi({ CI: v })).toBe(false)
  })
  it('is true for CI=true/1 and for each provider variable', () => {
    expect(detectCi({ CI: 'true' })).toBe(true)
    expect(detectCi({ CI: '1' })).toBe(true)
    for (const k of ['GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI', 'TRAVIS', 'BUILDKITE', 'JENKINS_URL', 'TF_BUILD', 'TEAMCITY_VERSION', 'BITBUCKET_BUILD_NUMBER', 'APPVEYOR', 'DRONE', 'CODEBUILD_BUILD_ID']) {
      expect(detectCi({ [k]: '1' }), k).toBe(true)
      expect(detectCi({ [k]: '' }), `${k} empty (presence is enough)`).toBe(true)
    }
  })
})

describe('sendTelemetry and the install id', () => {
  const base = { SHIPGUARD_TELEMETRY_URL: 'https://sink.example/t' }
  const input = { cliVersion: '1.2.3', verdict: 'safe' as const, durationMs: 50 }
  function stub() {
    const f = vi.fn().mockResolvedValue(new Response('ok'))
    vi.stubGlobal('fetch', f)
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    return f
  }
  const bodyOf = (f: ReturnType<typeof vi.fn>) => JSON.parse((f.mock.calls[0] as [string, RequestInit])[1].body as string)

  it('non-CI: sends the saved id; CI: sends null and creates nothing', async () => {
    const f = stub()
    await sendTelemetry(input, { published: true, env: base, configDir: dir })
    const id = readInstallId(dir)
    expect(bodyOf(f)).toMatchObject({ schema: 2, installId: id, ci: false, provenance: 'published', durationBucket: 'lt1s' })

    const ciDir = mkdtempSync(join(tmpdir(), 'sg-tel-ci-'))
    try {
      const g = stub()
      await sendTelemetry(input, { published: true, env: { ...base, GITHUB_ACTIONS: 'true' }, configDir: ciDir })
      expect(bodyOf(g)).toMatchObject({ installId: null, ci: true })
      expect(existsSync(join(ciDir, 'telemetry.json'))).toBe(false)
    } finally {
      rmSync(ciDir, { recursive: true, force: true })
    }
  })
  it('disabled or dev (no loopback URL): no id is created', async () => {
    const f = stub()
    await sendTelemetry(input, { published: true, env: { ...base, DO_NOT_TRACK: 'true' }, configDir: dir })
    await sendTelemetry(input, { published: false, env: base, configDir: dir })
    expect(f).not.toHaveBeenCalled()
    expect(existsSync(join(dir, 'telemetry.json'))).toBe(false)
  })
  it('does not send when the id cannot be saved', async () => {
    const f = stub()
    const blocker = join(dir, 'file')
    writeFileSync(blocker, 'x')
    await sendTelemetry(input, { published: true, env: base, configDir: join(blocker, 'sub') })
    expect(f).not.toHaveBeenCalled()
  })
  it('the body never contains paths or the project dir', async () => {
    const f = stub()
    await sendTelemetry(input, { published: true, env: base, configDir: dir, projectDir: '/home/alice/secret-repo' })
    expect((f.mock.calls[0] as [string, RequestInit])[1].body).not.toMatch(/alice|secret-repo|\/home/)
  })
})
