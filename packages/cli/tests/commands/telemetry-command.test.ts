/**
 * C3 e2e: the built CLI, real process, real exit codes. Nothing can leave the
 * machine (tests/helpers/recorded-cli.ts replaces fetch in every CLI run with a recorder).
 */
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { UUID_V4 } from '../../src/core/telemetry-config.js'
import { buildVariant, makeRecordedCli, type RecordedCli } from '../helpers/recorded-cli.js'

vi.setConfig({ testTimeout: 60_000, hookTimeout: 120_000 })

const SINK = 'http://127.0.0.1:1/cli-telemetry' // loopback: a dev build sends here; the recorder captures it
const ON = { SHIPGUARD_TELEMETRY: '1', DO_NOT_TRACK: '0', SHIPGUARD_TELEMETRY_URL: SINK }
const NOTICE_MARK = 'sends a pseudonymous usage ping'

let devPath: string
let dev: RecordedCli
let pub: RecordedCli

beforeAll(() => {
  devPath = buildVariant('dev', 'c3')
  dev = makeRecordedCli(devPath)
  pub = makeRecordedCli(buildVariant('published', 'c3'))
})
afterAll(() => {
  dev?.cleanup()
  pub?.cleanup()
})

function stdoutIsPureJson(stdout: string): void {
  expect(() => JSON.parse(stdout)).not.toThrow()
}

describe('one-line stderr notice before the first ping, in every mode, once per install', () => {
  const modes: Array<[string, string[], NodeJS.ProcessEnv]> = [
    ['human', [], {}],
    ['--json', ['--json'], {}],
    ['--quiet', ['--quiet'], {}],
    ['--sarif', ['--sarif'], {}],
    ['CI=true', ['--json'], { CI: 'true' }],
  ]
  for (const [name, flags, extra] of modes) {
    it(`${name}: notice on stderr (never stdout), then silent on the next run`, async () => {
      const cli = makeRecordedCli(devPath)
      try {
        const first = await cli.run(['scan', cli.project, ...flags], { env: { ...ON, ...extra } })
        expect(first.attempts).toHaveLength(1)
        const noticeLines = first.stderr.split('\n').filter((l) => l.includes(NOTICE_MARK))
        expect(noticeLines).toHaveLength(1)
        for (const s of ['SHIPGUARD_TELEMETRY=0', 'DO_NOT_TRACK=1', 'shipguard telemetry disable']) {
          expect(noticeLines[0]).toContain(s)
        }
        expect(first.stdout).not.toContain(NOTICE_MARK)
        if (flags.includes('--json') || flags.includes('--sarif')) stdoutIsPureJson(first.stdout)

        const second = await cli.run(['scan', cli.project, ...flags], { env: { ...ON, ...extra } })
        expect(second.attempts).toHaveLength(1)
        expect(second.stderr).not.toContain(NOTICE_MARK)
      } finally {
        cli.cleanup()
      }
    })
  }

  it('no notice and no ping when telemetry is opted out', async () => {
    const r = await dev.run(['scan', dev.project, '--json'], { env: { ...ON, SHIPGUARD_TELEMETRY: '0' } })
    expect(r.attempts).toEqual([])
    expect(r.stderr).not.toContain(NOTICE_MARK)
  })
})

describe('telemetry.enabled: false is honoured (was: read by nothing)', () => {
  it('.shipguard.yml (written by the first `scan --pro`): flipping enabled to false stops the ping and the notice', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      const cfg = join(cli.project, '.shipguard.yml')
      writeFileSync(cfg, 'configVersion: 2\ntelemetry:\n  enabled: true\n')
      const on = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(on.attempts).toHaveLength(1)

      writeFileSync(cfg, 'configVersion: 2\ntelemetry:\n  enabled: false\n')
      const off = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(off.attempts, 'fail-before: telemetry.enabled was never read').toEqual([])
      expect(off.stderr).not.toContain(NOTICE_MARK)
      const st = await cli.run(['telemetry', 'status', '--json'], { env: {} })
      expect(JSON.parse(st.stdout)).toMatchObject({ enabled: false, source: 'project-policy' })
    } finally {
      cli.cleanup()
    }
  })

  it('shipguard.policy.yml (written by `shipguard init`): appending telemetry.enabled: false stops the ping', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      const init = await cli.run(['init'], { env: {} })
      expect(init.code).toBe(0)
      const policyPath = join(cli.project, 'shipguard.policy.yml')
      expect(existsSync(policyPath)).toBe(true)
      const on = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(on.attempts).toHaveLength(1)

      writeFileSync(policyPath, readFileSync(policyPath, 'utf-8') + 'telemetry:\n  enabled: false\n')
      const off = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(off.attempts).toEqual([])
      expect(off.code).toBe(0)
    } finally {
      cli.cleanup()
    }
  })
})

describe('shipguard telemetry status | enable | disable', () => {
  it('status --json reports provenance, state and source; stdout is pure JSON', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      const s = await cli.run(['telemetry', 'status', '--json'], { env: {} })
      expect(s.code).toBe(0)
      const j = JSON.parse(s.stdout)
      expect(j).toMatchObject({ enabled: true, source: 'default', provenance: 'dev', endpoint: null })
      const withEnv = await cli.run(['telemetry', 'status', '--json'], { env: { DO_NOT_TRACK: '1' } })
      expect(JSON.parse(withEnv.stdout)).toMatchObject({ enabled: false, source: 'env:DO_NOT_TRACK' })
      expect(s.attempts).toEqual([])
    } finally {
      cli.cleanup()
    }
  })

  it('published build reports provenance=published and the prod relay as its endpoint', async () => {
    const s = await pub.run(['telemetry', 'status', '--json'], { env: {} })
    expect(JSON.parse(s.stdout)).toMatchObject({
      provenance: 'published',
      endpoint: 'https://cheery-toucan-348.convex.site/cli-telemetry',
    })
    expect(s.attempts).toEqual([])
  })

  it('disable persists across runs, stops pings; enable turns them back on', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      const d = await cli.run(['telemetry', 'disable'], { env: {} })
      expect(d.code).toBe(0)
      expect(JSON.parse((await cli.run(['telemetry', 'status', '--json'], { env: {} })).stdout)).toMatchObject({
        enabled: false,
        source: 'user-config',
      })
      const scan = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(scan.attempts).toEqual([])
      expect(scan.stderr).not.toContain(NOTICE_MARK)

      const e = await cli.run(['telemetry', 'enable'], { env: {} })
      expect(e.code).toBe(0)
      const scan2 = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(scan2.attempts).toHaveLength(1)
    } finally {
      cli.cleanup()
    }
  })

  it('unknown subcommand is a usage error (exit 2), not a silent success', async () => {
    const r = await dev.run(['telemetry', 'bogus'], { env: {} })
    expect(r.code).toBe(2)
  })
})

describe('SHIPGUARD_TELEMETRY_DEBUG=1 prints the exact payload and sends nothing', () => {
  it('published build, default endpoint: payload on stderr, zero attempts, stdout JSON intact', async () => {
    const r = await pub.run(['scan', pub.project, '--json'], {
      env: { SHIPGUARD_TELEMETRY: '1', DO_NOT_TRACK: '0', SHIPGUARD_TELEMETRY_DEBUG: '1' },
    })
    expect(r.attempts).toEqual([])
    stdoutIsPureJson(r.stdout)
    const m = r.stderr.match(/\[shipguard:telemetry\][^\n]*?(\{"schema":2.*\})/)
    expect(m, r.stderr).not.toBeNull()
    const payload = JSON.parse(m![1])
    expect(Object.keys(payload).sort()).toEqual([
      'ci', 'cliVersion', 'durationBucket', 'eventId', 'installId', 'provenance', 'schema', 'verdict',
    ])
    expect(payload).toMatchObject({ schema: 2, provenance: 'published', ci: false })
    expect(payload.installId).toMatch(UUID_V4)
  })
})

describe('a --strict exit no longer loses the ping, and the exit code is unchanged', () => {
  it('blocked scan with --strict: exit 1 AND the (slow) ping was delivered before exit', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      // A hardcoded secret the free rules block on.
      writeFileSync(
        join(cli.project, 'leak.js'),
        'const k = "sk_live_' + 'abcdefghijklmnopqrstuvwx' + '"\nconst aws = "AKIA' + 'IOSFODNN7EXAMPLE' + '"\n',
      )
      const lenient = await cli.run(['scan', cli.project, '--json'], { env: ON })
      const verdict = JSON.parse(lenient.stdout).recommendation
      const strict = await cli.run(['scan', cli.project, '--json', '--strict'], { env: ON, fetchDelayMs: 400 })
      expect(verdict).not.toBe('SAFE_TO_SHIP') // the fixture really is unsafe
      expect(strict.code).toBe(1)
      expect(strict.attempts, 'fail-before: process.exit dropped the in-flight ping').toHaveLength(1)
      stdoutIsPureJson(strict.stdout)
    } finally {
      cli.cleanup()
    }
  })

  it('a hung endpoint cannot delay a strict exit beyond ~1.5 s or change its code', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      writeFileSync(join(cli.project, 'leak.js'), 'const aws = "AKIA' + 'IOSFODNN7EXAMPLE' + '"\n')
      const t0 = Date.now()
      const r = await cli.run(['scan', cli.project, '--json', '--strict'], { env: ON, fetchDelayMs: 60_000 })
      const dt = Date.now() - t0
      expect(r.code).toBe(1)
      expect(dt).toBeLessThan(6000) // process start + scan + <=1.5s bound (generous for a loaded box)
    } finally {
      cli.cleanup()
    }
  })
})

describe('C4: pseudonymous install id, v2 payload, never in CI, telemetry reset', () => {
  const V2 = ['ci', 'cliVersion', 'durationBucket', 'eventId', 'installId', 'provenance', 'schema', 'verdict']
  const sent = (r: { attempts: Array<{ body: string }> }) => JSON.parse(r.attempts[0].body) as Record<string, unknown>

  it('human run: v2 payload with a random v4 install id, saved 0600 next to other keys, stable across runs', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      writeFileSync(join(cli.home, '.keep'), '')
      const a = await cli.run(['scan', cli.project, '--json'], { env: ON })
      const pa = sent(a)
      expect(Object.keys(pa).sort()).toEqual(V2)
      expect(pa).toMatchObject({ schema: 2, provenance: 'dev', ci: false, durationBucket: expect.stringMatching(/^(lt1s|1to5s|5to30s|gt30s)$/) })
      expect(pa.installId).toMatch(UUID_V4)
      expect(pa.eventId).toMatch(UUID_V4)
      const file = join(cli.home, '.config', 'shipguard', 'telemetry.json')
      expect(JSON.parse(readFileSync(file, 'utf-8')).installId).toBe(pa.installId)
      expect(statSync(file).mode & 0o777).toBe(0o600)
      const b = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(sent(b).installId).toBe(pa.installId)
      expect(sent(b).eventId).not.toBe(pa.eventId)
      // never the path, repo or anything else local
      expect(a.attempts[0].body).not.toContain(cli.project)
      expect(a.attempts[0].body).not.toContain(cli.home)
    } finally {
      cli.cleanup()
    }
  })

  const CI_ENVS: Array<[string, NodeJS.ProcessEnv]> = [
    ['CI=true', { CI: 'true' }],
    ['GITHUB_ACTIONS', { GITHUB_ACTIONS: 'true' }],
    ['GITLAB_CI', { GITLAB_CI: 'true' }],
    ['JENKINS_URL', { JENKINS_URL: 'http://j' }],
    ['BUILDKITE', { BUILDKITE: 'true' }],
  ]
  for (const [name, env] of CI_ENVS) {
    it(`${name}: ci=true, installId null, no id created on disk`, async () => {
      const cli = makeRecordedCli(devPath)
      try {
        const r = await cli.run(['scan', cli.project, '--json'], { env: { ...ON, ...env } })
        expect(sent(r)).toMatchObject({ ci: true, installId: null })
        const file = join(cli.home, '.config', 'shipguard', 'telemetry.json')
        expect(existsSync(file) && readFileSync(file, 'utf-8').includes('installId')).toBe(false)
      } finally {
        cli.cleanup()
      }
    })
  }

  it('CI=false is not CI', async () => {
    const r = await dev.run(['scan', dev.project, '--json'], { env: { ...ON, CI: 'false' } })
    expect(sent(r).ci).toBe(false)
    expect(sent(r).installId).toMatch(UUID_V4)
  })

  it('an id made on a laptop is not sent from CI that shares the same HOME', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      const h = await cli.run(['scan', cli.project, '--json'], { env: ON })
      const ci = await cli.run(['scan', cli.project, '--json'], { env: { ...ON, CI: 'true' } })
      expect(sent(h).installId).toMatch(UUID_V4)
      expect(sent(ci).installId).toBeNull()
    } finally {
      cli.cleanup()
    }
  })

  it('status shows install id presence and provenance; reset gives a new id and says past events can be deleted', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      const none = JSON.parse((await cli.run(['telemetry', 'status', '--json'], { env: {} })).stdout)
      expect(none).toMatchObject({ installIdPresent: false, installId: null, provenance: 'dev' })
      const first = sent(await cli.run(['scan', cli.project, '--json'], { env: ON }))
      const st = JSON.parse((await cli.run(['telemetry', 'status', '--json'], { env: {} })).stdout)
      expect(st).toMatchObject({ installIdPresent: true, installId: first.installId })

      const reset = await cli.run(['telemetry', 'reset'], { env: {} })
      expect(reset.code).toBe(0)
      expect(reset.stdout).toContain(first.installId as string)
      expect(reset.stdout).toMatch(/deleted on request/)
      expect(JSON.parse((await cli.run(['telemetry', 'status', '--json'], { env: {} })).stdout).installIdPresent).toBe(false)

      const second = sent(await cli.run(['scan', cli.project, '--json'], { env: ON }))
      expect(second.installId).toMatch(UUID_V4)
      expect(second.installId).not.toBe(first.installId)
      // reset on an empty config is a clean no-op
      const fresh = makeRecordedCli(devPath)
      try {
        expect((await fresh.run(['telemetry', 'reset'], { env: {} })).code).toBe(0)
      } finally {
        fresh.cleanup()
      }
    } finally {
      cli.cleanup()
    }
  })

  it('reset keeps other keys (enabled=false survives)', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      await cli.run(['scan', cli.project, '--json'], { env: ON })
      await cli.run(['telemetry', 'disable'], { env: {} })
      await cli.run(['telemetry', 'reset'], { env: {} })
      const cfg = JSON.parse(readFileSync(join(cli.home, '.config', 'shipguard', 'telemetry.json'), 'utf-8'))
      expect(cfg).toEqual({ enabled: false })
    } finally {
      cli.cleanup()
    }
  })

  it('opted out: no id is created at all', async () => {
    const cli = makeRecordedCli(devPath)
    try {
      await cli.run(['scan', cli.project, '--json'], { env: { ...ON, DO_NOT_TRACK: 'true' } })
      expect(existsSync(join(cli.home, '.config', 'shipguard', 'telemetry.json'))).toBe(false)
    } finally {
      cli.cleanup()
    }
  })
})
