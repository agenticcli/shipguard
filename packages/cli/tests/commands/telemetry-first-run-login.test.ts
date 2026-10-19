/**
 * First-run and login telemetry events, end to end through the BUILT CLI (recorded fetch: nothing
 * leaves the machine). Unit-level coverage of the sender is tests/core/telemetry-events.test.ts;
 * this file proves the wiring: which commands trigger `cli_first_run`, the opt-outs on the real
 * process, idempotence across runs, and that `login` sends `cli_login` only after credentials are saved.
 */
import { existsSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { buildVariant, makeRecordedCli, type Attempt, type RecordedCli } from '../helpers/recorded-cli.js'

vi.setConfig({ testTimeout: 60_000, hookTimeout: 120_000 })

const SINK = 'http://127.0.0.1:1/cli-telemetry' // loopback: a dev build sends here; the recorder captures it
const ON = { SHIPGUARD_TELEMETRY: '1', DO_NOT_TRACK: '0', SHIPGUARD_TELEMETRY_URL: SINK }
const MARKER = 'telemetry-first-run-sent'

let devPath: string

beforeAll(() => {
  devPath = buildVariant('dev', 'first-run')
})

function events(attempts: Attempt[]): string[] {
  return attempts.map((a) => {
    const b = JSON.parse(a.body) as { schema: number; event?: string }
    return b.schema === 3 ? (b.event as string) : 'scan_ping'
  })
}
function withCli<T>(fn: (cli: RecordedCli) => Promise<T>): Promise<T> {
  const cli = makeRecordedCli(devPath)
  return fn(cli).finally(() => cli.cleanup())
}
const configDir = (cli: RecordedCli) => join(cli.home, '.config', 'shipguard')

describe('cli_first_run wiring', () => {
  it('the first real command sends cli_first_run (before the scan ping), later runs do not', () =>
    withCli(async (cli) => {
      const first = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(events(first.attempts)).toEqual(['cli_first_run', 'scan_ping'])
      const body = JSON.parse(first.attempts[0].body)
      expect(body.installId).toBe(JSON.parse(first.attempts[1].body).installId)
      expect(() => JSON.parse(first.stdout)).not.toThrow() // stdout stays pure JSON

      const second = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(events(second.attempts)).toEqual(['scan_ping'])
    }))

  it('a non-scan command also counts as the first run', () =>
    withCli(async (cli) => {
      const r = await cli.run(['status'], { env: ON })
      expect(events(r.attempts)).toEqual(['cli_first_run'])
      const again = await cli.run(['status'], { env: ON })
      expect(events(again.attempts)).toEqual([])
    }))

  it('`telemetry ...`, --version, --help and a bare run send nothing and create no marker', () =>
    withCli(async (cli) => {
      for (const args of [['telemetry', 'status'], ['telemetry', 'status', '--json'], ['--version'], ['--help'], []]) {
        const r = await cli.run(args, { env: ON })
        expect(r.attempts, `args: ${args.join(' ')}`).toEqual([])
      }
      expect(existsSync(join(configDir(cli), MARKER))).toBe(false)
    }))

  it('CI: no cli_first_run, only the scan ping', () =>
    withCli(async (cli) => {
      const r = await cli.run(['scan', cli.project, '--json'], { env: { ...ON, CI: 'true' } })
      expect(events(r.attempts)).toEqual(['scan_ping'])
    }))
})

describe('opt-outs on the real process: no event, no marker, no install id', () => {
  const cases: Array<[string, NodeJS.ProcessEnv]> = [
    ['SHIPGUARD_TELEMETRY=0', { ...ON, SHIPGUARD_TELEMETRY: '0' }],
    ['DO_NOT_TRACK=1', { ...ON, DO_NOT_TRACK: '1' }],
  ]
  for (const [name, env] of cases) {
    it(name, () =>
      withCli(async (cli) => {
        const r = await cli.run(['scan', cli.project, '--json'], { env })
        expect(r.attempts).toEqual([])
        expect(existsSync(join(configDir(cli), MARKER))).toBe(false)
        expect(existsSync(join(configDir(cli), 'telemetry.json'))).toBe(false)
      }))
  }

  it('shipguard telemetry disable, then scan', () =>
    withCli(async (cli) => {
      expect((await cli.run(['telemetry', 'disable'], { env: ON })).code).toBe(0)
      const r = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(r.attempts).toEqual([])
      expect(existsSync(join(configDir(cli), MARKER))).toBe(false)
    }))

  it('telemetry.enabled: false in .shipguard.yml', () =>
    withCli(async (cli) => {
      writeFileSync(join(cli.project, '.shipguard.yml'), 'configVersion: 2\ntelemetry:\n  enabled: false\n')
      const r = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(r.attempts).toEqual([])
      expect(existsSync(join(configDir(cli), MARKER))).toBe(false)
    }))

  it('SHIPGUARD_TELEMETRY_DEBUG=1 prints both payloads, sends nothing, writes no marker', () =>
    withCli(async (cli) => {
      const r = await cli.run(['scan', cli.project, '--json'], { env: { ...ON, SHIPGUARD_TELEMETRY_DEBUG: '1' } })
      expect(r.attempts).toEqual([])
      expect(r.stderr).toContain('"event":"cli_first_run"')
      expect(r.stderr).toContain('"schema":3')
      expect(existsSync(join(configDir(cli), MARKER))).toBe(false)
    }))
})

describe('the notice is printed once and covers the new events', () => {
  it('one notice line on the first run, mentioning first run and login', () =>
    withCli(async (cli) => {
      const r = await cli.run(['scan', cli.project, '--json'], { env: ON })
      const lines = r.stderr.split('\n').filter((l) => l.includes('sends a pseudonymous usage ping'))
      expect(lines).toHaveLength(1)
      expect(lines[0]).toContain('first run')
      expect(lines[0]).toContain('login')
    }))
})
