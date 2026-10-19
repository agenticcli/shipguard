/**
 * Regression: a CLI spawned from a test,
 * even with a stripped env (`{PATH, HOME}`) or none at all, must NOT attempt a telemetry send.
 *
 * Method: a preload (NODE_OPTIONS=--require) replaces the child's global fetch with a recorder, so
 * nothing ever leaves the machine, and every attempted URL is appended to a file. Fail-before (setup
 * file removed): the stripped-env scan records the prod Convex URL. Pass-after: zero attempts.
 * The canary test proves the recorder really sees a send, so the zero-assertions are not vacuous.
 */
import { spawnSync, execSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { spawnNode } from '../helpers/spawn-cli.js'
import { DEAD_TELEMETRY_URL, withTelemetryOff } from '../setup/telemetry-env.js'

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const distCli = resolve(pkgRoot, 'dist/cli.js')
const PROD_HOST = 'cheery-toucan-348.convex.site'

let work: string
let project: string
let recorder: string
let log: string

beforeAll(() => {
  if (!existsSync(distCli)) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  work = mkdtempSync(join(tmpdir(), 'sg-telemetry-'))
  project = join(work, 'proj')
  mkdirSync(project)
  writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }))
  writeFileSync(join(project, 'index.js'), 'console.log("hi")\n')
  log = join(work, 'attempts.log')
  recorder = join(work, 'record-fetch.cjs')
  writeFileSync(
    recorder,
    `const fs=require('fs');globalThis.fetch=function(u){fs.appendFileSync(${JSON.stringify(log)},String(u&&u.url||u)+'\\n');return Promise.resolve(new Response('ok'))}\n`,
  )
})
afterAll(() => rmSync(work, { recursive: true, force: true }))

const attempts = (): string[] => (existsSync(log) ? readFileSync(log, 'utf-8').split('\n').filter(Boolean) : [])
const reset = () => rmSync(log, { force: true })
const nodeOpts = () => `--require ${recorder}`

describe('spawned CLI never attempts a telemetry send from tests', () => {
  it('canary: the recorder DOES see a send when a loopback opt-in is explicit', async () => {
    reset()
    await spawnNode(distCli, ['scan', project, '--json', '--quiet'], {
      cwd: project,
      env: {
        PATH: process.env.PATH,
        HOME: work,
        NODE_OPTIONS: nodeOpts(),
        SHIPGUARD_TELEMETRY: '1',
        SHIPGUARD_TELEMETRY_URL: 'http://127.0.0.1:1/cli-telemetry',
      },
    })
    // Two sends on a fresh HOME: the one-off cli_first_run event, then the scan ping.
    expect(attempts()).toEqual(['http://127.0.0.1:1/cli-telemetry', 'http://127.0.0.1:1/cli-telemetry'])
  }, 30_000)

  it('stripped env {PATH, HOME} (the nrun.test.ts pattern) -> zero attempts', async () => {
    reset()
    await spawnNode(distCli, ['scan', project, '--json', '--quiet'], {
      cwd: project,
      env: { PATH: process.env.PATH, HOME: work, NODE_OPTIONS: nodeOpts() },
    })
    expect(attempts(), `telemetry attempted: ${attempts().join(', ')}`).toEqual([])
  }, 30_000)

  it('spawnSync with no env option at all -> zero attempts', () => {
    reset()
    process.env.NODE_OPTIONS = nodeOpts()
    try {
      spawnSync('node', [distCli, 'scan', project, '--json', '--quiet'], { cwd: project, encoding: 'utf-8' })
    } finally {
      delete process.env.NODE_OPTIONS
    }
    expect(attempts()).toEqual([])
  }, 30_000)

  it('execSync string command -> zero attempts', () => {
    reset()
    process.env.NODE_OPTIONS = nodeOpts()
    try {
      execSync(`node ${distCli} scan ${project} --json --quiet`, { cwd: project, stdio: 'pipe' })
    } catch {
      // A nonzero scan exit is irrelevant here; only telemetry attempts are asserted.
    } finally {
      delete process.env.NODE_OPTIONS
    }
    expect(attempts()).toEqual([])
  }, 30_000)

  it('explicit opt-in to a NON-loopback endpoint is neutralised -> zero attempts', async () => {
    reset()
    await spawnNode(distCli, ['scan', project, '--json', '--quiet'], {
      cwd: project,
      env: {
        PATH: process.env.PATH,
        HOME: work,
        NODE_OPTIONS: nodeOpts(),
        SHIPGUARD_TELEMETRY: '1',
        DO_NOT_TRACK: '0',
        SHIPGUARD_TELEMETRY_URL: `https://${PROD_HOST}/cli-telemetry`,
      },
    })
    expect(attempts()).toEqual([])
  }, 30_000)
})

describe('in-process guards', () => {
  it('this test process has telemetry off and a dead endpoint', () => {
    expect(process.env.SHIPGUARD_TELEMETRY).toBe('0')
    expect(process.env.DO_NOT_TRACK).toBe('1')
    expect(process.env.SHIPGUARD_TELEMETRY_URL).toBe(DEAD_TELEMETRY_URL)
  })

  it('withTelemetryOff forces opt-out on a stripped env and drops prod URLs, keeps loopback capture', () => {
    const off = withTelemetryOff({ PATH: '/bin' })
    expect(off).toMatchObject({ SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1', SHIPGUARD_TELEMETRY_URL: DEAD_TELEMETRY_URL })
    const prod = withTelemetryOff({ SHIPGUARD_TELEMETRY: '1', SHIPGUARD_TELEMETRY_URL: `https://${PROD_HOST}/x` })
    expect(prod.SHIPGUARD_TELEMETRY).toBe('0')
    const local = withTelemetryOff({ SHIPGUARD_TELEMETRY: '1', SHIPGUARD_TELEMETRY_URL: 'http://127.0.0.1:5/x' })
    expect(local.SHIPGUARD_TELEMETRY).toBe('1')
  })

  it('global fetch throws for the production telemetry host', () => {
    expect(() => fetch(`https://${PROD_HOST}/cli-telemetry`, { method: 'POST' })).toThrow(/test-guard/)
  })
})
