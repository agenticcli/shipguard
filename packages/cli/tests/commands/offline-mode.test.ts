/**
 * `shipguard scan --offline` (also SHIPGUARD_OFFLINE=1): the agent-safe mode.
 *
 * Promise under test: nothing is sent (no usage ping, no first-run ping, no rulebook / login calls),
 * nothing is written outside the project, `.gitignore` stays byte-identical, and the first output
 * line says so. `--offline` with `--pro` is a config error (exit 2) because `--pro` downloads rules.
 *
 * FAIL-BEFORE (0.11.0): `--offline` is an unknown option (exit 2), and a plain scan pings, writes
 * ~/.config/shipguard and appends `.shipguard/` to `.gitignore`.
 *
 * DISCIPLINE: behavioral. Spawns the built binary with a loopback capture server standing in for
 * the usage-ping endpoint and a fresh empty HOME, then asserts on what reached the server and disk.
 */
import { createServer, type Server } from 'node:http'
import { mkdtempSync, readdirSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, runCli } from '../helpers/cli-fixture.js'
import { OFFLINE_ANNOUNCE } from '../../src/core/offline.js'

vi.setConfig({ testTimeout: 30_000 })

const homes: string[] = []
const servers: Server[] = []
afterEach(() => {
  cleanupTrees()
  for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true })
  for (const s of servers.splice(0)) s.close()
})

function mkHome(): string {
  const h = mkdtempSync(join(tmpdir(), 'sg-offline-home-'))
  homes.push(h)
  return h
}

/** Loopback server that counts every request it receives. */
async function capture(): Promise<{ url: string; hits: () => number }> {
  let n = 0
  const server = createServer((req, res) => {
    req.on('data', () => undefined)
    req.on('end', () => {
      n++
      res.statusCode = 200
      res.end('ok')
    })
  })
  servers.push(server)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()))
  const addr = server.address()
  const port = typeof addr === 'object' && addr ? addr.port : 0
  return { url: `http://127.0.0.1:${port}/cli-telemetry`, hits: () => n }
}

const GITIGNORE = 'node_modules\n.env\n'
const files = { 'package.json': '{"name":"fixture"}', 'app.js': 'const x = 1\n', '.gitignore': GITIGNORE }

function pingEnv(url: string, home: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  // A loopback URL is the one sanctioned way for a test to keep telemetry on (tests/setup).
  return { HOME: home, SHIPGUARD_TELEMETRY_URL: url, SHIPGUARD_TELEMETRY: '1', DO_NOT_TRACK: '0', ...extra }
}

function tree(home: string): string[] {
  return readdirSync(home, { recursive: true }).map(String)
}

describe('--offline sends nothing and writes nothing', () => {
  it('control: the same scan without --offline pings, writes the config dir and edits .gitignore', async () => {
    const { url, hits } = await capture()
    const home = mkHome()
    const dir = mkTree(files, { git: true })
    const r = await runCli(['scan', dir, '--json'], { env: pingEnv(url, home) })
    expect(r.code).toBe(0)
    expect(hits()).toBeGreaterThan(0)
    expect(tree(home).length).toBeGreaterThan(0)
    expect(readFileSync(join(dir, '.gitignore'), 'utf-8')).not.toBe(GITIGNORE)
  })

  it('--offline: zero requests, empty HOME, .gitignore byte-identical, no .shipguard folder, no report files', async () => {
    const { url, hits } = await capture()
    const home = mkHome()
    const dir = mkTree(files, { git: true })
    const r = await runCli(['scan', dir, '--json', '--offline'], { env: pingEnv(url, home) })
    expect(r.code).toBe(0)
    await new Promise((res) => setTimeout(res, 300))
    expect(hits()).toBe(0)
    expect(tree(home)).toEqual([])
    expect(readFileSync(join(dir, '.gitignore'), 'utf-8')).toBe(GITIGNORE)
    expect(existsSync(join(dir, '.shipguard'))).toBe(false)
  })

  it('SHIPGUARD_OFFLINE=1 behaves the same as --offline', async () => {
    const { url, hits } = await capture()
    const home = mkHome()
    const dir = mkTree(files, { git: true })
    const r = await runCli(['scan', dir, '--json'], { env: pingEnv(url, home, { SHIPGUARD_OFFLINE: '1' }) })
    expect(r.code).toBe(0)
    await new Promise((res) => setTimeout(res, 300))
    expect(hits()).toBe(0)
    expect(tree(home)).toEqual([])
    expect(readFileSync(join(dir, '.gitignore'), 'utf-8')).toBe(GITIGNORE)
    expect(r.json?.mode).toBe('offline')
  })

  it('human mode: the first stdout line announces offline mode', async () => {
    const home = mkHome()
    const dir = mkTree(files, { git: true })
    const r = await runCli(['scan', dir, '--offline'], { env: { HOME: home } })
    expect(r.code).toBe(0)
    expect(r.stdout.split('\n')[0]).toBe(OFFLINE_ANNOUNCE)
  })

  it('--json: stdout stays one valid JSON document with mode "offline"; the same line is on stderr', async () => {
    const home = mkHome()
    const dir = mkTree(files, { git: true })
    const r = await runCli(['scan', dir, '--json', '--offline'], { env: { HOME: home } })
    expect(r.json).toBeDefined()
    expect(r.json?.mode).toBe('offline')
    expect(r.stderr.split('\n')[0]).toBe(OFFLINE_ANNOUNCE)
    expect(r.stdout.trimStart().startsWith('{')).toBe(true)
  })

  it('a normal scan has no offline announcement and no mode field', async () => {
    const home = mkHome()
    const dir = mkTree(files, { git: true })
    const r = await runCli(['scan', dir, '--json'], { env: { HOME: home } })
    expect(r.json?.mode).toBeUndefined()
    expect(r.stderr).not.toContain(OFFLINE_ANNOUNCE)
  })
})

describe('--offline with --pro is a config error', () => {
  it('exits 2 with one JSON error object on stdout', async () => {
    const home = mkHome()
    const dir = mkTree(files, { git: true })
    const r = await runCli(['scan', dir, '--json', '--offline', '--pro'], { env: { HOME: home } })
    expect(r.code).toBe(2)
    expect(r.json?.code).toBe('OFFLINE_WITH_PRO')
    expect(String(r.json?.error)).toMatch(/--offline/)
    expect(tree(home)).toEqual([])
  })

  it('exits 2 in human mode with a plain message', async () => {
    const home = mkHome()
    const dir = mkTree(files, { git: true })
    const r = await runCli(['scan', dir, '--offline', '--pro'], { env: { HOME: home } })
    expect(r.code).toBe(2)
    expect(r.stderr).toMatch(/--offline.*--pro|--pro.*--offline/)
  })

  it('SHIPGUARD_OFFLINE=1 with --pro is also exit 2', async () => {
    const home = mkHome()
    const dir = mkTree(files, { git: true })
    const r = await runCli(['scan', dir, '--json', '--pro'], { env: { HOME: home, SHIPGUARD_OFFLINE: '1' } })
    expect(r.code).toBe(2)
    expect(r.json?.code).toBe('OFFLINE_WITH_PRO')
  })
})

describe('commands that need the network refuse under offline mode', () => {
  const LINE = 'offline mode: this command needs the network'
  const cases: Array<[string, string[]]> = [
    ['login', ['login']],
    ['status', ['status']],
    ['rate', ['rate', '1', 'helpful']],
  ]
  for (const [name, args] of cases) {
    it(`${name}: exit 2, one line, nothing sent, nothing written`, async () => {
      const { url, hits } = await capture()
      const home = mkHome()
      const r = await runCli(args, { env: pingEnv(url, home, { SHIPGUARD_OFFLINE: '1' }) })
      expect(r.code).toBe(2)
      expect(r.stderr.trim().split('\n')).toHaveLength(1)
      expect(r.stderr).toContain(LINE)
      expect(r.stdout).toBe('')
      await new Promise((res) => setTimeout(res, 300))
      expect(hits()).toBe(0)
      expect(tree(home)).toEqual([])
    })
  }

  it('without offline mode the same command is not refused', async () => {
    const home = mkHome()
    const r = await runCli(['status'], { env: { HOME: home, SHIPGUARD_OFFLINE: '0' } })
    expect(r.code).toBe(0)
    expect(r.stderr).not.toContain(LINE)
  })

  it('commands that need no network still run (schema, hook outside git is a normal config error)', async () => {
    const home = mkHome()
    const r = await runCli(['schema', '--json'], { env: { HOME: home, SHIPGUARD_OFFLINE: '1' } })
    expect(r.code).toBe(0)
    expect(r.stderr).not.toContain(LINE)
  })
})

describe('SHIPGUARD_OFFLINE parsing fails closed (end to end)', () => {
  for (const v of ['1', 'true', 'yes', 'on', 'banana']) {
    it(`SHIPGUARD_OFFLINE=${v} turns offline mode on`, async () => {
      const home = mkHome()
      const dir = mkTree(files, { git: true })
      const r = await runCli(['scan', dir, '--json'], { env: { HOME: home, SHIPGUARD_OFFLINE: v } })
      expect(r.json?.mode).toBe('offline')
    })
  }
  for (const v of ['0', 'false', 'no', 'off', '']) {
    it(`SHIPGUARD_OFFLINE=${JSON.stringify(v)} leaves it off`, async () => {
      const home = mkHome()
      const dir = mkTree(files, { git: true })
      const r = await runCli(['scan', dir, '--json'], { env: { HOME: home, SHIPGUARD_OFFLINE: v } })
      expect(r.json?.mode).toBeUndefined()
    })
  }
})
