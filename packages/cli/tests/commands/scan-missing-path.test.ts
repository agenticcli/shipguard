/**
 * `shipguard scan <missing-path>` must fail cleanly (terminal-lab finding, issue-register row 263).
 *
 * Symptom: `shipguard scan /nonexistent` printed "Unhandled rejection: ENOENT ... chdir" and exited 3
 * with no telemetry, although the telemetry schema has verdict "error".
 * Exit-code decision: a path the user typed that does not exist (or is not a directory) is a
 * CONFIG/usage error = exit 2 - the same class as the existing "refusing to scan a non-project
 * directory" and bad-flag cases (see the exit-code contract in commands/scan.ts: 2 = config error,
 * 3 = runtime error where a valid scan could not run). It is not a runtime failure of a scan.
 *
 * Spawns the BUILT binary: in-process tests never exercise the real exit path.
 */
import { execSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { createServer, type Server } from 'node:http'
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'
import { spawnNode, type SpawnResult } from '../helpers/spawn-cli.js'

vi.setConfig({ testTimeout: 30_000 })

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

const tempDirs: string[] = []
function mkTmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'shipguard-missing-path-'))
  tempDirs.push(d)
  return d
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true })
})
beforeAll(() => {
  if (!existsSync(distCli)) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
}, 120_000)

interface Run extends SpawnResult {
  pings: Array<Record<string, unknown>>
}

/** Run the built CLI with telemetry pointed at a local capture server and an isolated HOME. */
async function run(args: string[], env: Record<string, string> = {}): Promise<Run> {
  const pings: Array<Record<string, unknown>> = []
  const server: Server = createServer((req, res) => {
    let data = ''
    req.on('data', (c) => (data += c))
    req.on('end', () => {
      try {
        const parsed = JSON.parse(data) as Record<string, unknown>
        // Schema 3 = one-off lifecycle events (cli_first_run); this file is about the scan ping.
        if (parsed.schema !== 3) pings.push(parsed)
      } catch { /* not JSON: ignore */ }
      res.statusCode = 200
      res.end('ok')
    })
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const addr = server.address()
  const port = typeof addr === 'object' && addr ? addr.port : 0
  try {
    const result = await spawnNode(distCli, args, {
      cwd: mkTmp(),
      env: {
        ...process.env,
        HOME: mkTmp(),
        SHIPGUARD_TELEMETRY_URL: `http://127.0.0.1:${port}/cli-telemetry`,
        SHIPGUARD_TELEMETRY: '1',
        DO_NOT_TRACK: '0',
        ...env,
      },
    })
    await new Promise((r) => setTimeout(r, 300))
    return { ...result, pings }
  } finally {
    await new Promise((r) => server.close(r))
  }
}

describe('scan with a missing / non-directory path', () => {
  it('prints a clean human error, exits 2, never "Unhandled rejection"', async () => {
    const r = await run(['scan', '/nonexistent-shipguard-path'])
    expect(r.stderr).not.toMatch(/Unhandled rejection|ENOENT|chdir/)
    expect(r.stderr).toMatch(/does not exist/i)
    expect(r.stderr).toContain('/nonexistent-shipguard-path')
    expect(r.code).toBe(2)
  })

  it('--json: stdout is exactly one error object with a stable code, exit 2', async () => {
    const r = await run(['scan', '/nonexistent-shipguard-path', '--json'])
    const parsed = JSON.parse(r.stdout)
    expect(parsed.code).toBe('PATH_NOT_FOUND')
    expect(typeof parsed.error).toBe('string')
    expect(r.code).toBe(2)
  })

  it('a path that is a file (not a directory) is the same config error', async () => {
    const dir = mkTmp()
    const file = join(dir, 'a.txt')
    writeFileSync(file, 'x')
    const r = await run(['scan', file, '--json'])
    expect(JSON.parse(r.stdout).code).toBe('PATH_NOT_A_DIRECTORY')
    expect(r.code).toBe(2)
  })

  it('sends one cli_run ping with verdict "error"', async () => {
    const r = await run(['scan', '/nonexistent-shipguard-path'])
    expect(r.pings).toHaveLength(1)
    expect(r.pings[0].verdict).toBe('error')
  })

  it('sends no ping when telemetry is opted out', async () => {
    const r = await run(['scan', '/nonexistent-shipguard-path'], { SHIPGUARD_TELEMETRY: '0' })
    expect(r.code).toBe(2)
    expect(r.pings).toHaveLength(0)
  })
})

// Every error exit of `scan` must send exactly one verdict "error" ping, through ONE helper.
describe('every scan error exit sends one error ping (central helper)', () => {
  it('bad policy file: exit 2 + error ping', async () => {
    const proj = mkTmp()
    writeFileSync(join(proj, 'package.json'), '{"name":"x"}')
    writeFileSync(join(proj, 'shipguard.policy.yml'), 'block: [unclosed\n  : :')
    const r = await run(['scan', proj])
    expect(r.code).toBe(2)
    expect(r.pings.map((p) => p.verdict)).toEqual(['error'])
  })

  it('non-project directory refusal: exit 2 + error ping', async () => {
    // run() uses an empty temp dir as cwd, which is not a project root.
    const r = await run(['scan'])
    expect(r.code).toBe(2)
    expect(r.pings.map((p) => p.verdict)).toEqual(['error'])
  })

  it('--pro that cannot fetch rules: exit 3 + error ping', async () => {
    const proj = mkTmp()
    writeFileSync(join(proj, 'package.json'), '{"name":"x"}')
    const r = await run(['scan', proj, '--pro', '--api-url', 'http://127.0.0.1:9'])
    expect(r.code).toBe(3)
    expect(r.pings.map((p) => p.verdict)).toEqual(['error'])
  })

  it('source guard: scan.ts has no bare error process.exit outside the central helper', () => {
    const src = readFileSync(resolve(pkgRoot, 'src/commands/scan.ts'), 'utf-8')
    const bare = src.match(/process\.exit\(EXIT_CODES\.(CONFIG_ERROR|RUNTIME_ERROR)\)/g) ?? []
    expect(bare).toHaveLength(0)
  })
})
