/**
 * G-10: the usage ping's verdict equals the run's verdict. An incomplete scan (an empty folder reads nothing) ends
 * DO_NOT_SHIP; it must ping `blocked`, not `review`. Spawns the built CLI against a local capture server.
 */
import { spawnSync, execSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { createServer } from 'node:http'
import { describe, it, expect, beforeAll, vi } from 'vitest'

vi.setConfig({ testTimeout: 60_000 })
const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

beforeAll(() => {
  if (!existsSync(distCli)) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
}, 120_000)

describe('usage ping verdict equals the run verdict (G-10)', () => {
  it('an incomplete DO_NOT_SHIP scan pings blocked', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sg-g10-'))
    let body: Record<string, unknown> | null = null
    const server = createServer((req, res) => {
      let data = ''
      req.on('data', (c) => (data += c))
      req.on('end', () => {
        try { body = JSON.parse(data) } catch { body = null }
        res.end('ok')
      })
    })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    const addr = server.address()
    const port = typeof addr === 'object' && addr ? addr.port : 0
    const run = spawnSync('node', [distCli, 'scan', dir, '--json'], {
      cwd: pkgRoot, encoding: 'utf-8', timeout: 30_000,
      env: { ...process.env, SHIPGUARD_TELEMETRY_URL: `http://127.0.0.1:${port}/cli-telemetry`, SHIPGUARD_TELEMETRY: '1', DO_NOT_TRACK: '0' },
    })
    await new Promise((r) => setTimeout(r, 1500))
    await new Promise((r) => server.close(r))
    rmSync(dir, { recursive: true, force: true })
    const recommendation = JSON.parse(run.stdout).recommendation as string
    expect(recommendation).toBe('DO_NOT_SHIP')
    expect(body).not.toBeNull()
    expect((body as unknown as Record<string, unknown>).verdict).toBe('blocked')
  })
})
