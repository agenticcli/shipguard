/**
 * B16 (BUG 2): `scan --json --strict | head -c 100`. The reader closes the pipe early (EPIPE).
 * The CLI must keep the exit code the scan computed (1), print no unhandled EPIPE stack and no
 * "Unexpected error", and not hang. Variant: telemetry ON with a slow local server, so the EPIPE
 * lands while the CLI is waiting for the ping (the case that used to reach handlers.ts and exit 3).
 *
 * B16 proves EPIPE handling only. The bare-process.exit proof belongs to B12/B13.
 */
import { spawn } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, cliPath, pkgRoot } from '../helpers/cli-fixture.js'
import { mkBigFindingsTree } from '../helpers/pipe-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

interface PipeRun {
  cliCode: number
  headBytes: number
  stderr: string
  ms: number
}

function runThroughHead(args: string[], env: NodeJS.ProcessEnv): Promise<PipeRun> {
  return new Promise((resolveRun, reject) => {
    const t0 = Date.now()
    // PIPESTATUS[0] is the CLI's own exit code; `wc -c` after head reports the bytes head kept.
    const script = 'node "$0" "$@" | head -c 100 | wc -c; echo "CLI_EXIT=${PIPESTATUS[0]}" >&2'
    const child = spawn('bash', ['-c', script, cliPath(), ...args], { cwd: pkgRoot, env, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    child.stdout.setEncoding('utf-8').on('data', (d: string) => { out += d })
    child.stderr.setEncoding('utf-8').on('data', (d: string) => { err += d })
    const killer = setTimeout(() => child.kill('SIGKILL'), 30_000)
    child.on('error', reject)
    child.on('close', () => {
      clearTimeout(killer)
      const m = err.match(/CLI_EXIT=(\d+)/)
      resolveRun({ cliCode: m ? Number(m[1]) : -1, headBytes: Number(out.trim()), stderr: err, ms: Date.now() - t0 })
    })
  })
}

function expectCleanStderr(stderr: string): void {
  expect(stderr).not.toMatch(/EPIPE/)
  expect(stderr).not.toMatch(/Unexpected error/)
  expect(stderr).not.toMatch(/Unhandled rejection/)
}

describe('strict JSON with a reader that closes early (B16)', () => {
  it('keeps exit code 1 under --strict, no EPIPE noise, no hang', async () => {
    const dir = mkBigFindingsTree(120)
    const run = await runThroughHead(['scan', dir, '--json', '--strict'], process.env)
    expect(run.headBytes).toBe(100)
    expect(run.cliCode).toBe(1)
    expectCleanStderr(run.stderr)
    expect(run.ms).toBeLessThan(10_000)
  })

  it('keeps exit code 0 without --strict', async () => {
    const dir = mkBigFindingsTree(120)
    const run = await runThroughHead(['scan', dir, '--json'], process.env)
    expect(run.cliCode).toBe(0)
    expectCleanStderr(run.stderr)
  })

  it('telemetry variant: EPIPE while waiting for a slow ping still exits 1 (not 3)', async () => {
    const dir = mkBigFindingsTree(120)
    let hits = 0
    const server: Server = createServer((req, res) => {
      hits++
      req.resume()
      // Answer only after the CLI's own 1 s abort, so it really waits for the ping.
      setTimeout(() => res.end('{}'), 3000).unref()
    })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    try {
      const port = (server.address() as AddressInfo).port
      // tests/setup/no-telemetry.ts forces telemetry off in the parent: undo it for this child only.
      const env: NodeJS.ProcessEnv = { ...process.env, SHIPGUARD_TELEMETRY_URL: `http://127.0.0.1:${port}/cli-telemetry` }
      delete env.SHIPGUARD_TELEMETRY
      delete env.DO_NOT_TRACK
      const run = await runThroughHead(['scan', dir, '--json', '--strict'], env)
      expect(hits, 'the ping must really have been attempted for this variant to mean anything').toBeGreaterThan(0)
      expect(run.cliCode).toBe(1)
      expectCleanStderr(run.stderr)
      expect(run.ms).toBeLessThan(15_000)
    } finally {
      server.closeAllConnections()
      await new Promise<void>((r) => server.close(() => r()))
    }
  })
})
