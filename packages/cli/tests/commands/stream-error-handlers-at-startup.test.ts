/**
 * QA (2026-11-02, qa-final on ed3a6ae9): plan A5 / judge R3 decision 2, "EPIPE handlers installed AT
 * STARTUP in cli.ts, before parseAsync, for stdout and stderr".
 *
 * Why this test exists: the plan's mutation row "EPIPE handlers installed late (in setExitCode instead
 * of cli.ts startup) must turn the B16 telemetry-delay variant red" does NOT hold on this tree. On
 * Node 24, console.log guards its own write, so B16 passes even with the handlers moved (QA mutation
 * M11: 9 of 9 rows green). This test observes the property directly: after the JSON has been written
 * and while the CLI still waits for a slow telemetry ping, process.stdout must already carry a
 * persistent 'error' listener. With the handlers installed late the count is 0 in that window.
 */
import { spawn } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, cliPath, mkTree, pkgRoot, ENV_KEY_LINE } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

const PROBE = resolve(dirname(fileURLToPath(import.meta.url)), '../helpers/stdout-listener-probe.mjs')

function runProbed(args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolveRun, reject) => {
    const child = spawn(process.execPath, ['--import', PROBE, cliPath(), ...args], { cwd: pkgRoot, env, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    child.stdout.setEncoding('utf-8').on('data', (d: string) => { out += d })
    child.stderr.setEncoding('utf-8').on('data', (d: string) => { err += d })
    const killer = setTimeout(() => child.kill('SIGKILL'), 30_000)
    child.on('error', reject)
    child.on('close', (code) => {
      clearTimeout(killer)
      resolveRun({ code, stdout: out, stderr: err })
    })
  })
}

describe('QA: stdout/stderr error handlers exist from startup, not only at exit', () => {
  it('while the CLI waits for a slow telemetry ping after writing --json --strict, stdout already has an error listener', async () => {
    const dir = mkTree({ 'cfg.env': ENV_KEY_LINE, 'package.json': '{"name":"probe"}' })
    let hits = 0
    const server: Server = createServer((req, res) => {
      hits++
      req.resume()
      setTimeout(() => res.end('{}'), 3000).unref()
    })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    try {
      const port = (server.address() as AddressInfo).port
      // tests/setup/no-telemetry.ts forces telemetry off in the parent: undo it for this child only.
      // A throwaway HOME keeps the telemetry notice marker and install id out of the real config dir.
      const env: NodeJS.ProcessEnv = { ...process.env, HOME: mkTree({}), SHIPGUARD_TELEMETRY_URL: `http://127.0.0.1:${port}/cli-telemetry` }
      delete env.SHIPGUARD_TELEMETRY
      delete env.DO_NOT_TRACK
      const run = await runProbed(['scan', dir, '--json', '--strict'], env)
      expect(hits, 'the ping must really have been attempted, or there is no waiting window to observe').toBeGreaterThan(0)
      const m = run.stderr.match(/STDOUT_ERROR_LISTENERS=(\d+)/)
      expect(m, `probe line missing; stderr: ${run.stderr.slice(0, 300)}`).not.toBeNull()
      expect(Number(m![1])).toBeGreaterThanOrEqual(1)
      expect(JSON.parse(run.stdout).schemaVersion).toBe('6')
      expect(run.code).toBe(1)
    } finally {
      server.closeAllConnections()
      await new Promise<void>((r) => server.close(() => r()))
    }
  })
})
