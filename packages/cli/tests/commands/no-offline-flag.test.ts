/**
 * `--offline` was tried in the 0.12 prep and removed before release: it is not a ShipGuard option.
 * Pass: `scan --offline` is an unknown option (exit 2), `--help` does not list it, and
 * SHIPGUARD_OFFLINE=1 does nothing (the scan runs normally, no `mode` field).
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, runCli } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 30_000 })
afterEach(cleanupTrees)

const CLEAN = { 'package.json': '{"name":"fixture"}', 'ok.js': 'const ok = 1\n' }
const NOPING = { SHIPGUARD_TELEMETRY: '0' }

describe('no --offline flag', () => {
  it('scan --offline is an unknown option, exit 2', async () => {
    const dir = mkTree(CLEAN)
    const r = await runCli(['scan', dir, '--offline'], { env: NOPING })
    expect(r.code).toBe(2)
    expect(r.stdout + r.stderr).toMatch(/unknown option.*--offline/i)
  })

  it('scan --help does not mention offline', async () => {
    const r = await runCli(['scan', '--help'], { env: NOPING })
    expect(r.stdout + r.stderr).not.toMatch(/offline/i)
  })

  it('SHIPGUARD_OFFLINE=1 is ignored: normal scan, no mode field', async () => {
    const dir = mkTree(CLEAN)
    const r = await runCli(['scan', dir, '--json'], { env: { ...NOPING, SHIPGUARD_OFFLINE: '1' } })
    expect(r.code).toBe(0)
    expect(r.json).toBeDefined()
    expect(r.json).not.toHaveProperty('mode')
    expect(r.stdout + r.stderr).not.toMatch(/offline mode/i)
  })
})
