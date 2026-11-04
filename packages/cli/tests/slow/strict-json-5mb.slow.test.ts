/**
 * B13 (BUG 2 at scale, slow lane): about 5.7 MB of `--strict` JSON over a held pipe.
 *
 * Same handshake as B12 (tests/helpers/pipe-run.ts + exit-probe.mjs). The reader is held a further
 * 12 s AFTER the handshake, so any timer-based forced exit (the 10 s design that still truncated in
 * review) would already have fired. Then it is released: the output must be complete valid JSON with
 * the same findings as the non-strict run, and the exit code 1. Run by scripts/release-gate.sh (G8)
 * through VITEST_SLOW=1.
 */
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, cliPath, pkgRoot, scanJson } from '../helpers/cli-fixture.js'
import { runHeld } from '../helpers/pipe-run.js'
import { mkBigFindingsTree } from '../helpers/pipe-fixture.js'

vi.setConfig({ testTimeout: 240_000 })
afterAll(cleanupTrees)

const HOLD_MS = 12_000

describe('strict JSON, 5 MB, slow reader (B13)', () => {
  const dir = mkBigFindingsTree(1200)

  it('--json --strict: whole document after a 12 s hold, exit 1', async () => {
    const plain = await scanJson(dir, [], { timeoutMs: 120_000 })
    const expectedFindings = plain.json!.findings.length

    const run = await runHeld({
      script: cliPath(),
      args: ['scan', dir, '--json', '--strict'],
      cwd: pkgRoot,
      holdMs: HOLD_MS,
      timeoutMs: 200_000,
    })
    expect(run.timedOut).toBe(false)
    expect(run.exitPoint, `no EXIT_POINT; stderr: ${run.stderr.slice(0, 300)}`).toBeDefined()
    expect(run.exitPoint!.queued).toBeGreaterThan(0)
    expect(run.heldMs).toBeGreaterThanOrEqual(HOLD_MS - 200)
    // A forced exit on a timer would have ended the process during the hold: it must still be alive.
    expect(run.aliveAfterHold).toBe(true)
    expect(run.stdout.length).toBeGreaterThan(5_000_000)
    const parsed = JSON.parse(run.stdout.toString('utf-8'))
    expect(parsed.findings.length).toBe(expectedFindings)
    expect(run.code).toBe(1)
  })

  it('--sarif --strict: whole document after the hold, exit 1', async () => {
    const run = await runHeld({
      script: cliPath(),
      args: ['scan', dir, '--sarif', '--strict'],
      cwd: pkgRoot,
      holdMs: HOLD_MS,
      timeoutMs: 200_000,
    })
    expect(run.exitPoint).toBeDefined()
    expect(run.exitPoint!.queued).toBeGreaterThan(0)
    expect(run.aliveAfterHold).toBe(true)
    const sarif = JSON.parse(run.stdout.toString('utf-8'))
    expect(Array.isArray(sarif.runs)).toBe(true)
    expect(run.code).toBe(1)
  })
})
