/**
 * B12 (BUG 2, fast lane): `scan --json --strict` must not lose piped stdout.
 *
 * Size note: a spawned child gets its stdout as a unix socket pair (about 200 KB of kernel buffer), not
 * a 64 KiB shell pipe, so the fixture is about 580 KB; the handshake below proves output was queued.
 *
 * Handshake: the child's stdout pipe is held PAUSED; the preloaded exit probe reports the instant the
 * CLI decides to exit and how much stdout is still queued; only then is the pipe released. On the OLD
 * code the CLI calls process.exit with data queued and the reader gets a cut payload. On the new
 * code it only sets process.exitCode, so the reader drains everything and the process exits by
 * itself with code 1. If nothing was queued at the exit point the test is invalid and fails.
 */
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, cliPath, pkgRoot, scanJson } from '../helpers/cli-fixture.js'
import { runHeld } from '../helpers/pipe-run.js'
import { mkBigFindingsTree } from '../helpers/pipe-fixture.js'

vi.setConfig({ testTimeout: 90_000 })
afterAll(cleanupTrees)

describe('strict JSON over a held pipe (B12)', () => {
  it('delivers the whole JSON document and exits 1 after the reader releases the pipe', async () => {
    const dir = mkBigFindingsTree(120)
    const plain = await scanJson(dir)
    const expectedFindings = plain.json!.findings.length
    expect(expectedFindings).toBeGreaterThan(100)

    const run = await runHeld({ script: cliPath(), args: ['scan', dir, '--json', '--strict'], cwd: pkgRoot })

    expect(run.timedOut).toBe(false)
    // The harness is only valid when output was still queued at the moment of the exit decision.
    expect(run.exitPoint, `no EXIT_POINT line; stderr: ${run.stderr.slice(0, 300)}`).toBeDefined()
    expect(run.exitPoint!.queued).toBeGreaterThan(0)
    expect(run.exitPoint!.code).toBe(1)

    expect(run.stdout.length).toBeGreaterThan(300_000)
    const parsed = JSON.parse(run.stdout.toString('utf-8'))
    expect(parsed.findings.length).toBe(expectedFindings)
    expect(run.code).toBe(1)
  })
})
