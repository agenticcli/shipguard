/**
 * B21 (guard for the test harness): the exit probe works before B12/B13 rely on it.
 * Two tiny scripts write 200 KB to a held (paused) pipe:
 *  (a) bare process.exit(1) with data queued,
 *  (b) set process.exitCode = 1 and return.
 * The probe must emit exactly one EXIT_POINT line with queued > 0 in BOTH cases.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { runHeld } from './pipe-run.js'

vi.setConfig({ testTimeout: 30_000 })

const dir = mkdtempSync(join(tmpdir(), 'sg-probe-'))
afterAll(() => rmSync(dir, { recursive: true, force: true }))

// Larger than a socketpair buffer, so something is always still queued.
const BYTES = 2_000_000

function script(name: string, body: string): string {
  const p = join(dir, name)
  writeFileSync(p, `process.stdout.write(Buffer.alloc(${BYTES}, 97));\n${body}\n`)
  return p
}

describe('exit probe self-test (B21)', () => {
  it('reports queued > 0 for a bare process.exit(1)', async () => {
    const run = await runHeld({ script: script('bare-exit.mjs', 'process.exit(1)'), args: [], cwd: dir })
    expect(run.stderr.match(/EXIT_POINT/g)).toHaveLength(1)
    expect(run.exitPoint).toMatchObject({ code: 1, via: 'exit' })
    expect(run.exitPoint!.queued).toBeGreaterThan(0)
    // The old behaviour this probe exists to catch: queued data is lost.
    expect(run.stdout.length).toBeLessThan(BYTES)
  })

  it('reports queued > 0 for process.exitCode = 1 and return, and nothing is lost', async () => {
    const run = await runHeld({ script: script('set-code.mjs', 'process.exitCode = 1'), args: [], cwd: dir })
    expect(run.stderr.match(/EXIT_POINT/g)).toHaveLength(1)
    expect(run.exitPoint).toMatchObject({ code: 1, via: 'exitCode' })
    expect(run.exitPoint!.queued).toBeGreaterThan(0)
    expect(run.stdout.length).toBe(BYTES)
    expect(run.code).toBe(1)
  })
})
