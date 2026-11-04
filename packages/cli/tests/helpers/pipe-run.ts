/**
 * Pipe-handshake runner for the BUG 2 tests (B12, B13, B14, B21).
 *
 * The read end of the child's stdout pipe is held PAUSED, so the pipe fills and the child must queue
 * the rest. The child is preloaded with tests/helpers/exit-probe.mjs, which writes one
 * `EXIT_POINT code=<n> queued=<bytes>` line to stderr at the moment the child decides to exit. Only
 * after the test has read that line does it (optionally wait `holdMs`, then) release the pipe. CPU
 * idleness is never used as a signal.
 */
import { spawn } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
export const PROBE_PATH = resolve(here, 'exit-probe.mjs')

export interface HeldRun {
  code: number | null
  stdout: Buffer
  stderr: string
  /** Parsed EXIT_POINT line, or undefined when the child never reported one. */
  exitPoint?: { code: number; queued: number; via: string }
  /** Milliseconds from the handshake to the end of the hold (real wall time). */
  heldMs: number
  /** True when the child was still running when the hold ended. */
  aliveAfterHold: boolean
  timedOut: boolean
}

export function runHeld(opts: {
  /** node script (dist/cli.js or a fixture) */
  script: string
  args: string[]
  cwd: string
  env?: NodeJS.ProcessEnv
  /** Wait this long after the handshake before reading stdout. */
  holdMs?: number
  /** Kill after this many ms in total. */
  timeoutMs?: number
}): Promise<HeldRun> {
  return new Promise((resolveRun) => {
    const child = spawn(process.execPath, ['--import', PROBE_PATH, opts.script, ...opts.args], {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    child.stdout.pause() // the reader is "slow": nothing is read until the handshake and the hold
    const out: Buffer[] = []
    let stderr = ''
    let exitPoint: HeldRun['exitPoint']
    let released = false
    let heldMs = 0
    let aliveAfterHold = false
    let timedOut = false
    let exited = false

    const release = (): void => {
      if (released) return
      released = true
      const started = Date.now()
      const hold = opts.holdMs ?? 0
      setTimeout(() => {
        heldMs = Date.now() - started
        aliveAfterHold = !exited
        child.stdout.on('data', (d: Buffer) => out.push(d))
        child.stdout.resume()
      }, hold)
    }

    child.stderr.setEncoding('utf-8').on('data', (d: string) => {
      stderr += d
      const m = stderr.match(/EXIT_POINT code=(\d+) queued=(\d+) via=(\w+)/)
      if (m && !exitPoint) {
        exitPoint = { code: Number(m[1]), queued: Number(m[2]), via: m[3] }
        release()
      }
    })
    const killer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, opts.timeoutMs ?? 60_000)
    child.on('exit', () => {
      exited = true
      // A child that exits without ever reporting (clean exit 0 path) must still release the pipe.
      release()
    })
    child.on('close', (code) => {
      clearTimeout(killer)
      resolveRun({ code, stdout: Buffer.concat(out), stderr, exitPoint, heldMs, aliveAfterHold, timedOut })
    })
  })
}
