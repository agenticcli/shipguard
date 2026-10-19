/**
 * Async spawn of a node script for e2e tests.
 *
 * Why async, never spawnSync: spawnSync blocks the vitest worker's event loop, so the worker
 * cannot answer vitest's RPC (onTaskUpdate) while a file of back-to-back CLI spawns runs. Vitest's
 * RPC timeout is a fixed 60s, so a file that blocks ~50s+ (easily, under load) exits 1 with
 * "Timeout calling onTaskUpdate" though every test passed.
 */
import { spawn } from 'node:child_process'

/** Default kill timeout: < the 30s file-scoped testTimeout of the e2e files. */
export const DEFAULT_KILL_TIMEOUT_MS = 25_000
const KILL_GRACE_MS = 2_000

export interface SpawnResult {
  code: number
  stdout: string
  stderr: string
  /** True when the kill timeout fired (the result is then a kill, not a real exit code). */
  timedOut: boolean
}

export function spawnNode(
  script: string,
  args: string[],
  opts: { cwd: string; timeoutMs?: number; env?: NodeJS.ProcessEnv },
): Promise<SpawnResult> {
  return new Promise((resolveRun) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd: opts.cwd,
      env: opts.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      // Own process group, so a timeout can kill the child AND its descendants: a grandchild
      // that inherited our stdout/stderr pipes would otherwise keep them open and stall 'close'.
      detached: true,
    })
    const killGroup = (signal: NodeJS.Signals) => {
      try {
        if (child.pid !== undefined) process.kill(-child.pid, signal)
        else child.kill(signal)
      } catch (err) {
        // ESRCH = group already gone (expected race); anything else: fall back to the child alone.
        if ((err as NodeJS.ErrnoException).code !== 'ESRCH') child.kill(signal)
      }
    }
    let timedOut = false
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf-8').on('data', (d: string) => { stdout += d })
    child.stderr.setEncoding('utf-8').on('data', (d: string) => { stderr += d })
    // Kill budget must stay BELOW the calling file's vitest testTimeout (30s in the e2e files),
    // so a hung child surfaces as a code -1 result, not as an opaque test timeout. SIGTERM
    // first, then SIGKILL after a grace period in case the child ignores SIGTERM.
    let killTimer: NodeJS.Timeout | undefined
    const timer = setTimeout(() => {
      timedOut = true
      killGroup('SIGTERM')
      killTimer = setTimeout(() => killGroup('SIGKILL'), KILL_GRACE_MS)
    }, opts.timeoutMs ?? DEFAULT_KILL_TIMEOUT_MS)
    const clear = () => {
      clearTimeout(timer)
      if (killTimer) clearTimeout(killTimer)
    }
    child.on('error', (err) => {
      clear()
      resolveRun({ code: -1, stdout, stderr: `${stderr}\nspawn error: ${err.message}`, timedOut })
    })
    child.on('close', (status) => {
      clear()
      // status is null when killed by a signal (same mapping as spawnSync callers used).
      if (timedOut) killGroup('SIGKILL') // reap any descendant that survived SIGTERM
      resolveRun({ code: status === null ? -1 : status, stdout, stderr, timedOut })
    })
  })
}
