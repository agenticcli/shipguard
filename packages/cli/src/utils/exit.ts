/**
 * Exit handling that never loses piped output.
 *
 * Rule: `process.exit()` is NEVER called while stdout may hold queued data. A pipe is written
 * asynchronously; `process.exit()` discards whatever is still queued, which cut `scan --json --strict`
 * output at the pipe size (about 64 KiB) when the reader was slow. So the code only SETS
 * `process.exitCode` and returns; Node then exits by itself once stdout has drained and the event
 * loop is empty. There is deliberately NO timer and NO forced exit: a reader that is slow just makes
 * the process wait (standard pipe back-pressure), a truncated JSON document is worse.
 */
import { logger } from './logger.js'

/** Record the exit code. The caller must then return (stop executing); Node exits when output is drained. */
export function setExitCode(code: number): void {
  process.exitCode = code
}

let installed = false

/**
 * Install 'error' handlers on stdout and stderr. Called ONCE at startup in cli.ts, before any output
 * and before parseAsync. Without them a reader that closes early (`| head -c 100`) raises EPIPE as an
 * uncaught exception, and the uncaught-exception handler turns a finished scan into exit 3.
 *
 * The handlers never set or change `process.exitCode`: the code the scan computed is kept.
 * They log (debug for EPIPE, warn for anything else) and do nothing else.
 */
export function installStreamErrorHandlers(): void {
  if (installed) return
  installed = true
  for (const [name, stream] of [['stdout', process.stdout], ['stderr', process.stderr]] as const) {
    stream.on('error', (err: NodeJS.ErrnoException) => {
      // The logger writes to stderr. If stderr itself is the broken stream there is nowhere left to
      // log to, and logging would raise another stderr error (a loop). Keep the code and stop.
      if (name === 'stderr') return
      if (err?.code === 'EPIPE') {
        // The reader went away. Nothing more can be delivered; keep the computed exit code.
        logger.debug(`${name}: reader closed the pipe (EPIPE); keeping the computed exit code`)
        return
      }
      logger.warn(`${name} stream error (${err?.code ?? 'unknown'}): ${err?.message ?? String(err)}`)
    })
  }
}

/** Test hook: forget that handlers were installed. */
export function resetStreamErrorHandlersForTest(): void {
  installed = false
}

/**
 * Called by cli.ts after the command finished. If a non-zero exit code was set, exit once BOTH
 * stdout and stderr are drained. This is the only permitted `process.exit`: it runs from inside an
 * empty-write callback (writes are ordered, so the callback fires only after everything queued
 * before it has been flushed) and only when `writableLength === 0`, so nothing queued can be lost.
 * It exists so a late open handle (a hung telemetry socket, a keep-alive connection) cannot hold a
 * finished `--strict` run open. It is never started from a timer.
 */
export function exitWhenDrained(): void {
  const code = process.exitCode
  if (code === undefined || code === 0) return
  let pending = 2
  const done = (err?: Error | null): void => {
    if (err) logger.debug(`exit: stream write callback reported ${err.message}; nothing more can be delivered`)
    pending--
    if (pending > 0) return
    if (process.stdout.writableLength === 0 && process.stderr.writableLength === 0) {
      process.exit(Number(code))
    }
  }
  process.stdout.write('', done)
  process.stderr.write('', done)
}
