/**
 * Global process error handlers — exported for unit testing.
 *
 * These prevent raw Node.js/V8 crash output from reaching the user.
 *
 * NOTE: A true heap-OOM (out of memory) is NOT catchable here — the V8 process
 * is killed at the OS level before these handlers can run. OOM is PREVENTED by
 * the per-file size cap and cumulative total-bytes cap in utils/fs.ts (Part A).
 * These handlers catch all OTHER uncaught errors (logic errors, network failures, etc.)
 */

import { EXIT_CODES } from '@agenticcli/shared'
import { goLink } from './core/links.js'

const ISSUES_URL = 'https://github.com/agenticcli/shipguard/issues'
const DOCS_URL = goLink('docs')
const REPORT_LINE = `Report this: ${ISSUES_URL} · Docs: ${DOCS_URL}`

/** Handle an uncaught exception. Exported for unit testing. */
export function handleUncaughtException(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error)
  console.error(`\x1b[31m✗\x1b[0m Unexpected error: ${message}`)
  if (process.env.SHIPGUARD_DEBUG && error instanceof Error) {
    console.error(error.stack)
  }
  console.error(REPORT_LINE)
  process.exit(EXIT_CODES.RUNTIME_ERROR)
}

/** Handle an unhandled promise rejection. Exported for unit testing. */
export function handleUnhandledRejection(reason: unknown, _promise: Promise<unknown>): void {
  const message = reason instanceof Error ? reason.message : String(reason)
  console.error(`\x1b[31m✗\x1b[0m Unhandled rejection: ${message}`)
  if (process.env.SHIPGUARD_DEBUG && reason instanceof Error) {
    console.error(reason.stack)
  }
  console.error(REPORT_LINE)
  process.exit(EXIT_CODES.RUNTIME_ERROR)
}

/** Handle SIGINT / SIGTERM. Exported for unit testing. */
export function handleSignal(): void {
  console.error('\nInterrupted.')
  process.exit(130)
}
