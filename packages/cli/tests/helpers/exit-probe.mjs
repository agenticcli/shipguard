// Test-only probe (never shipped). Preloaded with `node --import <this file> dist/cli.js ...`.
//
// It reports, exactly once, the moment a process DECIDES to exit and how much stdout is still queued:
//   EXIT_POINT code=<n> queued=<bytes> via=<exit|exitCode>
// written with fs.writeSync(2, ...) so the line itself is never queued.
//
// `process.exitCode` is non-configurable on Node 24 (defining a setter throws), so it is NOT touched:
//  (a) process.exit is wrapped (the OLD code calls it with data still queued);
//  (b) an unref'd 5 ms interval watches process.exitCode (the NEW code only sets it and returns).
// The interval is unref'd, so it never keeps the process alive.
import { writeSync } from 'node:fs'

let reported = false
function report(code, via) {
  if (reported) return
  reported = true
  const queued = process.stdout.writableLength
  try {
    writeSync(2, `EXIT_POINT code=${code} queued=${queued} via=${via}\n`)
  } catch {
    // stderr gone: nothing left to report to.
  }
}

const realExit = process.exit
process.exit = function probedExit(code) {
  report(code ?? process.exitCode ?? 0, 'exit')
  return realExit.call(process, code)
}

const timer = setInterval(() => {
  if (process.exitCode !== undefined && process.exitCode !== null) report(process.exitCode, 'exitCode')
}, 5)
timer.unref()
