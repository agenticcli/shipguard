// Test-only probe (never shipped). Preloaded with `node --import <this file> dist/cli.js ...`.
//
// QA (2026-11-02): reports how many 'error' listeners process.stdout has right AFTER the first
// stdout write has returned (sampled on the next macrotask, so the temporary no-op listener that
// console.log adds around its own write is already gone). Plan A5 / judge R3 decision 2: the stream
// error handlers must be installed AT STARTUP, so this count is at least 1 while the CLI is still
// waiting (for example for the telemetry ping) after it wrote its JSON.
//   STDOUT_ERROR_LISTENERS=<n>
// written with fs.writeSync(2, ...) so the line itself is never queued.
import { writeSync } from 'node:fs'

let sampled = false
const stdout = process.stdout
const realWrite = stdout.write
stdout.write = function probedWrite(...args) {
  const r = realWrite.apply(stdout, args)
  if (!sampled) {
    sampled = true
    setImmediate(() => {
      try {
        writeSync(2, `STDOUT_ERROR_LISTENERS=${stdout.listenerCount('error')}\n`)
      } catch {
        // stderr gone: nothing left to report to.
      }
    })
  }
  return r
}
