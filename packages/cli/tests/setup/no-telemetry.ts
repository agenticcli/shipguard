/**
 * Global vitest setup (vitest.config.ts -> setupFiles): no test may send usage telemetry to the
 * real production analytics endpoint. Fail-closed, three layers.
 *
 * RCA: src/core/telemetry.ts shouldSendTelemetry() defaults to ON and the endpoint defaults to the
 * PROD Convex site, and the e2e/determinism tests spawn dist/cli.js with a stripped env
 * (`{PATH, HOME}`) or no opt-out, so every test scan pinged prod: ~12.8k fake `scan_run` events.
 *
 * 1. This process: HOME -> throwaway dir (never write the real ~/.config/shipguard); SHIPGUARD_TELEMETRY=0, DO_NOT_TRACK=1, endpoint -> dead loopback port.
 * 2. Every child process spawned from a test (spawn, spawnSync, exec and fork variants) gets the same vars forced
 *    into its env, even when the test passes its own stripped `env`. The one sanctioned exception:
 *    a test that points SHIPGUARD_TELEMETRY_URL at a LOOPBACK capture server keeps whatever opt-in
 *    it asked for (tests/commands/telemetry-version.test.ts). A non-loopback URL is never honoured.
 * 3. global fetch is wrapped: any request to a non-loopback host from a test throws. (Tests that
 *    vi.stubGlobal('fetch') replace the wrapper with their own mock, which is fine: no real send.)
 */
import childProcess from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { syncBuiltinESMExports } from 'node:module'
import { DEAD_TELEMETRY_URL, isLoopbackUrl, withTelemetryOff } from './telemetry-env.js'

// ---- layer 1: this process ------------------------------------------------------------------
process.env.SHIPGUARD_TELEMETRY = '0'
process.env.DO_NOT_TRACK = '1'
process.env.SHIPGUARD_TELEMETRY_URL = DEAD_TELEMETRY_URL

// A test must never write the developer's real ~/.config/shipguard (telemetry.json, the "notice shown"
// marker): point HOME at a throwaway dir for this worker. Children that inherit the env follow it.
const testHome = mkdtempSync(join(tmpdir(), 'sg-test-home-'))
process.env.HOME = testHome
process.on('exit', () => {
  try {
    rmSync(testHome, { recursive: true, force: true })
  } catch {
    // Best-effort temp cleanup; the OS tmp reaper handles leftovers.
  }
})

// ---- layer 2: child processes ---------------------------------------------------------------
type AnyFn = (...args: unknown[]) => unknown

/** Find the options object (the last plain-object argument before an optional callback) and force env. */
function patchArgs(args: unknown[]): unknown[] {
  const a = [...args]
  const cbIdx = typeof a[a.length - 1] === 'function' ? a.length - 1 : a.length
  // options is the last non-callback arg if it is a plain object (not an array / string)
  const optIdx = cbIdx - 1
  const cand = optIdx >= 1 ? a[optIdx] : undefined
  if (cand && typeof cand === 'object' && !Array.isArray(cand)) {
    const opts = cand as { env?: NodeJS.ProcessEnv }
    a[optIdx] = { ...opts, env: withTelemetryOff(opts.env) }
  } else {
    // No options given: insert one (after the command / file+args, before any callback).
    const hasArgsArray = Array.isArray(a[1])
    const insertAt = hasArgsArray ? 2 : 1
    a.splice(insertAt, 0, { env: withTelemetryOff() })
  }
  return a
}

const cp = childProcess as unknown as Record<string, AnyFn>
for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync', 'fork']) {
  const original = cp[name]
  if (typeof original !== 'function' || (original as { __telemetryGuard?: boolean }).__telemetryGuard) continue
  const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
    return original.apply(this, patchArgs(args))
  }
  ;(wrapped as { __telemetryGuard?: boolean }).__telemetryGuard = true
  cp[name] = wrapped
}
// Make `import { spawnSync } from 'node:child_process'` (live ESM bindings) see the wrapped versions.
syncBuiltinESMExports()

// ---- layer 3: real network ------------------------------------------------------------------
const realFetch = globalThis.fetch
if (typeof realFetch === 'function' && !(realFetch as { __telemetryGuard?: boolean }).__telemetryGuard) {
  const guarded = function (input: unknown, init?: unknown) {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.href : (input as { url?: string })?.url
    if (url && /^https?:/i.test(url) && !isLoopbackUrl(url)) {
      throw new Error(`[test-guard] real network fetch to ${new URL(url).host} is forbidden in tests; mock fetch`)
    }
    return (realFetch as AnyFn)(input, init)
  }
  ;(guarded as { __telemetryGuard?: boolean }).__telemetryGuard = true
  globalThis.fetch = guarded as typeof fetch
}
