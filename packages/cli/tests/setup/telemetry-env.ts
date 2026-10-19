/** Pure helpers shared by the global test setup and the regression test (no side effects on import). */
/** Discard-protocol port on loopback: connection is refused, nothing ever leaves the machine. */
export const DEAD_TELEMETRY_URL = 'http://127.0.0.1:9/cli-telemetry'

export function isLoopbackUrl(raw: string | undefined): boolean {
  if (!raw) return false
  try {
    const host = new URL(raw).hostname
    return host === '127.0.0.1' || host === 'localhost' || host === '[::1]' || host === '::1'
  } catch {
    return false
  }
}

/** Return a copy of `env` (default: process.env) with telemetry forced off unless a loopback capture URL is set. */
export function withTelemetryOff(env?: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = { ...(env ?? process.env) }
  if (isLoopbackUrl(out.SHIPGUARD_TELEMETRY_URL)) return out // explicit local capture server
  out.SHIPGUARD_TELEMETRY = '0'
  out.DO_NOT_TRACK = '1'
  out.SHIPGUARD_TELEMETRY_URL = DEAD_TELEMETRY_URL
  return out
}

