/**
 * ShipGuard CLI telemetry — pseudonymous, opt-out, fire-and-forget. Schema v2
 * (cli-telemetry contract v2).
 *
 * WHAT IS SENT (always and only, exactly these keys):
 *   schema         — 2
 *   eventId        — random v4 UUID per ping (lets the relay drop retries)
 *   installId      — random v4 UUID kept in ~/.config/shipguard/telemetry.json; null in CI
 *   cliVersion     — semver string, e.g. "0.7.0"
 *   provenance     — "published" (npm build) | "dev" (checkout / local build)
 *   verdict        — "safe" | "review" | "blocked" | "error"
 *   durationBucket — "lt1s" | "1to5s" | "5to30s" | "gt30s"
 *   ci             — boolean, from well-known CI environment variables being present
 *
 * The install id is pseudonymous, not anonymous: random, never derived from the machine, user or repo,
 * never created or sent in CI, never linked to a ShipGuard account, sent only to the telemetry endpoint.
 * `shipguard telemetry reset` forgets it.
 *
 * WHAT IS NEVER SENT:
 *   file paths, file contents, project/repo/branch/commit names (hashed or not), hostnames, usernames,
 *   env values, rule ids, finding text, exact counts or durations — anything identifying
 *
 * OPT OUT (first match wins): DO_NOT_TRACK=1 or SHIPGUARD_TELEMETRY=0 in the environment
 * > `shipguard telemetry disable` (user config) > `telemetry.enabled: false` in shipguard.policy.yml
 * or .shipguard.yml (the file `scan --pro` generates)
 * > default on. `shipguard telemetry status` shows the effective state and why.
 * Details: https://agenticcli.dev/docs#telemetry
 *
 * NOTICE: before the first ping on an install, ONE line is written to stderr (every mode: human,
 * --json, --quiet, CI; stdout stays pure) and a marker is persisted so it is never repeated.
 * DEBUG: SHIPGUARD_TELEMETRY_DEBUG=1 prints the exact payload to stderr and sends nothing.
 *
 * PROVENANCE: the production endpoint is only reachable from a PUBLISHED build (tsup `define`
 * __SHIPGUARD_PUBLISHED_BUILD__, set only by `pnpm build:publish`). A dev build, a source checkout,
 * `tsup --watch` and the test suite send NOTHING unless SHIPGUARD_TELEMETRY_URL points at a loopback
 * address (a local capture server). A published build also honours SHIPGUARD_TELEMETRY_URL.
 */

// Injected by tsup `define`. Undeclared under vitest / ts-node, where `typeof` is ReferenceError-safe.
declare const __SHIPGUARD_PUBLISHED_BUILD__: boolean | undefined

export type TelemetryProvenance = 'published' | 'dev'

/** True only in a build made by the release/publish path (`SHIPGUARD_PUBLISHED_BUILD=1 tsup`). */
export const IS_PUBLISHED_BUILD: boolean =
  typeof __SHIPGUARD_PUBLISHED_BUILD__ !== 'undefined' && __SHIPGUARD_PUBLISHED_BUILD__ === true

export function getProvenance(published: boolean = IS_PUBLISHED_BUILD): TelemetryProvenance {
  return published ? 'published' : 'dev'
}

export const PROD_TELEMETRY_ENDPOINT = 'https://cheery-toucan-348.convex.site/cli-telemetry'

/** True for http(s) URLs whose host is this machine (127.0.0.1, localhost, ::1). */
export function isLoopbackUrl(raw: string | undefined): boolean {
  if (!raw) return false
  try {
    const host = new URL(raw).hostname
    return host === '127.0.0.1' || host === 'localhost' || host === '[::1]' || host === '::1'
  } catch {
    return false
  }
}

/**
 * Where a ping would go, or null when this build must not send at all.
 *  - published build: SHIPGUARD_TELEMETRY_URL if set, else the production relay.
 *  - dev build: only a loopback SHIPGUARD_TELEMETRY_URL; never production, never a remote override.
 */
export function resolveEndpoint(
  published: boolean = IS_PUBLISHED_BUILD,
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  const override = env.SHIPGUARD_TELEMETRY_URL
  if (published) return override || PROD_TELEMETRY_ENDPOINT
  return isLoopbackUrl(override) ? (override as string) : null
}

import { randomUUID } from 'node:crypto'
import { logger } from '../utils/logger.js'
import { goLink } from './links.js'
import {
  UUID_V4,
  firstRunHandled,
  getConfigDir,
  getOrCreateInstallId,
  markFirstRunHandled,
  markNoticeShown,
  noticeShown,
  projectTelemetryEnabled,
  readInstallId,
  readUserConfig,
  userConfigUnreadable,
} from './telemetry-config.js'

export type TelemetryVerdict = 'safe' | 'review' | 'blocked' | 'error'
export type DurationBucket = 'lt1s' | '1to5s' | '5to30s' | 'gt30s'

/** The v2 wire payload. Exactly these keys, all required. */
export interface TelemetryPayload {
  schema: 2
  eventId: string
  installId: string | null
  cliVersion: string
  provenance: TelemetryProvenance
  verdict: TelemetryVerdict
  durationBucket: DurationBucket
  ci: boolean
}

/** What a caller knows about a finished scan. Everything else is derived inside this module. */
export interface TelemetryInput {
  cliVersion: string
  verdict: TelemetryVerdict
  durationMs: number
}

const ALLOWED_KEYS: ReadonlyArray<keyof TelemetryPayload> = [
  'schema',
  'eventId',
  'installId',
  'cliVersion',
  'provenance',
  'verdict',
  'durationBucket',
  'ci',
]

const VERSION_RE = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})(-[0-9A-Za-z.-]{1,24})?$/
const DURATION_BUCKETS: readonly string[] = ['lt1s', '1to5s', '5to30s', 'gt30s']

export function durationBucket(ms: number): DurationBucket {
  if (!(ms >= 1000)) return 'lt1s' // also NaN / negative
  if (ms < 5000) return '1to5s'
  if (ms < 30000) return '5to30s'
  return 'gt30s'
}

/** Env vars whose mere presence means "running in CI" (values are never read or sent). */
const CI_PROVIDER_VARS = [
  'GITHUB_ACTIONS',
  'GITLAB_CI',
  'CIRCLECI',
  'TRAVIS',
  'BUILDKITE',
  'JENKINS_URL',
  'TF_BUILD',
  'TEAMCITY_VERSION',
  'BITBUCKET_BUILD_NUMBER',
  'APPVEYOR',
  'DRONE',
  'CODEBUILD_BUILD_ID',
  'SEMAPHORE',
  'BUILD_BUILDID',
  'CF_BUILD_ID',
  'NETLIFY',
  'VERCEL',
  'WOODPECKER',
  'BUDDY',
  'HUDSON_URL',
] as const

/** CI=false / 0 / "" counts as NOT CI; any other CI value, or a provider variable, counts as CI. */
export function detectCi(env: NodeJS.ProcessEnv = process.env): boolean {
  const ci = env.CI
  if (ci !== undefined && !['', '0', 'false'].includes(ci.trim().toLowerCase())) return true
  // Presence is enough (contract): an empty GITHUB_ACTIONS="" still means a CI runner.
  return CI_PROVIDER_VARS.some((k) => env[k] !== undefined)
}

/**
 * Environment-only opt-out check (SHIPGUARD_TELEMETRY=0|false OR DO_NOT_TRACK=1|true). The full decision,
 * including user config and project policy, is decideTelemetry().
 */
export function shouldSendTelemetry(): boolean {
  return !envOptOut(process.env)
}

function isTruthyOff(v: string | undefined, offValues: string[]): boolean {
  return v !== undefined && offValues.includes(v.trim().toLowerCase())
}

function envOptOut(env: NodeJS.ProcessEnv): 'env:SHIPGUARD_TELEMETRY' | 'env:DO_NOT_TRACK' | null {
  if (isTruthyOff(env.SHIPGUARD_TELEMETRY, ['0', 'false'])) return 'env:SHIPGUARD_TELEMETRY'
  if (isTruthyOff(env.DO_NOT_TRACK, ['1', 'true'])) return 'env:DO_NOT_TRACK'
  return null
}

/**
 * Build the v2 payload. Guaranteed to contain ONLY the allowed keys: the input is copied field by
 * field, so extra properties on it can never leak in.
 */
export function buildPayload(input: TelemetryPayload): TelemetryPayload {
  const { schema, eventId, installId, cliVersion, provenance, verdict, durationBucket, ci } = input
  return { schema, eventId, installId, cliVersion, provenance, verdict, durationBucket, ci }
}

/**
 * Validate a payload against the contract: exact key set, types, bounds, and the ci/installId rule
 * (installId null iff ci). Returns true if the payload is safe to send.
 */
export function validatePayload(payload: unknown): payload is TelemetryPayload {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return false
  const obj = payload as Record<string, unknown>

  const keys = Object.keys(obj)
  if (keys.length !== ALLOWED_KEYS.length) return false
  for (const k of ALLOWED_KEYS) if (!(k in obj)) return false

  if (obj.schema !== 2) return false
  if (typeof obj.eventId !== 'string' || !UUID_V4.test(obj.eventId)) return false
  if (typeof obj.ci !== 'boolean') return false
  if (obj.ci) {
    if (obj.installId !== null) return false
  } else if (typeof obj.installId !== 'string' || !UUID_V4.test(obj.installId)) {
    return false
  }
  if (typeof obj.cliVersion !== 'string' || obj.cliVersion.length > 40 || !VERSION_RE.test(obj.cliVersion)) return false
  if (obj.provenance !== 'published' && obj.provenance !== 'dev') return false
  if (!['safe', 'review', 'blocked', 'error'].includes(obj.verdict as string)) return false
  if (!DURATION_BUCKETS.includes(obj.durationBucket as string)) return false
  return true
}

export type TelemetryDecisionSource =
  | 'env:SHIPGUARD_TELEMETRY'
  | 'env:DO_NOT_TRACK'
  | 'user-config'
  | 'project-policy'
  | 'default'

export interface TelemetryDecision {
  enabled: boolean
  source: TelemetryDecisionSource
}

/**
 * Whether pings are enabled, and which rule decided. Precedence, first match wins:
 *   DO_NOT_TRACK=1|true / SHIPGUARD_TELEMETRY=0|false  >  user config (`telemetry disable`)
 *   >  project policy (`telemetry.enabled: false`)  >  default on.
 * A positive setting (SHIPGUARD_TELEMETRY=1, `telemetry.enabled: true`) never overrides a lower-level opt-out.
 */
export function decideTelemetry(
  input: { env?: NodeJS.ProcessEnv; configDir?: string; policy?: unknown; projectDir?: string } = {},
): TelemetryDecision {
  const env = input.env ?? process.env
  const envOff = envOptOut(env)
  if (envOff) return { enabled: false, source: envOff }
  const dir = input.configDir ?? getConfigDir()
  // Fail closed: a config file that exists but cannot be read (truncated, corrupt) may have held
  // `enabled:false`. Do not ping until the user rewrites it (`shipguard telemetry enable|disable`).
  if (userConfigUnreadable(dir) || readUserConfig(dir).enabled === false) {
    return { enabled: false, source: 'user-config' }
  }
  if (projectTelemetryEnabled({ policy: input.policy, projectDir: input.projectDir }) === false) return { enabled: false, source: 'project-policy' }
  return { enabled: true, source: 'default' }
}

/** The one-line stderr notice printed before the first ping on an install. */
export const NOTICE_TEXT =
  'shipguard: sends a pseudonymous usage ping after each scan, once on first run and after login (version, verdict, duration bucket, a random install id outside CI; never code, paths or your account). ' +
  'Turn it off: SHIPGUARD_TELEMETRY=0, DO_NOT_TRACK=1, or `shipguard telemetry disable`. ' + goLink('telemetry')

/** Hard ceiling on how long a caller waits for the ping (abort fires at 1 s; this covers slow teardown). */
export const PING_WAIT_MS = 1500
const FETCH_TIMEOUT_MS = 1000

export interface SendOptions {
  /** Override build provenance (tests). Default: this build's. */
  published?: boolean
  /** The loaded shipguard.policy.yml, for `telemetry.enabled`. */
  policy?: unknown
  /** Project directory; its `.shipguard.yml` (and policy file, if `policy` is not given) is checked for `telemetry.enabled`. */
  projectDir?: string
  env?: NodeJS.ProcessEnv
  configDir?: string
}

function debugEnabled(env: NodeJS.ProcessEnv): boolean {
  const v = env.SHIPGUARD_TELEMETRY_DEBUG
  return Boolean(v) && v !== '0'
}

/**
 * Telemetry ping. Starts the request synchronously and returns a promise that ALWAYS resolves, within
 * PING_WAIT_MS, so a caller can `await` it before an explicit process.exit (a --strict exit used to
 * drop the in-flight ping). Never rejects, never throws, never writes to stdout.
 */
export function sendTelemetry(input: TelemetryInput, opts: SendOptions = {}): Promise<void> {
  try {
    const env = opts.env ?? process.env
    const configDir = opts.configDir ?? getConfigDir()
    const published = opts.published ?? IS_PUBLISHED_BUILD
    const debug = debugEnabled(env)

    const decision = decideTelemetry({ env, configDir, policy: opts.policy, projectDir: opts.projectDir })
    if (!decision.enabled) {
      if (debug) process.stderr.write(`[shipguard:telemetry] disabled (${decision.source}); nothing would be sent\n`)
      return Promise.resolve()
    }

    const endpoint = resolveEndpoint(published, env)
    const ci = detectCi(env)
    const base = {
      schema: 2 as const,
      eventId: randomUUID(),
      cliVersion: input.cliVersion,
      provenance: getProvenance(published),
      verdict: input.verdict,
      durationBucket: durationBucket(input.durationMs),
      ci,
    }

    if (debug) {
      // Nothing is sent or saved. Outside CI with no id yet, show a throwaway id so the shape is exact.
      const stored = ci ? null : readInstallId(configDir)
      const installId = ci ? null : (stored ?? randomUUID())
      const note = !ci && !stored ? ' (installId is a preview: none saved yet, one is created on the first real ping)' : ''
      process.stderr.write(
        `[shipguard:telemetry] SHIPGUARD_TELEMETRY_DEBUG=1: not sending. provenance=${base.provenance} ` +
          `endpoint=${endpoint ?? '(none: dev build without a loopback SHIPGUARD_TELEMETRY_URL)'} ` +
          `payload=${JSON.stringify(buildPayload({ ...base, installId }))}${note}\n`,
      )
      return Promise.resolve()
    }
    if (endpoint === null) {
      // Dev build / source checkout: production is unreachable by design.
      logger.debug('telemetry: dev build, not sending (set a loopback SHIPGUARD_TELEMETRY_URL to capture)')
      return Promise.resolve()
    }

    // Notice BEFORE the first ping, in every output mode. stderr only, so --json stdout stays pure.
    if (!noticeShown(configDir)) {
      process.stderr.write(NOTICE_TEXT + '\n')
      markNoticeShown(configDir)
    }

    // The install id is made here, lazily, and never in CI. If it cannot be saved, skip the ping.
    const installId = ci ? null : (getOrCreateInstallId(configDir) ?? undefined)
    if (installId === undefined) {
      logger.debug('telemetry: no install id could be saved; not sending')
      return Promise.resolve()
    }
    const payload = buildPayload({ ...base, installId })
    if (!validatePayload(payload)) {
      logger.debug('telemetry: payload failed validation; not sending')
      return Promise.resolve()
    }
    const body = JSON.stringify(payload)

    return postBounded(endpoint, body)
  } catch (err) {
    logger.debug(`telemetry: skipped after error (ignored): ${err instanceof Error ? err.message : String(err)}`)
    return Promise.resolve()
  }
}

/** POST with the 1 s abort; resolves (never rejects) within PING_WAIT_MS. */
function postBounded(endpoint: string, body: string): Promise<void> {
  const controller = new AbortController()
  const abortTimer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  const request = fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    signal: controller.signal,
  })
    .then(
      () => undefined,
      (err: unknown) => {
        // Telemetry failure must never affect the command result, output or exit code.
        logger.debug(`telemetry: ping failed (ignored): ${err instanceof Error ? err.message : String(err)}`)
      },
    )
    .finally(() => clearTimeout(abortTimer))

  return new Promise<void>((resolve) => {
    const cap = setTimeout(resolve, PING_WAIT_MS)
    cap.unref()
    void request.then(() => {
      clearTimeout(cap)
      resolve()
    })
  })
}

// Injected by tsup `define` (same source as cli.ts / scan.ts); falls back under vitest.
declare const __SHIPGUARD_VERSION__: string | undefined
export const CLI_VERSION: string =
  typeof __SHIPGUARD_VERSION__ !== 'undefined' ? __SHIPGUARD_VERSION__ : (process.env.npm_package_version ?? '0.0.0-dev')

export type LifecycleEvent = 'cli_first_run' | 'cli_login'

/** The v3 wire payload (cli-telemetry contract v3). Exactly these keys, all required. */
export interface LifecyclePayload {
  schema: 3
  event: LifecycleEvent
  eventId: string
  installId: string | null
  cliVersion: string
  provenance: TelemetryProvenance
  ci: boolean
}

const LIFECYCLE_KEYS = ['schema', 'event', 'eventId', 'installId', 'cliVersion', 'provenance', 'ci']

/** Same rules as the relay: exact keys; cli_first_run never from CI; installId null iff ci. */
export function validateLifecyclePayload(payload: unknown): payload is LifecyclePayload {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return false
  const o = payload as Record<string, unknown>
  const keys = Object.keys(o)
  if (keys.length !== LIFECYCLE_KEYS.length || !LIFECYCLE_KEYS.every((k) => k in o)) return false
  if (o.schema !== 3) return false
  if (o.event !== 'cli_first_run' && o.event !== 'cli_login') return false
  if (typeof o.eventId !== 'string' || !UUID_V4.test(o.eventId)) return false
  if (typeof o.ci !== 'boolean') return false
  if (o.ci) {
    if (o.installId !== null || o.event === 'cli_first_run') return false
  } else if (typeof o.installId !== 'string' || !UUID_V4.test(o.installId)) {
    return false
  }
  if (typeof o.cliVersion !== 'string' || o.cliVersion.length > 40 || !VERSION_RE.test(o.cliVersion)) return false
  return o.provenance === 'published' || o.provenance === 'dev'
}

/**
 * One-off lifecycle event: `cli_first_run` (first command on an install, once) or `cli_login` (after a
 * successful `login`). Same opt-outs, CI rule, dev-build rule, notice, id, timeout and "never throws,
 * never writes stdout" behaviour as sendTelemetry. Payload carries no path, code or repo name.
 *  - cli_first_run is never sent from CI (the relay rejects it; there is no install id there).
 *  - An install that already has an id (pings from before this event existed) is marked handled
 *    without sending, so upgrades are not counted as new installs.
 */
export function sendLifecycleEvent(event: LifecycleEvent, input: { cliVersion: string }, opts: SendOptions = {}): Promise<void> {
  try {
    const env = opts.env ?? process.env
    const configDir = opts.configDir ?? getConfigDir()
    const published = opts.published ?? IS_PUBLISHED_BUILD
    const debug = debugEnabled(env)
    const ci = detectCi(env)

    if (event === 'cli_first_run' && ci) return Promise.resolve()

    const decision = decideTelemetry({ env, configDir, policy: opts.policy, projectDir: opts.projectDir })
    if (!decision.enabled) {
      if (debug) process.stderr.write(`[shipguard:telemetry] disabled (${decision.source}); nothing would be sent\n`)
      return Promise.resolve()
    }
    const endpoint = resolveEndpoint(published, env)

    const base = {
      schema: 3 as const,
      event,
      eventId: randomUUID(),
      cliVersion: input.cliVersion,
      provenance: getProvenance(published),
      ci,
    }
    if (debug) {
      const installId = ci ? null : (readInstallId(configDir) ?? randomUUID())
      process.stderr.write(
        `[shipguard:telemetry] SHIPGUARD_TELEMETRY_DEBUG=1: not sending. endpoint=${endpoint ?? '(none)'} ` +
          `payload=${JSON.stringify({ ...base, installId })}\n`,
      )
      return Promise.resolve()
    }
    if (endpoint === null) {
      logger.debug('telemetry: dev build, not sending (set a loopback SHIPGUARD_TELEMETRY_URL to capture)')
      return Promise.resolve()
    }

    if (event === 'cli_first_run') {
      if (firstRunHandled(configDir)) return Promise.resolve()
      if (readInstallId(configDir)) {
        markFirstRunHandled(configDir)
        return Promise.resolve()
      }
    }

    if (!noticeShown(configDir)) {
      process.stderr.write(NOTICE_TEXT + '\n')
      markNoticeShown(configDir)
    }
    const installId = ci ? null : (getOrCreateInstallId(configDir) ?? undefined)
    if (installId === undefined) {
      logger.debug('telemetry: no install id could be saved; not sending')
      return Promise.resolve()
    }
    // Mark before sending: a failed ping is not retried on every later command.
    if (event === 'cli_first_run' && !markFirstRunHandled(configDir)) return Promise.resolve()

    const payload: LifecyclePayload = { ...base, installId }
    if (!validateLifecyclePayload(payload)) {
      logger.debug('telemetry: lifecycle payload failed validation; not sending')
      return Promise.resolve()
    }
    return postBounded(endpoint, JSON.stringify(payload))
  } catch (err) {
    logger.debug(`telemetry: skipped after error (ignored): ${err instanceof Error ? err.message : String(err)}`)
    return Promise.resolve()
  }
}
