/**
 * ShipGuard CLI lifecycle telemetry — two one-off events beside the per-scan ping (schema 3).
 * Same path (CLI -> /cli-telemetry relay -> PostHog), same privacy design as core/telemetry.ts.
 * Contract: agenticcli docs/posthog/contracts/cli-telemetry-v2.md (section 4b).
 *
 *   cli_first_run  the first time this install id runs a command. Idempotent: a marker file
 *                  (`telemetry-first-run-sent`, content = the install id) is written BEFORE the request,
 *                  so a failed or slow send is never retried in a loop, and if the marker cannot be
 *                  written nothing is sent. Never sent in CI (no install id exists there).
 *   cli_login      after a successful `shipguard login`. In CI it carries installId null.
 *
 * WHAT IS SENT (always and only, exactly these keys):
 *   schema 3 · event · eventId (random v4 UUID) · installId (random v4 UUID, null in CI) ·
 *   cliVersion · provenance ("published" | "dev") · ci
 *
 * WHAT IS NEVER SENT: anything about the account (id, email, token, API URL), paths, repo names,
 * hostnames, environment values. The install id is NOT linked to an account: the login event carries the
 * same pseudonymous id as every other ping and no account field; the server-side account events
 * (e.g. `cli_login_completed`) use an unrelated distinct id and no install id.
 *
 * OPT OUT: identical to the scan ping, decided by decideTelemetry(): DO_NOT_TRACK / SHIPGUARD_TELEMETRY=0,
 * `shipguard telemetry disable`, `telemetry.enabled: false` in shipguard.policy.yml or .shipguard.yml.
 * SHIPGUARD_TELEMETRY_DEBUG=1 prints the payload to stderr and sends nothing, writes nothing.
 * When opted out, nothing is written either (no install id, no marker, no notice).
 */
import { randomUUID } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { logger } from '../utils/logger.js'
import { ensureSecureDir, writeSecureFileSync } from '../utils/secure-fs.js'
import {
  FETCH_TIMEOUT_MS,
  IS_PUBLISHED_BUILD,
  NOTICE_TEXT,
  PING_WAIT_MS,
  debugEnabled,
  decideTelemetry,
  detectCi,
  getProvenance,
  resolveEndpoint,
  type SendOptions,
  type TelemetryProvenance,
} from './telemetry.js'
import {
  UUID_V4,
  getConfigDir,
  getOrCreateInstallId,
  markNoticeShown,
  noticeShown,
  readInstallId,
} from './telemetry-config.js'

export type LifecycleEvent = 'cli_first_run' | 'cli_login'

/** The schema-3 wire payload. Exactly these keys, all required. */
export interface LifecyclePayload {
  schema: 3
  event: LifecycleEvent
  eventId: string
  installId: string | null
  cliVersion: string
  provenance: TelemetryProvenance
  ci: boolean
}

export interface LifecycleInput {
  cliVersion: string
}

/** File in the config dir whose content is the install id that already sent `cli_first_run`. */
export const FIRST_RUN_MARKER = 'telemetry-first-run-sent'

const ALLOWED_KEYS: ReadonlyArray<keyof LifecyclePayload> = [
  'schema',
  'event',
  'eventId',
  'installId',
  'cliVersion',
  'provenance',
  'ci',
]
const EVENTS: readonly string[] = ['cli_first_run', 'cli_login']
const VERSION_RE = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})(-[0-9A-Za-z.-]{1,24})?$/

/** Copy field by field so an extra property on the input can never leak into the request. */
export function buildLifecyclePayload(input: LifecyclePayload): LifecyclePayload {
  const { schema, event, eventId, installId, cliVersion, provenance, ci } = input
  return { schema, event, eventId, installId, cliVersion, provenance, ci }
}

/**
 * Contract check: exact key set, types, bounds, installId null iff ci, and no `cli_first_run` in CI.
 * True when the payload is safe to send.
 */
export function validateLifecyclePayload(payload: unknown): payload is LifecyclePayload {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return false
  const obj = payload as Record<string, unknown>
  const keys = Object.keys(obj)
  if (keys.length !== ALLOWED_KEYS.length) return false
  for (const k of ALLOWED_KEYS) if (!(k in obj)) return false

  if (obj.schema !== 3) return false
  if (typeof obj.event !== 'string' || !EVENTS.includes(obj.event)) return false
  if (typeof obj.eventId !== 'string' || !UUID_V4.test(obj.eventId)) return false
  if (typeof obj.ci !== 'boolean') return false
  if (obj.ci) {
    if (obj.installId !== null) return false
    if (obj.event === 'cli_first_run') return false // first run needs an install id, which CI never has
  } else if (typeof obj.installId !== 'string' || !UUID_V4.test(obj.installId)) {
    return false
  }
  if (typeof obj.cliVersion !== 'string' || obj.cliVersion.length > 40 || !VERSION_RE.test(obj.cliVersion)) return false
  if (obj.provenance !== 'published' && obj.provenance !== 'dev') return false
  return true
}

type FirstRunState = 'sent' | 'unsent' | 'unknown'

/** Whether this install id already sent `cli_first_run`. 'unknown' (unreadable marker) means: do not send. */
function firstRunState(dir: string, installId: string): FirstRunState {
  const file = join(dir, FIRST_RUN_MARKER)
  try {
    if (!existsSync(file)) return 'unsent'
    return readFileSync(file, 'utf-8').trim() === installId ? 'sent' : 'unsent'
  } catch (err) {
    logger.debug(`telemetry: first-run marker unreadable: ${err instanceof Error ? err.message : String(err)}`)
    return 'unknown'
  }
}

/** Persist the marker. Returns false when it cannot be written (caller must then not send). */
function writeFirstRunMarker(dir: string, installId: string): boolean {
  try {
    ensureSecureDir(dir)
    writeSecureFileSync(join(dir, FIRST_RUN_MARKER), installId + '\n')
    return true
  } catch (err) {
    logger.debug(`telemetry: could not persist the first-run marker: ${err instanceof Error ? err.message : String(err)}`)
    return false
  }
}

/**
 * Send one lifecycle event. Resolves within PING_WAIT_MS, never rejects, never throws, never writes
 * to stdout. All opt-outs are honoured before anything is read or written.
 */
export function sendLifecycleEvent(
  event: LifecycleEvent,
  input: LifecycleInput,
  opts: SendOptions = {},
): Promise<void> {
  try {
    const env = opts.env ?? process.env
    const configDir = opts.configDir ?? getConfigDir()
    const published = opts.published ?? IS_PUBLISHED_BUILD
    const debug = debugEnabled(env)

    const decision = decideTelemetry({ env, configDir, policy: opts.policy, projectDir: opts.projectDir })
    if (!decision.enabled) {
      if (debug) process.stderr.write(`[shipguard:telemetry] disabled (${decision.source}); no ${event} event would be sent\n`)
      return Promise.resolve()
    }

    const ci = detectCi(env)
    // First run is keyed on the install id; CI never has one, so it never reports a first run.
    if (event === 'cli_first_run' && ci) return Promise.resolve()

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
      // Nothing is sent or saved. Without a saved id, show a throwaway one so the shape is exact.
      const stored = ci ? null : readInstallId(configDir)
      const installId = ci ? null : (stored ?? randomUUID())
      const note = !ci && !stored ? ' (installId is a preview: none saved yet, one is created on the first real ping)' : ''
      process.stderr.write(
        `[shipguard:telemetry] SHIPGUARD_TELEMETRY_DEBUG=1: not sending. provenance=${base.provenance} ` +
          `endpoint=${endpoint ?? '(none: dev build without a loopback SHIPGUARD_TELEMETRY_URL)'} ` +
          `payload=${JSON.stringify(buildLifecyclePayload({ ...base, installId }))}${note}\n`,
      )
      return Promise.resolve()
    }
    if (endpoint === null) {
      logger.debug(`telemetry: dev build, not sending ${event}`)
      return Promise.resolve()
    }

    // Notice BEFORE the first request in every output mode. stderr only.
    if (!noticeShown(configDir)) {
      process.stderr.write(NOTICE_TEXT + '\n')
      markNoticeShown(configDir)
    }

    const installId = ci ? null : (getOrCreateInstallId(configDir) ?? undefined)
    if (installId === undefined) {
      logger.debug('telemetry: no install id could be saved; not sending')
      return Promise.resolve()
    }

    if (event === 'cli_first_run' && installId !== null) {
      // At-most-once: decide, then record BEFORE the request. A failed request is never retried.
      if (firstRunState(configDir, installId) !== 'unsent') return Promise.resolve()
      if (!writeFirstRunMarker(configDir, installId)) return Promise.resolve()
    }

    const payload = buildLifecyclePayload({ ...base, installId })
    if (!validateLifecyclePayload(payload)) {
      logger.debug(`telemetry: ${event} payload failed validation; not sending`)
      return Promise.resolve()
    }
    const body = JSON.stringify(payload)

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
          // Telemetry failure must never affect the command, its output or its exit code.
          logger.debug(`telemetry: ${event} failed (ignored): ${err instanceof Error ? err.message : String(err)}`)
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
  } catch (err) {
    logger.debug(`telemetry: ${event} skipped after error (ignored): ${err instanceof Error ? err.message : String(err)}`)
    return Promise.resolve()
  }
}
