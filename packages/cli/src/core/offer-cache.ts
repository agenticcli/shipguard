/**
 * offer-cache.ts: the PUBLIC signed offer (what a plan would add for a stack) and its cache.
 *
 * Files in ~/.config/shipguard (0600 in a 0700 dir), the raw signed text only, verified again on EVERY read:
 *   offer-<hash>.jws   one per detected stack set (hash of the sorted stack names), at most 8, oldest removed
 *   offer-generic.jws  written only by primeOfferCache() (`shipguard setup`): the generic offer, no stack data
 * The gap line reads the stack-set file first, else the generic file. A second repo keeps its own file.
 *
 * Network: GET <api>/api/cli/v1/offer?stacks=a,b (stack names only; none for the generic offer). No sign-in,
 * no code, no paths, no ids. At most one fetch per 7 days (ONE counter shared by the weekly scan fetch and the
 * priming, recorded as an ATTEMPT). Never in a hook, the gate, CI, --quiet, safe mode or with tracking off.
 */
import { createHash } from 'node:crypto'
import { statSync } from 'node:fs'
import { join } from 'node:path'
import { assertTrustedApiUrl } from '../utils/trust.js'
import { listConfigDir, readConfigText, removeConfigFile, writeConfigText } from './config-store.js'
import { loadNag, markOfferFetch, offerFetchDue, type NagContext } from './nag.js'
import { mapOfferPayload, planBlockFrom, unavailableBlock, verifyPlanDocument } from './plan.js'
import type { PlanBlock, PlanUnavailableReason } from './plan-types.js'
import { logger } from '../utils/logger.js'

export const DEFAULT_API_URL = 'https://agenticcli.dev'
export const OFFER_GENERIC_FILE = 'offer-generic.jws'
export const MAX_OFFER_FILES = 8
const OFFER_MAX_BYTES = 65536
/** The weekly fetch runs after the scan result is shown, so it is short; a hang must never hold a terminal. */
export const OFFER_FETCH_TIMEOUT_MS = 4000
const STACK_NAME = /^[a-z0-9][a-z0-9._-]{0,39}$/
const MAX_STACKS = 8

/** Lower-case, valid, unique, sorted, at most 8. Anything else is dropped (the request carries stack names only). */
export function normalizeStacks(stacks: readonly string[]): string[] {
  const set = new Set<string>()
  for (const s of stacks) {
    const n = typeof s === 'string' ? s.trim().toLowerCase() : ''
    if (STACK_NAME.test(n)) set.add(n)
  }
  return [...set].sort().slice(0, MAX_STACKS)
}

export function stackSetFile(stacks: readonly string[]): string {
  const key = createHash('sha256').update('shipguard-offer-stacks-v1' + normalizeStacks(stacks).join(',')).digest('hex').slice(0, 16)
  return `offer-${key}.jws`
}

export interface OfferRead {
  block: PlanBlock
  source: 'stack-set' | 'generic' | 'none'
}

/**
 * The cached public offer for these stacks. A missing, expired or unverifiable file is never used; the result
 * is "unavailable" (NOT_FETCHED, or PLAN_UNVERIFIED when a file was present and failed a real check).
 */
export async function readOffer(ctx: { configDir: string; now: number; safeMode: boolean }, stacks: readonly string[]): Promise<OfferRead> {
  const none: OfferRead = { block: unavailableBlock('NOT_FETCHED'), source: 'none' }
  if (ctx.safeMode) return none
  const names = normalizeStacks(stacks)
  let unverified = false
  for (const [file, source] of [[stackSetFile(names), 'stack-set'], [OFFER_GENERIC_FILE, 'generic']] as const) {
    if (source === 'stack-set' && names.length === 0) continue
    const f = readConfigText(join(ctx.configDir, file), OFFER_MAX_BYTES)
    if (f.state === 'missing') continue
    if (f.state === 'unsafe') { unverified = true; continue }
    const r = await verifyPlanDocument('offer', f.text.trim(), { now: ctx.now })
    if (!r.ok) {
      if (!r.expired) unverified = true
      continue
    }
    return { block: planBlockFrom(mapOfferPayload(r.payload, names), 'cached'), source }
  }
  return unverified ? { block: unavailableBlock('PLAN_UNVERIFIED'), source: 'none' } : none
}

/** Keep at most MAX_OFFER_FILES stack-set files, newest first. The generic file is never counted or removed here. */
function pruneStackSetFiles(configDir: string): void {
  const files = listConfigDir(configDir)
    .filter((n) => /^offer-[0-9a-f]{16}\.jws$/.test(n))
    .map((n) => {
      try { return { n, t: statSync(join(configDir, n)).mtimeMs } } catch (err) {
        logger.debug(`offer-cache: cannot stat ${n}: ${err instanceof Error ? err.message : String(err)}`)
        return { n, t: 0 }
      }
    })
    .sort((a, b) => b.t - a.t)
  for (const old of files.slice(MAX_OFFER_FILES)) removeConfigFile(join(configDir, old.n))
}

/** Read a response body without ever holding more than maxBytes (a hostile server cannot make us buffer without end). */
async function readCapped(res: Response, maxBytes: number): Promise<string | null> {
  const declared = Number(res.headers?.get?.('content-length') ?? '0')
  if (Number.isFinite(declared) && declared > maxBytes) return null
  if (!res.body || typeof res.body.getReader !== 'function') {
    const text = await res.text()
    return text.length > maxBytes ? null : text
  }
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maxBytes) { await reader.cancel(); return null }
    chunks.push(value)
  }
  return Buffer.concat(chunks).toString('utf8')
}

export type OfferFetchResult = { ok: true; block: PlanBlock } | { ok: false; reason: Extract<PlanUnavailableReason, 'OFFLINE' | 'FETCH_FAILED' | 'PLAN_UNVERIFIED'> }

export interface FetchOfferOptions {
  configDir: string
  now: number
  /** null = the generic offer (no stack names in the request). */
  stacks: readonly string[] | null
  safeMode: boolean
  apiUrl?: string
  fetchImpl?: typeof fetch
  timeoutMs?: number
}

/**
 * One public offer request. Verifies before it caches; stores nothing in safe mode. Never throws.
 * Does NOT check the gates or the 7-day counter: callers use maybeFetchWeeklyOffer / primeOfferCache for that,
 * or call this directly for an explicit `shipguard upgrade` (user-initiated, always allowed).
 */
export async function fetchPublicOffer(o: FetchOfferOptions): Promise<OfferFetchResult> {
  const apiUrl = o.apiUrl ?? DEFAULT_API_URL
  try {
    assertTrustedApiUrl(apiUrl)
  } catch (err) {
    logger.debug(`offer-cache: not fetching, ${err instanceof Error ? err.message : String(err)}`)
    return { ok: false, reason: 'FETCH_FAILED' }
  }
  const names = o.stacks === null ? [] : normalizeStacks(o.stacks)
  const url = `${apiUrl.replace(/\/+$/, '')}/api/cli/v1/offer${names.length > 0 ? `?stacks=${encodeURIComponent(names.join(','))}` : ''}`
  let body: string | null
  try {
    const res = await (o.fetchImpl ?? fetch)(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(o.timeoutMs ?? OFFER_FETCH_TIMEOUT_MS),
    })
    if (!res.ok) {
      logger.debug(`offer-cache: offer request answered ${res.status}`)
      return { ok: false, reason: 'FETCH_FAILED' }
    }
    body = await readCapped(res, OFFER_MAX_BYTES + 1024)
  } catch (err) {
    logger.debug(`offer-cache: offer request failed: ${err instanceof Error ? err.message : String(err)}`)
    return { ok: false, reason: 'OFFLINE' }
  }
  if (body === null) return { ok: false, reason: 'FETCH_FAILED' }
  // The reply is either the raw compact JWS or { "offer": "<JWS>" }; both are verified the same way.
  let token = body.trim()
  if (token.startsWith('{')) {
    try {
      const parsed: unknown = JSON.parse(token)
      token = typeof (parsed as { offer?: unknown } | null)?.offer === 'string' ? ((parsed as { offer: string }).offer) : ''
    } catch (err) {
      logger.debug(`offer-cache: offer reply is not JSON: ${err instanceof Error ? err.message : String(err)}`)
      return { ok: false, reason: 'FETCH_FAILED' }
    }
  }
  const r = await verifyPlanDocument('offer', token, { now: o.now })
  if (!r.ok) {
    logger.debug(`offer-cache: offer document not trusted (${r.step})`)
    return { ok: false, reason: 'PLAN_UNVERIFIED' }
  }
  if (!o.safeMode) {
    const file = names.length > 0 ? stackSetFile(names) : OFFER_GENERIC_FILE
    if (writeConfigText(o.configDir, file, token) && names.length > 0) pruneStackSetFiles(o.configDir)
  }
  return { ok: true, block: planBlockFrom(mapOfferPayload(r.payload, names), 'cached') }
}

// ---------------------------------------------------------------------------
// Gates: when the CLI may fetch on its own
// ---------------------------------------------------------------------------

export interface OfferFetchGate {
  signedIn: boolean
  /** Interactive terminal (stdout is a TTY). */
  terminal: boolean
  /** `CI` set. */
  ci: boolean
  quiet: boolean
  /** A hook or the gate. */
  hookOrGate: boolean
  safeMode: boolean
  /** DO_NOT_TRACK, SHIPGUARD_TELEMETRY=0 or `telemetry disable`. */
  trackingOff: boolean
  dryRun: boolean
}

/** Weekly fetch for a signed-out Free scan on an interactive terminal (stack names only). */
export function weeklyFetchAllowed(g: OfferFetchGate, nag: ReturnType<typeof loadNag>, now: number): boolean {
  return !g.signedIn && g.terminal && !g.ci && !g.quiet && !g.hookOrGate && !g.safeMode && !g.trackingOff && !g.dryRun && offerFetchDue(nag, now)
}

/** `shipguard setup` priming: explicit, user-run, interactive, signed out. */
export function primeAllowed(g: OfferFetchGate, nag: ReturnType<typeof loadNag>, now: number): boolean {
  return !g.signedIn && g.terminal && !g.ci && !g.safeMode && !g.trackingOff && !g.dryRun && offerFetchDue(nag, now)
}

export type OfferAttempt = { attempted: false } | { attempted: true; result: OfferFetchResult }

async function attempt(ctx: NagContext, stacks: readonly string[] | null, opts: { apiUrl?: string; fetchImpl?: typeof fetch; timeoutMs?: number }): Promise<OfferAttempt> {
  markOfferFetch(ctx) // the attempt is counted before the network is touched: a failing network is not retried on every scan
  const result = await fetchPublicOffer({ configDir: ctx.configDir, now: ctx.now, stacks, safeMode: ctx.safeMode, ...opts })
  return { attempted: true, result }
}

/** The weekly public fetch for a terminal scan. Returns attempted:false when a gate or the counter says no. */
export async function maybeFetchWeeklyOffer(
  ctx: NagContext,
  gate: OfferFetchGate,
  stacks: readonly string[],
  opts: { apiUrl?: string; fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<OfferAttempt> {
  if (normalizeStacks(stacks).length === 0) return { attempted: false }
  if (!weeklyFetchAllowed(gate, loadNag(ctx), ctx.now)) return { attempted: false }
  return attempt(ctx, stacks, opts)
}

/**
 * `shipguard setup` calls this once, after the user confirmed: ONE generic public offer fetch, NO stack data in the
 * request, stored as the generic offer file. Same 7-day counter, same exclusions plus signed in and --dry-run.
 * A failed fetch is silent for setup (the result says why; the exit code is the caller's and unchanged).
 */
export async function primeOfferCache(
  ctx: NagContext,
  gate: OfferFetchGate,
  opts: { apiUrl?: string; fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<OfferAttempt> {
  if (!primeAllowed(gate, loadNag(ctx), ctx.now)) return { attempted: false }
  return attempt(ctx, null, opts)
}
