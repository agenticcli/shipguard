/**
 * plan-client.ts: the call-site glue for the signed plan block (W1b). The pure modules (plan.ts, nag.ts,
 * hint.ts, offer-cache.ts, plan-lines.ts) decide and format; this file gathers the run facts (terminal, CI,
 * safe mode, tracking), makes the ONE fresh plan read used by `status`, `upgrade` and `login`
 * (GET /api/user/me with the client hello and a nonce), and records what a verified reply teaches the CLI
 * (account cache, hint, last account status).
 *
 * HARD RULES (public repo): no plan fact lives here. Plan data is display state only: nothing in this file
 * unlocks a rule. Every failure ends in "plan unavailable" and plain Free behaviour, never a crash.
 */
import { getAuthToken, loadCredentials, isTokenExpired, RefreshUnavailableError } from './auth.js'
import { PlatformUnavailableError, isPlatformUnavailable, parseRetryAfterSeconds } from './platform-status.js'
import { getConfigDir, isSafeMode } from './telemetry-config.js'
import { CLI_VERSION, decideTelemetry, detectCi } from './telemetry.js'
import {
  acctFromAccessToken,
  cachedWithReason,
  clearAccountCache,
  clientHelloHeaders,
  newNonce,
  readAccountCache,
  readAccountReply,
  unavailableBlock,
  writeAccountCache,
  type PlanRead,
} from './plan.js'
import type { AccountStatus, PlanBlock } from './plan-types.js'
import { clearHint, writeHint } from './hint.js'
import { lastAccountStatus, loadNag, recordAccountStatus, type NagContext, type NagData } from './nag.js'
import { assertTrustedApiUrl } from '../utils/trust.js'
import { logger } from '../utils/logger.js'

export const DEFAULT_API_URL = 'https://agenticcli.dev'
/** The plan read is short and user-initiated: a hang must never hold a terminal. */
const PLAN_READ_TIMEOUT_MS = 10_000
const PLAN_REPLY_MAX_BYTES = 64 * 1024

/** The run facts every plan decision needs, gathered once per command. */
export interface PlanEnv {
  configDir: string
  now: number
  safeMode: boolean
  ci: boolean
  /** stdout is an interactive terminal. */
  terminal: boolean
  /** SHIPGUARD_API_KEY mode: no account cache at all, nothing written about the account. */
  apiKeyMode: boolean
  /** DO_NOT_TRACK, SHIPGUARD_TELEMETRY=0, `telemetry disable` or a project opt-out. */
  trackingOff: boolean
}

export function getPlanEnv(opts: { policy?: unknown; projectDir?: string } = {}): PlanEnv {
  let trackingOff = false
  try {
    trackingOff = !decideTelemetry({ policy: opts.policy, projectDir: opts.projectDir }).enabled
  } catch (err) {
    // Cannot tell: treat tracking as off (fail closed: no optional network call).
    logger.debug(`plan-client: tracking decision failed, treating as off: ${err instanceof Error ? err.message : String(err)}`)
    trackingOff = true
  }
  return {
    configDir: getConfigDir(),
    now: Date.now(),
    safeMode: isSafeMode(),
    ci: detectCi(),
    terminal: Boolean(process.stdout.isTTY),
    apiKeyMode: Boolean(process.env.SHIPGUARD_API_KEY),
    trackingOff,
  }
}

export function nagCtx(env: PlanEnv): NagContext {
  // API-key mode keeps no per-account files: it is treated like safe mode for writes.
  return { configDir: env.configDir, now: env.now, safeMode: env.safeMode || env.apiKeyMode }
}

export function loadNagFor(env: PlanEnv): NagData {
  return loadNag({ configDir: env.configDir, safeMode: env.safeMode })
}

/** Nothing about the account is written in safe mode or in API-key mode. */
export function noAccountWrites(env: PlanEnv): boolean {
  return env.safeMode || env.apiKeyMode
}

/**
 * What a VERIFIED live account document teaches the CLI: store the raw document (verified again on every
 * read), remember the last account status (never pitch a paying user who is later offline), and set or clear the
 * hint. A document that did not verify teaches nothing. Best effort: a failed write is logged by the stores.
 */
export function persistLivePlan(env: PlanEnv, read: PlanRead, acct: string | null): void {
  if (!read.live || read.token === null || acct === null || noAccountWrites(env)) return
  writeAccountCache(env.configDir, read.token, { noWrite: false })
  const status = read.block.server?.account?.status
  if (status !== undefined) recordAccountStatus(nagCtx(env), acct, status)
  // The server's "no plan" answer sets the hint (an hour at most); a pending payment never does (it may land any minute).
  const noPlan = status === 'none' || status === 'lapsed'
  if (noPlan) writeHint({ configDir: env.configDir, now: env.now, safeMode: env.safeMode }, acct)
  else clearHint(env.configDir)
}

/** Login, logout and a changed account: nothing cached about the old account may linger. */
export function forgetAccountState(env: PlanEnv): void {
  clearAccountCache(env.configDir)
  clearHint(env.configDir)
}

/** The account status to reason about: this run's verified block first, else the LAST verified one for this account. */
export function accountStatusOf(plan: PlanBlock, nag: NagData, acct: string | null): AccountStatus | null {
  const own = plan.server?.account?.status
  if (own !== undefined) return own
  return acct !== null ? lastAccountStatus(nag, acct) : null
}

// ---------------------------------------------------------------------------
// The fresh plan read (status, upgrade, login)
// ---------------------------------------------------------------------------

export type SignIn = 'signed-out' | 'expired' | 'signed-in'

export interface FreshPlan {
  signIn: SignIn
  plan: PlanBlock
  acct: string | null
  accountStatus: AccountStatus | null
  /** Why the live read did not happen (a cached copy may still be shown); null when it worked or nothing was tried. */
  failure: 'OFFLINE' | 'FETCH_FAILED' | null
  /** Seconds the server asked to wait (Retry-After), when known. */
  retryAfterSeconds?: number
  /** The login must be redone (401 from the server). */
  authRejected?: boolean
  expiresAt?: number
}

async function readCapped(res: Response): Promise<string | null> {
  const text = await res.text()
  return text.length > PLAN_REPLY_MAX_BYTES ? null : text
}

type LiveRead =
  | { ok: true; read: PlanRead }
  | { ok: false; failure: 'OFFLINE' | 'FETCH_FAILED'; retryAfterSeconds?: number; authRejected?: boolean }

async function liveRead(apiUrl: string, token: string, acct: string | null, env: PlanEnv): Promise<LiveRead> {
  assertTrustedApiUrl(apiUrl)
  const nonce = newNonce()
  let res: Response
  try {
    res = await fetch(`${apiUrl.replace(/\/+$/, '')}/api/user/me`, {
      headers: { Authorization: `Bearer ${token}`, ...clientHelloHeaders(CLI_VERSION, nonce) },
      redirect: 'error',
      signal: AbortSignal.timeout(PLAN_READ_TIMEOUT_MS),
    })
  } catch (err) {
    logger.debug(`plan-client: plan read failed: ${err instanceof Error ? err.message : String(err)}`)
    return { ok: false, failure: 'OFFLINE' }
  }
  if (res.status === 401) return { ok: false, failure: 'FETCH_FAILED', authRejected: true }
  if (!res.ok) {
    // Any 5xx (including 503 TOKEN_CHECK_UNAVAILABLE: the server cannot read its revocation list) is "the server is
    // unavailable", never "sign in again" (that is 401). 429 is the same class: retry later.
    const retryAfterSeconds = parseRetryAfterSeconds(res.headers)
    let code: unknown
    try {
      code = (JSON.parse((await readCapped(res)) ?? '{}') as { code?: unknown }).code
    } catch (err) {
      logger.debug(`plan-client: plan read answered ${res.status} with an unreadable body: ${err instanceof Error ? err.message : String(err)}`)
    }
    logger.debug(`plan-client: plan read answered ${res.status}${typeof code === 'string' ? ` (${code})` : ''}${isPlatformUnavailable(res, { code }) ? ' (platform unavailable)' : ''}`)
    return { ok: false, failure: 'FETCH_FAILED', ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}) }
  }
  let body: { account?: unknown } | null = null
  try {
    const text = await readCapped(res)
    body = text === null ? null : (JSON.parse(text) as { account?: unknown })
  } catch (err) {
    logger.debug(`plan-client: plan reply is not JSON: ${err instanceof Error ? err.message : String(err)}`)
    return { ok: false, failure: 'FETCH_FAILED' }
  }
  if (body === null) return { ok: false, failure: 'FETCH_FAILED' }
  const read = await readAccountReply(body.account, { acct, nonce, now: env.now })
  return { ok: true, read }
}

/**
 * One fresh plan read for `status`, `upgrade` and `login`: never trusts the cache first. A failed live read shows a
 * verified cached copy (status `cached`, reason OFFLINE or FETCH_FAILED), else "unavailable". Never throws.
 */
export async function readPlanFresh(apiUrl: string, env: PlanEnv): Promise<FreshPlan> {
  const nag = loadNagFor(env)
  const creds = loadCredentials()
  const keyMode = env.apiKeyMode
  if (!creds && !keyMode) {
    return { signIn: 'signed-out', plan: unavailableBlock('NOT_FETCHED'), acct: null, accountStatus: null, failure: null }
  }
  let token: string | null = null
  try {
    token = await getAuthToken(apiUrl)
  } catch (err) {
    // The service is down or rate limiting the refresh: the login is kept, this is not "sign in again".
    if (err instanceof PlatformUnavailableError || err instanceof RefreshUnavailableError) {
      logger.debug(`plan-client: token not available right now: ${err.message}`)
      const acct = creds ? acctFromAccessToken(creds.accessToken) : null
      return withCache(env, nag, acct, 'FETCH_FAILED', err.retryAfterSeconds)
    }
    logger.debug(`plan-client: token not available: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (token === null) {
    return {
      signIn: 'expired',
      plan: unavailableBlock('NOT_FETCHED'),
      acct: null,
      accountStatus: null,
      failure: null,
      ...(creds && isTokenExpired(creds) ? { expiresAt: creds.expiresAt } : {}),
    }
  }
  const acct = acctFromAccessToken(token)
  const live = await liveRead(apiUrl, token, acct, env)
  if (live.ok) {
    persistLivePlan(env, live.read, acct)
    return {
      signIn: 'signed-in',
      plan: live.read.block,
      acct,
      accountStatus: accountStatusOf(live.read.block, nag, acct),
      failure: null,
    }
  }
  if (live.authRejected) {
    return { signIn: 'expired', plan: unavailableBlock('NOT_FETCHED'), acct: null, accountStatus: null, failure: null, authRejected: true }
  }
  return withCache(env, nag, acct, live.failure, live.retryAfterSeconds)
}

async function withCache(env: PlanEnv, nag: NagData, acct: string | null, failure: 'OFFLINE' | 'FETCH_FAILED', retryAfterSeconds?: number): Promise<FreshPlan> {
  let block = unavailableBlock(failure)
  if (!env.safeMode && !env.apiKeyMode && acct !== null) {
    const cached = await readAccountCache(env.configDir, { acct, now: env.now })
    if (cached.block.status === 'cached') block = cachedWithReason(cached.block, failure)
    else if (cached.block.reason === 'PLAN_UNVERIFIED') block = cached.block
  }
  return {
    signIn: 'signed-in',
    plan: block,
    acct,
    accountStatus: accountStatusOf(block, nag, acct),
    failure,
    ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
  }
}
