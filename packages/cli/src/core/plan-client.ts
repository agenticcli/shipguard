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
import { isMuted, lastAccountStatus, loadNag, markMoment, momentDue, recordAccountStatus, repoKey, type NagContext, type NagData } from './nag.js'
import { readOffer } from './offer-cache.js'
import { buildRerunCommand } from './rerun.js'
import { gateGapLine, type DetectedStack } from './plan-lines.js'
import { detectFrameworks } from './framework.js'
import { loadPolicy } from './policy.js'
import { resolveRepoIdentity } from './history/index.js'
import { openHistoryStore } from './history/store.js'
import { stackDisplayName } from './fix-guidance.js'
import { bundledRulesMeta } from './bundled-rules.js'
import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
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

/** A hook or the gate runs this process (the gate sets SHIPGUARD_GATE_KIND; only the three known values count). */
export function isHookOrGate(env: NodeJS.ProcessEnv = process.env): boolean {
  const kind = env.SHIPGUARD_GATE_KIND
  return kind === 'claude' || kind === 'git' || kind === 'ci'
}

/** The id the display counters are keyed by: the git root path of the scanned folder, else the folder itself. */
export function repoIdOf(cwd: string): string {
  let dir = resolve(cwd)
  for (;;) {
    if (existsSync(join(dir, '.git'))) return dir
    const parent = dirname(dir)
    if (parent === dir) return resolve(cwd)
    dir = parent
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
export function persistLivePlan(env: PlanEnv, read: PlanRead, acct: string | null, opts: { hint?: boolean } = {}): void {
  if (!read.live || read.token === null || acct === null || noAccountWrites(env)) return
  writeAccountCache(env.configDir, read.token, { noWrite: false })
  const status = read.block.server?.account?.status
  if (status !== undefined) recordAccountStatus(nagCtx(env), acct, status)
  // The server's "no plan" answer sets the hint (an hour at most); a pending payment never does (it may land any minute).
  const noPlan = status === 'none' || status === 'lapsed'
  // `status`, `upgrade` and `login` clear the hint (spec 02): only a scan's "no plan" answer sets it.
  if (noPlan && opts.hint !== false) writeHint({ configDir: env.configDir, now: env.now, safeMode: env.safeMode }, acct)
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
  if (!env.safeMode) clearHint(env.configDir)
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
    persistLivePlan(env, live.read, acct, { hint: false })
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

// ---------------------------------------------------------------------------
// The gate's weekly gap line (spec 05 moment 1, hook column): first line only, read from the verified cache
// ---------------------------------------------------------------------------

/**
 * The only plan line a gate may print, on a clean pass: the first line of the weekly "Not run here" line, read from
 * the VERIFIED cache (account document when signed in, else the cached public offer). It never fetches, never prints
 * offer text or a price, shares the scan screen's 7-day counter, and is silent in CI, safe mode, API-key mode and when
 * muted. Any failure is "no line". Never throws.
 */
export async function gateGapFromCache(dir: string): Promise<string | null> {
  try {
    const env = getPlanEnv({ projectDir: dir })
    if (env.ci || env.safeMode || env.apiKeyMode || env.trackingOff) return null
    const nag = loadNagFor(env)
    if (isMuted(nag)) return null
    const frameworks = detectFrameworks(dir).frameworks.filter((f) => f.name !== 'generic')
    if (frameworks.length === 0) return null
    const detected: DetectedStack[] = frameworks.map((f) => ({ key: f.name, display: stackDisplayName(f.name), version: f.version ?? null }))
    const creds = loadCredentials()
    const acct = creds ? acctFromAccessToken(creds.accessToken) : null
    const plan = creds
      ? acct !== null ? (await readAccountCache(env.configDir, { acct, now: env.now })).block : unavailableBlock('NOT_FETCHED')
      : (await readOffer({ configDir: env.configDir, now: env.now, safeMode: env.safeMode }, detected.map((d) => d.key))).block
    const rk = repoKey(repoIdOf(dir))
    const pitch = gateGapLine({
      plan, signedIn: creds !== null, accountStatus: accountStatusOf(plan, nag, acct), detected,
      rulesApplied: bundledRulesMeta().ruleCount, scanComplete: true, blocking: false, fallbackActive: false, ci: false,
      hookOrGate: false, safeMode: false, muted: false, recentlyShown: false, terminal: false, quiet: false,
      screenDue: momentDue(nag, 'screenPitch', rk, env.now),
    })
    if (pitch.lines.length === 0) return null
    markMoment(nagCtx(env), 'screenPitch', rk)
    return pitch.lines[0]
  } catch (err) {
    logger.debug(`plan-client: the gate gap line is not available: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}

// ---------------------------------------------------------------------------
// Facts the plan commands share (local, read-only)
// ---------------------------------------------------------------------------

/** The frameworks detected in a folder (never 'generic'). A failed detection is "none", logged. */
export function detectedStacks(dir: string): DetectedStack[] {
  try {
    return detectFrameworks(dir).frameworks
      .filter((f) => f.name !== 'generic')
      .map((f) => ({ key: f.name, display: stackDisplayName(f.name), version: f.version ?? null }))
  } catch (err) {
    logger.debug(`plan-client: stack detection failed: ${err instanceof Error ? err.message : String(err)}`)
    return []
  }
}

export interface LastScan {
  runId: string; corpus: 'rulebook' | 'general'; applied: number; at: string
  /** The re-run builder's command for that scan's target (history keeps the target only), word for word as the scan screen prints it. */
  scanCommand: string
}

/** The newest run in this folder's history (`Last scan here`), or null. Read-only; never throws. */
export async function lastScanHere(dir: string): Promise<LastScan | null> {
  try {
    const policy = await loadPolicy(dir)
    const opened = await openHistoryStore(dir, policy, CLI_VERSION)
    if (!opened.ok) return null
    try {
      const row = opened.store.listRecentScans(resolveRepoIdentity(dir).repoId, 1)[0]
      const m = row?.rulesLabel ? /^(rulebook|general)(?::(\d+))?$/.exec(row.rulesLabel) : null
      if (!row || !m) return null
      const applied = m[2] !== undefined ? Number(m[2]) : bundledRulesMeta().ruleCount
      const scanCommand = buildRerunCommand({ invocationCwd: dir, scanRoot: resolve(dir, row.target ?? '.') })
      return { runId: row.scanId, corpus: m[1] as 'rulebook' | 'general', applied, at: new Date(row.timestamp).toISOString(), scanCommand }
    } finally {
      opened.store.close()
    }
  } catch (err) {
    logger.debug(`plan-client: no last scan (${err instanceof Error ? err.message : String(err)})`)
    return null
  }
}

export const generalRuleCount = (): number => bundledRulesMeta().ruleCount

/** Header fields every plan command's `--json` envelope shares (spec 05: same as a scan, exit keys null where not applicable). */
export function planEnvelope(cliVersion: string, plan: Record<string, unknown>, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: '7', cliVersion, runId: null, ok: true, agentAction: 'proceed',
    exit: { code: 0, strict: null, strictWouldExit: null },
    plan, ...extra,
  }
}
