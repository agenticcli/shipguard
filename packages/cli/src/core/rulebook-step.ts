/**
 * rulebook-step.ts: the ONE place that decides how a scan gets its rules and what the plan block says about it
 *. scan.ts hands it the facts of the run
 * and gets back: the rules to run, the plan block, the fallback (if any) or the error to exit with.
 *
 * HARD RULES (public repo): no plan fact lives here; the rulebook is used ONLY when the server serves a verified,
 * attested bundle (the plan block is display state and never unlocks anything). A signed-out run is a plain Free
 * run. Every failure is "general rules + what ran", or exit 3 for an explicit --pro. Never a crash.
 */
import type { DegradeReason, QualityGateRule } from '@agenticcli/shared'
import { acctFromAccessToken, decideRulebookUse, fallbackApplies, readAccountCache, unavailableBlock, cacheMaySkipRulebookCall } from './plan.js'
import type { RulebookCause, RulebookFallbackCode } from './plan.js'
import { hintSkipsCall } from './hint.js'
import { readOffer } from './offer-cache.js'
import { fallbackMessage } from './plan-lines.js'
import type { PlanBlock, AccountStatus } from './plan-types.js'
import { loadCredentials } from './auth.js'
import { accountStatusOf, loadNagFor, persistLivePlan, type PlanEnv } from './plan-client.js'
import type { ProFetchError, ProFetchResult } from './pro-scanner.js'
import { loadBundledRules } from './bundled-rules.js'
import { logger } from '../utils/logger.js'

export type FetchProRulesFn = (
  frameworks: string[],
  categories: string[] | undefined,
  apiUrl: string,
  scanId?: string,
) => Promise<ProFetchResult>

export interface RulebookStepInput {
  env: PlanEnv
  /** The user typed --pro: the rulebook is REQUIRED. */
  explicitPro: boolean
  /** --general: general rules only, no rulebook call. */
  general: boolean
  allowDegraded: boolean
  /** A hook or the gate (a signed-in Free hook may skip the call on a valid hint). */
  hookOrGate: boolean
  apiUrl: string
  /** Detected framework names ('generic' = none recognised). */
  frameworks: string[]
  categories: string[]
  scanId: string
  fetchProRules: FetchProRulesFn
}

export interface StepFallback {
  code: RulebookFallbackCode
  /** ALLOWANCE_USED only when the server's SIGNED reply said the limit is used up. */
  reason: 'ALLOWANCE_USED' | null
  message: string
  serverText: string | null
}

export interface StepError {
  /** A code of the 02 table. */
  code: 'LOGIN_REQUIRED' | 'TOKEN_EXPIRED' | RulebookFallbackCode | 'RATE_LIMITED' | 'NO_RULES_APPLIED'
  message: string
  /** The internal class of the failed request (ProFetchErrorCode), for the calm wording of some causes. */
  proErrorCode?: string
  retryAfterSeconds?: number
}

export interface RulebookStepResult {
  signedIn: boolean
  acct: string | null
  /** Rules to hand to the scanner (undefined = general rules only). */
  proRules: QualityGateRule[] | undefined
  rulesVersion: string | undefined
  /** The served rules include rules that are not in the bundled general set, or the account has a plan: a rulebook run. */
  rulebookRan: boolean
  partial: boolean
  tiersApplied: string[] | null
  fallback: StepFallback | null
  /** An explicit --pro with --allow-degraded that ran general rules: the old degraded-scan record. */
  degradedReason: DegradeReason | null
  plan: PlanBlock
  /** This run's verified account status, else the LAST verified one for this account. */
  accountStatus: AccountStatus | null
  areaByRuleId: Record<string, string>
  /** Plain stderr lines for a human run (for example "sign-in expired"). */
  notes: string[]
  error: StepError | null
}

const RULEBOOK_AREA_NONE: Record<string, string> = {}

function base(partial: Partial<RulebookStepResult> & Pick<RulebookStepResult, 'plan'>): RulebookStepResult {
  return {
    signedIn: false, acct: null, proRules: undefined, rulesVersion: undefined, rulebookRan: false, partial: false,
    tiersApplied: null, fallback: null, degradedReason: null, accountStatus: null, areaByRuleId: RULEBOOK_AREA_NONE,
    notes: [], error: null, ...partial,
  }
}

function causeOf(err: ProFetchError): RulebookCause {
  const code: RulebookFallbackCode =
    err.code === 'ALLOWANCE_USED' || err.code === 'INSUFFICIENT_CREDITS' ? 'RULEBOOK_WITHHELD'
    : err.code === 'PLAN_INACTIVE' ? 'PLAN_INACTIVE'
    : 'RULEBOOK_UNREACHABLE'
  return { code, serverCode: err.context?.serverCode ?? null, serverText: err.context?.serverText ?? null }
}

const REMOVE_PRO = 'Remove --pro to fall back to general rules automatically, or add --allow-degraded.'

/** The cached plan block for a signed-in run that makes no call: account cache, else the unavailable block. */
async function cachedPlan(env: PlanEnv, acct: string | null): Promise<PlanBlock> {
  if (env.safeMode || env.apiKeyMode || acct === null) return unavailableBlock('NOT_FETCHED')
  return (await readAccountCache(env.configDir, { acct, now: env.now })).block
}

export async function runRulebookStep(i: RulebookStepInput): Promise<RulebookStepResult> {
  const { env } = i
  const creds = loadCredentials()
  const signedIn = creds !== null || env.apiKeyMode
  const acctPre = creds ? acctFromAccessToken(creds.accessToken) : null
  const nag = loadNagFor(env)

  // --general: general rules only, nothing asked of the server.
  if (i.general) {
    const plan = signedIn ? await cachedPlan(env, acctPre) : unavailableBlock('NOT_FETCHED')
    return base({ signedIn, acct: acctPre, plan, accountStatus: accountStatusOf(plan, nag, acctPre) })
  }

  // A plain run while signed out is a plain Free run: nothing is asked of the server (the weekly public offer fetch is the
  // caller's, it needs the stack names). An explicit --pro still goes through the request below, which fails with
  // AUTH_FAILED before any network call when there is no sign-in.
  if (!signedIn && !i.explicitPro) return base({ plan: unavailableBlock('NOT_FETCHED') })

  // A valid cached document or hint may let a DEFAULT scan skip the call (never --pro, never in API-key mode).
  if (!i.explicitPro && !env.apiKeyMode && !env.safeMode) {
    const cached = acctPre !== null ? await readAccountCache(env.configDir, { acct: acctPre, now: env.now }) : null
    const hintSkip = i.hookOrGate && hintSkipsCall(
      { configDir: env.configDir, now: env.now, safeMode: env.safeMode }, acctPre,
      { explicitPro: false, ci: env.ci, apiKeyMode: env.apiKeyMode },
    )
    if (cached !== null && cacheMaySkipRulebookCall(cached.block, env.now, { explicitPro: false })) {
      return base({ signedIn, acct: acctPre, plan: cached.block, accountStatus: accountStatusOf(cached.block, nag, acctPre) })
    }
    if (hintSkip) {
      const plan = cached?.block ?? unavailableBlock('NOT_FETCHED')
      return base({ signedIn, acct: acctPre, plan, accountStatus: accountStatusOf(plan, nag, acctPre) })
    }
  }

  const realFrameworks = i.frameworks
  let fetched: ProFetchResult
  try {
    fetched = await i.fetchProRules(realFrameworks, i.categories.length > 0 ? i.categories : undefined, i.apiUrl, i.scanId)
  } catch (raw) {
    return failedRequest(i, raw, acctPre, nag)
  }

  // ---- the rulebook was served and verified ----
  const acct = fetched.acct ?? acctPre
  const planRead = fetched.plan ?? { block: unavailableBlock('SERVER_NO_PLAN'), token: null, live: false }
  persistLivePlan(env, planRead, acct)
  const nagAfter = loadNagFor(env)
  const plan = planRead.block
  const status = accountStatusOf(plan, nagAfter, acct)

  const general = new Set(loadBundledRules().map((r) => r.id))
  const extra = fetched.rules.filter((r) => !general.has(r.id)).length
  const paid = status === 'active' || status === 'trialing' || status === 'past_due' || status === 'ending'
  // Free-tier rules the server sends to an account without a plan are the bundled general set: a plain Free run.
  const runServed = fetched.rules.length > 0 && (paid || extra > 0 || i.explicitPro)

  if (fetched.partial) {
    if (i.explicitPro && !i.allowDegraded) {
      return base({ signedIn, acct, plan, accountStatus: status, error: { code: 'RULEBOOK_PARTIAL', message: fallbackMessage('RULEBOOK_PARTIAL', null) } })
    }
    return base({
      signedIn, acct, plan, accountStatus: status, proRules: fetched.rules, rulesVersion: fetched.rulesVersion, rulebookRan: true,
      partial: true, tiersApplied: fetched.tiersApplied, areaByRuleId: fetched.areaByRuleId,
      fallback: { code: 'RULEBOOK_PARTIAL', reason: null, message: fallbackMessage('RULEBOOK_PARTIAL', null), serverText: null },
    })
  }
  if (!runServed) return base({ signedIn, acct, plan, accountStatus: status })
  return base({
    signedIn, acct, plan, accountStatus: status, proRules: fetched.rules, rulesVersion: fetched.rulesVersion, rulebookRan: true,
    tiersApplied: fetched.tiersApplied, areaByRuleId: fetched.areaByRuleId,
  })
}

/** The rulebook request failed: one rule for every cause. */
async function failedRequest(i: RulebookStepInput, raw: unknown, acctPre: string | null, nag: ReturnType<typeof loadNagFor>): Promise<RulebookStepResult> {
  const { env } = i
  const err = raw as ProFetchError
  const errCode: string = typeof err?.code === 'string' ? err.code : 'SERVER_ERROR'
  const message = err instanceof Error ? err.message : String(raw)
  logger.debug(`rulebook-step: rulebook request failed (${errCode}): ${message}`)

  // A zero-rule bundle is never a clean pass, whatever flags are set.
  if (errCode === 'NO_RULES_APPLIED') {
    return base({ signedIn: true, acct: acctPre, plan: unavailableBlock('NOT_FETCHED'), error: { code: 'NO_RULES_APPLIED', message, proErrorCode: errCode } })
  }

  const acct = err.context?.acct ?? acctPre
  const planRead = err.context?.plan ?? null
  if (planRead) persistLivePlan(env, planRead, acct)
  const plan: PlanBlock = planRead?.block ?? (await cachedPlan(env, acct))
  const nagNow = planRead ? loadNagFor(env) : nag
  const status = accountStatusOf(plan, nagNow, acct)

  // The sign-in is no longer good. A default scan runs on; an explicit --pro needs the login.
  if (errCode === 'AUTH_FAILED') {
    const notSignedIn = /^Not authenticated/.test(message)
    const expired = /expired|no longer valid|refused/i.test(message)
    if (i.explicitPro && !i.allowDegraded) {
      return base({
        signedIn: !notSignedIn, acct, plan, accountStatus: status,
        error: {
          code: expired && !notSignedIn ? 'TOKEN_EXPIRED' : 'LOGIN_REQUIRED',
          message: notSignedIn ? '--pro uses the full rulebook, and you are not signed in.' : message,
          proErrorCode: errCode,
        },
      })
    }
    const notes = notSignedIn ? [] : ['Your sign-in is no longer valid. Your plan follows your account, so signing in again picks it up: shipguard login']
    return finishFallback(i, { code: 'RULEBOOK_UNREACHABLE', serverCode: null, serverText: null }, plan, status, acct, errCode, message, notes)
  }

  const cause = causeOf(err)
  const retryAfterSeconds = err.retryAfterSeconds
  const decision = decideRulebookUse({ signedIn: true, explicitPro: i.explicitPro, allowDegraded: i.allowDegraded, plan, cause })
  if (decision.action === 'exit-3') {
    const stepCode: StepError['code'] =
      errCode === 'RATE_LIMITED' ? 'RATE_LIMITED' : (decision.code === 'LOGIN_REQUIRED' ? 'LOGIN_REQUIRED' : decision.code)
    const text = cause.code === 'RULEBOOK_WITHHELD' || cause.code === 'PLAN_INACTIVE'
      ? `${cause.serverText ?? (cause.code === 'PLAN_INACTIVE' ? 'The account has no active plan.' : 'The server did not provide the rulebook for this scan.')} ${REMOVE_PRO}`
      : message
    return base({ signedIn: true, acct, plan, accountStatus: status, error: { code: stepCode, message: text, proErrorCode: errCode, ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}) } })
  }
  const soft = decision.action === 'run-general' ? decision.reason : null
  return finishFallback(i, cause, plan, status, acct, errCode, message, [], soft)
}

/** Default scan (or explicit --pro softened by a signed limit or --allow-degraded): general rules, and what ran. */
function finishFallback(
  i: RulebookStepInput, cause: RulebookCause, plan: PlanBlock, status: AccountStatus | null, acct: string | null,
  errCode: string, message: string, notes: string[], soft: 'ALLOWANCE_USED' | null = null,
): RulebookStepResult {
  const applies = fallbackApplies(cause.code, status)
  // The signed "limit used up" answer is the server saying the account has a plan: it always counts as a fallback.
  // An explicit --pro (with --allow-degraded) asked for the rulebook: the run always says it did not get it.
  const show = applies || soft === 'ALLOWANCE_USED' || i.explicitPro
  const fallback: StepFallback | null = show
    ? { code: cause.code, reason: soft, message: fallbackMessage(cause.code, cause.serverText ?? null), serverText: cause.serverText ?? null }
    : null
  // An explicit --pro that --allow-degraded turned into a general run keeps the 0.12 record (degraded scan);
  // a default scan or the signed soft path is not degraded.
  const degradedReason: DegradeReason | null = i.explicitPro && soft === null
    ? { code: 'PRO_RULES_UNAVAILABLE', detail: `[${errCode}] The rulebook could not be downloaded: ${message}` }
    : null
  return base({ signedIn: true, acct, plan, accountStatus: status, fallback, degradedReason, notes })
}

/** The cached public offer for a signed-out Free run (read-only; the weekly fetch is the caller's). */
export async function readPublicOffer(env: PlanEnv, stacks: readonly string[]): Promise<PlanBlock> {
  return (await readOffer({ configDir: env.configDir, now: env.now, safeMode: env.safeMode }, stacks)).block
}
