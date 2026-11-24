/**
 * plan.ts: verify, map and cache the signed plan block (contract: docs/contracts/plan-v2.json).
 *
 * HARD RULES (the CLI repo is public):
 *   - No plan fact lives here: no price, count, pack, trial length, plan name or limit. Every value arrives
 *     in a signed server document and is shown verbatim (after safe-text). Nothing is read from the scanned
 *     project.
 *   - Zero trust: a document that fails ANY check is thrown away. The result is "unavailable" with reason
 *     PLAN_UNVERIFIED, which means plain Free behaviour: never Pro, never a crash, exit codes unchanged.
 *   - The block is display data only. It never unlocks a rule; only the server's attested rulebook does.
 *
 * One key: documents are signed with the EXISTING pinned bundle key. The JWS header `typ` separates
 * account and offer documents from the bundle envelope (there is no second key and no new key role).
 */
import { createHash, randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { parseStrictNoDup } from '@agenticcli/matcher-contract'
import { verifyPlanDocumentSignature } from './crypto.js'
import { goLinkFromServerSlot, resolveServerSlot } from './links.js'
import { safeServerList, safeServerText, TEXT_CAPS } from './safe-text.js'
import { readConfigText, removeConfigFile, writeConfigText } from './config-store.js'
import { logger } from '../utils/logger.js'
import type {
  AccountStatus,
  OfferDocumentPayload,
  PlanBlock,
  PlanDocumentPayload,
  PlanServerBlock,
  PlanUnavailableReason,
  UsageState,
} from './plan-types.js'

// ---------------------------------------------------------------------------
// Contract constants (from docs/contracts/plan-v2.json; none of these is a plan fact)
// ---------------------------------------------------------------------------

export const PLAN_DV = 1
const ISSUER = 'agenticcli.dev'
const SKEW_FUTURE_SECONDS = 300
const KNOWN_ACCOUNT_STATUSES: readonly string[] = ['active', 'trialing', 'pending', 'past_due', 'ending', 'lapsed', 'none']
/** Account states that mean "this account has (or just had) a paid plan": never pitched. */
export const PAID_STATUSES: readonly AccountStatus[] = ['active', 'trialing', 'past_due', 'ending']

export type PlanDocKind = 'account' | 'offer'

const DOC_RULES = {
  account: {
    typ: 'shipguard-account+jws',
    aud: 'shipguard-cli',
    maxBytes: 16384,
    maxLifeSeconds: 72 * 3600,
    required: ['dv', 'iss', 'aud', 'acct', 'iat', 'exp'],
  },
  offer: {
    typ: 'shipguard-offer+jws',
    aud: 'shipguard-cli-offer',
    maxBytes: 65536,
    maxLifeSeconds: 7 * 86400,
    required: ['dv', 'iss', 'aud', 'iat', 'exp'],
  },
} as const

/** `refreshAfter` is clamped to this range; the server cannot make the CLI skip calls for longer. */
const REFRESH_MIN_SECONDS = 60
const REFRESH_MAX_SECONDS = 6 * 3600

export const ACCOUNT_CACHE_FILE = 'account.jws'

// ---------------------------------------------------------------------------
// Account binding, nonce and the client hello
// ---------------------------------------------------------------------------

/** `acct` = base64url(sha256("shipguard-acct-v1" + sub)); the same value is computed on the server. */
export function acctHash(sub: string): string {
  return createHash('sha256').update('shipguard-acct-v1' + sub).digest('base64url')
}

/**
 * The account hash of a signed-in access token (a JWT whose payload carries `sub`). The token is NOT
 * verified here: the hash is only the binding the server document must match, so a forged `sub` can only
 * make a document fail to verify.
 */
export function acctFromAccessToken(accessToken: unknown): string | null {
  if (typeof accessToken !== 'string') return null
  const parts = accessToken.split('.')
  if (parts.length !== 3) return null
  try {
    const payload: unknown = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    const sub = (payload as { sub?: unknown } | null)?.sub
    return typeof sub === 'string' && sub !== '' ? acctHash(sub) : null
  } catch (err) {
    logger.debug(`plan: access token payload not readable: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}

/** 128-bit random nonce, 22 base64url characters. One per request that expects a plan document. */
export function newNonce(): string {
  return randomBytes(16).toString('base64url')
}

export const NONCE_PATTERN = /^[A-Za-z0-9_-]{22}$/

/**
 * Headers for the client hello. `bundle-protocol=2` asks for envelope v2; a server that ignores it
 * answers as before (clean fallback). The nonce header is sent only on Bearer calls that expect a signed
 * document. No hello = a legacy reply, so the CLI must cope with either.
 */
export function clientHelloHeaders(cliVersion: string, nonce?: string): Record<string, string> {
  const headers: Record<string, string> = {
    'X-ShipGuard-Client': `shipguard/${cliVersion}; bundle-protocol=2`,
  }
  if (nonce !== undefined) headers['X-ShipGuard-Nonce'] = nonce
  return headers
}

// ---------------------------------------------------------------------------
// Verify (fixed order; any failure = not trusted)
// ---------------------------------------------------------------------------

export interface VerifyContext {
  /** Current time, milliseconds. */
  now: number
  /** Account hash of the signed-in user. REQUIRED for an account document (a document bound to nobody is refused). */
  acct?: string | null
  /** The nonce sent with this request. Set = a live reply: nonce (and scanId when given) must match. Null = a cached copy. */
  nonce?: string | null
  /** The scan id of this request, for scan replies. */
  scanId?: string | null
}

export type VerifyResult =
  | { ok: true; payload: Record<string, unknown>; live: boolean }
  | { ok: false; step: string; expired?: true }

const fail = (step: string, expired?: true): VerifyResult => (expired ? { ok: false, step, expired } : { ok: false, step })

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

/**
 * Verify one compact JWS plan or offer document. Never throws; a document that is not trusted returns
 * { ok: false, step }. Order: size cap, three base64url parts, strict header (alg, kid, typ only), alg and
 * typ exact, pinned key (role bundle), signature, strict payload parse (duplicate keys rejected), iss + aud + dv,
 * account binding, live nonce + scanId (replay), then the time window (iat, exp, lifetime) for live and cached alike.
 */
export async function verifyPlanDocument(kind: PlanDocKind, token: unknown, ctx: VerifyContext): Promise<VerifyResult> {
  const rules = DOC_RULES[kind]
  try {
    if (typeof token !== 'string') return fail('not a string')
    if (token.length > rules.maxBytes) return fail('size cap')
    const parts = token.split('.')
    if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return fail('not three base64url parts')

    const header = parseStrictNoDup(Buffer.from(parts[0], 'base64url').toString('utf8'))
    if (!isRecord(header)) return fail('header not an object')
    if (Object.keys(header).some((k) => k !== 'alg' && k !== 'kid' && k !== 'typ')) return fail('header key not allowed')
    if (header['alg'] !== 'EdDSA') return fail('alg')
    if (header['typ'] !== rules.typ) return fail('typ')
    const kid = header['kid']
    if (typeof kid !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(kid)) return fail('kid')

    const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
    if (!(await verifyPlanDocumentSignature(signingInput, parts[2], kid))) return fail('signature')

    const payload = parseStrictNoDup(Buffer.from(parts[1], 'base64url').toString('utf8'))
    if (!isRecord(payload)) return fail('payload not an object')
    if (payload['iss'] !== ISSUER || payload['aud'] !== rules.aud) return fail('iss or aud')
    if (payload['dv'] !== PLAN_DV) return fail('unsupported dv')
    for (const key of rules.required) if (!(key in payload)) return fail(`missing ${key}`)
    const iat = payload['iat']
    const exp = payload['exp']
    if (!Number.isSafeInteger(iat) || !Number.isSafeInteger(exp)) return fail('iat or exp')

    if (kind === 'account') {
      if (typeof ctx.acct !== 'string' || ctx.acct === '') return fail('no account to bind to')
      if (payload['acct'] !== ctx.acct) return fail('wrong account')
    }

    const live = kind === 'account' && typeof ctx.nonce === 'string'
    if (live) {
      // A live reply is bound to THIS request: a recorded reply cannot be replayed.
      if (!NONCE_PATTERN.test(ctx.nonce as string) || payload['nonce'] !== ctx.nonce) return fail('nonce mismatch')
      if (typeof ctx.scanId === 'string') {
        const binding = payload['binding']
        if (!isRecord(binding) || binding['scanId'] !== ctx.scanId) return fail('scanId mismatch')
      }
    }
    // Time window: live replies AND cached copies (an expired plan block is
    // plain Free, whether it just arrived or was kept). A signed reply that is already past exp, or issued in the
    // future, is never trusted.
    const nowSeconds = Math.floor(ctx.now / 1000)
    if ((iat as number) > nowSeconds + SKEW_FUTURE_SECONDS) return fail('issued in the future')
    if (nowSeconds >= (exp as number)) return fail('expired', true)
    if ((exp as number) - (iat as number) > rules.maxLifeSeconds) return fail('lifetime too long')
    return { ok: true, payload, live }
  } catch (err) {
    logger.debug(`plan: ${kind} document rejected: ${err instanceof Error ? err.message : String(err)}`)
    return fail('exception')
  }
}

// ---------------------------------------------------------------------------
// Map (signed payload -> PlanServerBlock; every string through safe-text, nothing invented)
// ---------------------------------------------------------------------------

const iso = (seconds: number): string => new Date(seconds * 1000).toISOString()
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/

export function normalizeAccountStatus(value: unknown): AccountStatus {
  return typeof value === 'string' && KNOWN_ACCOUNT_STATUSES.includes(value) ? (value as AccountStatus) : 'unsupported'
}

function mapOffer(value: unknown): PlanServerBlock['offer'] {
  if (!isRecord(value)) return null
  const text = safeServerText(value['text'], TEXT_CAPS.offer)
  if (text === null) return null
  return { text, slot: resolveServerSlot(value['slot']) }
}

function mapUsage(value: unknown): PlanServerBlock['usage'] {
  if (!isRecord(value)) return null
  const percent = value['percent']
  if (typeof percent !== 'number' || !Number.isInteger(percent) || percent < 0 || percent > 100) return null
  const state: UsageState = value['state'] === 'warn' || value['state'] === 'used' ? value['state'] : 'ok'
  const resetsAt = typeof value['resetsAt'] === 'string' && ISO_TIME.test(value['resetsAt']) && !Number.isNaN(Date.parse(value['resetsAt']))
    ? value['resetsAt']
    : null
  return {
    percent,
    state,
    resetsAt,
    text: safeServerText(value['text'], TEXT_CAPS.usage),
    counted: typeof value['counted'] === 'boolean' ? value['counted'] : null,
  }
}

function mapProAdds(value: unknown): PlanServerBlock['proAdds'] {
  if (!isRecord(value)) return null
  const rules = value['rules']
  return {
    planName: safeServerText(value['planName'], TEXT_CAPS.label),
    rules: typeof rules === 'number' && Number.isSafeInteger(rules) && rules >= 0 ? rules : null,
    stacks: safeServerList(value['stacks']),
    areas: safeServerList(value['areas']),
  }
}

function mapCapabilities(value: unknown): PlanServerBlock['capabilities'] {
  if (!isRecord(value) || typeof value['rulebookDefault'] !== 'boolean') return null
  const tiers = Array.isArray(value['rulebookTiers'])
    ? value['rulebookTiers'].filter((t): t is string => typeof t === 'string' && /^[a-z0-9-]{1,32}$/.test(t)).slice(0, 16)
    : []
  return { rulebookDefault: value['rulebookDefault'], rulebookTiers: tiers }
}

/** Map a VERIFIED account payload. Missing server fields stay null (never defaulted). */
export function mapAccountPayload(p: Record<string, unknown>): PlanServerBlock {
  const account = p['account']
  const limit = p['limit']
  const refresh = p['refreshAfter']
  const limitText = isRecord(limit) ? safeServerText(limit['text'], TEXT_CAPS.limit) : null
  return {
    fetchedAt: iso(p['iat'] as number),
    validUntil: iso(p['exp'] as number),
    label: safeServerText(p['label'], TEXT_CAPS.label),
    account: isRecord(account)
      ? { status: normalizeAccountStatus(account['status']), text: safeServerText(account['text'], TEXT_CAPS.account) }
      : null,
    usage: mapUsage(p['usage']),
    limit: limitText === null ? null : { text: limitText },
    capabilities: mapCapabilities(p['capabilities']),
    refreshAfter:
      typeof refresh === 'number' && Number.isFinite(refresh)
        ? Math.min(REFRESH_MAX_SECONDS, Math.max(REFRESH_MIN_SECONDS, Math.floor(refresh)))
        : null,
    updateNotice: safeServerText(p['updateNotice'], TEXT_CAPS.updateNotice),
    proAdds: mapProAdds(p['proAdds']),
    offer: mapOffer(p['offer']),
  }
}

/**
 * Map a VERIFIED public offer payload for the stacks this scan detected. Per-stack counts share rules, so they are
 * NEVER added together: one stack gives its own count; several give the server's `combined["a+b"]` (sorted names
 * joined with "+") when present, else no number ("more rules"). The generic offer (no counts) gives null.
 */
export function mapOfferPayload(p: Record<string, unknown>, stacks: string[]): PlanServerBlock {
  const counts = isRecord(p['counts']) ? p['counts'] : {}
  const combined = isRecord(p['combined']) ? p['combined'] : {}
  const has = (o: Record<string, unknown>, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k)
  const isCount = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0
  let rules: number | null = null
  const areas: string[] = []
  for (const stack of stacks) {
    const entry = has(counts, stack) ? counts[stack] : undefined
    if (isRecord(entry)) for (const a of safeServerList(entry['areas'])) if (!areas.includes(a)) areas.push(a)
  }
  if (stacks.length === 1) {
    const entry = has(counts, stacks[0]) ? counts[stacks[0]] : undefined
    if (isRecord(entry) && isCount(entry['rules'])) rules = entry['rules']
  } else if (stacks.length > 1) {
    const key = [...stacks].sort().join('+')
    if (has(combined, key) && isCount(combined[key])) rules = combined[key] as number
  }
  return {
    fetchedAt: iso(p['iat'] as number),
    validUntil: iso(p['exp'] as number),
    label: null,
    account: null,
    usage: null,
    limit: null,
    capabilities: null,
    refreshAfter: null,
    updateNotice: null,
    proAdds: { planName: null, rules, stacks: [...stacks], areas: areas.slice(0, TEXT_CAPS.items) },
    offer: mapOffer(p['offer']),
  }
}

// ---------------------------------------------------------------------------
// The block the rest of the CLI reads
// ---------------------------------------------------------------------------

export function hasPaidPlan(status: AccountStatus | null | undefined): boolean {
  return status !== null && status !== undefined && PAID_STATUSES.includes(status)
}

export function unavailableBlock(reason: PlanUnavailableReason): PlanBlock {
  return { status: 'unavailable', reason, command: 'shipguard upgrade', link: null, server: null }
}

/** Build the block from a mapped server section. The link is built from the closed slot list, never from server text. */
export function planBlockFrom(server: PlanServerBlock, status: 'live' | 'cached', reason: PlanUnavailableReason | null = null): PlanBlock {
  return {
    status,
    reason: status === 'cached' ? reason : null,
    command: hasPaidPlan(server.account?.status) ? 'shipguard status' : 'shipguard upgrade',
    link: server.offer ? goLinkFromServerSlot(server.offer.slot) : null,
    server,
  }
}

/** A cached block shown after a failed fresh read (`status`, `upgrade`, `login`): same data, with the reason. */
export function cachedWithReason(block: PlanBlock, reason: 'OFFLINE' | 'FETCH_FAILED'): PlanBlock {
  return block.status === 'unavailable' || block.server === null ? block : { ...block, status: 'cached', reason }
}

export interface PlanRead {
  block: PlanBlock
  /** The raw verified document, for the caller to cache. Null when nothing verified. */
  token: string | null
  /** Set when the account document verified live. */
  live: boolean
}

const NOT_VERIFIED = (reason: PlanUnavailableReason): PlanRead => ({ block: unavailableBlock(reason), token: null, live: false })

/**
 * A signed document that arrived with a reply. `token` undefined or null means the server sent none (an old
 * server, or no hello): SERVER_NO_PLAN, no note. Anything that fails a check: PLAN_UNVERIFIED.
 */
export async function readAccountReply(
  token: unknown,
  req: { acct: string | null; nonce: string; scanId?: string | null; now: number },
): Promise<PlanRead> {
  if (token === undefined || token === null) return NOT_VERIFIED('SERVER_NO_PLAN')
  const result = await verifyPlanDocument('account', token, { now: req.now, acct: req.acct, nonce: req.nonce, scanId: req.scanId ?? null })
  if (!result.ok) {
    logger.debug(`plan: account document not trusted (${result.step})`)
    return NOT_VERIFIED('PLAN_UNVERIFIED')
  }
  return { block: planBlockFrom(mapAccountPayload(result.payload), 'live'), token: token as string, live: true }
}

// ---------------------------------------------------------------------------
// Account cache: ~/.config/shipguard/account.jws (raw signed text only, verified again on EVERY read)
// ---------------------------------------------------------------------------

export interface CacheOptions {
  /** Safe mode or API-key mode: nothing is written to disk. */
  noWrite?: boolean
}

/** Store a document that has just verified. Best-effort; returns false when nothing was written. */
export function writeAccountCache(configDir: string, token: string, opts: CacheOptions = {}): boolean {
  if (opts.noWrite) return false
  return writeConfigText(configDir, ACCOUNT_CACHE_FILE, token)
}

export function clearAccountCache(configDir: string): void {
  removeConfigFile(join(configDir, ACCOUNT_CACHE_FILE))
}

/**
 * Read the cached account document. Missing = NOT_FETCHED. Unsafe file, bad signature, wrong account,
 * tampered, too long-lived = PLAN_UNVERIFIED. An otherwise valid copy that has simply expired is treated
 * as no cache (NOT_FETCHED): ageing out is normal, not a failed check, so it prints no warning.
 */
export async function readAccountCache(configDir: string, req: { acct: string | null; now: number }): Promise<PlanRead> {
  const file = readConfigText(join(configDir, ACCOUNT_CACHE_FILE), DOC_RULES.account.maxBytes)
  if (file.state === 'missing') return NOT_VERIFIED('NOT_FETCHED')
  if (file.state === 'unsafe') {
    logger.debug(`plan: ignoring account cache (${file.why})`)
    return NOT_VERIFIED('PLAN_UNVERIFIED')
  }
  const token = file.text.trim()
  const result = await verifyPlanDocument('account', token, { now: req.now, acct: req.acct, nonce: null, scanId: null })
  if (!result.ok) {
    if (result.expired) return NOT_VERIFIED('NOT_FETCHED')
    logger.debug(`plan: cached account document not trusted (${result.step})`)
    return NOT_VERIFIED('PLAN_UNVERIFIED')
  }
  return { block: planBlockFrom(mapAccountPayload(result.payload), 'cached'), token, live: false }
}

/** Does a cached block tell the CLI it may skip a rulebook call right now? (only for a verified, fresh block) */
export function cacheMaySkipRulebookCall(block: PlanBlock, now: number, opts: { explicitPro: boolean }): boolean {
  if (opts.explicitPro || block.status !== 'cached' || block.server === null) return false
  const s = block.server
  if (s.capabilities === null || s.capabilities.rulebookDefault !== false) return false
  if (s.refreshAfter === null) return false
  // An account with no plan, a pending one or a state this CLI does not know always asks (a plan bought a minute ago).
  const status = s.account?.status
  if (status === undefined || status === 'none' || status === 'pending' || status === 'lapsed' || status === 'unsupported') return false
  const fetched = Date.parse(s.fetchedAt)
  if (Number.isNaN(fetched) || now < fetched || now - fetched > s.refreshAfter * 1000) return false
  if (s.usage?.resetsAt && now >= Date.parse(s.usage.resetsAt)) return false
  return true
}

// ---------------------------------------------------------------------------
// The one rule for "the rulebook did not run". Pure decisions; call sites wire them.
// ---------------------------------------------------------------------------

export type RulebookFallbackCode = 'RULEBOOK_WITHHELD' | 'RULEBOOK_UNREACHABLE' | 'RULEBOOK_PARTIAL' | 'PLAN_INACTIVE'

export interface RulebookCause {
  code: RulebookFallbackCode
  /** The server's own error code from the reply (for the soft-limit exception). Unsigned data: only ever makes --pro stricter. */
  serverCode?: string | null
  /** The server's wording for the cause, already through safe-text. */
  serverText?: string | null
}

export type ProDecision =
  | { action: 'run-rulebook' }
  /** Signed out and no explicit --pro: a plain Free run (no cause, no notice). */
  | { action: 'plain-free' }
  | { action: 'run-general'; code: RulebookFallbackCode | 'LOGIN_REQUIRED'; reason: 'ALLOWANCE_USED' | null }
  | { action: 'exit-3'; code: RulebookFallbackCode | 'LOGIN_REQUIRED' }

/**
 * Decision v21-prolimit. The ONE case where the limit being used up softens a run: the reply is SIGNED and verified
 * live (this request's nonce), says `usage.state: used`, and the server's own code is ALLOWANCE_USED. An unsigned or
 * unverified answer can only make an explicit --pro stricter, never softer.
 */
export function isSignedLimitUsed(plan: PlanBlock, serverCode: string | null | undefined): boolean {
  return plan.status === 'live' && plan.server?.usage?.state === 'used' && serverCode === 'ALLOWANCE_USED'
}

export function decideRulebookUse(input: {
  signedIn: boolean
  explicitPro: boolean
  allowDegraded: boolean
  plan: PlanBlock
  cause: RulebookCause | null
}): ProDecision {
  const { signedIn, explicitPro, allowDegraded, plan, cause } = input
  if (!signedIn) {
    if (!explicitPro) return { action: 'plain-free' }
    return allowDegraded ? { action: 'run-general', code: 'LOGIN_REQUIRED', reason: null } : { action: 'exit-3', code: 'LOGIN_REQUIRED' }
  }
  if (cause === null) return { action: 'run-rulebook' }
  if (isSignedLimitUsed(plan, cause.serverCode)) {
    return { action: 'run-general', code: 'RULEBOOK_WITHHELD', reason: 'ALLOWANCE_USED' }
  }
  if (explicitPro && !allowDegraded) return { action: 'exit-3', code: cause.code }
  return { action: 'run-general', code: cause.code, reason: null }
}

/**
 * Is a failed rulebook run a "fallback" worth telling the user about? Only for an account that
 * has a plan (current verified status) or whose LAST verified status was an active one, so a paying user who is
 * offline or expired is told what ran. A signed-in account without a plan (none, pending, unsupported, never
 * verified) is a plain Free run: no notice, `rules.fallback` null. PLAN_INACTIVE is for a lapsed plan.
 */
export function fallbackApplies(code: RulebookFallbackCode, status: AccountStatus | null): boolean {
  if (code === 'PLAN_INACTIVE') return status === 'lapsed' || status === 'past_due'
  return hasPaidPlan(status)
}
