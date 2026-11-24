/**
 * nag.ts: the display counters (~/.config/shipguard/nag.json). They decide
 * only HOW OFTEN a Free-to-Pro line, a usage notice or the first-Pro receipt may be shown. They hold no plan
 * facts. The file lives outside the scanned folder, so a cloned repo cannot reset, fill or read it.
 *
 * Per repo (a hash of the repo id): screenPitchAt (ONE shared screen counter for the gap line, the pointer and
 * the coverage line), jsonPitchAt, setupHintAt (the `Next:` setup suggestion: once per 7 days, not a plan counter). Per account hash: usageScreenAt, usageJsonAt (also used by the update notice),
 * receiptShownAt, receiptJsonAt, lastAccountStatus, lastAccountAt. Global: muted, offerFetchAt (the one counter of
 * the weekly public fetch and the setup priming).
 *
 * Safe mode: nothing is read and nothing is written; callers show no promotion in safe mode.
 */
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { readConfigText, writeConfigText } from './config-store.js'
import { logger } from '../utils/logger.js'
import type { AccountStatus } from './plan-types.js'

export const NAG_FILE = 'nag.json'
const MAX_BYTES = 64 * 1024
/** Display timing, not plan facts. */
export const WEEK_MS = 7 * 24 * 60 * 60 * 1000
export const DAY_MS = 24 * 60 * 60 * 1000
const MAX_REPOS = 120
const MAX_ACCOUNTS = 20

export interface NagRepo { screenPitchAt?: number; jsonPitchAt?: number; setupHintAt?: number }
export interface NagAccount {
  usageScreenAt?: number; usageJsonAt?: number; receiptShownAt?: number; receiptJsonAt?: number
  lastAccountStatus?: AccountStatus; lastAccountAt?: number
}
export interface NagData { muted?: boolean; offerFetchAt?: number; repos: Record<string, NagRepo>; accounts: Record<string, NagAccount> }

export interface NagContext {
  configDir: string
  /** Current time, milliseconds. */
  now: number
  safeMode: boolean
}

export type Moment = 'screenPitch' | 'jsonPitch' | 'setupHint' | 'usageScreen' | 'usageJson' | 'receiptShown' | 'receiptJson'
export type Channel = 'screen' | 'json'

const STATUSES: readonly string[] = ['active', 'trialing', 'pending', 'past_due', 'ending', 'lapsed', 'none', 'unsupported']
const emptyNag = (): NagData => ({ repos: {}, accounts: {} })
const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

/** Hash of the repo id the counters are keyed by (the id itself is never stored). */
export function repoKey(repoId: string): string {
  return createHash('sha256').update('shipguard-nag-repo-v1' + repoId).digest('hex').slice(0, 16)
}

/** Read the counters. Missing, unsafe or malformed = empty (the worst case is one extra notice, never a crash). */
export function loadNag(ctx: Pick<NagContext, 'configDir' | 'safeMode'>): NagData {
  if (ctx.safeMode) return emptyNag()
  const file = readConfigText(join(ctx.configDir, NAG_FILE), MAX_BYTES)
  if (file.state !== 'ok') {
    if (file.state === 'unsafe') logger.debug(`nag: ignoring nag.json (${file.why})`)
    return emptyNag()
  }
  try {
    const raw: unknown = JSON.parse(file.text)
    if (!isRecord(raw)) return emptyNag()
    const out = emptyNag()
    if (raw['muted'] === true) out.muted = true
    if (isNum(raw['offerFetchAt'])) out.offerFetchAt = raw['offerFetchAt']
    const repos = raw['repos']
    if (isRecord(repos)) {
      for (const [k, v] of Object.entries(repos)) {
        if (!isRecord(v) || !/^[0-9a-f]{16}$/.test(k)) continue
        out.repos[k] = {
          ...(isNum(v['screenPitchAt']) ? { screenPitchAt: v['screenPitchAt'] } : {}),
          ...(isNum(v['jsonPitchAt']) ? { jsonPitchAt: v['jsonPitchAt'] } : {}),
          ...(isNum(v['setupHintAt']) ? { setupHintAt: v['setupHintAt'] } : {}),
        }
      }
    }
    const accounts = raw['accounts']
    if (isRecord(accounts)) {
      for (const [k, v] of Object.entries(accounts)) {
        if (!isRecord(v) || k.length > 64) continue
        const a: NagAccount = {}
        for (const f of ['usageScreenAt', 'usageJsonAt', 'receiptShownAt', 'receiptJsonAt', 'lastAccountAt'] as const) if (isNum(v[f])) a[f] = v[f]
        if (typeof v['lastAccountStatus'] === 'string' && STATUSES.includes(v['lastAccountStatus'])) a.lastAccountStatus = v['lastAccountStatus'] as AccountStatus
        out.accounts[k] = a
      }
    }
    return out
  } catch (err) {
    logger.debug(`nag: ignoring unreadable nag.json: ${err instanceof Error ? err.message : String(err)}`)
    return emptyNag()
  }
}

const newest = (o: Record<string, number | undefined>): number => Math.max(0, ...Object.values(o).filter(isNum))

function prune(data: NagData): NagData {
  const keep = <T extends object>(entries: Record<string, T>, max: number): Record<string, T> =>
    Object.fromEntries(
      Object.entries(entries)
        .sort(([, a], [, b]) => newest(b as Record<string, number | undefined>) - newest(a as Record<string, number | undefined>))
        .slice(0, max),
    )
  return { ...data, repos: keep(data.repos, MAX_REPOS), accounts: keep(data.accounts, MAX_ACCOUNTS) }
}

/** Entry caps keep the file far below its size cap (a repo entry is about 80 bytes); the oldest entries go first. */
function save(ctx: NagContext, data: NagData): boolean {
  return writeConfigText(ctx.configDir, NAG_FILE, JSON.stringify(prune(data)))
}

/** Load, change, save. No-op (false) in safe mode. */
function update(ctx: NagContext, change: (d: NagData) => void): boolean {
  if (ctx.safeMode) return false
  const data = loadNag(ctx)
  change(data)
  return save(ctx, data)
}

// ---- mute --------------------------------------------------------------------------------------------------

/** Promotion is muted by `shipguard upgrade --mute` (file) or SHIPGUARD_NO_PROMO=1 (environment, for agents and CI). */
export function isMuted(nag: NagData, env: NodeJS.ProcessEnv = process.env): boolean {
  const e = env['SHIPGUARD_NO_PROMO']
  return nag.muted === true || e === '1' || e === 'true'
}

export function setMuted(ctx: NagContext, muted: boolean): boolean {
  return update(ctx, (d) => { if (muted) d.muted = true; else delete d.muted })
}

// ---- once-per-interval moments ---------------------------------------------------------------------------

function field(m: Moment): { scope: 'repos' | 'accounts'; key: string } {
  switch (m) {
    case 'screenPitch': return { scope: 'repos', key: 'screenPitchAt' }
    case 'jsonPitch': return { scope: 'repos', key: 'jsonPitchAt' }
    case 'setupHint': return { scope: 'repos', key: 'setupHintAt' }
    case 'usageScreen': return { scope: 'accounts', key: 'usageScreenAt' }
    case 'usageJson': return { scope: 'accounts', key: 'usageJsonAt' }
    case 'receiptShown': return { scope: 'accounts', key: 'receiptShownAt' }
    case 'receiptJson': return { scope: 'accounts', key: 'receiptJsonAt' }
  }
}

const INTERVAL: Record<Moment, number> = {
  screenPitch: WEEK_MS, jsonPitch: WEEK_MS, setupHint: WEEK_MS, usageScreen: DAY_MS, usageJson: DAY_MS,
  receiptShown: Number.POSITIVE_INFINITY, receiptJson: Number.POSITIVE_INFINITY, // the receipt is shown once per account
}

function lastShown(nag: NagData, m: Moment, id: string): number | undefined {
  const f = field(m)
  const entry = (f.scope === 'repos' ? nag.repos[id] : nag.accounts[id]) as Record<string, number | undefined> | undefined
  return entry?.[f.key]
}

/** Is this moment due for `id` (repoKey for the pitch moments, the account hash for the others)? */
export function momentDue(nag: NagData, m: Moment, id: string, now: number): boolean {
  const last = lastShown(nag, m, id)
  if (last === undefined) return true
  if (last > now + 5 * 60 * 1000) return true // a stored time far in the future is not trusted: it cannot silence anything for long
  return now - last >= INTERVAL[m]
}

/** Record that the moment was shown now. */
export function markMoment(ctx: NagContext, m: Moment, id: string): boolean {
  const f = field(m)
  return update(ctx, (d) => {
    const bucket = (f.scope === 'repos' ? d.repos : d.accounts) as Record<string, Record<string, number>>
    bucket[id] = { ...(bucket[id] ?? {}), [f.key]: ctx.now }
  })
}

// ---- last verified account status ----------------------------------------------------------------------

/** The LAST verified account status for this account hash (kept after the document expires; never shown). */
export function lastAccountStatus(nag: NagData, acct: string): AccountStatus | null {
  return nag.accounts[acct]?.lastAccountStatus ?? null
}

export function recordAccountStatus(ctx: NagContext, acct: string, status: AccountStatus): boolean {
  return update(ctx, (d) => { d.accounts[acct] = { ...(d.accounts[acct] ?? {}), lastAccountStatus: status, lastAccountAt: ctx.now } })
}

// ---- the public fetch counter ------------------------------------------------------------------------------

/** Is the weekly public fetch (or the setup priming) due? One counter for both. */
export function offerFetchDue(nag: NagData, now: number): boolean {
  const last = nag.offerFetchAt
  if (last === undefined) return true
  if (last > now + 5 * 60 * 1000) return true
  return now - last >= WEEK_MS
}

/** Record an ATTEMPT (success or not), so a failing network is not retried on every scan. */
export function markOfferFetch(ctx: NagContext): boolean {
  return update(ctx, (d) => { d.offerFetchAt = ctx.now })
}
