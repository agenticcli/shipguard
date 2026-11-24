/**
 * hint.ts: the hint file (~/.config/shipguard/hint.json). The server's "no plan" answer sets it; while valid
 * it lets a signed-in Free hook skip the rulebook call, so signed-in Free hooks make 0 server calls.
 *
 * It can only SKIP a call. It holds no plan data and unlocks nothing; a forged hint can only make that user's
 * own default scans general for at most an hour. Unsigned, bound to the signed-in account, TTL at most 1 hour,
 * mode 0600. Ignored with `--pro`, with `CI` set and in API-key mode; cleared on login, logout, upgrade, status
 * and on any served rulebook bundle (call sites call clearHint). Safe mode: never read, never written.
 */
import { join } from 'node:path'
import { readConfigText, removeConfigFile, writeConfigText } from './config-store.js'
import { logger } from '../utils/logger.js'

export const HINT_FILE = 'hint.json'
/** Longest a hint may live. A longer `until` in the file is refused, whatever wrote it. */
export const HINT_MAX_TTL_MS = 60 * 60 * 1000
const MAX_BYTES = 1024
const SKEW_FUTURE_MS = 5 * 60 * 1000

export interface HintContext {
  configDir: string
  /** Current time, milliseconds. */
  now: number
  safeMode: boolean
}

/** Record "this account has no plan" for at most `ttlMs` (clamped to the 1 hour maximum). */
export function writeHint(ctx: HintContext, acct: string, ttlMs: number = HINT_MAX_TTL_MS): boolean {
  if (ctx.safeMode || acct === '') return false
  const ttl = Math.min(HINT_MAX_TTL_MS, Math.max(0, Math.floor(ttlMs)))
  if (ttl === 0) return false
  return writeConfigText(ctx.configDir, HINT_FILE, JSON.stringify({ v: 1, acct, at: ctx.now, until: ctx.now + ttl }))
}

/** True when a valid hint for THIS account says the rulebook call may be skipped. */
export function hintSkipsCall(ctx: HintContext, acct: string | null, opts: { explicitPro: boolean; ci: boolean; apiKeyMode: boolean }): boolean {
  if (ctx.safeMode || opts.explicitPro || opts.ci || opts.apiKeyMode || acct === null || acct === '') return false
  const file = readConfigText(join(ctx.configDir, HINT_FILE), MAX_BYTES)
  if (file.state !== 'ok') return false
  try {
    const h: unknown = JSON.parse(file.text)
    if (typeof h !== 'object' || h === null) return false
    const { v, acct: hintAcct, at, until } = h as Record<string, unknown>
    if (v !== 1 || hintAcct !== acct) return false
    if (typeof at !== 'number' || typeof until !== 'number' || !Number.isFinite(at) || !Number.isFinite(until)) return false
    if (until - at > HINT_MAX_TTL_MS || at > ctx.now + SKEW_FUTURE_MS) return false
    return ctx.now < until
  } catch (err) {
    logger.debug(`hint: ignoring unreadable hint file: ${err instanceof Error ? err.message : String(err)}`)
    return false
  }
}

export function clearHint(configDir: string): void {
  removeConfigFile(join(configDir, HINT_FILE))
}
