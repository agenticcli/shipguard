/**
 * plan-lines.ts: the ONE renderer for everything that comes from the plan block (spec 05, 02 "Moments and
 * bounds"). Screen, `--json`, `upgrade`, `status` and the gate read the same block through these pure functions;
 * call sites (scan, gate, status, upgrade, login) only gather facts and print what comes back.
 *
 * What is authored here: the plain words around a server value and the facts the scan itself observed (what ran,
 * the detected stack names). What is NEVER authored here: a price, a count, a limit, a trial, a plan name or any
 * limit behaviour. Those arrive in the signed block (already through safe-text) and are printed verbatim. With no
 * server value the line says less, never more; the plan name falls back to neutral wording.
 */
import type { AccountStatus, PlanBlock } from './plan-types.js'
import { hasPaidPlan } from './plan.js'
import { goLink } from './links.js'

const MUTE_ENV = 'SHIPGUARD_NO_PROMO=1'
const UPGRADE_JSON = 'shipguard upgrade --json'
const NOT_PROVIDED = 'not provided by the server'

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

/** A framework this scan detected: `key` is the stack name the server knows (nextjs), `display` the words (Next.js). */
export interface DetectedStack { key: string; display: string; version?: string | null }

const joinStacks = (stacks: DetectedStack[]): string => stacks.map((s) => s.display).join(' + ')
const sameStackSet = (a: string[], b: DetectedStack[]): boolean => {
  const x = [...a].map((s) => s.toLowerCase()).sort()
  const y = b.map((s) => s.key.toLowerCase()).sort()
  return x.length === y.length && x.every((v, i) => v === y[i])
}

/** "A, B, C and more" (first three; "and more" when the server lists more). */
function areasPhrase(areas: string[]): string {
  const first = areas.slice(0, 3).join(', ')
  return areas.length > 3 ? `${first} and more` : first
}

/** `{plan}` in a sentence about what a plan would add: proAdds.planName, else the neutral wording. */
function addsSubject(plan: PlanBlock): string {
  return plan.server?.proAdds?.planName ?? 'The full rulebook'
}
function planName(plan: PlanBlock): string | null {
  return plan.server?.proAdds?.planName ?? plan.server?.label ?? null
}
/** `{plan}` after a verb ("what X would add"): the name, else neutral. */
const nameOr = (name: string | null, neutral: string): string => name ?? neutral

const pad = (n: number): string => String(n).padStart(2, '0')
/** 2026-11-17 23:07 UTC (null-safe). */
export function formatUtc(iso: string | null | undefined): string | null {
  const t = iso ? Date.parse(iso) : NaN
  if (Number.isNaN(t)) return null
  const d = new Date(t)
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`
}
export function formatDate(iso: string | null | undefined): string | null {
  const u = formatUtc(iso)
  return u === null ? null : u.slice(0, 10)
}
const endSentence = (s: string): string => (/[.!?]$/.test(s) ? s : `${s}.`)

// ---------------------------------------------------------------------------
// Moment 1: recommendation (the agent's ready-made, honest recommendation) and the screen line
// ---------------------------------------------------------------------------

export type RecKind = 'offer' | 'coverage' | null
export type RecReason =
  | 'ALREADY_PRO' | 'PAYMENT_PENDING' | 'NO_GAP' | 'NO_PLAN_DATA' | 'ACCOUNT_STATE_UNSUPPORTED' | 'UNVERIFIED'
  | 'BLOCKING_FINDINGS' | 'INCOMPLETE_SCAN' | 'CI' | 'HOOK' | 'MUTED' | 'RECENTLY_SHOWN'

export interface Recommendation {
  eligible: boolean
  relay: boolean
  kind: RecKind
  reason: RecReason | null
  sentence: string | null
  next: { command: string | null; link: string | null; then?: string } | null
  mute: string | null
}

export interface RecommendationInput {
  plan: PlanBlock
  signedIn: boolean
  /** Account status of THIS run's verified block, else the LAST verified one (nag.json), else null. */
  accountStatus: AccountStatus | null
  detected: DetectedStack[]
  /** rules.applied: the general rules that ran (a run-time count). */
  rulesApplied: number
  scanComplete: boolean
  blocking: boolean
  /** rules.fallback is set (the rulebook was not used). */
  fallbackActive: boolean
  ci: boolean
  hookOrGate: boolean
  safeMode: boolean
  muted: boolean
  /** This channel's cap (the JSON counter for `--json`, the screen counter for the screen) says it was shown recently. */
  recentlyShown: boolean
}

/** The first suppression reason that applies, in the spec's order; null = may be shown. */
function suppression(i: RecommendationInput): RecReason | null {
  if (i.blocking) return 'BLOCKING_FINDINGS'
  if (!i.scanComplete) return 'INCOMPLETE_SCAN'
  if (i.ci) return 'CI'
  if (i.hookOrGate) return 'HOOK'
  if (i.muted || i.safeMode) return 'MUTED' // safe mode shows no Free-to-Pro line: the closest closed reason is "nothing shown"
  if (i.recentlyShown) return 'RECENTLY_SHOWN'
  return null
}

const NO: Recommendation = { eligible: false, relay: false, kind: null, reason: null, sentence: null, next: null, mute: null }
const coverageSentence = (stacks: DetectedStack[]): string => `Checks for ${joinStacks(stacks)} beyond the general rules did not run here; details: shipguard upgrade`

/** Offer sentence: a fixed template over verified server fields; each part is dropped when the field is missing. */
function offerSentence(plan: PlanBlock, detected: DetectedStack[], applied: number): string {
  const p = plan.server?.proAdds
  const adds = p?.rules === null || p?.rules === undefined ? 'adds more rules' : `adds ${p.rules} rules`
  const areas = p && p.areas.length > 0 ? ` (${areasPhrase(p.areas)})` : ''
  return `ShipGuard ran ${applied} general rules on this repo. ${addsSubject(plan)} ${adds} for ${joinStacks(detected)} that did not run here${areas}. These are checks that did not run, not problems found.`
}

export function decideRecommendation(i: RecommendationInput): Recommendation {
  const status = i.signedIn ? i.accountStatus : null
  if (status === 'unsupported') return { ...NO, reason: 'ACCOUNT_STATE_UNSUPPORTED' }
  if (hasPaidPlan(status)) return { ...NO, reason: 'ALREADY_PRO' }
  if (status === 'pending') return { ...NO, reason: 'PAYMENT_PENDING', next: { command: 'shipguard status', link: null } }
  if (i.plan.reason === 'PLAN_UNVERIFIED') return { ...NO, reason: 'UNVERIFIED', next: { command: UPGRADE_JSON, link: null }, mute: MUTE_ENV }
  // Signed in, status never verified: no pitch and no sentence.
  if (i.signedIn && status === null) return { ...NO, reason: 'NO_PLAN_DATA', next: { command: UPGRADE_JSON, link: null }, mute: MUTE_ENV }
  if (i.detected.length === 0) return { ...NO, reason: 'NO_GAP' }

  const why = suppression(i)
  const next = { command: UPGRADE_JSON, link: i.plan.link }
  if (i.plan.status === 'unavailable') {
    // The no-data coverage branch: observed facts only, no number, no offer, no plan name.
    if (!i.scanComplete || i.fallbackActive) return { ...NO, reason: i.scanComplete ? 'NO_PLAN_DATA' : 'INCOMPLETE_SCAN' }
    return { eligible: false, relay: why === null, kind: 'coverage', reason: why ?? 'NO_PLAN_DATA', sentence: coverageSentence(i.detected), next: { command: UPGRADE_JSON, link: null }, mute: MUTE_ENV }
  }
  const adds = i.plan.server?.proAdds ?? null
  if (adds === null || !sameStackSet(adds.stacks, i.detected)) return { ...NO, reason: 'NO_GAP' }
  return { eligible: true, relay: why === null, kind: 'offer', reason: why, sentence: offerSentence(i.plan, i.detected, i.rulesApplied), next, mute: MUTE_ENV }
}

export interface ScreenPitchInput extends RecommendationInput {
  terminal: boolean
  quiet: boolean
  /** The shared screen counter is due (once per 7 days per repo: gap line, pointer and coverage line share it). */
  screenDue: boolean
}

export interface ScreenPitch {
  kind: 'gap' | 'pointer' | 'coverage' | null
  /** Lines for stdout, after `Rules ran:` (gap, pointer) or after `Next:` (coverage). */
  lines: string[]
  /** The caller marks the screen counter when true (after printing). */
  mark: boolean
}
const NONE_SHOWN: ScreenPitch = { kind: null, lines: [], mark: false }

/**
 * The Free-to-Pro line for a TERMINAL scan (moment 1). One of: gap line (clean scan with a verified offer for this
 * stack), pointer (no data yet), coverage line (blocking scan; number-free). Never in quiet, CI, a hook, safe mode,
 * when muted, for a paying account, or when the scan is incomplete.
 */
export function screenPitch(i: ScreenPitchInput): ScreenPitch {
  if (!i.terminal || i.quiet || i.ci || i.hookOrGate || i.safeMode || i.muted || !i.screenDue || !i.scanComplete) return NONE_SHOWN
  // Compute the recommendation WITHOUT the per-channel suppressions (checked above) and without the blocking one
  // (a blocking scan gets the coverage line instead of the gap line).
  const rec = decideRecommendation({ ...i, blocking: false, recentlyShown: false })
  if (rec.kind === null) return NONE_SHOWN
  const stacks = joinStacks(i.detected)
  if (i.blocking) {
    return { kind: 'coverage', lines: [`Checks for ${stacks} that did not run here: shipguard upgrade`], mark: true }
  }
  if (rec.kind === 'coverage') {
    return { kind: 'pointer', lines: [`See what the full rulebook would add for ${stacks} here (checks that did not run; no login, no code sent): shipguard upgrade`], mark: true }
  }
  return { kind: 'gap', lines: gapLines(i.plan, i.detected, false), mark: true }
}

/**
 * The weekly "Not run here" gap line. `firstLineOnly` is the gate form (clean pass, read from the cache, no offer text).
 * With no areas the first sentence is left off; with no rule count it says "more rules".
 */
export function gapLines(plan: PlanBlock, detected: DetectedStack[], firstLineOnly: boolean): string[] {
  const p = plan.server?.proAdds
  const stacks = joinStacks(detected)
  const adds = p?.rules === null || p?.rules === undefined ? 'adds more rules' : `adds ${p.rules} rules`
  const lead = p && p.areas.length > 0 ? `Not run here (checks, not problems found): ${areasPhrase(p.areas)}. ` : ''
  const first = `${lead}${addsSubject(plan)} ${adds} for ${stacks}; the general-rule results above stay as they are.`
  if (firstLineOnly) return [first]
  const offer = plan.server?.offer?.text
  return [first, offer ? `${offer}   Details: shipguard upgrade` : 'Details: shipguard upgrade']
}

/** Gate form (clean pass only): the first line of the gap line, from the verified cache, or nothing. */
export function gateGapLine(i: ScreenPitchInput): ScreenPitch {
  if (i.blocking || i.plan.status === 'unavailable' || i.quiet || i.ci || i.safeMode || i.muted || !i.screenDue || !i.scanComplete) return NONE_SHOWN
  const rec = decideRecommendation({ ...i, blocking: false, recentlyShown: false, hookOrGate: false })
  if (rec.kind !== 'offer' || !rec.eligible) return NONE_SHOWN
  return { kind: 'gap', lines: gapLines(i.plan, i.detected, true), mark: true }
}

// ---------------------------------------------------------------------------
// Moment 3: usage notice and update notice (stderr, terminal only, once per day)
// ---------------------------------------------------------------------------

/** "80% of your scan allowance used (resets 2026-12-01)." The percentage and wording are the server's. */
export function usageSentence(plan: PlanBlock): string | null {
  const u = plan.server?.usage
  if (!u) return null
  const text = u.text ?? `${u.percent}% of your scan allowance used`
  const date = formatDate(u.resetsAt)
  const withDate = date !== null && !text.includes(date) ? `${text} (resets ${date})` : text
  return endSentence(withDate)
}

export interface NoticeContext { terminal: boolean; quiet: boolean; ci: boolean; hookOrGate: boolean; safeMode: boolean; due: boolean }
const noticeOpen = (c: NoticeContext): boolean => c.terminal && !c.quiet && !c.ci && !c.hookOrGate && !c.safeMode && c.due

/** Allowance notice lines (empty unless usage.state is warn or used). */
export function usageNoticeLines(plan: PlanBlock, c: NoticeContext): string[] {
  const u = plan.server?.usage
  if (!u || (u.state !== 'warn' && u.state !== 'used') || !noticeOpen(c)) return []
  const lines = [usageSentence(plan) as string]
  if (plan.server?.limit) lines.push(plan.server.limit.text)
  return lines
}

/** Update notice (server text only, never a command): same slot, same daily cap. */
export function updateNoticeLines(plan: PlanBlock, c: NoticeContext): string[] {
  const n = plan.server?.updateNotice
  return n && noticeOpen(c) ? [n] : []
}

export interface UsageNote { relay: boolean; reason: 'NO_USAGE' | 'STATE_OK' | 'RECENTLY_SHOWN' | 'QUIET_CONTEXT' | null }
/** `usageNote` for `--json`: relay once per day when the state is warn/used or an update notice is present. */
export function usageNote(plan: PlanBlock, opts: { quietContext: boolean; jsonDue: boolean }): UsageNote {
  const s = plan.server
  const hasNotice = !!s?.updateNotice
  if (!s || (!s.usage && !hasNotice)) return { relay: false, reason: 'NO_USAGE' }
  if (!hasNotice && s.usage?.state !== 'warn' && s.usage?.state !== 'used') return { relay: false, reason: 'STATE_OK' }
  if (opts.quietContext) return { relay: false, reason: 'QUIET_CONTEXT' }
  if (!opts.jsonDue) return { relay: false, reason: 'RECENTLY_SHOWN' }
  return { relay: true, reason: null }
}

// ---------------------------------------------------------------------------
// Moment 4: the rulebook was not used (fallback notice, Rules ran line)
// ---------------------------------------------------------------------------

export type FallbackCode = 'RULEBOOK_WITHHELD' | 'RULEBOOK_UNREACHABLE' | 'RULEBOOK_PARTIAL' | 'PLAN_INACTIVE'

/** `rules.fallback.message` (JSON) and the notice sentence: the server's text (if any) then what this run did. */
export function fallbackMessage(code: FallbackCode, serverText: string | null): string {
  switch (code) {
    case 'RULEBOOK_WITHHELD':
      return serverText ? `${endSentence(serverText)} This scan ran general rules only.` : 'The rulebook was not provided for this scan. This scan ran general rules only.'
    case 'RULEBOOK_UNREACHABLE':
      return 'Rulebook could not be reached. This scan ran general rules only; it is not a full rulebook scan.'
    case 'RULEBOOK_PARTIAL':
      return 'Only part of the rulebook was provided; the verdict covers the rules that ran.'
    case 'PLAN_INACTIVE':
      return serverText ? `${endSentence(serverText)} This scan ran general rules only.` : 'Your plan is no longer active. This scan ran general rules only.'
  }
}

/**
 * The stdout notice under the verdict header (terminal form). `rulesApplied` = the rules that ran (general rules,
 * or the partial rulebook for RULEBOOK_PARTIAL).
 */
export function fallbackNoticeLines(code: FallbackCode, serverText: string | null, rulesApplied: number): string[] {
  const msg = code === 'RULEBOOK_WITHHELD' || code === 'PLAN_INACTIVE'
    ? `${serverText ? `${endSentence(serverText)} ` : code === 'PLAN_INACTIVE' ? 'Your plan is no longer active. ' : 'The rulebook was not provided for this scan. '}This scan ran general rules only; the verdict covers those rules only.`
    : code === 'RULEBOOK_UNREACHABLE'
      ? 'Rulebook could not be reached. This scan ran general rules only; it is not a full rulebook scan. Retry when you are online.'
      : fallbackMessage('RULEBOOK_PARTIAL', null)
  return [msg, rulesRanLine({ kind: code === 'RULEBOOK_PARTIAL' ? 'partial' : 'fallback', applied: rulesApplied })]
}

/** The `Rules ran:` line. `label` is the server's plan name for a rulebook run (absent: "full rulebook"). */
export function rulesRanLine(r: { kind: 'free' | 'rulebook' | 'fallback' | 'partial'; applied: number; label?: string | null }): string {
  switch (r.kind) {
    case 'free': return `Rules ran: ${r.applied} general rules (Free).`
    case 'rulebook': return `Rules ran: ${nameOr(r.label ?? null, 'full')} rulebook, ${r.applied} rules.`
    case 'fallback': return `Rules ran: ${r.applied} general rules (full rulebook not used).`
    case 'partial': return `Rules ran: ${r.applied} rules (part of the rulebook).`
  }
}

// ---------------------------------------------------------------------------
// Moment 5: the first-Pro receipt
// ---------------------------------------------------------------------------

export interface Receipt { extraRules: number; extraCategories: string[]; extraAreas: string[]; extraFindings: number }

/**
 * What the rulebook ran that the bundled general set did not, computed from the rules the CLI actually executed and
 * its OWN bundled general set (never from `proAdds`, never a total or a difference from a Free scan).
 */
export function computeReceipt(
  executed: Array<{ id: string; category?: string | null; area?: string | null }>,
  generalIds: ReadonlySet<string>,
  findingRuleIds: readonly string[],
): Receipt {
  const extra = executed.filter((r) => !generalIds.has(r.id))
  const extraIds = new Set(extra.map((r) => r.id))
  const categories = new Set<string>()
  const areas = new Set<string>()
  for (const r of extra) {
    if (r.category) categories.add(r.category)
    const a = r.area ?? r.category ?? null // a rule with no area shows its category code
    if (a) areas.add(a)
  }
  return {
    extraRules: extra.length,
    extraCategories: [...categories].sort(),
    extraAreas: [...areas].sort(),
    extraFindings: findingRuleIds.filter((id) => extraIds.has(id)).length,
  }
}

/** `[Pro rule]` marker text for a finding from a rulebook rule (neutral: `[rulebook rule]`). */
export function ruleMarker(plan: PlanBlock): string {
  return `[${nameOr(plan.server?.label ?? null, 'rulebook')} rule]`
}

/** Receipt block. Prints nothing when extraRules is 0 (and must then not be marked as shown). */
export function receiptLines(receipt: Receipt, plan: PlanBlock): string[] {
  if (receipt.extraRules <= 0) return []
  const label = plan.server?.label ?? null
  const head = label ? `${label} rules ran here (first ${label} scan on this machine):` : 'Rulebook rules ran here (first rulebook scan on this machine):'
  const where = receipt.extraAreas.length > 0 ? `, in: ${receipt.extraAreas.join(', ')}` : ''
  const found = receipt.extraFindings > 0
    ? `Findings from them: ${receipt.extraFindings} (marked ${ruleMarker(plan)} above).`
    : 'Findings from them: none. Those checks ran and nothing matched.'
  return [head, `  ${receipt.extraRules} additional rules ran beyond the built-in general rules${where}`, `  ${found}`]
}

export interface ReceiptNote { relay: boolean; reason: 'NO_RECEIPT' | 'RECENTLY_SHOWN' | 'QUIET_CONTEXT' | null; sentence?: string }
/** `receiptNote` for `--json`: once per account, only when extra rules ran on a complete rulebook run. */
export function receiptNote(r: { receipt: Receipt | null; plan: PlanBlock; quietContext: boolean; jsonDue: boolean }): ReceiptNote {
  if (!r.receipt || r.receipt.extraRules <= 0) return { relay: false, reason: 'NO_RECEIPT' }
  if (r.quietContext) return { relay: false, reason: 'QUIET_CONTEXT' }
  if (!r.jsonDue) return { relay: false, reason: 'RECENTLY_SHOWN' }
  const label = r.plan.server?.label ?? null
  const areas = r.receipt.extraAreas.length > 0 ? `, in: ${r.receipt.extraAreas.join(', ')}` : ''
  const found = r.receipt.extraFindings > 0 ? String(r.receipt.extraFindings) : 'none (those checks ran and nothing matched)'
  return {
    relay: true,
    reason: null,
    sentence: `On this scan the ${nameOr(label, 'full')} rulebook ran ${r.receipt.extraRules} additional rules beyond the built-in general rules${areas}. Findings from them: ${found}.`,
  }
}

// ---------------------------------------------------------------------------
// `--json` plan object (the same for scan, status and upgrade)
// ---------------------------------------------------------------------------

export function planJson(r: { plan: PlanBlock; recommendation: Recommendation; usageNote: UsageNote; receiptNote: ReceiptNote }): Record<string, unknown> {
  const { plan } = r
  return {
    status: plan.status,
    reason: plan.reason,
    command: plan.command,
    link: plan.link,
    server: plan.server,
    recommendation: r.recommendation,
    usageNote: r.usageNote,
    receiptNote: r.receiptNote,
  }
}

// ---------------------------------------------------------------------------
// `shipguard status`
// ---------------------------------------------------------------------------

export interface StatusInput {
  auth: 'signed-out' | 'expired' | 'signed-in'
  /** For auth 'expired': the expiry time (ISO). */
  expiredAt?: string | null
  plan: PlanBlock
  /** Bundled general rules (run-time count). */
  generalCount: number
  /** The scan command a checkout should be followed by (the re-run builder's command; default `shipguard scan`). */
  scanCommand?: string
  lastScan?: { corpus: 'rulebook' | 'general'; applied: number; at: string } | null
}

export function statusLines(i: StatusInput): string[] {
  const scan = i.scanCommand ?? 'shipguard scan'
  if (i.auth === 'signed-out') {
    return [`Not signed in. Rules: general rules only (${i.generalCount} bundled, offline). What a plan would add: shipguard upgrade`]
  }
  if (i.auth === 'expired') {
    const when = formatUtc(i.expiredAt ?? null)
    return [`Signed in as this machine, but the sign-in expired${when ? ` on ${when.slice(0, 16)} UTC` : ''}. Fix: shipguard login`]
  }
  const p = i.plan
  if (p.reason === 'PLAN_UNVERIFIED') return ['Plan details could not be verified, so none are shown. Try again: shipguard status']
  if (p.status === 'unavailable' || p.server === null) {
    return ['Signed in. Plan details are not available right now (the rulebook service could not be reached). Try again when online: shipguard status']
  }
  const s = p.server
  const out: string[] = []
  const status = s.account?.status ?? null
  const acctText = s.account?.text ?? null
  const startLine = p.link ? `To start: ${p.link}   then: ${scan}` : null
  if (status === 'unsupported') {
    out.push('This ShipGuard version does not recognise this plan state. Update ShipGuard to read it.')
    if (acctText) out.push(acctText)
  } else if (status === 'pending') {
    out.push(`Payment not confirmed yet.${acctText ? ` ${acctText}` : ''} Check again in a minute: shipguard status`)
  } else if (status === 'none') {
    out.push(`Signed in. No active plan on this account yet.${acctText ? ` ${acctText}` : ''}`)
    if (startLine) out.push(startLine)
    out.push('Paid with a different account? Sign in with that one: shipguard login')
  } else if (status === 'lapsed') {
    out.push(`Signed in. Your plan is no longer active.${acctText ? ` ${acctText}` : ''}`)
    if (startLine) out.push(startLine)
  } else {
    // A plan (active, trialing, past_due, ending) or an account block the server sent without a status: every line
    // is a server field; a missing one says so instead of guessing.
    const asOf = formatUtc(s.fetchedAt)
    out.push(`Plan: ${s.label ?? NOT_PROVIDED}${asOf ? ` (as of ${asOf})` : ''}.`)
    out.push(`Usage: ${usageSentence(p) ?? NOT_PROVIDED}`)
    out.push(`At the limit: ${s.limit?.text ?? NOT_PROVIDED}`)
    out.push(`Account: ${acctText ?? NOT_PROVIDED}`)
    if (i.lastScan) {
      const when = formatUtc(i.lastScan.at)
      const what = i.lastScan.corpus === 'rulebook' ? 'full rulebook' : 'general rules'
      out.push(`Last scan here: ${what}, ${i.lastScan.applied} rules${when ? ` (${when})` : ''}.`)
    }
  }
  if (p.status === 'cached') out.push('Could not refresh (offline); showing the last verified details.')
  if (s.updateNotice) out.push(s.updateNotice)
  return out
}

// ---------------------------------------------------------------------------
// `shipguard upgrade`
// ---------------------------------------------------------------------------

export interface UpgradeInput {
  plan: PlanBlock
  signedIn: boolean
  accountStatus: AccountStatus | null
  detected: DetectedStack[]
  generalCount: number
  /** The re-run builder's command from the scan that brought the user here (history), else `shipguard scan`. */
  scanCommand?: string
  /** A previous scan exists in this repo's history (so "Ran in your last scan" is true). */
  hasHistory: boolean
}

export interface UpgradePath { step: number; command?: string; link?: string }

/** The three (or two) printed steps as data: login when signed out, the checkout link, the scan to run again. */
export function upgradePath(i: UpgradeInput): UpgradePath[] | null {
  const status = i.accountStatus
  if (hasPaidPlan(status) || status === 'pending' || status === 'unsupported') return null
  const link = i.plan.link
  if (!link) return null
  const steps: UpgradePath[] = []
  if (!i.signedIn) steps.push({ step: 1, command: 'shipguard login' })
  steps.push({ step: steps.length + 1, link })
  steps.push({ step: steps.length + 1, command: i.scanCommand ?? 'shipguard scan' })
  return steps
}

export function upgradeLines(i: UpgradeInput): string[] {
  const p = i.plan
  const status = i.signedIn ? i.accountStatus : null
  const acctText = p.server?.account?.text ?? null
  const scan = i.scanCommand ?? 'shipguard scan'
  if (p.reason === 'PLAN_UNVERIFIED') return ['Plan details could not be verified, so none are shown. Your scan is not affected. Try again: shipguard upgrade']
  if (status === 'unsupported') {
    return ['This ShipGuard version does not recognise this plan state. Update ShipGuard to read it.', ...(acctText ? [acctText] : [])]
  }
  if (hasPaidPlan(status)) {
    const name = p.server?.label
    return [name ? `${name} is already active on this account.` : 'This account already has an active plan.', ...statusLines({ auth: 'signed-in', plan: p, generalCount: i.generalCount, scanCommand: scan })]
  }
  if (status === 'pending') return [`Payment not confirmed yet.${acctText ? ` ${acctText}` : ''} Check again in a minute: shipguard status`]
  if (p.status === 'unavailable' || p.server === null) {
    return ['Plan details are not available right now (the rulebook service could not be reached). Your scan is not affected. Try again when online: shipguard upgrade', 'Free keeps working offline with no account.']
  }
  const s = p.server
  const out: string[] = []
  const subject = nameOr(s.proAdds?.planName ?? s.label, 'the full rulebook')
  if (i.detected.length === 0) {
    out.push('What the full rulebook adds depends on your stack, which was not detected.')
  } else {
    const names = i.detected.map((d) => (d.version ? `${d.display} ${d.version}` : d.display)).join(', ')
    out.push(`What ${subject} would add for this repo (${names}):`)
    if (i.hasHistory) out.push(`  Ran in your last scan:      ${i.generalCount} general rules (Free)`)
    const adds = s.proAdds
    if (adds) {
      out.push(`  Did not run here:           ${adds.rules === null ? 'more rules for this stack' : `${adds.rules} ${s.proAdds?.planName ? `${s.proAdds.planName} ` : ''}rules for this stack`}`)
      if (adds.areas.length > 0) out.push(`  Areas without those checks: ${areasPhrase(adds.areas)}`)
    }
    out.push('These are checks that did not run, not problems found. They do not change the findings you already have. Free keeps working offline with no account.')
  }
  if (s.offer) out.push('', s.offer.text)
  if (s.limit) out.push(s.limit.text)
  const path = upgradePath(i)
  if (path === null) {
    if (status === 'lapsed') out.unshift('Your plan is no longer active.', ...(acctText ? [acctText] : []))
    out.push('', 'The server did not provide a checkout link right now. Try again later: shipguard upgrade')
  } else {
    if (status === 'lapsed') out.unshift('Your plan is no longer active.', ...(acctText ? [acctText] : []))
    out.push('', `To start ${nameOr(s.proAdds?.planName ?? null, 'the full rulebook')}:`)
    for (const step of path) {
      if (step.command === 'shipguard login') out.push(`  ${step.step}. Sign in:           shipguard login`)
      else if (step.link) {
        out.push(`  ${step.step}. Start checkout:    ${step.link}${i.signedIn ? '' : '      (on the page, sign in with the same account you used in step 1)'}`)
        if (i.signedIn && acctText) out.push(`                        ${acctText}`)
      } else out.push(`  ${step.step}. Run a scan again:  ${step.command}      (same project as before; your plan is picked up on this run: no reinstall, no second sign-in)`)
    }
    out.push('Check at any time what ShipGuard sees: shipguard status')
  }
  out.push('A plain scan that cannot use the rulebook runs general rules and says so; its exit code does not change. A scan run with --pro requires the rulebook: it exits 3 when there is no signed server reply (missing, unverified or offline); when the server\'s signed reply says the limit is used up it runs general rules and its exit code does not change (--allow-degraded runs general rules instead of exiting 3 in the other cases).')
  if (i.detected.length > 0) out.push(`Asked the rulebook service for: ${i.detected.map((d) => d.key).join(', ')} (framework names only, no code, no paths). Inspect first: shipguard upgrade --dry-run`)
  out.push(`Plans as plain text (for agents): ${goLink('pricing-md')}`, 'Stop these hints: shipguard upgrade --mute')
  return out
}

/** `upgrade --json` recommendation: always relayed for an eligible account (the user asked for plan data). */
export function upgradeRecommendation(i: UpgradeInput): Recommendation {
  const status = i.signedIn ? i.accountStatus : null
  if (status === 'unsupported') return { ...NO, reason: 'ACCOUNT_STATE_UNSUPPORTED' }
  if (hasPaidPlan(status)) return { ...NO, reason: 'ALREADY_PRO' }
  if (status === 'pending') return { ...NO, reason: 'PAYMENT_PENDING', next: { command: 'shipguard status', link: null } }
  if (i.plan.reason === 'PLAN_UNVERIFIED') return { ...NO, reason: 'UNVERIFIED', next: { command: UPGRADE_JSON, link: null }, mute: MUTE_ENV }
  if (i.plan.status === 'unavailable') {
    if (i.detected.length === 0) return { ...NO, reason: 'NO_GAP' }
    return { eligible: false, relay: true, kind: 'coverage', reason: 'NO_PLAN_DATA', sentence: coverageSentence(i.detected), next: { command: UPGRADE_JSON, link: null }, mute: null }
  }
  const adds = i.plan.server?.proAdds ?? null
  if (i.detected.length === 0 || adds === null || !sameStackSet(adds.stacks, i.detected)) return { ...NO, reason: 'NO_GAP' }
  const path = upgradePath(i)
  const first = path?.[0]
  return {
    eligible: true,
    relay: true,
    kind: 'offer',
    reason: null,
    sentence: offerSentence(i.plan, i.detected, i.generalCount),
    next: { command: first?.command ?? null, link: i.plan.link, then: i.scanCommand ?? 'shipguard scan' },
    mute: MUTE_ENV,
  }
}
