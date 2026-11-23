/** W1b: how a scan gets its rules and what the plan block says (spec 02 "rulebook did not run", 05 "Explicit --pro"). */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { QualityGateRule } from '@agenticcli/shared'
import { runRulebookStep, type FetchProRulesFn } from '../../src/core/rulebook-step.js'
import { mapAccountPayload, planBlockFrom, acctHash } from '../../src/core/plan.js'
import { writeHint } from '../../src/core/hint.js'
import { recordAccountStatus } from '../../src/core/nag.js'
import { loadBundledRules } from '../../src/core/bundled-rules.js'
import type { PlanEnv } from '../../src/core/plan-client.js'
import type { ProFetchResult } from '../../src/core/pro-scanner.js'

let home: string
let env: PlanEnv
const SUB = 'user_123'
const ACCT = acctHash(SUB)

function b64(o: unknown): string { return Buffer.from(JSON.stringify(o)).toString('base64url') }
function signIn(): void {
  const dir = join(home, '.config', 'shipguard')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, 'credentials.json'), JSON.stringify({
    accessToken: `${b64({ alg: 'none' })}.${b64({ sub: SUB })}.x`, refreshToken: 'r', expiresAt: Date.now() + 3600_000, apiUrl: 'https://agenticcli.dev',
  }), { mode: 0o600 })
}
const NOW = 1_800_000_000
const livePlan = (over: Record<string, unknown> = {}) => ({
  block: planBlockFrom(mapAccountPayload({ iat: NOW, exp: NOW + 3600, label: 'Pro', account: { status: 'active', text: 'Renews soon.' }, ...over }), 'live'),
  token: 'doc', live: true,
})

function generalRule(): QualityGateRule { const r = loadBundledRules()[0]; return { ...r } }
const extraRule = (): QualityGateRule => ({ ...generalRule(), id: 'rulebook.only.extra-rule' })
const served = (rules: QualityGateRule[], over: Partial<ProFetchResult> = {}): FetchProRulesFn =>
  async () => ({ rules, creditsRemaining: undefined, plan: livePlan(), acct: ACCT, partial: false, tiersApplied: ['free', 'pro'], areaByRuleId: {}, ...over })
const failing = (code: string, message: string, context?: unknown, retryAfterSeconds?: number): FetchProRulesFn => async () => {
  throw Object.assign(new Error(message), { code, context, retryAfterSeconds })
}
const input = (over: Partial<Parameters<typeof runRulebookStep>[0]> & { fetchProRules: FetchProRulesFn }) => ({
  env, explicitPro: false, general: false, allowDegraded: false, hookOrGate: false, apiUrl: 'https://agenticcli.dev',
  frameworks: ['nextjs'], categories: [], scanId: 's1', ...over,
})

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sg-w1b-'))
  vi.stubEnv('HOME', home)
  vi.stubEnv('SHIPGUARD_API_KEY', '')
  env = { configDir: join(home, '.config', 'shipguard'), now: Date.now(), safeMode: false, ci: false, terminal: true, apiKeyMode: false, trackingOff: false }
})
afterEach(() => { vi.unstubAllEnvs(); rmSync(home, { recursive: true, force: true }) })

describe('signed out', () => {
  it('a plain scan is a plain Free run and asks the server nothing', async () => {
    const f = vi.fn()
    const r = await runRulebookStep(input({ fetchProRules: f }))
    expect(f).not.toHaveBeenCalled()
    expect(r).toMatchObject({ signedIn: false, rulebookRan: false, fallback: null, error: null, proRules: undefined })
    expect(r.plan.status).toBe('unavailable')
  })

  it('--pro goes through the request, which fails before any network call: LOGIN_REQUIRED, exit 3 class', async () => {
    const r = await runRulebookStep(input({ explicitPro: true, fetchProRules: failing('AUTH_FAILED', 'Not authenticated. Run `shipguard login` first.') }))
    expect(r.error).toMatchObject({ code: 'LOGIN_REQUIRED', message: '--pro uses the full rulebook, and you are not signed in.' })
  })

  it('--pro --allow-degraded runs general rules and says the rulebook was not used (0.12 degraded record kept)', async () => {
    const r = await runRulebookStep(input({ explicitPro: true, allowDegraded: true, fetchProRules: failing('AUTH_FAILED', 'Not authenticated. Run `shipguard login` first.') }))
    expect(r.error).toBeNull()
    expect(r.fallback).toMatchObject({ code: 'RULEBOOK_UNREACHABLE', reason: null })
    expect(r.degradedReason?.code).toBe('PRO_RULES_UNAVAILABLE')
  })
})

describe('signed in: the rulebook is served', () => {
  beforeEach(signIn)

  it('a paying account runs the served rulebook; the plan block is the live one', async () => {
    const r = await runRulebookStep(input({ fetchProRules: served([generalRule(), extraRule()]) }))
    expect(r).toMatchObject({ rulebookRan: true, fallback: null, accountStatus: 'active' })
    expect(r.proRules).toHaveLength(2)
    expect(r.plan.status).toBe('live')
  })

  it('an account with no plan that is sent only general-set rules is a plain Free run (nothing printed, no fallback)', async () => {
    const r = await runRulebookStep(input({ fetchProRules: served([generalRule()], { plan: livePlan({ label: null, account: { status: 'none' } }) }) }))
    expect(r).toMatchObject({ rulebookRan: false, fallback: null, proRules: undefined, accountStatus: 'none' })
  })

  it('RULEBOOK_PARTIAL: a default scan runs what it has and says so; --pro exits 3; --allow-degraded runs it', async () => {
    const fetch = served([generalRule(), extraRule()], { partial: true, tiersApplied: ['free'] })
    const def = await runRulebookStep(input({ fetchProRules: fetch }))
    expect(def).toMatchObject({ partial: true, rulebookRan: true, fallback: { code: 'RULEBOOK_PARTIAL' } })
    const pro = await runRulebookStep(input({ explicitPro: true, fetchProRules: fetch }))
    expect(pro.error?.code).toBe('RULEBOOK_PARTIAL')
    const soft = await runRulebookStep(input({ explicitPro: true, allowDegraded: true, fetchProRules: fetch }))
    expect(soft.error).toBeNull()
    expect(soft.partial).toBe(true)
  })

  it('a verified live reply writes the account cache and last status (a later offline run never pitches this account)', async () => {
    await runRulebookStep(input({ fetchProRules: served([extraRule()]) }))
    const down = await runRulebookStep(input({ fetchProRules: failing('SERVER_ERROR', 'boom') }))
    expect(down.fallback?.code).toBe('RULEBOOK_UNREACHABLE')
  })
})

describe('signed in: the rulebook is refused or unreachable', () => {
  beforeEach(signIn)
  const limitUsed = { plan: livePlan({ usage: { percent: 100, state: 'used', text: 'Scan allowance used up' } }), acct: ACCT, serverCode: 'ALLOWANCE_USED', serverText: 'Scan allowance used up.' }

  it('signed ALLOWANCE_USED: a plain scan AND an explicit --pro run general rules, exit unchanged, reason ALLOWANCE_USED', async () => {
    for (const explicitPro of [false, true]) {
      const r = await runRulebookStep(input({ explicitPro, fetchProRules: failing('ALLOWANCE_USED', 'Scan allowance used up.', limitUsed) }))
      expect(r.error).toBeNull()
      expect(r.fallback).toMatchObject({ code: 'RULEBOOK_WITHHELD', reason: 'ALLOWANCE_USED' })
      expect(r.degradedReason).toBeNull()
    }
  })

  it('an UNSIGNED refusal can only make --pro stricter: exit 3 with the server text and the fix sentence', async () => {
    const unsigned = { plan: null, acct: ACCT, serverCode: 'ALLOWANCE_USED', serverText: 'Scan allowance used up.' }
    const r = await runRulebookStep(input({ explicitPro: true, fetchProRules: failing('ALLOWANCE_USED', 'Scan allowance used up.', unsigned) }))
    expect(r.error?.code).toBe('RULEBOOK_WITHHELD')
    expect(r.error?.message).toContain('Scan allowance used up.')
    expect(r.error?.message).toContain('Remove --pro to fall back to general rules automatically, or add --allow-degraded.')
  })

  it('a signed-in account that never had a plan, refused: plain Free (no fallback, no notice)', async () => {
    const none = { plan: livePlan({ label: null, account: { status: 'none' } }), acct: ACCT, serverCode: 'PLAN_INACTIVE', serverText: null }
    const r = await runRulebookStep(input({ fetchProRules: failing('PLAN_INACTIVE', 'no plan', none) }))
    expect(r.fallback).toBeNull()
    expect(r.error).toBeNull()
    const pro = await runRulebookStep(input({ explicitPro: true, fetchProRules: failing('PLAN_INACTIVE', 'no plan', none) }))
    expect(pro.error?.code).toBe('PLAN_INACTIVE')
  })

  it('a lapsed plan: PLAN_INACTIVE fallback on a default scan', async () => {
    const lapsed = { plan: livePlan({ account: { status: 'lapsed' } }), acct: ACCT, serverCode: 'PLAN_INACTIVE', serverText: null }
    const r = await runRulebookStep(input({ fetchProRules: failing('PLAN_INACTIVE', 'x', lapsed) }))
    expect(r.fallback).toMatchObject({ code: 'PLAN_INACTIVE' })
  })

  it('503 TOKEN_CHECK_UNAVAILABLE is "server unavailable": a default scan falls back, --pro exits 3 as RULEBOOK_UNREACHABLE (never "sign in again")', async () => {
    recordAccountStatus({ configDir: env.configDir, now: env.now, safeMode: false }, ACCT, 'active')
    const f = failing('SERVER_ERROR', 'The rulebook service could not check your sign-in right now. Retry in a minute.', undefined, 60)
    const def = await runRulebookStep(input({ fetchProRules: f }))
    expect(def.fallback).toMatchObject({ code: 'RULEBOOK_UNREACHABLE' })
    const pro = await runRulebookStep(input({ explicitPro: true, fetchProRules: f }))
    expect(pro.error).toMatchObject({ code: 'RULEBOOK_UNREACHABLE', retryAfterSeconds: 60 })
  })

  it('a paying user who is offline is told what ran and is never pitched; a never-paid account sees a plain Free run', async () => {
    recordAccountStatus({ configDir: env.configDir, now: env.now, safeMode: false }, ACCT, 'trialing')
    const paying = await runRulebookStep(input({ fetchProRules: failing('SERVER_ERROR', 'offline') }))
    expect(paying.fallback?.code).toBe('RULEBOOK_UNREACHABLE')
    recordAccountStatus({ configDir: env.configDir, now: env.now, safeMode: false }, ACCT, 'none')
    const free = await runRulebookStep(input({ fetchProRules: failing('SERVER_ERROR', 'offline') }))
    expect(free.fallback).toBeNull()
  })

  it('a zero-rule bundle is never a clean pass, even with --allow-degraded', async () => {
    const r = await runRulebookStep(input({ allowDegraded: true, fetchProRules: failing('NO_RULES_APPLIED', 'zero rules') }))
    expect(r.error?.code).toBe('NO_RULES_APPLIED')
  })
})

describe('calls that are skipped', () => {
  beforeEach(signIn)

  it('--general asks the server nothing', async () => {
    const f = vi.fn()
    const r = await runRulebookStep(input({ general: true, fetchProRules: f }))
    expect(f).not.toHaveBeenCalled()
    expect(r.proRules).toBeUndefined()
  })

  it('a valid hint skips the call in a hook or gate only; --pro and CI ignore it', async () => {
    writeHint({ configDir: env.configDir, now: env.now, safeMode: false }, ACCT)
    const f = vi.fn(served([extraRule()]))
    await runRulebookStep(input({ hookOrGate: true, fetchProRules: f }))
    expect(f).not.toHaveBeenCalled()
    await runRulebookStep(input({ hookOrGate: false, fetchProRules: f }))
    expect(f).toHaveBeenCalledTimes(1)
    await runRulebookStep(input({ hookOrGate: true, explicitPro: true, fetchProRules: f }))
    expect(f).toHaveBeenCalledTimes(2)
    await runRulebookStep({ ...input({ hookOrGate: true, fetchProRules: f }), env: { ...env, ci: true } })
    expect(f).toHaveBeenCalledTimes(3)
  })
})
