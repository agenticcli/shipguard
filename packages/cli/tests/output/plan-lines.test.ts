/**
 * W2a acceptance tests: Free-to-Pro screen lines (spec 05), built from one verified server block.
 * Number-free in the CLI: every number, plan name and area below comes from the test's "server" block.
 */
import { describe, it, expect } from 'vitest'
import { planLines, type PlanLineContext } from '../../src/core/plan-lines.js'
import { renderScanScreen } from '../../src/core/render.js'
import { a1Findings, result } from './_fixtures.js'
import type { PlanServerBlock } from '../../src/core/plan-types.js'

const server = (o: Partial<PlanServerBlock> = {}): PlanServerBlock => ({
  fetchedAt: '2026-11-17T22:50:11Z',
  validUntil: '2026-11-20T22:50:11Z',
  label: null,
  account: null,
  usage: null,
  limit: null,
  capabilities: null,
  refreshAfter: null,
  updateNotice: null,
  proAdds: { planName: 'Pro', rules: 41, stacks: ['nextjs', 'supabase'], areas: ['Supabase row-level security', 'Next.js server actions', 'Stripe webhooks'] },
  offer: { text: '<offer wording from server>', slot: 'checkout' },
  ...o,
})

const ctx = (o: Partial<PlanLineContext> = {}): PlanLineContext => ({
  server: server(),
  planReason: null,
  signedIn: false,
  accountStatus: null,
  stacks: ['nextjs', 'supabase'],
  complete: true,
  blockingCount: 0,
  plainGeneralRun: true,
  counterAllowed: true,
  muted: false,
  quiet: false,
  ci: false,
  safeMode: false,
  terminal: true,
  surface: 'screen',
  ...o,
})

describe('gap line (clean scan, verified server data)', () => {
  it('prints the two lines, all numbers and names from the server block', () => {
    const r = planLines(ctx())
    expect(r.kind).toBe('gap')
    expect(r.lines).toEqual([
      'Not run here (checks, not problems found): Supabase row-level security, Next.js server actions, Stripe webhooks. Pro adds 41 rules for Next.js + Supabase; the general-rule results above stay as they are.',
      '<offer wording from server>   Details: shipguard upgrade',
    ])
  })

  it('no offer: only the Details pointer; no plan name: "The full rulebook"; more than three areas: "and more"', () => {
    const r = planLines(ctx({ server: server({ offer: null, proAdds: { planName: null, rules: 41, stacks: ['nextjs'], areas: ['a', 'b', 'c', 'd'] } }) }))
    expect(r.lines[0]).toContain('Not run here (checks, not problems found): a, b, c, and more. The full rulebook adds 41 rules for Next.js;')
    expect(r.lines[1]).toBe('Details: shipguard upgrade')
  })

  it('generic primed offer (rules and areas null): one sentence, then the offer line', () => {
    const r = planLines(ctx({ server: server({ proAdds: { planName: 'Pro', rules: null, stacks: [], areas: [] } }) }))
    expect(r.lines[0]).toBe('Pro adds more rules for Next.js + Supabase.')
  })

  it('on a clean gate pass only the first line shows (no offer text)', () => {
    const r = planLines(ctx({ surface: 'gate', terminal: false }))
    expect(r.kind).toBe('gap')
    expect(r.lines).toHaveLength(1)
    expect(r.lines[0]).not.toContain('<offer')
  })

  it('a signed-in account with status lapsed or none is pitched; a paying one never', () => {
    expect(planLines(ctx({ signedIn: true, accountStatus: 'lapsed' })).kind).toBe('gap')
    expect(planLines(ctx({ signedIn: true, accountStatus: 'none' })).kind).toBe('gap')
    for (const st of ['active', 'trialing', 'past_due', 'ending'] as const) {
      expect(planLines(ctx({ signedIn: true, accountStatus: st, server: null })).kind).toBeNull()
    }
    expect(planLines(ctx({ signedIn: true, accountStatus: null })).kind).toBeNull()
    expect(planLines(ctx({ signedIn: true, accountStatus: 'unsupported' })).kind).toBeNull()
    expect(planLines(ctx({ signedIn: true, accountStatus: 'pending' })).kind).toBeNull()
  })
})

describe('pointer (no plan data): number-free', () => {
  it('names only the detected stacks and the command', () => {
    const r = planLines(ctx({ server: null }))
    expect(r.kind).toBe('pointer')
    expect(r.lines).toEqual(['See what the full rulebook would add for Next.js + Supabase here (checks that did not run; no login, no code sent): shipguard upgrade'])
    expect(r.lines[0]).not.toMatch(/\d|Pro|\$/)
  })

  it('a failed verification shows nothing at all; the gate never prints a pointer', () => {
    expect(planLines(ctx({ server: null, planReason: 'PLAN_UNVERIFIED' })).kind).toBeNull()
    expect(planLines(ctx({ server: null, surface: 'gate' })).kind).toBeNull()
  })
})

describe('coverage line after a blocking scan', () => {
  it('one line, terminal only, no number, no price, no offer', () => {
    const r = planLines(ctx({ blockingCount: 3 }))
    expect(r).toEqual({ kind: 'coverage', lines: ['Checks for Next.js + Supabase that did not run here: shipguard upgrade'] })
    expect(planLines(ctx({ blockingCount: 3, terminal: false })).kind).toBeNull()
    expect(planLines(ctx({ blockingCount: 3, surface: 'gate' })).kind).toBeNull()
  })
})

describe('no promotion where it must not appear', () => {
  it.each([
    ['muted', { muted: true }],
    ['quiet', { quiet: true }],
    ['CI', { ci: true }],
    ['safe mode (isSafeMode() true)', { safeMode: true }],
    ['counter says shown in the last 7 days', { counterAllowed: false }],
    ['incomplete scan', { complete: false }],
    ['stack not detected', { stacks: ['generic'] }],
    ['the rulebook ran (not a plain general-rules run)', { plainGeneralRun: false }],
  ] as const)('%s: nothing', (_n, o) => {
    expect(planLines(ctx(o as Partial<PlanLineContext>)).lines).toEqual([])
  })

  it('the screen prints plan lines only after Rules ran, and a CI screen gets none', () => {
    const lines = planLines(ctx()).lines
    const out = renderScanScreen({ elapsedMs: 200, strict: false, generalRuleCount: 36, result: result([]), planLines: lines })
    const all = out.split('\n')
    expect(all.indexOf(lines[0])).toBeGreaterThan(all.findIndex((l) => l.startsWith('Rules ran:')))
    const none = renderScanScreen({ elapsedMs: 200, strict: false, generalRuleCount: 36, result: result([]), planLines: planLines(ctx({ ci: true })).lines })
    expect(none).not.toContain('Not run here')
    expect(none).not.toContain('shipguard upgrade')
  })

  it('a blocked A1 screen with a verified block prints no gap line and no offer, only the coverage line', () => {
    const lines = planLines(ctx({ blockingCount: 3 })).lines
    const out = renderScanScreen({ elapsedMs: 200, strict: false, generalRuleCount: 36, result: result(a1Findings()), planLines: lines })
    expect(out).not.toContain('Not run here')
    expect(out).not.toContain('<offer')
    expect(out.split('\n').pop()).toBe('Checks for Next.js + Supabase that did not run here: shipguard upgrade')
  })
})
