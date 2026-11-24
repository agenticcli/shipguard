/** End-to-end flows across the modules (the way the call sites will chain them), with a fake clock and a fake server. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { OFFER_GENERIC_FILE, maybeFetchWeeklyOffer, primeOfferCache, readOffer, type OfferFetchGate } from '../../src/core/offer-cache.js'
import { loadNag, markMoment, momentDue, repoKey, WEEK_MS } from '../../src/core/nag.js'
import { decideRecommendation, gateGapLine, screenPitch, type DetectedStack, type RecommendationInput } from '../../src/core/plan-lines.js'
import { unavailableBlock } from '../../src/core/plan.js'
import { NOW_MS, NOW_S, makeSigner, offerPayload, tempConfigDir, type TestSigner } from './helpers.js'
import { existsSync } from 'node:fs'
import { join } from 'node:path'

let signer: TestSigner
beforeAll(() => { signer = makeSigner('flows-signer') })
afterAll(() => signer.cleanup())

const gate: OfferFetchGate = { signedIn: false, terminal: true, ci: false, quiet: false, hookOrGate: false, safeMode: false, trackingOff: false, dryRun: false }
const stacks: DetectedStack[] = [{ key: 'nextjs', display: 'Next.js' }]
const server = (token: string) => (async () => new Response(token, { status: 200 })) as unknown as typeof fetch

describe('hook-only user: setup primes the generic offer, then a clean gate pass prints the gap line once a week', () => {
  it('prime (no stack data) -> gate reads the generic file -> first line only -> counter blocks the repeat for 7 days', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW_MS, safeMode: false }
      const generic = signer.sign(offerPayload({ offer: { text: 'Generic offer words', slot: 'pricing' } }), { typ: 'shipguard-offer+jws' })
      const primed = await primeOfferCache(ctx, gate, { fetchImpl: server(generic) })
      expect(primed.attempted && primed.result.ok).toBe(true)
      expect(existsSync(join(dir, OFFER_GENERIC_FILE))).toBe(true)

      const read = await readOffer(ctx, ['nextjs'])
      expect(read.source).toBe('generic')
      const repo = repoKey('/work/app')
      const input = (now: number, due: boolean) => ({
        plan: read.block, signedIn: false, accountStatus: null, detected: stacks, rulesApplied: 36, scanComplete: true, blocking: false, fallbackActive: false,
        ci: false, hookOrGate: true, safeMode: false, muted: false, recentlyShown: false, terminal: false, quiet: false, screenDue: due && now > 0,
      } as RecommendationInput & { terminal: boolean; quiet: boolean; screenDue: boolean })

      const first = gateGapLine(input(NOW_MS, momentDue(loadNag(ctx), 'screenPitch', repo, NOW_MS)))
      expect(first.kind).toBe('gap')
      expect(first.lines).toEqual(['The full rulebook adds more rules for Next.js; the general-rule results above stay as they are.'])
      markMoment(ctx, 'screenPitch', repo)
      const again = gateGapLine(input(NOW_MS + 1000, momentDue(loadNag(ctx), 'screenPitch', repo, NOW_MS + 1000)))
      expect(again.kind).toBeNull()
      const nextWeek = gateGapLine(input(NOW_MS + WEEK_MS, momentDue(loadNag(ctx), 'screenPitch', repo, NOW_MS + WEEK_MS)))
      expect(nextWeek.kind).toBe('gap')
    } finally { cleanup() }
  })
})

describe('offline Free user with no cache', () => {
  it('a hanging server is cut off by the bound, nothing is cached, and the scan prints the number-free pointer', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW_MS, safeMode: false }
      const hang = ((_u: string, init?: RequestInit) => new Promise((_r, rej) => init?.signal?.addEventListener('abort', () => rej(new Error('aborted'))))) as unknown as typeof fetch
      const t0 = Date.now()
      const attempt = await maybeFetchWeeklyOffer(ctx, gate, ['nextjs'], { fetchImpl: hang, timeoutMs: 100 })
      expect(Date.now() - t0).toBeLessThan(3000)
      expect(attempt.attempted && !attempt.result.ok && attempt.result.reason).toBe('OFFLINE')
      const read = await readOffer(ctx, ['nextjs'])
      expect(read.block).toEqual(unavailableBlock('NOT_FETCHED'))
      const p = screenPitch({
        plan: read.block, signedIn: false, accountStatus: null, detected: stacks, rulesApplied: 36, scanComplete: true, blocking: false, fallbackActive: false,
        ci: false, hookOrGate: false, safeMode: false, muted: false, recentlyShown: false, terminal: true, quiet: false, screenDue: true,
      })
      expect(p.kind).toBe('pointer')
      // and it does not try again on the next scan (one attempt per 7 days)
      const second = await maybeFetchWeeklyOffer({ ...ctx, now: NOW_MS + 5000 }, gate, ['nextjs'], { fetchImpl: hang, timeoutMs: 100 })
      expect(second.attempted).toBe(false)
    } finally { cleanup() }
  })
})

describe('every recommendation object has exactly the spec keys, whatever the situation', () => {
  it('eligible, relay, kind, reason, sentence, next, mute', () => {
    const KEYS = ['eligible', 'kind', 'mute', 'next', 'reason', 'relay', 'sentence']
    const plans = [unavailableBlock('NOT_FETCHED'), unavailableBlock('PLAN_UNVERIFIED'), unavailableBlock('OFFLINE')]
    for (const plan of plans) for (const signedIn of [false, true]) for (const accountStatus of [null, 'none', 'active', 'pending', 'unsupported', 'lapsed'] as const) {
      for (const blocking of [false, true]) for (const detected of [stacks, []]) {
        const r = decideRecommendation({ plan, signedIn, accountStatus, detected, rulesApplied: 36, scanComplete: true, blocking, fallbackActive: false, ci: false, hookOrGate: false, safeMode: false, muted: false, recentlyShown: false })
        expect(Object.keys(r).sort(), JSON.stringify({ plan: plan.reason, signedIn, accountStatus, blocking })).toEqual(KEYS)
        expect(typeof r.eligible).toBe('boolean')
        expect(typeof r.relay).toBe('boolean')
        if (r.relay) expect(r.sentence).not.toBeNull()
        if (!r.eligible && r.kind === 'offer') throw new Error('an offer must be eligible')
      }
    }
    void NOW_S
  })
})
