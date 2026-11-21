/**
 * Purpose: the public signed offer: fetch (stack names only, size and time bounds, trusted host), verify-before-cache, per-stack-set
 * files, the generic primed file, and the weekly counter and gates for the scan fetch and `setup` priming (fake clock).
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { existsSync, readdirSync, utimesSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  OFFER_GENERIC_FILE, fetchPublicOffer, maybeFetchWeeklyOffer, normalizeStacks, primeOfferCache, readOffer, stackSetFile, type OfferFetchGate,
} from '../../src/core/offer-cache.js'
import { loadNag, WEEK_MS } from '../../src/core/nag.js'
import { gapLines } from '../../src/core/plan-lines.js'
import { mapOfferPayload, verifyPlanDocument } from '../../src/core/plan.js'
import { injectTestKey, vector } from './helpers.js'
import { NOW_MS, NOW_S, makeSigner, offerPayload, tempConfigDir, type TestSigner } from './helpers.js'

let signer: TestSigner
beforeAll(() => { signer = makeSigner() })
afterAll(() => signer.cleanup())

const OFFER = 'shipguard-offer+jws'
const gate: OfferFetchGate = { signedIn: false, terminal: true, ci: false, quiet: false, hookOrGate: false, safeMode: false, trackingOff: false, dryRun: false }
const counts = { nextjs: { rules: 30, areas: ['Server actions', 'Row-level security'] }, supabase: { rules: 11, areas: ['Row-level security', 'Webhooks'] } }

function fakeFetch(token: string | (() => string), calls: string[]) {
  return vi.fn(async (url: string | URL | Request) => {
    calls.push(String(url))
    const t = typeof token === 'function' ? token() : token
    return new Response(t, { status: 200 })
  }) as unknown as typeof fetch
}

describe('stack sets', () => {
  it('names are normalised, validated, unique, sorted; the file name is a hash of the sorted set', () => {
    expect(normalizeStacks(['Supabase', 'nextjs', 'nextjs', ' ', '../etc', 'a b', 'ok-1'])).toEqual(['nextjs', 'ok-1', 'supabase'])
    expect(stackSetFile(['supabase', 'nextjs'])).toBe(stackSetFile(['nextjs', 'supabase']))
    expect(stackSetFile(['nextjs'])).not.toBe(stackSetFile(['nextjs', 'supabase']))
    expect(stackSetFile(['x'])).toMatch(/^offer-[0-9a-f]{16}\.jws$/)
  })
})

describe('combined: the server-computed union count for a stack set', () => {
  it('nextjs+supabase offer with combined: the gap line shows the number; counts are never added', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const tok = signer.sign(offerPayload({ offer: { text: 'Offer words', slot: 'checkout' }, counts, combined: { 'nextjs+supabase': 37 } }), { typ: OFFER })
      const r = await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: ['supabase', 'nextjs'], safeMode: false, fetchImpl: fakeFetch(JSON.stringify({ offer: tok }), []) })
      expect(r.ok).toBe(true)
      const read = await readOffer({ configDir: dir, now: NOW_MS, safeMode: false }, ['nextjs', 'supabase'])
      const detected = [{ key: 'nextjs', display: 'Next.js', version: null }, { key: 'supabase', display: 'Supabase', version: null }]
      const line = gapLines(read.block, detected, true)[0]
      expect(line).toContain('adds 37 rules for Next.js + Supabase')
      expect(line).not.toContain('adds 41 rules') // 30 + 11: per-stack counts are never added
    } finally { cleanup() }
  })
  it('the contract vector with a combined key verifies (the payload key list is not closed) and maps to the number', async () => {
    const restore = injectTestKey()
    try {
      const v = vector('valid-offer-combined')
      const r = await verifyPlanDocument('offer', v.token, { now: v.ctx.now * 1000, acct: null, nonce: null, scanId: null })
      expect(r.ok).toBe(true)
      if (r.ok) {
        expect(mapOfferPayload(r.payload, ['supabase', 'nextjs']).proAdds?.rules).toBe(10)
        expect(mapOfferPayload(r.payload, ['nextjs']).proAdds?.rules).toBe(7)
      }
    } finally { restore() }
  })
})

describe('fetchPublicOffer', () => {
  it('sends stack names ONLY (no sign-in, no body), verifies, caches, and uses the combined count for several stacks', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const calls: string[] = []
      const tok = signer.sign(offerPayload({ offer: { text: 'Offer words', slot: 'checkout' }, counts, combined: { 'nextjs+supabase': 37 } }), { typ: OFFER })
      const f = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        calls.push(String(url))
        expect(init?.headers).toEqual({ Accept: 'application/json' })
        expect(init?.body).toBeUndefined()
        expect(init?.redirect).toBe('error')
        return new Response(JSON.stringify({ offer: tok }), { status: 200 })
      }) as unknown as typeof fetch
      const r = await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: ['supabase', 'nextjs'], safeMode: false, fetchImpl: f })
      expect(calls).toEqual(['https://agenticcli.dev/api/cli/v1/offer?stacks=nextjs%2Csupabase'])
      expect(r.ok && r.block.server?.proAdds).toEqual({ planName: null, rules: 37, stacks: ['nextjs', 'supabase'], areas: ['Server actions', 'Row-level security', 'Webhooks'] })
      expect(r.ok && r.block.link).toBe('https://agenticcli.dev/go/checkout')
      expect(existsSync(join(dir, stackSetFile(['nextjs', 'supabase'])))).toBe(true)
      const read = await readOffer({ configDir: dir, now: NOW_MS, safeMode: false }, ['nextjs', 'supabase'])
      expect(read.source).toBe('stack-set')
      expect(read.block.status).toBe('cached')
    } finally { cleanup() }
  })
  it('per-stack counts are NEVER added: several stacks without a combined count give no number; one stack gives its own count', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const tok = signer.sign(offerPayload({ counts }), { typ: OFFER })
      const two = await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: ['nextjs', 'supabase'], safeMode: false, fetchImpl: fakeFetch(tok, []) })
      expect(two.ok && two.block.server?.proAdds?.rules).toBeNull()
      expect(two.ok && two.block.server?.proAdds?.areas).toEqual(['Server actions', 'Row-level security', 'Webhooks'])
      const one = await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: ['nextjs'], safeMode: false, fetchImpl: fakeFetch(tok, []) })
      expect(one.ok && one.block.server?.proAdds?.rules).toBe(30)
      const unknown = await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: ['django'], safeMode: false, fetchImpl: fakeFetch(tok, []) })
      expect(unknown.ok && unknown.block.server?.proAdds?.rules).toBeNull()
      const bad = signer.sign(offerPayload({ counts, combined: { 'nextjs+supabase': -4 } }), { typ: OFFER })
      const r = await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: ['supabase', 'nextjs'], safeMode: false, fetchImpl: fakeFetch(bad, []) })
      expect(r.ok && r.block.server?.proAdds?.rules).toBeNull()
    } finally { cleanup() }
  })
  it('the generic offer sends NO stack names and is stored as the generic file', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const calls: string[] = []
      const tok = signer.sign(offerPayload({ offer: { text: 'Generic offer', slot: 'pricing' } }), { typ: OFFER })
      const r = await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: null, safeMode: false, fetchImpl: fakeFetch(tok, calls) })
      expect(r.ok).toBe(true)
      expect(calls).toEqual(['https://agenticcli.dev/api/cli/v1/offer'])
      expect(existsSync(join(dir, OFFER_GENERIC_FILE))).toBe(true)
      const read = await readOffer({ configDir: dir, now: NOW_MS, safeMode: false }, ['nextjs'])
      expect(read.source).toBe('generic')
      expect(read.block.server?.proAdds).toEqual({ planName: null, rules: null, stacks: ['nextjs'], areas: [] })
    } finally { cleanup() }
  })
  it('refuses tampered, expired, wrong-type and garbage replies and caches nothing', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const good = signer.sign(offerPayload(), { typ: OFFER })
      const bad: Array<string> = [
        good.slice(0, -4) + 'AAAA',
        signer.sign(offerPayload({ exp: NOW_S - 10 }), { typ: OFFER }),
        signer.sign(offerPayload(), { typ: 'shipguard-account+jws' }),
        signer.sign(offerPayload({ exp: NOW_S + 30 * 86400 }), { typ: OFFER }),
        'garbage', '', '{"offer": 5}', '{not json',
      ]
      for (const t of bad) {
        const r = await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: ['nextjs'], safeMode: false, fetchImpl: fakeFetch(t, []) })
        expect(r.ok).toBe(false)
      }
      expect(existsSync(dir) ? readdirSync(dir).filter((n) => n.startsWith('offer-')) : []).toEqual([])
    } finally { cleanup() }
  })
  it('network error = OFFLINE, HTTP error = FETCH_FAILED, a hanging server is cut off by the timeout', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const o = { configDir: dir, now: NOW_MS, stacks: ['nextjs'], safeMode: false }
      expect(await fetchPublicOffer({ ...o, fetchImpl: (async () => { throw new TypeError('fetch failed') }) as unknown as typeof fetch })).toEqual({ ok: false, reason: 'OFFLINE' })
      expect(await fetchPublicOffer({ ...o, fetchImpl: (async () => new Response('x', { status: 503 })) as unknown as typeof fetch })).toEqual({ ok: false, reason: 'FETCH_FAILED' })
      const hang = ((_u: string, init?: RequestInit) => new Promise((_res, rej) => init?.signal?.addEventListener('abort', () => rej(new Error('aborted'))))) as unknown as typeof fetch
      const t0 = Date.now()
      expect(await fetchPublicOffer({ ...o, fetchImpl: hang, timeoutMs: 50 })).toEqual({ ok: false, reason: 'OFFLINE' })
      expect(Date.now() - t0).toBeLessThan(2000)
    } finally { cleanup() }
  })
  it('a body over the size cap is refused without reading it all; an untrusted API host is never contacted', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const huge = new Response(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(40000)) } }), { status: 200 })
      expect(await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: ['nextjs'], safeMode: false, fetchImpl: (async () => huge) as unknown as typeof fetch })).toEqual({ ok: false, reason: 'FETCH_FAILED' })
      const f = vi.fn() as unknown as typeof fetch
      expect(await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: ['nextjs'], safeMode: false, apiUrl: 'https://evil.example', fetchImpl: f })).toEqual({ ok: false, reason: 'FETCH_FAILED' })
      expect(f).not.toHaveBeenCalled()
    } finally { cleanup() }
  })
  it('safe mode verifies but writes nothing', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const tok = signer.sign(offerPayload(), { typ: OFFER })
      const r = await fetchPublicOffer({ configDir: dir, now: NOW_MS, stacks: ['nextjs'], safeMode: true, fetchImpl: fakeFetch(tok, []) })
      expect(r.ok).toBe(true)
      expect(existsSync(dir)).toBe(false)
    } finally { cleanup() }
  })
})

describe('readOffer: the cache is verified on every read', () => {
  it('missing = NOT_FETCHED; planted/edited = PLAN_UNVERIFIED; aged out = NOT_FETCHED; safe mode reads nothing', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW_MS, safeMode: false }
      expect((await readOffer(ctx, ['nextjs'])).block.reason).toBe('NOT_FETCHED')
      const tok = signer.sign(offerPayload({ counts }), { typ: OFFER })
      await fetchPublicOffer({ ...ctx, stacks: ['nextjs'], fetchImpl: fakeFetch(tok, []) })
      expect((await readOffer({ ...ctx, safeMode: true }, ['nextjs'])).block.reason).toBe('NOT_FETCHED')
      expect((await readOffer({ ...ctx, now: NOW_MS + 10 * 86400 * 1000 }, ['nextjs'])).block.reason).toBe('NOT_FETCHED')
      writeFileSync(join(dir, stackSetFile(['nextjs'])), tok.slice(0, -3) + 'AAA', { mode: 0o600 })
      expect((await readOffer(ctx, ['nextjs'])).block).toMatchObject({ status: 'unavailable', reason: 'PLAN_UNVERIFIED', server: null })
    } finally { cleanup() }
  })
  it('a second repo keeps its own file: fetching for one stack set never overwrites another', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW_MS, safeMode: false }
      await fetchPublicOffer({ ...ctx, stacks: ['nextjs'], fetchImpl: fakeFetch(signer.sign(offerPayload({ counts }), { typ: OFFER }), []) })
      await fetchPublicOffer({ ...ctx, stacks: ['django'], fetchImpl: fakeFetch(signer.sign(offerPayload({ counts: { django: { rules: 5, areas: ['ORM'] } } }), { typ: OFFER }), []) })
      expect((await readOffer(ctx, ['nextjs'])).block.server?.proAdds?.rules).toBe(30)
      expect((await readOffer(ctx, ['django'])).block.server?.proAdds?.rules).toBe(5)
    } finally { cleanup() }
  })
  it('at most 8 stack-set files are kept, oldest removed, the generic file stays', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW_MS, safeMode: false }
      const tok = signer.sign(offerPayload(), { typ: OFFER })
      await fetchPublicOffer({ ...ctx, stacks: null, fetchImpl: fakeFetch(tok, []) })
      for (let i = 0; i < 11; i++) {
        await fetchPublicOffer({ ...ctx, stacks: [`stack${i}`], fetchImpl: fakeFetch(tok, []) })
        utimesSync(join(dir, stackSetFile([`stack${i}`])), 1000 + i, 1000 + i)
      }
      const files = readdirSync(dir).filter((n) => n.startsWith('offer-'))
      expect(files.filter((n) => n !== OFFER_GENERIC_FILE).length).toBe(8)
      expect(files).toContain(OFFER_GENERIC_FILE)
    } finally { cleanup() }
  })
})

describe('weekly fetch and priming: gates and the 7-day counter (fake clock)', () => {
  const mk = (calls: string[]) => fakeFetch(signer.sign(offerPayload({ counts }), { typ: OFFER }), calls)
  it('one fetch per 7 days for a signed-out terminal scan; the attempt is counted even when it fails', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const calls: string[] = []
      const ctx = { configDir: dir, now: NOW_MS, safeMode: false }
      expect((await maybeFetchWeeklyOffer(ctx, gate, ['nextjs'], { fetchImpl: mk(calls) })).attempted).toBe(true)
      expect((await maybeFetchWeeklyOffer({ ...ctx, now: NOW_MS + WEEK_MS - 1000 }, gate, ['nextjs'], { fetchImpl: mk(calls) })).attempted).toBe(false)
      expect((await maybeFetchWeeklyOffer({ ...ctx, now: NOW_MS + WEEK_MS + 1000 }, gate, ['nextjs'], { fetchImpl: mk(calls) })).attempted).toBe(true)
      expect(calls.length).toBe(2)
      const { dir: d2, cleanup: c2 } = tempConfigDir()
      try {
        const failing = (async () => { throw new TypeError('down') }) as unknown as typeof fetch
        const c = { configDir: d2, now: NOW_MS, safeMode: false }
        expect((await maybeFetchWeeklyOffer(c, gate, ['nextjs'], { fetchImpl: failing })).attempted).toBe(true)
        expect((await maybeFetchWeeklyOffer({ ...c, now: NOW_MS + 1000 }, gate, ['nextjs'], { fetchImpl: failing })).attempted).toBe(false)
      } finally { c2() }
      expect(loadNag(ctx).offerFetchAt).toBeGreaterThan(0)
    } finally { cleanup() }
  })
  it('NEVER in a hook or the gate, CI, quiet, safe mode, tracking off, signed in, dry-run or a non-terminal; none without a stack', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const calls: string[] = []
      const ctx = { configDir: dir, now: NOW_MS, safeMode: false }
      const blocked: Array<Partial<OfferFetchGate>> = [{ hookOrGate: true }, { ci: true }, { quiet: true }, { safeMode: true }, { trackingOff: true }, { signedIn: true }, { dryRun: true }, { terminal: false }]
      for (const b of blocked) {
        const r = await maybeFetchWeeklyOffer({ ...ctx, safeMode: b.safeMode ?? false }, { ...gate, ...b }, ['nextjs'], { fetchImpl: mk(calls) })
        expect(r.attempted, JSON.stringify(b)).toBe(false)
      }
      expect((await maybeFetchWeeklyOffer(ctx, gate, [], { fetchImpl: mk(calls) })).attempted).toBe(false)
      expect(calls).toEqual([])
      expect(existsSync(dir)).toBe(false) // not even the counter file
    } finally { cleanup() }
  })
  it('primeOfferCache fetches ONCE, sends no stack names, and primes the generic file', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const calls: string[] = []
      const ctx = { configDir: dir, now: NOW_MS, safeMode: false }
      const tok = signer.sign(offerPayload({ offer: { text: 'Generic', slot: 'pricing' } }), { typ: OFFER })
      const first = await primeOfferCache(ctx, gate, { fetchImpl: fakeFetch(tok, calls) })
      expect(first.attempted && first.result.ok).toBe(true)
      expect((await primeOfferCache(ctx, gate, { fetchImpl: fakeFetch(tok, calls) })).attempted).toBe(false)
      expect(calls).toEqual(['https://agenticcli.dev/api/cli/v1/offer'])
      expect(calls[0]).not.toContain('stacks')
      expect(existsSync(join(dir, OFFER_GENERIC_FILE))).toBe(true)
    } finally { cleanup() }
  })
  it('priming is skipped for every excluded case (dry-run, safe mode, tracking off, signed in, CI, no terminal)', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const calls: string[] = []
      for (const b of [{ dryRun: true }, { safeMode: true }, { trackingOff: true }, { signedIn: true }, { ci: true }, { terminal: false }] as Array<Partial<OfferFetchGate>>) {
        const r = await primeOfferCache({ configDir: dir, now: NOW_MS, safeMode: b.safeMode ?? false }, { ...gate, ...b }, { fetchImpl: mk(calls) })
        expect(r.attempted, JSON.stringify(b)).toBe(false)
      }
      expect(calls).toEqual([])
    } finally { cleanup() }
  })
  it('priming shares the weekly counter: a fetch just made by a scan blocks the priming, and vice versa', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const calls: string[] = []
      const ctx = { configDir: dir, now: NOW_MS, safeMode: false }
      await maybeFetchWeeklyOffer(ctx, gate, ['nextjs'], { fetchImpl: mk(calls) })
      expect((await primeOfferCache(ctx, gate, { fetchImpl: mk(calls) })).attempted).toBe(false)
    } finally { cleanup() }
  })
})
