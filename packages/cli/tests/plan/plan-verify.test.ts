/**
 * The signed plan block: every P0 vector gives the contract's answer through the REAL module, and every
 * failure is plain Free (unavailable + PLAN_UNVERIFIED), never a crash, never Pro.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  acctFromAccessToken, acctHash, cacheMaySkipRulebookCall, clearAccountCache, clientHelloHeaders, decideRulebookUse,
  fallbackApplies, isSignedLimitUsed, mapAccountPayload, newNonce, NONCE_PATTERN, readAccountCache, readAccountReply,
  verifyPlanDocument, writeAccountCache, unavailableBlock,
} from '../../src/core/plan.js'
import { injectTestKey, tempConfigDir, vector, vectorFile } from './helpers.js'

let cleanupKey: () => void
beforeAll(() => { cleanupKey = injectTestKey() })
afterAll(() => cleanupKey())

describe('every vector verifies as the contract says', () => {
  for (const v of vectorFile.vectors) {
    it(`${v.name} -> ${v.expect}`, async () => {
      const r = await verifyPlanDocument(v.kind, v.token, { now: v.ctx.now * 1000, acct: v.ctx.acct, nonce: v.ctx.nonce, scanId: v.ctx.scanId })
      expect(r.ok ? 'ok' : 'PLAN_UNVERIFIED').toBe(v.expect)
    })
  }
})

describe('rejection classes the plan names (explicit)', () => {
  const ctxOf = (name: string) => { const v = vector(name); return { now: v.ctx.now * 1000, acct: v.ctx.acct, nonce: v.ctx.nonce, scanId: v.ctx.scanId } }
  it('tampered, expired, replayed (nonce and scanId), wrong account all fail', async () => {
    for (const name of ['tampered-payload', 'bad-signature', 'expired', 'live-expired', 'live-issued-in-future', 'replayed-nonce', 'replayed-scanid', 'wrong-account', 'wrong-typ', 'offer-as-account', 'header-jku', 'header-crit', 'alg-none', 'unknown-kid', 'duplicate-key']) {
      const r = await verifyPlanDocument('account', vector(name).token, ctxOf(name))
      expect(r.ok, name).toBe(false)
    }
  })
  it('an account document with no signed-in account to bind to is refused (fail closed)', async () => {
    const v = vector('valid-live')
    expect((await verifyPlanDocument('account', v.token, { now: v.ctx.now * 1000, acct: null, nonce: v.ctx.nonce, scanId: v.ctx.scanId })).ok).toBe(false)
  })
  it('a live reply needs the nonce: a valid document with a different request nonce is a replay', async () => {
    const v = vector('valid-live')
    expect((await verifyPlanDocument('account', v.token, { now: v.ctx.now * 1000, acct: v.ctx.acct, nonce: newNonce(), scanId: v.ctx.scanId })).ok).toBe(false)
  })
  it('garbage input of every type never throws', async () => {
    for (const t of [undefined, null, 5, {}, [], '', '..', 'a.b.c', 'x'.repeat(70000), '\u0000.\u0000.\u0000']) {
      const r = await verifyPlanDocument('account', t, { now: Date.now(), acct: 'x', nonce: newNonce() })
      expect(r.ok).toBe(false)
    }
  })
  it('an unpinned key id and a placeholder-free keyring: the test key is refused once it is not injected', async () => {
    cleanupKey()
    try {
      const v = vector('valid-live')
      expect((await verifyPlanDocument('account', v.token, { now: v.ctx.now * 1000, acct: v.ctx.acct, nonce: v.ctx.nonce, scanId: v.ctx.scanId })).ok).toBe(false)
    } finally {
      cleanupKey = injectTestKey()
    }
  })
})

describe('readAccountReply: live documents', () => {
  const v = vector('valid-live')
  const req = { acct: v.ctx.acct, nonce: v.ctx.nonce!, scanId: v.ctx.scanId, now: v.ctx.now * 1000 }
  it('valid live reply is a live block mapped one to one, link built from the closed slot list', async () => {
    const r = await readAccountReply(v.token, req)
    expect(r.block.status).toBe('live')
    expect(r.block.reason).toBeNull()
    expect(r.block.command).toBe('shipguard status')
    expect(r.block.link).toBe('https://agenticcli.dev/go/pricing')
    expect(r.block.server?.account).toEqual({ status: 'active', text: 'Test account text.' })
    expect(r.block.server?.usage).toMatchObject({ percent: 40, state: 'ok', counted: true })
    expect(r.block.server?.updateNotice).toBeNull()
    expect(r.token).toBe(v.token)
  })
  it('no document in the reply (old server, no hello) = SERVER_NO_PLAN, no crash', async () => {
    for (const t of [undefined, null]) expect((await readAccountReply(t, req)).block).toEqual(unavailableBlock('SERVER_NO_PLAN'))
  })
  it('tampered / replayed / wrong-account / garbage = PLAN_UNVERIFIED and no token to cache', async () => {
    for (const name of ['tampered-payload', 'replayed-nonce', 'wrong-account']) {
      const r = await readAccountReply(vector(name).token, req)
      expect(r.block).toEqual(unavailableBlock('PLAN_UNVERIFIED'))
      expect(r.token).toBeNull()
    }
    expect((await readAccountReply(12345, req)).block.reason).toBe('PLAN_UNVERIFIED')
  })
  it('unknown account status is kept as unsupported, never as none', async () => {
    const u = vector('valid-unknown-status')
    const r = await readAccountReply(u.token, { acct: u.ctx.acct, nonce: u.ctx.nonce!, scanId: u.ctx.scanId, now: u.ctx.now * 1000 })
    expect(r.block.server?.account?.status).toBe('unsupported')
  })
  it('the update notice is carried as safe text', async () => {
    const u = vector('valid-update-notice')
    const r = await readAccountReply(u.token, { acct: u.ctx.acct, nonce: u.ctx.nonce!, scanId: u.ctx.scanId, now: u.ctx.now * 1000 })
    expect(typeof r.block.server?.updateNotice).toBe('string')
    expect(r.block.server?.updateNotice).not.toMatch(/[\u001b]/)
  })
  it('only the signed used state may soften a --pro run (live + usage used + the server code)', async () => {
    const used = vector('valid-used')
    const live = await readAccountReply(used.token, { acct: used.ctx.acct, nonce: used.ctx.nonce!, scanId: used.ctx.scanId, now: used.ctx.now * 1000 })
    expect(live.block.server?.usage?.state).toBe('used')
    expect(isSignedLimitUsed(live.block, 'ALLOWANCE_USED')).toBe(true)
    expect(isSignedLimitUsed(live.block, 'RATE_LIMITED')).toBe(false)
    expect(isSignedLimitUsed(live.block, null)).toBe(false)
    expect(isSignedLimitUsed({ ...live.block, status: 'cached', reason: 'OFFLINE' }, 'ALLOWANCE_USED')).toBe(false)
    expect(isSignedLimitUsed(unavailableBlock('PLAN_UNVERIFIED'), 'ALLOWANCE_USED')).toBe(false)
  })
})

describe('account cache (re-verified on every read)', () => {
  const v = vector('valid-cached')
  const now = v.ctx.now * 1000
  it('round trip: written 0600 in a 0700 folder, read back as cached', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      expect(writeAccountCache(dir, v.token)).toBe(true)
      const file = join(dir, 'account.jws')
      if (process.platform !== 'win32') {
        const { statSync } = await import('node:fs')
        expect(statSync(file).mode & 0o777).toBe(0o600)
        expect(statSync(dir).mode & 0o777).toBe(0o700)
      }
      const r = await readAccountCache(dir, { acct: v.ctx.acct, now })
      expect(r.block.status).toBe('cached')
      expect(r.block.server?.account?.status).toBe('active')
    } finally { cleanup() }
  })
  it('nothing cached = NOT_FETCHED; safe mode / API-key mode write nothing', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      expect((await readAccountCache(dir, { acct: v.ctx.acct, now })).block.reason).toBe('NOT_FETCHED')
      expect(writeAccountCache(dir, v.token, { noWrite: true })).toBe(false)
      expect(existsSync(join(dir, 'account.jws'))).toBe(false)
    } finally { cleanup() }
  })
  it('a planted or edited file = PLAN_UNVERIFIED; another account = PLAN_UNVERIFIED; the file is never trusted blindly', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      writeAccountCache(dir, v.token)
      const file = join(dir, 'account.jws')
      writeFileSync(file, vector('tampered-payload').token, { mode: 0o600 })
      expect((await readAccountCache(dir, { acct: v.ctx.acct, now })).block.reason).toBe('PLAN_UNVERIFIED')
      writeFileSync(file, v.token, { mode: 0o600 })
      expect((await readAccountCache(dir, { acct: acctHash('someone-else'), now })).block.reason).toBe('PLAN_UNVERIFIED')
      writeFileSync(file, 'not a token', { mode: 0o600 })
      expect((await readAccountCache(dir, { acct: v.ctx.acct, now })).block.reason).toBe('PLAN_UNVERIFIED')
    } finally { cleanup() }
  })
  it('a group-readable file is refused (like the credentials file)', async () => {
    if (process.platform === 'win32') return
    const { dir, cleanup } = tempConfigDir()
    try {
      writeAccountCache(dir, v.token)
      chmodSync(join(dir, 'account.jws'), 0o644)
      expect((await readAccountCache(dir, { acct: v.ctx.acct, now })).block.reason).toBe('PLAN_UNVERIFIED')
    } finally { cleanup() }
  })
  it('an otherwise valid copy that has aged out is simply no cache (no warning), a clock jump back is not trusted', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      writeAccountCache(dir, v.token)
      expect((await readAccountCache(dir, { acct: v.ctx.acct, now: now + 10 * 86400 * 1000 })).block.reason).toBe('NOT_FETCHED')
      expect((await readAccountCache(dir, { acct: v.ctx.acct, now: now - 3 * 3600 * 1000 })).block.reason).toBe('PLAN_UNVERIFIED')
    } finally { cleanup() }
  })
  it('clearAccountCache removes it and a missing file is fine', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      writeAccountCache(dir, v.token)
      clearAccountCache(dir)
      clearAccountCache(dir)
      expect(existsSync(join(dir, 'account.jws'))).toBe(false)
    } finally { cleanup() }
  })
  it('hostile file contents never crash a read', async () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      writeAccountCache(dir, 'x')
      writeFileSync(join(dir, 'account.jws'), Buffer.alloc(100000, 7), { mode: 0o600 })
      expect((await readAccountCache(dir, { acct: v.ctx.acct, now })).block.reason).toBe('PLAN_UNVERIFIED')
      expect(readFileSync(join(dir, 'account.jws')).length).toBe(100000)
    } finally { cleanup() }
  })
})

describe('hello, nonce, account binding', () => {
  it('nonce is 22 base64url characters and unique', () => {
    const a = newNonce(), b = newNonce()
    expect(a).toMatch(NONCE_PATTERN)
    expect(a).not.toBe(b)
  })
  it('hello header names the bundle protocol; the nonce header only when given', () => {
    expect(clientHelloHeaders('9.9.9')).toEqual({ 'X-ShipGuard-Client': 'shipguard/9.9.9; bundle-protocol=2' })
    expect(clientHelloHeaders('9.9.9', 'n')['X-ShipGuard-Nonce']).toBe('n')
  })
  it('acctHash is the contract value and acctFromAccessToken reads sub only', () => {
    const payload = Buffer.from(JSON.stringify({ sub: 'user_1' })).toString('base64url')
    expect(acctFromAccessToken(`h.${payload}.s`)).toBe(acctHash('user_1'))
    for (const t of [undefined, 'x', 'a.b.c', `h.${Buffer.from('{}').toString('base64url')}.s`]) expect(acctFromAccessToken(t)).toBeNull()
  })
})

describe('mapAccountPayload never invents a value', () => {
  const base = { dv: 1, iss: 'agenticcli.dev', aud: 'shipguard-cli', acct: 'a', iat: 1795000000, exp: 1795086400 }
  it('missing fields stay null; refreshAfter is clamped; bad usage is dropped; unknown states are safe', () => {
    const s = mapAccountPayload({ ...base })
    expect(s).toMatchObject({ label: null, account: null, usage: null, limit: null, capabilities: null, refreshAfter: null, updateNotice: null, proAdds: null, offer: null })
    expect(mapAccountPayload({ ...base, refreshAfter: 1 }).refreshAfter).toBe(60)
    expect(mapAccountPayload({ ...base, refreshAfter: 99999999 }).refreshAfter).toBe(21600)
    expect(mapAccountPayload({ ...base, usage: { percent: 101, state: 'ok' } }).usage).toBeNull()
    expect(mapAccountPayload({ ...base, usage: { percent: 5.5, state: 'ok' } }).usage).toBeNull()
    expect(mapAccountPayload({ ...base, usage: { percent: 50, state: 'weird' } }).usage?.state).toBe('ok')
    expect(mapAccountPayload({ ...base, account: { status: 'martian' } }).account?.status).toBe('unsupported')
  })
  it('server text is sanitized and an unknown slot becomes the pricing link slot', () => {
    const s = mapAccountPayload({ ...base, label: 'Pro\u001b[31m', offer: { text: 'Go https://evil.example now', slot: 'not-a-slot' } })
    expect(s.label).toBe('Pro')
    expect(s.offer).toEqual({ text: 'Go now', slot: 'pricing' })
  })
})

describe('--pro decisions', () => {
  const live = unavailableBlock('NOT_FETCHED')
  const base = { signedIn: true, explicitPro: true, allowDegraded: false, plan: live }
  it('explicit --pro with no signed reply exits 3 for every cause; --allow-degraded runs general rules', () => {
    for (const code of ['RULEBOOK_WITHHELD', 'RULEBOOK_UNREACHABLE', 'RULEBOOK_PARTIAL', 'PLAN_INACTIVE'] as const) {
      expect(decideRulebookUse({ ...base, cause: { code } })).toEqual({ action: 'exit-3', code })
      expect(decideRulebookUse({ ...base, allowDegraded: true, cause: { code } })).toMatchObject({ action: 'run-general', code })
    }
  })
  it('an UNSIGNED allowance-used refusal can only make --pro stricter', () => {
    expect(decideRulebookUse({ ...base, cause: { code: 'RULEBOOK_WITHHELD', serverCode: 'ALLOWANCE_USED' } })).toEqual({ action: 'exit-3', code: 'RULEBOOK_WITHHELD' })
  })
  it('a plain scan never exits 3 for a rulebook cause; signed out + --pro = LOGIN_REQUIRED', () => {
    expect(decideRulebookUse({ ...base, explicitPro: false, cause: { code: 'RULEBOOK_UNREACHABLE' } })).toMatchObject({ action: 'run-general' })
    expect(decideRulebookUse({ ...base, explicitPro: false, cause: null })).toEqual({ action: 'run-rulebook' })
    expect(decideRulebookUse({ ...base, signedIn: false, cause: null })).toEqual({ action: 'exit-3', code: 'LOGIN_REQUIRED' })
    expect(decideRulebookUse({ ...base, signedIn: false, explicitPro: false, cause: null })).toEqual({ action: 'plain-free' })
  })
  it('fallback applies only to a paying account (or lapsed for PLAN_INACTIVE); none/pending/unsupported/unknown are plain Free', () => {
    for (const s of ['active', 'trialing', 'past_due', 'ending'] as const) expect(fallbackApplies('RULEBOOK_UNREACHABLE', s)).toBe(true)
    for (const s of ['none', 'pending', 'unsupported', 'lapsed', null] as const) expect(fallbackApplies('RULEBOOK_UNREACHABLE', s)).toBe(false)
    expect(fallbackApplies('PLAN_INACTIVE', 'lapsed')).toBe(true)
    expect(fallbackApplies('PLAN_INACTIVE', 'none')).toBe(false)
  })
})

describe('cache may skip a rulebook call only for a verified fresh block that says so', () => {
  const mk = (over: Record<string, unknown>) => {
    const server = { fetchedAt: new Date(1000000).toISOString(), validUntil: new Date(9e9).toISOString(), label: null, account: { status: 'active', text: null }, usage: null, limit: null, capabilities: { rulebookDefault: false, rulebookTiers: [] }, refreshAfter: 600, updateNotice: null, proAdds: null, offer: null, ...over }
    return { status: 'cached', reason: null, command: 'shipguard status', link: null, server } as never
  }
  it('skips inside refreshAfter with rulebookDefault false, and never with --pro or an account without a plan', () => {
    expect(cacheMaySkipRulebookCall(mk({}), 1000000 + 1000, { explicitPro: false })).toBe(true)
    expect(cacheMaySkipRulebookCall(mk({}), 1000000 + 1000, { explicitPro: true })).toBe(false)
    expect(cacheMaySkipRulebookCall(mk({}), 1000000 + 601000, { explicitPro: false })).toBe(false)
    expect(cacheMaySkipRulebookCall(mk({ capabilities: { rulebookDefault: true, rulebookTiers: [] } }), 1000000, { explicitPro: false })).toBe(false)
    expect(cacheMaySkipRulebookCall(mk({ capabilities: null }), 1000000, { explicitPro: false })).toBe(false)
    for (const status of ['none', 'pending', 'lapsed', 'unsupported']) expect(cacheMaySkipRulebookCall(mk({ account: { status, text: null } }), 1000000, { explicitPro: false })).toBe(false)
    expect(cacheMaySkipRulebookCall(unavailableBlock('NOT_FETCHED'), 1000000, { explicitPro: false })).toBe(false)
  })
})
