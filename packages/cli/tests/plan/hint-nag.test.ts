import { describe, expect, it } from 'vitest'
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { clearHint, hintSkipsCall, writeHint, HINT_MAX_TTL_MS } from '../../src/core/hint.js'
import {
  DAY_MS, WEEK_MS, isMuted, lastAccountStatus, loadNag, markMoment, markOfferFetch, momentDue, offerFetchDue, recordAccountStatus,
  repoKey, setMuted,
} from '../../src/core/nag.js'
import { tempConfigDir } from './helpers.js'

const NOW = 1_800_000_000_000
const open = { explicitPro: false, ci: false, apiKeyMode: false }

describe('hint file', () => {
  it('a hint for this account skips the call, for at most one hour', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW, safeMode: false }
      expect(writeHint(ctx, 'acct-1')).toBe(true)
      expect(hintSkipsCall(ctx, 'acct-1', open)).toBe(true)
      expect(hintSkipsCall({ ...ctx, now: NOW + HINT_MAX_TTL_MS - 1 }, 'acct-1', open)).toBe(true)
      expect(hintSkipsCall({ ...ctx, now: NOW + HINT_MAX_TTL_MS + 1 }, 'acct-1', open)).toBe(false)
    } finally { cleanup() }
  })
  it('TTL is clamped to one hour on write and refused above one hour on read', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW, safeMode: false }
      writeHint(ctx, 'acct-1', 10 * HINT_MAX_TTL_MS)
      expect(JSON.parse(readFileSync(join(dir, 'hint.json'), 'utf8')).until - NOW).toBe(HINT_MAX_TTL_MS)
      writeFileSync(join(dir, 'hint.json'), JSON.stringify({ v: 1, acct: 'acct-1', at: NOW, until: NOW + 5 * HINT_MAX_TTL_MS }), { mode: 0o600 })
      expect(hintSkipsCall(ctx, 'acct-1', open)).toBe(false)
    } finally { cleanup() }
  })
  it('is bound to the account and ignored with --pro, CI, API-key mode and for no account', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW, safeMode: false }
      writeHint(ctx, 'acct-1')
      expect(hintSkipsCall(ctx, 'acct-2', open)).toBe(false)
      expect(hintSkipsCall(ctx, null, open)).toBe(false)
      expect(hintSkipsCall(ctx, 'acct-1', { ...open, explicitPro: true })).toBe(false)
      expect(hintSkipsCall(ctx, 'acct-1', { ...open, ci: true })).toBe(false)
      expect(hintSkipsCall(ctx, 'acct-1', { ...open, apiKeyMode: true })).toBe(false)
    } finally { cleanup() }
  })
  it('safe mode neither writes nor reads it', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      expect(writeHint({ configDir: dir, now: NOW, safeMode: true }, 'acct-1')).toBe(false)
      expect(existsSync(join(dir, 'hint.json'))).toBe(false)
      writeHint({ configDir: dir, now: NOW, safeMode: false }, 'acct-1')
      expect(hintSkipsCall({ configDir: dir, now: NOW, safeMode: true }, 'acct-1', open)).toBe(false)
    } finally { cleanup() }
  })
  it('clear removes it; junk, a future start and a group-readable file are refused; it holds no plan data', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW, safeMode: false }
      writeHint(ctx, 'acct-1')
      expect(Object.keys(JSON.parse(readFileSync(join(dir, 'hint.json'), 'utf8'))).sort()).toEqual(['acct', 'at', 'until', 'v'])
      if (process.platform !== 'win32') {
        chmodSync(join(dir, 'hint.json'), 0o644)
        expect(hintSkipsCall(ctx, 'acct-1', open)).toBe(false)
      }
      writeFileSync(join(dir, 'hint.json'), '{not json', { mode: 0o600 })
      expect(hintSkipsCall(ctx, 'acct-1', open)).toBe(false)
      writeFileSync(join(dir, 'hint.json'), JSON.stringify({ v: 1, acct: 'acct-1', at: NOW + 86400000, until: NOW + 86400000 + 1000 }), { mode: 0o600 })
      expect(hintSkipsCall(ctx, 'acct-1', open)).toBe(false)
      clearHint(dir)
      clearHint(dir)
      expect(existsSync(join(dir, 'hint.json'))).toBe(false)
    } finally { cleanup() }
  })
})

describe('nag counters', () => {
  it('the screen pitch is due once per week per repo, and repos are independent', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW, safeMode: false }
      const a = repoKey('/work/a'), b = repoKey('/work/b')
      expect(momentDue(loadNag(ctx), 'screenPitch', a, NOW)).toBe(true)
      markMoment(ctx, 'screenPitch', a)
      expect(momentDue(loadNag(ctx), 'screenPitch', a, NOW + WEEK_MS - 1)).toBe(false)
      expect(momentDue(loadNag(ctx), 'screenPitch', a, NOW + WEEK_MS)).toBe(true)
      expect(momentDue(loadNag(ctx), 'screenPitch', b, NOW)).toBe(true)
      expect(momentDue(loadNag(ctx), 'jsonPitch', a, NOW)).toBe(true) // a JSON read never uses up what a person would see
    } finally { cleanup() }
  })
  it('the usage notice is once per day per account; the receipt once per account, screen and JSON separately', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW, safeMode: false }
      markMoment(ctx, 'usageScreen', 'acct')
      expect(momentDue(loadNag(ctx), 'usageScreen', 'acct', NOW + DAY_MS - 1)).toBe(false)
      expect(momentDue(loadNag(ctx), 'usageScreen', 'acct', NOW + DAY_MS)).toBe(true)
      expect(momentDue(loadNag(ctx), 'usageJson', 'acct', NOW)).toBe(true)
      markMoment(ctx, 'receiptShown', 'acct')
      expect(momentDue(loadNag(ctx), 'receiptShown', 'acct', NOW + 400 * DAY_MS)).toBe(false)
      expect(momentDue(loadNag(ctx), 'receiptJson', 'acct', NOW)).toBe(true)
    } finally { cleanup() }
  })
  it('a stored time far in the future cannot silence a moment for long', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW + 100 * DAY_MS, safeMode: false }
      markMoment(ctx, 'screenPitch', 'x')
      expect(momentDue(loadNag(ctx), 'screenPitch', 'x', NOW)).toBe(true)
    } finally { cleanup() }
  })
  it('mute: file and environment; unmute reverses the file', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW, safeMode: false }
      expect(isMuted(loadNag(ctx), {})).toBe(false)
      expect(isMuted(loadNag(ctx), { SHIPGUARD_NO_PROMO: '1' })).toBe(true)
      setMuted(ctx, true)
      expect(isMuted(loadNag(ctx), {})).toBe(true)
      setMuted(ctx, false)
      expect(isMuted(loadNag(ctx), {})).toBe(false)
    } finally { cleanup() }
  })
  it('last verified account status is kept per account, ignores unknown values, and is never the account id in clear', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW, safeMode: false }
      recordAccountStatus(ctx, 'acct-hash', 'active')
      expect(lastAccountStatus(loadNag(ctx), 'acct-hash')).toBe('active')
      expect(lastAccountStatus(loadNag(ctx), 'other')).toBeNull()
      const raw = JSON.parse(readFileSync(join(dir, 'nag.json'), 'utf8'))
      raw.accounts['acct-hash'].lastAccountStatus = 'martian'
      writeFileSync(join(dir, 'nag.json'), JSON.stringify(raw), { mode: 0o600 })
      expect(lastAccountStatus(loadNag(ctx), 'acct-hash')).toBeNull()
    } finally { cleanup() }
  })
  it('the weekly fetch counter is one shared global', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW, safeMode: false }
      expect(offerFetchDue(loadNag(ctx), NOW)).toBe(true)
      markOfferFetch(ctx)
      expect(offerFetchDue(loadNag(ctx), NOW + WEEK_MS - 1)).toBe(false)
      expect(offerFetchDue(loadNag(ctx), NOW + WEEK_MS)).toBe(true)
    } finally { cleanup() }
  })
  it('safe mode reads nothing and writes nothing', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const live = { configDir: dir, now: NOW, safeMode: false }
      markMoment(live, 'screenPitch', 'x')
      const safe = { ...live, safeMode: true }
      expect(loadNag(safe)).toEqual({ repos: {}, accounts: {} })
      expect(markMoment(safe, 'usageScreen', 'a')).toBe(false)
      expect(setMuted(safe, true)).toBe(false)
      expect(recordAccountStatus(safe, 'a', 'active')).toBe(false)
      expect(markOfferFetch(safe)).toBe(false)
      expect(JSON.parse(readFileSync(join(dir, 'nag.json'), 'utf8')).accounts).toEqual({})
    } finally { cleanup() }
  })
  it('a corrupt, oversized or foreign nag.json is treated as empty and never crashes; old entries are pruned', () => {
    const { dir, cleanup } = tempConfigDir()
    try {
      const ctx = { configDir: dir, now: NOW, safeMode: false }
      markMoment(ctx, 'screenPitch', 'a')
      writeFileSync(join(dir, 'nag.json'), '[1,2', { mode: 0o600 })
      expect(loadNag(ctx)).toEqual({ repos: {}, accounts: {} })
      writeFileSync(join(dir, 'nag.json'), Buffer.alloc(200000, 49), { mode: 0o600 })
      expect(loadNag(ctx)).toEqual({ repos: {}, accounts: {} })
      writeFileSync(join(dir, 'nag.json'), '{}', { mode: 0o600 })
      for (let i = 0; i < 300; i++) markMoment({ ...ctx, now: NOW + i }, 'screenPitch', repoKey(`r${i}`))
      const repos = Object.keys(loadNag(ctx).repos)
      expect(repos.length).toBeLessThanOrEqual(120)
      expect(repos).toContain(repoKey('r299'))
      expect(repos).not.toContain(repoKey('r0'))
    } finally { cleanup() }
  })
})
