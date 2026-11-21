/**
 * Finding tidy-up: one flaw = one finding, every file finding has a line, obviously fake keys
 * carry LOW confidence (real-looking ones never do and are never dropped).
 *
 * Runs the built CLI over the seeded fixture set (tests/helpers/tidy-fixtures.ts).
 */
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, scanJson } from '../helpers/cli-fixture.js'
import { TIDY_FIXTURES } from '../helpers/tidy-fixtures.js'
import { looksFakeKey } from '../../src/checks/secrets.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

type F = { id: string; file: string; line?: number | null; confidence?: string; severity: string; title: string; explanation: string }

async function scan(name: string): Promise<F[]> {
  const dir = mkTree(TIDY_FIXTURES[name])
  // The long prose (`explanation`) is part of the 0.12 shape: schema 7 keeps only the short `why`.
  const r = await scanJson(dir, ['--schema-version', '6'])
  expect(r.json, r.stdout + r.stderr).toBeDefined()
  return r.json!.findings as F[]
}

describe('one unsigned webhook = one finding', () => {
  it('seeded Stripe webhook: exactly 1 signature finding, critical', async () => {
    const f = (await scan('stripe-unsigned')).filter((x) => x.id === 'payment_webhook_without_signature_check')
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe('critical')
    expect(f[0].explanation).toContain('stripe-signature')
  })

  it('seeded mixed project: exactly 1 signature finding', async () => {
    const f = (await scan('seeded-mixed')).filter((x) => x.id === 'payment_webhook_without_signature_check')
    expect(f).toHaveLength(1)
  })

  it('Razorpay webhook gets only the Razorpay finding, not Stripe ones', async () => {
    const f = (await scan('razorpay-unsigned')).filter((x) => x.id === 'payment_webhook_without_signature_check')
    expect(f).toHaveLength(1)
    expect(f[0].title).toContain('Razorpay')
  })

  it('Stripe flaw in a file under a razorpay path is still flagged (decided by content, not path)', async () => {
    const f = (await scan('razorpay-path-stripe-flaw')).filter((x) => x.id === 'payment_webhook_without_signature_check')
    expect(f).toHaveLength(1)
    expect(f[0].title).toContain('Stripe')
  })

  it('razorpay path, content names no provider: the Stripe flaw is still reported (never hidden by path)', async () => {
    const f = (await scan('razorpay-path-no-provider-words')).filter((x) => x.id === 'payment_webhook_without_signature_check')
    expect(f.some((x) => x.title.includes('Stripe'))).toBe(true)
  })

  it('only the header missing: still exactly 1 finding', async () => {
    const f = (await scan('stripe-header-missing')).filter((x) => x.id === 'payment_webhook_without_signature_check')
    expect(f).toHaveLength(1)
  })

  it('signed webhook: no signature finding', async () => {
    const f = (await scan('stripe-signed')).filter((x) => x.id === 'payment_webhook_without_signature_check')
    expect(f).toHaveLength(0)
  })

  it('idempotency message is plain and says it may live elsewhere', async () => {
    const f = (await scan('stripe-unsigned')).find((x) => x.id === 'missing_idempotency')
    expect(f).toBeDefined()
    const text = `${f!.title} ${f!.explanation}`
    expect(text).toContain('elsewhere')
    expect(text.toLowerCase()).not.toMatch(/cloud|release gate/)
  })
})

describe('every finding with a file has a numeric line', () => {
  for (const name of Object.keys(TIDY_FIXTURES)) {
    it(`fixture ${name}: no missing or null line`, async () => {
      for (const f of await scan(name)) {
        expect(typeof f.line, `${f.id} in ${f.file}`).toBe('number')
        expect(f.line as number).toBeGreaterThanOrEqual(1)
      }
    })
  }

  it('webhook finding points at the POST handler, not just line 1', async () => {
    const f = (await scan('stripe-unsigned')).find((x) => x.id === 'payment_webhook_without_signature_check')
    expect(f!.line).toBe(2)
  })

  it('handler declaration beats an earlier outgoing .post( call', async () => {
    const f = (await scan('axios-before-handler')).find((x) => x.id === 'payment_webhook_without_signature_check')
    expect(f!.line).toBe(5)
  })

  it('file-level finding (tracked .env) gets line 1', async () => {
    const f = (await scan('seeded-mixed')).find((x) => x.file === '.env' && x.title.includes('tracked in git'))
    expect(f?.line).toBe(1)
  })
})

describe('fake-looking keys get LOW confidence; real-looking ones never do', () => {
  const sk = (...p: string[]) => p.join('')

  it('looksFakeKey: placeholder shapes', () => {
    expect(looksFakeKey(sk('sk-', 'proj-', 'a'.repeat(40)))).toBe(true)
    expect(looksFakeKey(sk('sk-', 'proj-', '1234567890'.repeat(4)))).toBe(true)
    expect(looksFakeKey(sk('sk_', 'live_', 'x'.repeat(24)))).toBe(true)
    expect(looksFakeKey(sk('sk-', 'ant-', 'api03-', 'x'.repeat(40)))).toBe(true)
    expect(looksFakeKey('AKIAIOSFODNN7EXAMPLE')).toBe(true)
    expect(looksFakeKey(sk('sk_', 'test_', 'abcdefghijklmnopqrstuvwxyz'))).toBe(true)
    expect(looksFakeKey(sk('sk_', 'live_', 'REPLACE_ME_REPLACE_ME_REPLACE'))).toBe(true)
  })

  it('looksFakeKey: real-looking values are not fake', () => {
    expect(looksFakeKey(sk('sk-proj-', 'Zq8rT2vB5nM7xK1cD4fG6hJ9lP3sW0yA8eR2uI5oQ7tY1'))).toBe(false)
    expect(looksFakeKey(sk('sk_', 'live_', '51HxYzAbCdEfGhIjKlMnOpQrStUv'))).toBe(false)
    expect(looksFakeKey('AKIAJ7Q2XK4M9TPB3NWR')).toBe(false)
    expect(looksFakeKey('')).toBe(false)
  })

  it('scan: fake keys LOW, real keys HIGH, and no key is dropped', async () => {
    const f = (await scan('keys-only')).filter((x) => x.id === 'hardcoded_secret' || x.id.includes('.secrets.'))
    const byLine = new Map<number, F[]>()
    for (const x of f) byLine.set(x.line as number, [...(byLine.get(x.line as number) ?? []), x])
    // line 1 = the real key (corpus rule); never lowered
    expect(byLine.get(1)?.length).toBeGreaterThan(0)
    for (const x of byLine.get(1)!) expect(x.confidence).toBe('HIGH')
    // lines 2, 3, 5 = placeholder-shaped keys: still reported, LOW
    for (const line of [2, 3, 5]) {
      expect(byLine.get(line)?.length, `line ${line} reported`).toBeGreaterThan(0)
      for (const x of byLine.get(line)!) expect(x.confidence, `line ${line}`).toBe('LOW')
    }
  })
})
