/** W2a acceptance tests: the per-finding fix record (spec 04): one sentence everywhere, stack handling, order. */
import { describe, it, expect } from 'vitest'
import { fixGuidance, firstSentence, orderFindings } from '../../src/core/fix-guidance.js'
import { a1Findings, finding } from './_fixtures.js'

describe('fixGuidance', () => {
  const auth = a1Findings()[2]

  it('uses the stack variant when one exists (Supabase, not next-auth or Clerk)', () => {
    const g = fixGuidance(auth, ['nextjs', 'supabase'])
    expect(g.certainty).toBe('stack-specific')
    expect(g.summary).toContain('supabase.auth.getUser()')
    expect(g.summary).not.toMatch(/next-auth|Clerk/i)
    expect(g.summary).toContain('403')
  })

  it('stack detected but no variant: generic text ends "(generic: no <stack> variant yet)"', () => {
    const g = fixGuidance(auth, ['nextjs'])
    expect(g.certainty).toBe('generic')
    expect(g.summary.endsWith('(generic: no Next.js variant yet)')).toBe(true)
  })

  it('stack not detected: generic text says so and never names a product', () => {
    for (const none of [undefined, [], ['generic']]) {
      const g = fixGuidance(auth, none)
      expect(g.summary.endsWith('(generic: stack not detected; adapt to your framework)')).toBe(true)
      expect(g.summary).not.toMatch(/supabase|clerk|next-auth/i)
    }
  })

  it('a rule with no data falls back to the first sentence of its own fix or recommendation', () => {
    const g = fixGuidance(finding({ id: 'unknown-rule', fix: 'Replace it. Then rotate.', recommendation: 'Other.' }), [])
    expect(g.summary).toBe('Replace it')
    expect(fixGuidance(finding({ id: 'unknown-rule', fix: undefined, recommendation: 'Do the thing. Later.' }), []).summary).toBe('Do the thing')
  })

  it('false-positive-capable findings carry "not a vulnerability if"; a real key does not', () => {
    expect(fixGuidance(a1Findings()[3], []).notAVulnerabilityIf).toMatch(/shared wrapper/)
    expect(fixGuidance(a1Findings()[0], []).notAVulnerabilityIf).toBeNull()
  })

  it('the admin-route condition requires BOTH the sign-in and the admin check (401 and 403)', () => {
    const t = fixGuidance(auth, []).notAVulnerabilityIf ?? ''
    expect(t).toMatch(/BOTH/)
    expect(t).toMatch(/401/)
    expect(t).toMatch(/403/)
  })
})

describe('firstSentence', () => {
  it('cuts at the first ". " but not inside identifiers or paths', () => {
    expect(firstSentence('Use process.env.KEY and .env.local (gitignored). Then rotate.')).toBe('Use process.env.KEY and .env.local (gitignored)')
    expect(firstSentence('no end')).toBe('no end')
  })
})

describe('orderFindings (spec 04 order)', () => {
  it('exposed secrets first, then other blocking by severity (payments and auth first), then non-blocking, LOW last', () => {
    const ids = orderFindings([...a1Findings()].reverse()).map((f) => f.id)
    expect(ids).toEqual([
      'generic.secrets.stripe-live-key',
      'payment_webhook_without_signature_check',
      'auth_route_without_guard',
      'missing_error_handling',
      'missing_idempotency',
    ])
  })
})
