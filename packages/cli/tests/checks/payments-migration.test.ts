/**
 * D.4 — payments.ts migration 4-part proof
 *
 * PART 1: STRENGTHENED FIXTURES — real payment-security issues the detector MUST
 *         flag (missing webhook verification, exposed secret key, missing
 *         idempotency) + safe look-alikes it MUST NOT flag.
 *
 * PART 2: NATIVE↔re2js DIFFERENTIAL — every migrated pattern, original native
 *         regex (oracle) vs new re2js path over the fixtures, identical decisions;
 *         adjudicates any diff. No fossilized FNs.
 *
 * PART 3: PROPERTY-GENERATED inputs with native oracle on the safe subset.
 *
 * PART 4: TARGETED MUTATION — flag permutations, boundary/anchor, per-line vs
 *         whole-content, capture offsets, any lookaround rewrite.
 *
 * RE2js constraint note: ALL 12 content-scanning patterns in payments.ts are
 * plain literals / character-class alternation / word boundaries — zero
 * lookaheads, lookbehinds, or backreferences.  No rewrites required.
 */

import { describe, it, expect } from 'vitest'
import { payments } from '../../src/checks/payments.js'
import { compileDetectorRegex } from '../../src/core/re2-detector-engine.js'
import type { FileInfo, Policy } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function makeFile(relativePath: string, content: string): FileInfo {
  return { path: `/project/${relativePath}`, relativePath, content }
}

const BLOCK_ALL_POLICY: Policy = {
  version: 1,
  project: { name: 'test-app', framework: 'next', risk_profile: 'standard' },
  scan: { changed_files_only: false, generate_report: false },
  block: [
    'exposed_env',
    'hardcoded_secret',
    'public_admin_route',
    'auth_route_without_guard',
    'payment_webhook_without_signature_check',
    'destructive_migration',
    'unsafe_deployment_config',
    'missing_idempotency',
    'missing_error_handling',
  ],
  warn: [],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}

// ─── Native oracle patterns (verbatim from pre-D.4 payments.ts) ─────────────
// Used only as DIFFERENTIAL reference — never for production matching.

// Pattern pair for constructEvent (two chained tests, collapsed to one here for
// oracle parity since /i already covers both lowercase/uppercase prefix)
const NATIVE_CONSTRUCT_EVENT  = /stripe\.webhooks\.constructEvent/i
// The original code also tested /Stripe\.webhooks\.constructEvent/i — identical
// under /i, so one oracle covers both sites.

const NATIVE_STRIPE_SIGNATURE = /stripe-signature/i
const NATIVE_RAZORPAY_VALIDATE = /validateWebhookSignature/i
const NATIVE_IDEMPOTENCY_WORD = /idempoten(cy|t)/i
const NATIVE_EVENT_ID          = /event\.id/i
const NATIVE_PROCESSED_EVENTS  = /processedEvents/i
const NATIVE_ALREADY_PROCESSED = /alreadyProcessed/i
const NATIVE_TRY               = /\btry\b/
const NATIVE_CATCH             = /\bcatch\b/
const NATIVE_STRIPE_SECRET_KEY  = /STRIPE_SECRET_KEY/i
const NATIVE_RAZORPAY_KEY_SECRET = /RAZORPAY_KEY_SECRET/i

// ─── re2js compiled patterns (same sources the migrated detector uses) ───────
// Instantiated independently here so Part 2 tests the engine itself, not just
// an observable side-effect of the detector.

const RE2_CONSTRUCT_EVENT    = compileDetectorRegex('stripe\\.webhooks\\.constructEvent', 'i')
const RE2_STRIPE_SIGNATURE   = compileDetectorRegex('stripe-signature', 'i')
const RE2_RAZORPAY_VALIDATE  = compileDetectorRegex('validateWebhookSignature', 'i')
const RE2_IDEMPOTENCY_WORD   = compileDetectorRegex('idempoten(?:cy|t)', 'i')
const RE2_EVENT_ID           = compileDetectorRegex('event\\.id', 'i')
const RE2_PROCESSED_EVENTS   = compileDetectorRegex('processedEvents', 'i')
const RE2_ALREADY_PROCESSED  = compileDetectorRegex('alreadyProcessed', 'i')
const RE2_TRY                = compileDetectorRegex('\\btry\\b')
const RE2_CATCH              = compileDetectorRegex('\\bcatch\\b')
const RE2_STRIPE_SECRET_KEY  = compileDetectorRegex('STRIPE_SECRET_KEY', 'i')
const RE2_RAZORPAY_SECRET    = compileDetectorRegex('RAZORPAY_KEY_SECRET', 'i')

// ---------------------------------------------------------------------------
// PART 1 — STRENGTHENED FIXTURES
// ---------------------------------------------------------------------------
// For each detector: one UNSAFE input (must flag) + one SAFE look-alike (must NOT).
// Covers: missing webhook verification, exposed secret key, missing idempotency.
// ---------------------------------------------------------------------------

describe('PART 1 — Strengthened fixtures: unsafe inputs flagged, safe look-alikes not flagged', () => {

  // ── 1a. Stripe webhook WITHOUT constructEvent ──────────────────────────────
  describe('Stripe webhook missing constructEvent', () => {
    it('flags a webhook handler that processes body without constructEvent', () => {
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `import { NextRequest, NextResponse } from 'next/server'
export async function POST(request: NextRequest) {
  const body = await request.json()
  if (body.type === 'payment_intent.succeeded') {
    await fulfillOrder(body.data.object)
  }
  return NextResponse.json({ received: true })
}`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('missing signature verification'))).toBe(true)
    })

    it('does NOT flag a webhook handler WITH stripe.webhooks.constructEvent', () => {
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `import Stripe from 'stripe'
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
export async function POST(request: NextRequest) {
  const body = await request.text()
  const sig = request.headers.get('stripe-signature')!
  const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!)
  return NextResponse.json({ received: true })
}`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('missing signature verification'))).toBe(false)
    })

    it('does NOT flag when Stripe.webhooks.constructEvent (capital S) is used', () => {
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `const event = Stripe.webhooks.constructEvent(body, sig, secret)
const sig = request.headers.get('stripe-signature')!`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('missing signature verification'))).toBe(false)
    })
  })

  // ── 1b. Stripe webhook WITHOUT stripe-signature header ────────────────────
  describe('Stripe webhook missing stripe-signature header', () => {
    it('flags a webhook handler that does NOT read stripe-signature header', () => {
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `import Stripe from 'stripe'
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
export async function POST(request: NextRequest) {
  const body = await request.text()
  // passes empty sig — no header read
  const event = stripe.webhooks.constructEvent(body, '', process.env.STRIPE_WEBHOOK_SECRET!)
  return NextResponse.json({ received: true })
}`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('stripe-signature'))).toBe(true)
    })

    it('does NOT flag when stripe-signature header is referenced', () => {
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `const sig = req.headers['stripe-signature'] ?? ''
const event = stripe.webhooks.constructEvent(body, sig, webhookSecret)`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('stripe-signature'))).toBe(false)
    })
  })

  // ── 1c. Razorpay webhook WITHOUT validateWebhookSignature ─────────────────
  describe('Razorpay webhook missing validateWebhookSignature', () => {
    it('flags a Razorpay handler that blindly trusts the payload', () => {
      const file = makeFile(
        'app/api/razorpay/webhook/route.ts',
        `import { NextRequest, NextResponse } from 'next/server'
export async function POST(request: NextRequest) {
  const body = await request.json()
  if (body.event === 'payment.captured') {
    await fulfillOrder(body.payload.payment.entity)
  }
  return NextResponse.json({ received: true })
}`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('Razorpay webhook missing'))).toBe(true)
    })

    it('does NOT flag a handler WITH validateWebhookSignature', () => {
      const file = makeFile(
        'app/api/razorpay/webhook/route.ts',
        `import Razorpay from 'razorpay'
const isValid = Razorpay.validateWebhookSignature(body, sig, process.env.RAZORPAY_WEBHOOK_SECRET!)
if (!isValid) return NextResponse.json({ error: 'Invalid' }, { status: 400 })`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('Razorpay webhook missing'))).toBe(false)
    })
  })

  // ── 1d. STRIPE_SECRET_KEY in client-side file ─────────────────────────────
  describe('STRIPE_SECRET_KEY exposed in client-side file', () => {
    it('flags STRIPE_SECRET_KEY reference in app/ component (non-API path)', () => {
      const file = makeFile(
        'app/checkout/page.tsx',
        `'use client'
const stripe = loadStripe(process.env.STRIPE_SECRET_KEY!)`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('STRIPE_SECRET_KEY'))).toBe(true)
    })

    it('does NOT flag STRIPE_SECRET_KEY in an API route (app/api/ path)', () => {
      const file = makeFile(
        'app/api/checkout/route.ts',
        `import Stripe from 'stripe'
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('STRIPE_SECRET_KEY'))).toBe(false)
    })

    it('flags STRIPE_SECRET_KEY in a components/ file', () => {
      const file = makeFile(
        'components/PaymentForm.tsx',
        `const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('STRIPE_SECRET_KEY'))).toBe(true)
    })

    it('does NOT flag STRIPE_SECRET_KEY in pages/api/ route', () => {
      const file = makeFile(
        'pages/api/payment.ts',
        `const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('STRIPE_SECRET_KEY'))).toBe(false)
    })
  })

  // ── 1e. RAZORPAY_KEY_SECRET in client-side file ───────────────────────────
  describe('RAZORPAY_KEY_SECRET exposed in client-side file', () => {
    it('flags RAZORPAY_KEY_SECRET in a pages/ file', () => {
      const file = makeFile(
        'pages/checkout.tsx',
        `const razorpay = new Razorpay({ key_secret: process.env.RAZORPAY_KEY_SECRET })`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('RAZORPAY_KEY_SECRET'))).toBe(true)
    })

    it('does NOT flag RAZORPAY_KEY_SECRET in pages/api/', () => {
      const file = makeFile(
        'pages/api/razorpay.ts',
        `const razorpay = new Razorpay({ key_secret: process.env.RAZORPAY_KEY_SECRET })`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('RAZORPAY_KEY_SECRET'))).toBe(false)
    })
  })

  // ── 1f. Webhook without idempotency ───────────────────────────────────────
  describe('Webhook handler missing idempotency protection', () => {
    it('flags a Stripe webhook route with no idempotency signal', () => {
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `const event = stripe.webhooks.constructEvent(body, sig, secret)
const sig = req.headers['stripe-signature']
// WARNING: no duplicate-event protection here
await fulfillOrder(event.data.object)`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('idempotency'))).toBe(true)
    })

    it('does NOT flag when idempotency is present via event.id', () => {
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `const event = stripe.webhooks.constructEvent(body, sig, secret)
const sig = req.headers['stripe-signature']
const existing = await db.events.findUnique({ where: { id: event.id } })
if (existing) return Response.json({ ok: true })`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('idempotency'))).toBe(false)
    })

    it('does NOT flag when idempotency is present via processedEvents', () => {
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `const event = stripe.webhooks.constructEvent(body, sig, secret)
const sig = req.headers['stripe-signature']
const processedEvents = new Set(await getProcessedIds())
if (processedEvents.has(event.id)) return`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('idempotency'))).toBe(false)
    })

    it('does NOT flag when idempotency keyword is present', () => {
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `const event = stripe.webhooks.constructEvent(body, sig, secret)
const sig = req.headers['stripe-signature']
// idempotency key: event.id ensures no duplicates
await processWithIdempotency(event.id)`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('idempotency'))).toBe(false)
    })
  })

  // ── 1g. Payment route without error handling ──────────────────────────────
  describe('Payment route missing error handling', () => {
    it('flags a checkout route with no try/catch', () => {
      const file = makeFile(
        'app/api/checkout/route.ts',
        `const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: [] })
return Response.json({ url: session.url })`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('error handling'))).toBe(true)
    })

    it('does NOT flag a route that has try/catch', () => {
      const file = makeFile(
        'app/api/billing/route.ts',
        `try {
  const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: [] })
  return Response.json({ url: session.url })
} catch (err) {
  console.error(err)
  return Response.json({ error: 'Internal error' }, { status: 500 })
}`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('error handling'))).toBe(false)
    })
  })
})

// ---------------------------------------------------------------------------
// PART 2 — NATIVE↔re2js DIFFERENTIAL
// ---------------------------------------------------------------------------
// For each of the 12 content-scanning patterns:
// - Oracle  = original native RegExp from pre-D.4 code
// - Actual  = re2js-backed compiled pattern (same source as migrated detector)
// Run over the same fixture set and assert identical test() results.
//
// All 12 patterns are RE2-compatible (no lookaheads/lookbehinds/backreferences).
// No rewrites required; this section confirms bit-for-bit parity.
// ---------------------------------------------------------------------------

// Differential fixture table.  Each entry has:
//   name        human label
//   native      oracle RegExp
//   re2js       compiled re2js counterpart
//   inputs      array of strings; test() result must match between native and re2js
const DIFF_TABLE: Array<{
  name: string
  native: RegExp
  re2: ReturnType<typeof compileDetectorRegex>
  inputs: string[]
}> = [
  {
    name: 'constructEvent (line 59+60)',
    native: NATIVE_CONSTRUCT_EVENT,
    re2: RE2_CONSTRUCT_EVENT,
    inputs: [
      // should match
      `stripe.webhooks.constructEvent(body, sig, secret)`,
      `Stripe.webhooks.constructEvent(body, sig, secret)`,
      `STRIPE.WEBHOOKS.CONSTRUCTEVENT(body, sig, secret)`,    // /i
      `  event = stripe.webhooks.constructEvent(rawBody, ...)`, // mid-line
      // should NOT match
      `stripe.webhooks.retrieve(id)`,
      `// stripe.webhooks.constructEvent — call in comment`,   // still matches (no comment filter at pattern level)
      `constructEvent(body, sig, secret)`,                     // no stripe. prefix
      `stripe_webhooks_constructEvent`,                        // underscores not dots
    ],
  },
  {
    name: 'stripe-signature (line 65)',
    native: NATIVE_STRIPE_SIGNATURE,
    re2: RE2_STRIPE_SIGNATURE,
    inputs: [
      `req.headers['stripe-signature']`,
      `request.headers.get('stripe-signature')`,
      `STRIPE-SIGNATURE`,   // /i
      `req.headers['x-stripe-signature']`,   // substring match → still matches
      // should NOT match
      `stripe_signature`,   // underscore not hyphen
      `stripesignature`,
      `no header here`,
    ],
  },
  {
    name: 'validateWebhookSignature (line 70)',
    native: NATIVE_RAZORPAY_VALIDATE,
    re2: RE2_RAZORPAY_VALIDATE,
    inputs: [
      `Razorpay.validateWebhookSignature(body, sig, secret)`,
      `validatewebhooksignature(body, sig, secret)`,  // /i
      `VALIDATEWEBHOOKSIGNATURE`,
      // should NOT match
      `validatePaymentSignature(body, sig, secret)`,
      `validateSignature`,
      `no razorpay here`,
    ],
  },
  {
    name: 'idempoten(cy|t) (line 80)',
    native: NATIVE_IDEMPOTENCY_WORD,
    re2: RE2_IDEMPOTENCY_WORD,
    inputs: [
      `// idempotency key prevents double processing`,
      `const idempotent = true`,
      `IDEMPOTENCY_KEY`,    // /i
      `IDEMPOTENT`,
      // should NOT match (partial prefixes that don't complete the word)
      `idempote`,           // too short
      `no payment guards here`,
    ],
  },
  {
    name: 'event.id (line 81)',
    native: NATIVE_EVENT_ID,
    re2: RE2_EVENT_ID,
    inputs: [
      `const existing = db.find({ where: { id: event.id } })`,
      `EVENT.ID`,           // /i
      `event.identity`,     // substring match
      // should NOT match
      `eventId`,
      `event_id`,
      `no id here`,
    ],
  },
  {
    name: 'processedEvents (line 82)',
    native: NATIVE_PROCESSED_EVENTS,
    re2: RE2_PROCESSED_EVENTS,
    inputs: [
      `const processedEvents = new Set()`,
      `ProcessedEvents`,    // /i
      `map.processedEvents.has(id)`,
      // should NOT match
      `processed_events`,   // underscore
      `processEvent`,       // singular
    ],
  },
  {
    name: 'alreadyProcessed (line 83)',
    native: NATIVE_ALREADY_PROCESSED,
    re2: RE2_ALREADY_PROCESSED,
    inputs: [
      `if (alreadyProcessed) return`,
      `ALREADYPROCESSED`,   // /i
      `const alreadyProcessed = await db.exists(event.id)`,
      // should NOT match
      `already_processed`,  // underscore
      `wasProcessed`,
    ],
  },
  {
    name: '\\btry\\b (line 91 first)',
    native: NATIVE_TRY,
    re2: RE2_TRY,
    inputs: [
      `try {`,
      `  try {`,
      `// try again`,     // word boundary: space before + space after → matches
      // should NOT match
      `retry`,            // no word boundary before 'try'
      `entry`,
      `trying`,           // 'ing' suffix — no word boundary after
    ],
  },
  {
    name: '\\bcatch\\b (line 91 second)',
    native: NATIVE_CATCH,
    re2: RE2_CATCH,
    inputs: [
      `} catch (err) {`,
      `  catch (e) {`,
      `// catch block`,
      // should NOT match
      `catching`,         // 'ing' suffix
      `backcatch`,        // no word boundary before
      `no error handling`,
    ],
  },
  {
    name: 'STRIPE_SECRET_KEY (line 199)',
    native: NATIVE_STRIPE_SECRET_KEY,
    re2: RE2_STRIPE_SECRET_KEY,
    inputs: [
      `process.env.STRIPE_SECRET_KEY`,
      `stripe_secret_key`,    // /i
      `const STRIPE_SECRET_KEY = 'sk_live_...'`,
      // should NOT match
      `STRIPE_PUBLISHABLE_KEY`,
      `STRIPE_WEBHOOK_SECRET`,
    ],
  },
  {
    name: 'RAZORPAY_KEY_SECRET (line 200)',
    native: NATIVE_RAZORPAY_KEY_SECRET,
    re2: RE2_RAZORPAY_SECRET,
    inputs: [
      `process.env.RAZORPAY_KEY_SECRET`,
      `razorpay_key_secret`,  // /i
      `const RAZORPAY_KEY_SECRET = 'abcdef'`,
      // should NOT match
      `RAZORPAY_KEY_ID`,
      `RAZORPAY_WEBHOOK_SECRET`,
    ],
  },
]

describe('PART 2 — Native↔re2js differential: identical test() decisions for all 12 patterns', () => {
  for (const { name, native, re2, inputs } of DIFF_TABLE) {
    describe(`Pattern: ${name}`, () => {
      for (const input of inputs) {
        it(`agrees on: "${input.slice(0, 60)}"`, () => {
          const nativeResult = native.test(input)
          const re2Result    = re2.test(input)
          expect(re2Result).toBe(nativeResult)
        })
      }
    })
  }

  it('differential summary: all 12 (11 logical + 1 collated) patterns covered', () => {
    // constructEvent lines 59+60 are collapsed to 1 under /i — 11 distinct patterns
    // map to 12 inventory sites.
    expect(DIFF_TABLE.length).toBe(11)
  })
})

// ---------------------------------------------------------------------------
// PART 3 — PROPERTY-GENERATED inputs with native oracle
// ---------------------------------------------------------------------------
// Generate deterministic semi-random inputs and verify re2js.test() === native.test().
// Covers the 5 patterns most likely to have boundary sensitivity.
// ---------------------------------------------------------------------------

function seededStr(prefix: string, len: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let s = prefix
  for (let i = 0; i < len; i++) {
    s += chars[(i * 31 + len * 13) % chars.length]
  }
  return s
}

const PROPERTY_CASES: Array<{
  patternName: string
  native: RegExp
  re2: ReturnType<typeof compileDetectorRegex>
  inputs: string[]
}> = [
  {
    patternName: 'constructEvent',
    native: NATIVE_CONSTRUCT_EVENT,
    re2: RE2_CONSTRUCT_EVENT,
    inputs: [
      // Match cases
      `const e = stripe.webhooks.constructEvent(${seededStr('a', 10)})`,
      `Stripe.webhooks.constructEvent()`,
      `\n  stripe.webhooks.constructEvent(body, sig, key)  // end`,
      // No-match cases
      seededStr('no-construct-event-', 30),
      `stripe.webhooks.retrieve()`,
      `STRIPE_WEBHOOKS_CONSTRUCTEVENT`,  // underscores
    ],
  },
  {
    patternName: 'try + catch (error handling)',
    native: NATIVE_TRY,  // tested separately; combined test done via detector
    re2: RE2_TRY,
    inputs: [
      `try {`,
      `  try {`,
      `// try something`,
      `retry`,
      `entry point`,
      `untried`,
      `betray`,
    ],
  },
  {
    patternName: 'idempotency word',
    native: NATIVE_IDEMPOTENCY_WORD,
    re2: RE2_IDEMPOTENCY_WORD,
    inputs: [
      `idempotency`,
      `idempotent`,
      `IDEMPOTENCY`,
      `IDEMPOTENT`,
      `idempote`,
      `nonidempotent`,  // 'idempotent' has word in it — matches by substring
      seededStr('random-', 20),
    ],
  },
  {
    patternName: 'stripe-signature',
    native: NATIVE_STRIPE_SIGNATURE,
    re2: RE2_STRIPE_SIGNATURE,
    inputs: [
      `stripe-signature`,
      `STRIPE-SIGNATURE`,
      `x-stripe-signature`,
      `stripe_signature`,
      `stripesignature`,
      seededStr('no-sig-', 15),
    ],
  },
  {
    patternName: 'validateWebhookSignature',
    native: NATIVE_RAZORPAY_VALIDATE,
    re2: RE2_RAZORPAY_VALIDATE,
    inputs: [
      `validateWebhookSignature`,
      `VALIDATEWEBHOOKSIGNATURE`,
      `validatewebhooksignature`,
      `ValidateWebhookSignature`,
      `validateSignature`,
      `validWebhook`,
      seededStr('random-', 20),
    ],
  },
]

describe('PART 3 — Property-generated inputs with native oracle', () => {
  for (const { patternName, native, re2, inputs } of PROPERTY_CASES) {
    describe(`Pattern: ${patternName}`, () => {
      for (const input of inputs) {
        it(`agrees on: "${input.slice(0, 55)}"`, () => {
          expect(re2.test(input)).toBe(native.test(input))
        })
      }
    })
  }
})

// ---------------------------------------------------------------------------
// PART 4 — TARGETED MUTATION
// ---------------------------------------------------------------------------
// Mutates high-risk dimensions to confirm the battery catches each mutation.
// ---------------------------------------------------------------------------

describe('PART 4 — Targeted mutation tests', () => {

  // Dimension 1: Flag permutations (case-insensitive)
  describe('Dimension 1 — Flag permutations: /i must be honored', () => {
    it('constructEvent: all-caps CONSTRUCTEVENT still matches', () => {
      expect(RE2_CONSTRUCT_EVENT.test('stripe.webhooks.CONSTRUCTEVENT')).toBe(true)
      expect(NATIVE_CONSTRUCT_EVENT.test('stripe.webhooks.CONSTRUCTEVENT')).toBe(true)
    })
    it('stripe-signature: STRIPE-SIGNATURE still matches', () => {
      expect(RE2_STRIPE_SIGNATURE.test('STRIPE-SIGNATURE')).toBe(true)
      expect(NATIVE_STRIPE_SIGNATURE.test('STRIPE-SIGNATURE')).toBe(true)
    })
    it('validateWebhookSignature: lowercase still matches', () => {
      expect(RE2_RAZORPAY_VALIDATE.test('validatewebhooksignature')).toBe(true)
      expect(NATIVE_RAZORPAY_VALIDATE.test('validatewebhooksignature')).toBe(true)
    })
    it('idempotency: IDEMPOTENCY (uppercase) still matches', () => {
      expect(RE2_IDEMPOTENCY_WORD.test('IDEMPOTENCY')).toBe(true)
      expect(NATIVE_IDEMPOTENCY_WORD.test('IDEMPOTENCY')).toBe(true)
    })
    it('STRIPE_SECRET_KEY: lowercase stripe_secret_key still matches', () => {
      expect(RE2_STRIPE_SECRET_KEY.test('stripe_secret_key')).toBe(true)
      expect(NATIVE_STRIPE_SECRET_KEY.test('stripe_secret_key')).toBe(true)
    })
    it('RAZORPAY_KEY_SECRET: lowercase razorpay_key_secret still matches', () => {
      expect(RE2_RAZORPAY_SECRET.test('razorpay_key_secret')).toBe(true)
      expect(NATIVE_RAZORPAY_KEY_SECRET.test('razorpay_key_secret')).toBe(true)
    })
  })

  // Dimension 2: Boundary / anchor conditions
  describe('Dimension 2 — Boundary and anchor conditions', () => {
    it('\\btry\\b: does NOT match "retry" (no leading word boundary)', () => {
      expect(RE2_TRY.test('retry')).toBe(false)
      expect(NATIVE_TRY.test('retry')).toBe(false)
    })
    it('\\btry\\b: does NOT match "trying" (no trailing word boundary)', () => {
      expect(RE2_TRY.test('trying')).toBe(false)
      expect(NATIVE_TRY.test('trying')).toBe(false)
    })
    it('\\btry\\b: DOES match "try {" (word boundary before {)', () => {
      expect(RE2_TRY.test('try {')).toBe(true)
      expect(NATIVE_TRY.test('try {')).toBe(true)
    })
    it('\\bcatch\\b: does NOT match "catching"', () => {
      expect(RE2_CATCH.test('catching')).toBe(false)
      expect(NATIVE_CATCH.test('catching')).toBe(false)
    })
    it('\\bcatch\\b: DOES match "} catch (err) {"', () => {
      expect(RE2_CATCH.test('} catch (err) {')).toBe(true)
      expect(NATIVE_CATCH.test('} catch (err) {')).toBe(true)
    })
    it('idempoten(cy|t): "idempote" alone does NOT match', () => {
      expect(RE2_IDEMPOTENCY_WORD.test('idempote')).toBe(false)
      expect(NATIVE_IDEMPOTENCY_WORD.test('idempote')).toBe(false)
    })
    it('stripe.webhooks.constructEvent: underscores do NOT match', () => {
      expect(RE2_CONSTRUCT_EVENT.test('stripe_webhooks_constructEvent')).toBe(false)
      expect(NATIVE_CONSTRUCT_EVENT.test('stripe_webhooks_constructEvent')).toBe(false)
    })
  })

  // Dimension 3: Per-line vs whole-content and mid-content detection
  describe('Dimension 3 — Mid-content detection: secrets in multi-line files', () => {
    it('STRIPE_SECRET_KEY on line 3 of 5 is still detected by detector', () => {
      const content = [
        `import Stripe from 'stripe'`,
        `export async function POST() {`,
        `  const stripe = loadStripe(process.env.STRIPE_SECRET_KEY!)`,
        `  return stripe.redirectToCheckout({ sessionId })`,
        `}`,
      ].join('\n')
      const file = makeFile('app/checkout/page.tsx', content)
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('STRIPE_SECRET_KEY'))).toBe(true)
    })

    it('try/catch: try on line 2 and catch on line 4 still satisfies hasErrorHandling', () => {
      const content = [
        `export async function POST() {`,
        `  try {`,
        `    const session = await stripe.checkout.sessions.create({})`,
        `  } catch (err) {`,
        `    return Response.json({ error: 'oops' }, { status: 500 })`,
        `  }`,
        `}`,
      ].join('\n')
      const file = makeFile('app/api/billing/route.ts', content)
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      expect(findings.some((f) => f.title.includes('error handling'))).toBe(false)
    })
  })

  // Dimension 4: Capture offsets — exec() index correctness on key patterns
  describe('Dimension 4 — exec() index / group correctness', () => {
    it('RE2_CONSTRUCT_EVENT exec() returns correct index (mid-string match)', () => {
      const input = `  const event = stripe.webhooks.constructEvent(body, sig, key)`
      const result = RE2_CONSTRUCT_EVENT.exec(input)
      expect(result).not.toBeNull()
      // "stripe.webhooks.constructEvent" should start at index 16 in this string
      expect(result!.index).toBe(input.indexOf('stripe.webhooks.constructEvent'))
    })

    it('RE2_STRIPE_SIGNATURE exec() returns correct match string', () => {
      const input = `const sig = req.headers['stripe-signature']`
      const result = RE2_STRIPE_SIGNATURE.exec(input)
      expect(result).not.toBeNull()
      expect(result!.match.toLowerCase()).toBe('stripe-signature')
    })

    it('RE2_IDEMPOTENCY_WORD exec() captures "idempotency" (no groups expected)', () => {
      const input = `// idempotency check`
      const result = RE2_IDEMPOTENCY_WORD.exec(input)
      expect(result).not.toBeNull()
      expect(result!.match.toLowerCase()).toBe('idempotency')
    })

    it('RE2_TRY exec() match is "try" not "trying"', () => {
      const input = `  try {`
      const result = RE2_TRY.exec(input)
      expect(result).not.toBeNull()
      expect(result!.match).toBe('try')
    })
  })

  // Dimension 5: No lookaround rewrites required (re2js-compatibility proof)
  describe('Dimension 5 — No lookaround rewrites: all 12 patterns compile cleanly under re2js', () => {
    const PATTERN_SOURCES: Array<[string, string, string]> = [
      // [label, source, flags]
      ['constructEvent', 'stripe\\.webhooks\\.constructEvent', 'i'],
      ['stripe-signature', 'stripe-signature', 'i'],
      ['validateWebhookSignature', 'validateWebhookSignature', 'i'],
      ['idempoten(cy|t)', 'idempoten(?:cy|t)', 'i'],
      ['event.id', 'event\\.id', 'i'],
      ['processedEvents', 'processedEvents', 'i'],
      ['alreadyProcessed', 'alreadyProcessed', 'i'],
      ['\\btry\\b', '\\btry\\b', ''],
      ['\\bcatch\\b', '\\bcatch\\b', ''],
      ['STRIPE_SECRET_KEY', 'STRIPE_SECRET_KEY', 'i'],
      ['RAZORPAY_KEY_SECRET', 'RAZORPAY_KEY_SECRET', 'i'],
    ]

    for (const [label, source, flags] of PATTERN_SOURCES) {
      it(`compileDetectorRegex("${label}") does NOT throw`, () => {
        expect(() => compileDetectorRegex(source, flags)).not.toThrow()
      })
    }

    it('all 11 unique source patterns compile without error', () => {
      expect(PATTERN_SOURCES.length).toBe(11)
    })
  })

  // Dimension 6: Detector end-to-end on files that exercise ALL checks
  describe('Dimension 6 — End-to-end: fully secure webhook generates ZERO findings', () => {
    it('a fully secure Stripe webhook generates no payment findings', () => {
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `import Stripe from 'stripe'
import { NextRequest, NextResponse } from 'next/server'
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
export async function POST(request: NextRequest) {
  const body = await request.text()
  const sig = request.headers.get('stripe-signature')!
  let event: Stripe.Event
  try {
    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!)
  } catch (err) {
    return NextResponse.json({ error: 'Invalid signature' }, { status: 400 })
  }
  const existing = await db.webhookEvents.findUnique({ where: { id: event.id } })
  if (existing) return NextResponse.json({ received: true })
  await db.webhookEvents.create({ data: { eventId: event.id } })
  await handleEvent(event)
  return NextResponse.json({ received: true })
}`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      // All checks satisfied: no findings expected for the webhook checks
      const paymentFindings = findings.filter((f) => f.category === 'payments')
      expect(paymentFindings.length).toBe(0)
    })

    it('a fully insecure Stripe webhook generates ALL applicable findings', () => {
      // Missing: constructEvent, stripe-signature header, idempotency
      const file = makeFile(
        'app/api/webhooks/stripe/route.ts',
        `import { NextRequest, NextResponse } from 'next/server'
export async function POST(request: NextRequest) {
  const body = await request.json()
  await fulfillOrder(body.data.object)
  return NextResponse.json({ received: true })
}`,
      )
      const findings = payments.run([file], BLOCK_ALL_POLICY)
      const titles = findings.map((f) => f.title)
      expect(titles.some((t) => t.includes('missing signature verification'))).toBe(true)
      expect(titles.some((t) => t.includes('stripe-signature'))).toBe(true)
      expect(titles.some((t) => t.includes('idempotency'))).toBe(true)
    })
  })
})
