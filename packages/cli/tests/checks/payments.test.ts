import { describe, it, expect } from 'vitest'
import { payments } from '../../src/checks/payments.js'
import type { FileInfo, Policy } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeFile(relativePath: string, content: string): FileInfo {
  return { path: `/project/${relativePath}`, relativePath, content }
}

const DEFAULT_POLICY: Policy = {
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
  ],
  warn: ['missing_tests_for_changed_code', 'missing_error_handling', 'missing_idempotency'],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}

// ---------------------------------------------------------------------------
// Stripe webhook checks
// ---------------------------------------------------------------------------

describe('Stripe webhook signature verification', () => {
  it('flags a webhook handler WITHOUT constructEvent (critical)', () => {
    const file = makeFile(
      'app/api/webhooks/stripe/route.ts',
      `
      import { NextRequest, NextResponse } from 'next/server'
      export async function POST(request: NextRequest) {
        const body = await request.json()
        // No signature verification!
        if (body.type === 'payment_intent.succeeded') {
          await fulfillOrder(body.data.object)
        }
        return NextResponse.json({ received: true })
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    // Title: 'Stripe webhook missing signature verification'
    const sigFindings = findings.filter((f) => f.title.includes('missing signature verification'))
    expect(sigFindings.length).toBeGreaterThan(0)
    expect(sigFindings[0].severity).toBe('critical')
    expect(sigFindings[0].category).toBe('payments')
    expect(sigFindings[0].blocking).toBe(true)
  })

  it('does NOT flag a webhook handler WITH constructEvent', () => {
    const file = makeFile(
      'app/api/webhooks/stripe/route.ts',
      `
      import Stripe from 'stripe'
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
        await handleEvent(event)
        return NextResponse.json({ received: true })
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    // Title: 'Stripe webhook missing signature verification'
    const sigFindings = findings.filter((f) => f.title.includes('missing signature verification'))
    expect(sigFindings.length).toBe(0)
  })

  it('flags missing stripe-signature header read (critical)', () => {
    const file = makeFile(
      'app/api/webhooks/stripe/route.ts',
      `
      import Stripe from 'stripe'
      import { NextRequest, NextResponse } from 'next/server'
      const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
      export async function POST(request: NextRequest) {
        const body = await request.text()
        // Header omitted — passing empty string to constructEvent
        let event: Stripe.Event
        try {
          event = stripe.webhooks.constructEvent(body, '', process.env.STRIPE_WEBHOOK_SECRET!)
        } catch (err) {
          return NextResponse.json({ error: 'Invalid signature' }, { status: 400 })
        }
        return NextResponse.json({ received: true })
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const headerFindings = findings.filter((f) => f.title.includes('stripe-signature'))
    expect(headerFindings.length).toBeGreaterThan(0)
    expect(headerFindings[0].severity).toBe('critical')
  })

  it('does NOT flag stripe-signature header when it is present', () => {
    const file = makeFile(
      'app/api/webhooks/stripe/route.ts',
      `
      import Stripe from 'stripe'
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
        return NextResponse.json({ received: true })
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const headerFindings = findings.filter((f) => f.title.includes('stripe-signature'))
    expect(headerFindings.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Razorpay webhook checks
// ---------------------------------------------------------------------------

describe('Razorpay webhook signature verification', () => {
  it('flags a Razorpay handler WITHOUT validateWebhookSignature (critical)', () => {
    const file = makeFile(
      'app/api/razorpay/webhook/route.ts',
      `
      import { NextRequest, NextResponse } from 'next/server'
      export async function POST(request: NextRequest) {
        const body = await request.json()
        // No signature verification — just trusting the payload
        if (body.event === 'payment.captured') {
          await fulfillOrder(body.payload.payment.entity)
        }
        return NextResponse.json({ received: true })
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const sigFindings = findings.filter((f) => f.title.includes('Razorpay webhook missing'))
    expect(sigFindings.length).toBeGreaterThan(0)
    expect(sigFindings[0].severity).toBe('critical')
    expect(sigFindings[0].blocking).toBe(true)
  })

  it('does NOT flag a Razorpay handler WITH validateWebhookSignature', () => {
    const file = makeFile(
      'app/api/razorpay/webhook/route.ts',
      `
      import Razorpay from 'razorpay'
      import { NextRequest, NextResponse } from 'next/server'
      export async function POST(request: NextRequest) {
        const body = await request.text()
        const signature = request.headers.get('x-razorpay-signature')!
        const isValid = Razorpay.validateWebhookSignature(body, signature, process.env.RAZORPAY_WEBHOOK_SECRET!)
        if (!isValid) {
          return NextResponse.json({ error: 'Invalid signature' }, { status: 400 })
        }
        const event = JSON.parse(body)
        await handleEvent(event)
        return NextResponse.json({ received: true })
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const sigFindings = findings.filter((f) => f.title.includes('Razorpay webhook missing'))
    expect(sigFindings.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Client-side payment secret exposure
// ---------------------------------------------------------------------------

describe('Client-side payment secret exposure', () => {
  it('flags STRIPE_SECRET_KEY in a client component (critical)', () => {
    const file = makeFile(
      'app/checkout/page.tsx',
      `
      'use client'
      import { loadStripe } from '@stripe/stripe-js'
      // BAD: using secret key on client
      const stripe = loadStripe(process.env.STRIPE_SECRET_KEY!)
      export default function CheckoutPage() {
        return <div>Checkout</div>
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const secretFindings = findings.filter((f) => f.title.includes('STRIPE_SECRET_KEY'))
    expect(secretFindings.length).toBeGreaterThan(0)
    expect(secretFindings[0].severity).toBe('critical')
    expect(secretFindings[0].blocking).toBe(true)
  })

  it('flags STRIPE_SECRET_KEY in a components/ file (critical)', () => {
    const file = makeFile(
      'components/PaymentForm.tsx',
      `
      // Accidentally using secret key in a component
      const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
      export function PaymentForm() {
        return <form />
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const secretFindings = findings.filter((f) => f.title.includes('STRIPE_SECRET_KEY'))
    expect(secretFindings.length).toBeGreaterThan(0)
    expect(secretFindings[0].severity).toBe('critical')
  })

  it('does NOT flag STRIPE_SECRET_KEY in a server-only API route file', () => {
    // A server-only file in app/api/ — not client-side
    const file = makeFile(
      'app/api/billing/route.ts',
      `
      import Stripe from 'stripe'
      const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
      export async function POST() {
        try {
          const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: [] })
          return Response.json({ url: session.url })
        } catch (err) {
          console.error(err)
          return Response.json({ error: 'Internal error' }, { status: 500 })
        }
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const secretFindings = findings.filter((f) => f.title.includes('STRIPE_SECRET_KEY'))
    expect(secretFindings.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Idempotency checks
// ---------------------------------------------------------------------------

describe('Webhook idempotency', () => {
  it('flags a webhook route with no idempotency handling (medium)', () => {
    const file = makeFile(
      'app/api/webhooks/stripe/route.ts',
      `
      import Stripe from 'stripe'
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
        // No duplicate-event protection here
        await fulfillOrder(event.data.object)
        return NextResponse.json({ received: true })
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const idempotencyFindings = findings.filter((f) => f.title.includes('idempotency'))
    expect(idempotencyFindings.length).toBeGreaterThan(0)
    expect(idempotencyFindings[0].severity).toBe('medium')
  })

  it('does NOT flag a webhook route WITH idempotency via event.id', () => {
    const file = makeFile(
      'app/api/webhooks/stripe/route.ts',
      `
      import Stripe from 'stripe'
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
        // Idempotency: skip if already processed
        const existing = await db.webhookEvents.findUnique({ where: { stripeEventId: event.id } })
        if (existing) return NextResponse.json({ received: true })
        await db.webhookEvents.create({ data: { stripeEventId: event.id } })
        await fulfillOrder(event.data.object)
        return NextResponse.json({ received: true })
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const idempotencyFindings = findings.filter((f) => f.title.includes('idempotency'))
    expect(idempotencyFindings.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Payment route error handling
// ---------------------------------------------------------------------------

describe('Payment route error handling', () => {
  it('flags a checkout route with no try/catch (low)', () => {
    const file = makeFile(
      'app/api/checkout/route.ts',
      `
      import Stripe from 'stripe'
      const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
      export async function POST() {
        // No error handling around Stripe call
        const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: [] })
        return Response.json({ url: session.url })
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const errorFindings = findings.filter((f) => f.title.includes('error handling'))
    expect(errorFindings.length).toBeGreaterThan(0)
    expect(errorFindings[0].severity).toBe('low')
  })

  it('does NOT flag a payment route that has try/catch', () => {
    const file = makeFile(
      'app/api/checkout/route.ts',
      `
      import Stripe from 'stripe'
      const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
      export async function POST() {
        try {
          const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: [] })
          return Response.json({ url: session.url })
        } catch (err) {
          console.error('Stripe session creation failed:', err)
          return Response.json({ error: 'Payment session failed' }, { status: 500 })
        }
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    const errorFindings = findings.filter((f) => f.title.includes('error handling'))
    expect(errorFindings.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Non-payment file — should not trigger
// ---------------------------------------------------------------------------

describe('Non-payment files', () => {
  it('produces no findings for a completely unrelated file', () => {
    const file = makeFile(
      'app/about/page.tsx',
      `
      export default function AboutPage() {
        return <div>About us</div>
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    expect(findings.length).toBe(0)
  })

  it('produces no findings for a utility lib file with no payment concerns', () => {
    const file = makeFile(
      'lib/formatDate.ts',
      `
      export function formatDate(date: Date): string {
        return date.toISOString()
      }
      `
    )
    const findings = payments.run([file], DEFAULT_POLICY)
    expect(findings.length).toBe(0)
  })
})
