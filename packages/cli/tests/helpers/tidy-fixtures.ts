/**
 * Seeded fixture projects for the finding tidy-up (one webhook flaw = one finding, no
 * `line: null`, fake-looking keys at lower confidence). Plain data: each fixture is a map of
 * relative path -> file content. Fake key values are built from parts so no scanner that reads
 * this repo's source sees a whole key-shaped literal.
 */
import type { FileMap } from './cli-fixture.js'

const sk = (...parts: string[]) => parts.join('')

const STRIPE_UNSIGNED = [
  "import { NextResponse } from 'next/server'",
  'export async function POST(req: Request) {',
  '  const event = await req.json()',
  "  if (event.type === 'payment_intent.succeeded') await fulfill(event.data.object)",
  '  return NextResponse.json({ ok: true })',
  '}',
  'async function fulfill(o: unknown) { return o }',
  '',
].join('\n')

const STRIPE_SIGNED = [
  "import Stripe from 'stripe'",
  "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? '')",
  'export async function POST(req: Request) {',
  '  const raw = await req.text()',
  "  const sig = req.headers.get('stripe-signature') ?? ''",
  '  const event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET ?? \'\')',
  '  // idempotency: skip events already processed (event.id stored)',
  '  return new Response(event.id)',
  '}',
  '',
].join('\n')

const STRIPE_HEADER_ONLY_MISSING = [
  "import Stripe from 'stripe'",
  "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? '')",
  'export async function POST(req: Request) {',
  '  const raw = await req.text()',
  '  const event = stripe.webhooks.constructEvent(raw, getSig(req), process.env.STRIPE_WEBHOOK_SECRET ?? \'\')',
  '  return new Response(event.id)',
  '}',
  'function getSig(_r: Request) { return \'\' }',
  '',
].join('\n')

const RAZORPAY_UNSIGNED = [
  'export async function POST(req: Request) {',
  '  const body = await req.json()',
  '  return Response.json({ got: body.event })',
  '}',
  '',
].join('\n')

const PKG = '{"name":"fixture","dependencies":{"stripe":"1.0.0"}}\n'

/** name -> project files. Order is stable (golden diffs depend on it). */
export const TIDY_FIXTURES: Record<string, FileMap> = {
  'seeded-mixed': {
    'package.json': PKG,
    'app/api/stripe/webhook/route.ts': STRIPE_UNSIGNED,
    'app/admin/page.tsx': 'export default function Admin() { return <div>admin</div> }\n',
    'db/reset.sql': 'DROP TABLE users;\n',
    'lib/keys.ts': [
      `export const openai = '${sk('sk-proj-', 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb3dEf6hIj9kLm2nOp5q')}'`,
      `export const stripeLive = '${sk('sk_', 'live_', '51HxYzAbCdEfGhIjKlMnOpQrStUv')}'`,
      `export const looksFake = '${sk('sk_', 'live_', 'x'.repeat(24))}'`,
      `export const looksFake2 = '${sk('sk-', 'your-api-key-goes-here-1234567890')}'`,
      'export const svc = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY',
      '',
    ].join('\n'),
    '.env': `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${sk('eyJhbGciOiJIUzI1NiIs', 'InR5cCI6IkpXVCJ9.abcdefghij.klmnopqrst')}\n`,
  },
  'stripe-unsigned': { 'package.json': PKG, 'app/api/webhooks/stripe/route.ts': STRIPE_UNSIGNED },
  'stripe-signed': { 'package.json': PKG, 'app/api/webhooks/stripe/route.ts': STRIPE_SIGNED },
  'stripe-header-missing': { 'package.json': PKG, 'app/api/webhooks/stripe/route.ts': STRIPE_HEADER_ONLY_MISSING },
  'razorpay-unsigned': { 'package.json': PKG, 'app/api/webhooks/razorpay/route.ts': RAZORPAY_UNSIGNED },
  'keys-only': {
    'package.json': '{"name":"keys"}\n',
    'src/a.ts': [
      `const real = '${sk('sk-proj-', 'Zq8rT2vB5nM7xK1cD4fG6hJ9lP3sW0yA8eR2uI5oQ7tY1')}'`,
      `const ph1 = '${sk('sk-', 'proj-', 'a'.repeat(40))}'`,
      `const ph2 = '${sk('sk-', 'proj-', '1234567890'.repeat(4))}'`,
      `const ph3 = '${sk('sk_', 'live_', 'REPLACE_ME_REPLACE_ME_REPLACE')}'`,
      `const ph4 = '${sk('sk-', 'ant-', 'api03-', 'x'.repeat(40))}'`,
      '',
    ].join('\n'),
  },
}
