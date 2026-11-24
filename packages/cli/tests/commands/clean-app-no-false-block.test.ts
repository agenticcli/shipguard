/**
 * A clean, real-shaped app must not be blocked.
 *
 * FAIL-BEFORE (published 0.11.0): a Next.js app without a `middleware.ts` (or whose only guard is the
 * Next 16 `proxy.ts`) was reported as "No Next.js middleware.ts found" (HIGH), so
 * `shipguard scan --strict` exited 1 on a clean app. 0.12 reads `proxy.ts` as the middleware file
 * and never reports a missing one.
 *
 * PASS-AFTER: `scan --strict --json` exits 0 with no blocking finding on each fixture below, and the
 * same Stripe app with its signature check removed is still blocked (the fixtures are not blind).
 *
 * DISCIPLINE: behavioral - spawns the built binary against temp apps.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, runCli, type FileMap } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 30_000 })

afterEach(cleanupTrees)

const PKG_NEXT15 = JSON.stringify({
  name: 'clean-app',
  private: true,
  scripts: { dev: 'next dev', build: 'next build', start: 'next start' },
  dependencies: { next: '15.1.0', react: '19.0.0', 'react-dom': '19.0.0', '@workos-inc/authkit-nextjs': '1.4.0' },
})
const PKG_NEXT16 = PKG_NEXT15.replace('15.1.0', '16.0.0')

const COMMON: FileMap = {
  '.gitignore': 'node_modules\n.next\n.env\n.env.local\n',
  '.env.example': 'NEXT_PUBLIC_APP_URL=http://localhost:3000\nWORKOS_API_KEY=\nWORKOS_CLIENT_ID=\n',
  'app/layout.tsx': 'export default function Root({ children }: { children: React.ReactNode }) {\n  return <html lang="en"><body>{children}</body></html>\n}\n',
  'app/page.tsx': 'export default function Home() {\n  return <main><h1>Welcome</h1></main>\n}\n',
  'app/dashboard/page.tsx':
    "import { withAuth } from '@workos-inc/authkit-nextjs'\n" +
    "import { redirect } from 'next/navigation'\n" +
    'export default async function Dashboard() {\n' +
    '  const { user } = await withAuth()\n' +
    "  if (!user) redirect('/login')\n" +
    '  return <main>Hello {user.firstName}</main>\n}\n',
  'app/api/health/route.ts': "export async function GET() {\n  return Response.json({ ok: true })\n}\n",
}

// The shape `create-next-app` + AuthKit produce: matcher excludes static assets, everything else goes through auth.
const MIDDLEWARE_BODY =
  "import { authkitMiddleware } from '@workos-inc/authkit-nextjs'\n\n" +
  'export default authkitMiddleware()\n\n' +
  'export const config = {\n' +
  "  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)'],\n" +
  '}\n'

const WEBHOOK_OK =
  "import Stripe from 'stripe'\n" +
  "import { headers } from 'next/headers'\n\n" +
  'const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string)\n' +
  'const processed = new Set<string>()\n\n' +
  'export async function POST(req: Request) {\n' +
  '  const body = await req.text()\n' +
  "  const sig = (await headers()).get('stripe-signature')\n" +
  "  if (!sig) return new Response('missing signature', { status: 400 })\n" +
  '  let event: Stripe.Event\n' +
  '  try {\n' +
  '    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET as string)\n' +
  '  } catch (err) {\n' +
  "    console.error('webhook signature check failed', err)\n" +
  "    return new Response('bad signature', { status: 400 })\n" +
  '  }\n' +
  "  if (processed.has(event.id)) return new Response('ok', { status: 200 })\n" +
  '  processed.add(event.id)\n' +
  '  try {\n' +
  "    if (event.type === 'checkout.session.completed') {\n" +
  '      console.log(`paid: ${event.id}`)\n' +
  '    }\n' +
  '  } catch (err) {\n' +
  "    console.error('webhook handler failed', err)\n" +
  "    return new Response('handler error', { status: 500 })\n" +
  '  }\n' +
  "  return new Response('ok', { status: 200 })\n" +
  '}\n'

const STRIPE_ENV_EXAMPLE =
  'NEXT_PUBLIC_APP_URL=http://localhost:3000\nSTRIPE_SECRET_KEY=\nSTRIPE_WEBHOOK_SECRET=\nWORKOS_API_KEY=\nWORKOS_CLIENT_ID=\n'

async function strictScan(files: FileMap) {
  const dir = mkTree(files, { git: true })
  return runCli(['scan', dir, '--json', '--strict'])
}

function blockingIds(json: Record<string, any> | undefined): string[] {
  return ((json?.findings ?? []) as Array<{ id: string; blocking?: boolean; suppressed?: boolean }>)
    .filter((f) => f.blocking && !f.suppressed)
    .map((f) => f.id)
}

describe('clean real-shaped apps are not blocked', () => {
  it('Next 15 app with a real middleware.ts: --strict exits 0, no blocking finding', async () => {
    const r = await strictScan({ ...COMMON, 'package.json': PKG_NEXT15, 'middleware.ts': MIDDLEWARE_BODY })
    expect(r.stderr).not.toMatch(/No Next\.js middleware/i)
    expect(blockingIds(r.json)).toEqual([])
    expect(r.code).toBe(0)
  })

  it('Next 16 app whose guard is proxy.ts: --strict exits 0, no blocking finding', async () => {
    const r = await strictScan({ ...COMMON, 'package.json': PKG_NEXT16, 'proxy.ts': MIDDLEWARE_BODY.replace('export default authkitMiddleware()', 'export const proxy = authkitMiddleware()') })
    expect(JSON.stringify(r.json?.findings ?? [])).not.toMatch(/No Next\.js middleware/i)
    expect(blockingIds(r.json)).toEqual([])
    expect(r.code).toBe(0)
  })

  it('Next app with no middleware file at all: missing middleware is not a finding', async () => {
    const r = await strictScan({ ...COMMON, 'package.json': PKG_NEXT15 })
    expect(JSON.stringify(r.json?.findings ?? [])).not.toMatch(/No Next\.js middleware/i)
    expect(r.code).toBe(0)
  })

  it('clean Stripe app (signature check, idempotency, error handling): --strict exits 0', async () => {
    const r = await strictScan({
      ...COMMON,
      'package.json': PKG_NEXT15.replace('"dependencies":{', '"dependencies":{"stripe":"17.0.0",'),
      '.env.example': STRIPE_ENV_EXAMPLE,
      'middleware.ts': MIDDLEWARE_BODY,
      'app/api/webhooks/stripe/route.ts': WEBHOOK_OK,
    })
    expect(blockingIds(r.json)).toEqual([])
    expect(r.code).toBe(0)
  })

  it('negative control: the same Stripe app without the signature check is still blocked', async () => {
    const unsigned = WEBHOOK_OK.replace(
      'event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET as string)',
      'event = JSON.parse(body) as Stripe.Event',
    )
    const r = await strictScan({
      ...COMMON,
      'package.json': PKG_NEXT15.replace('"dependencies":{', '"dependencies":{"stripe":"17.0.0",'),
      '.env.example': STRIPE_ENV_EXAMPLE,
      'middleware.ts': MIDDLEWARE_BODY,
      'app/api/webhooks/stripe/route.ts': unsigned,
    })
    expect(r.json?.findings?.some((f: { id: string }) => f.id === 'payment_webhook_without_signature_check')).toBe(true)
    expect(r.code).toBe(1)
  })
})
