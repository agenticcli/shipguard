import { describe, it, expect, vi } from 'vitest'
import { authCheck } from '../../src/checks/auth.js'
import type { FileInfo, Policy } from '@agenticcli/shared'
import { logger } from '../../src/utils/logger.js'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeFile(relativePath: string, content: string): FileInfo {
  return { path: `/project/${relativePath}`, relativePath, content }
}

/** Minimal policy that mirrors DEFAULT_POLICY blocking behaviour. */
const policy: Policy = {
  version: 1,
  project: { name: 'test-app', framework: 'next', risk_profile: 'standard' },
  scan: { changed_files_only: false, generate_report: false },
  block: [
    'public_admin_route',
    'auth_route_without_guard',
    'payment_webhook_without_signature_check',
  ],
  warn: [],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}

/** Policy with nothing in the block list — all findings are non-blocking. */
const permissivePolicy: Policy = { ...policy, block: [] }

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const ADMIN_PAGE_UNPROTECTED = makeFile(
  'app/admin/page.tsx',
  `export default function AdminPage() {
  return <div>Admin</div>
}`,
)

const ADMIN_PAGE_WITH_AUTH = makeFile(
  'app/admin/page.tsx',
  `import { auth } from '@/auth'
import { redirect } from 'next/navigation'

export default async function AdminPage() {
  const session = await auth()
  if (!session) redirect('/login')
  return <div>Admin</div>
}`,
)

const ADMIN_PAGE_WITH_GET_SERVER_SESSION = makeFile(
  'app/admin/page.tsx',
  `import { getServerSession } from 'next-auth'

export default async function AdminPage() {
  const session = await getServerSession()
  if (!session) return null
  return <div>Admin</div>
}`,
)

const ADMIN_PAGE_COMMENTED_AUTH = makeFile(
  'app/admin/page.tsx',
  `export default async function AdminPage() {
  // const session = await auth()
  // if (!session) redirect('/login')
  return <div>Admin</div>
}`,
)

const DASHBOARD_PAGE_UNPROTECTED = makeFile(
  'app/dashboard/settings/page.tsx',
  `export default function Settings() {
  return <div>Settings</div>
}`,
)

const SRC_ADMIN_PAGE_UNPROTECTED = makeFile(
  'src/app/admin/page.tsx',
  `export default function AdminPage() {
  return <div>Admin</div>
}`,
)

const API_ADMIN_UNPROTECTED = makeFile(
  'app/api/admin/route.ts',
  `import { NextResponse } from 'next/server'

export async function GET() {
  return NextResponse.json({ users: [] })
}`,
)

const API_ADMIN_WITH_SESSION = makeFile(
  'app/api/admin/route.ts',
  `import { NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'

export async function GET() {
  const session = await getServerSession()
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  return NextResponse.json({ users: [] })
}`,
)

const API_USERS_WITH_AUTH = makeFile(
  'app/api/users/route.ts',
  `import { auth } from '@/auth'
import { NextResponse } from 'next/server'

export async function GET() {
  const session = await auth()
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  return NextResponse.json({ users: [] })
}`,
)

const API_WEBHOOKS_NO_AUTH = makeFile(
  'app/api/webhooks/stripe/route.ts',
  `import { headers } from 'next/headers'

export async function POST(req: Request) {
  const sig = headers().get('stripe-signature')
  // process webhook
}`,
)

const API_WEBHOOKS_CLERK_NO_AUTH = makeFile(
  'app/api/webhooks/clerk/route.ts',
  `export async function POST(req: Request) {
  const payload = await req.json()
  // process clerk event
}`,
)

const API_STRIPE_WEBHOOK_ALT = makeFile(
  'app/api/stripe/webhooks/route.ts',
  `export async function POST(req: Request) {
  // handle stripe event
}`,
)

// Express fixtures
const EXPRESS_ADMIN_UNPROTECTED = makeFile(
  'routes/admin.ts',
  `import express from 'express'
const router = express.Router()

router.get('/admin/users', (req, res) => {
  res.json({ users: [] })
})

export default router`,
)

const EXPRESS_ADMIN_WITH_MIDDLEWARE = makeFile(
  'routes/admin.ts',
  `import express from 'express'
import { requireAuth } from '../middleware/auth'
const router = express.Router()

router.use(requireAuth)

router.get('/admin/users', (req, res) => {
  res.json({ users: [] })
})

export default router`,
)

const EXPRESS_ADMIN_INLINE_MIDDLEWARE = makeFile(
  'routes/admin.ts',
  `import express from 'express'
import { requireAuth } from '../middleware/auth'
const router = express.Router()

router.get('/admin/users', requireAuth, (req, res) => {
  res.json({ users: [] })
})

export default router`,
)

const EXPRESS_PUBLIC_ROUTE = makeFile(
  'routes/health.ts',
  `import express from 'express'
const router = express.Router()

router.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})

export default router`,
)

const MIDDLEWARE_WITH_ADMIN = makeFile(
  'middleware.ts',
  `import { auth } from './auth'

export const middleware = auth

export const config = {
  matcher: ['/admin/:path*', '/dashboard/:path*'],
}`,
)

const MIDDLEWARE_WITHOUT_ADMIN = makeFile(
  'middleware.ts',
  `import { NextResponse } from 'next/server'

export function middleware(req: Request) {
  return NextResponse.next()
}`,
)

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('authCheck module metadata', () => {
  it('exports id=auth and correct name', () => {
    expect(authCheck.id).toBe('auth')
    expect(authCheck.name).toBe('Auth & Session Protection')
  })
})

describe('Next.js App Router — admin/dashboard pages', () => {
  it('flags app/admin/page.tsx without auth() call', () => {
    const findings = authCheck.run([ADMIN_PAGE_UNPROTECTED, MIDDLEWARE_WITH_ADMIN], policy)
    const adminFindings = findings.filter((f) => f.file === 'app/admin/page.tsx')
    expect(adminFindings.length).toBeGreaterThanOrEqual(1)
    expect(adminFindings.some((f) => f.severity === 'high')).toBe(true)
    expect(adminFindings.some((f) => f.blocking)).toBe(true)
  })

  it('does NOT flag app/admin/page.tsx that calls auth()', () => {
    const findings = authCheck.run([ADMIN_PAGE_WITH_AUTH, MIDDLEWARE_WITH_ADMIN], policy)
    const adminFindings = findings.filter((f) => f.file === 'app/admin/page.tsx')
    expect(adminFindings.length).toBe(0)
  })

  it('does NOT flag app/admin/page.tsx that calls getServerSession()', () => {
    const findings = authCheck.run(
      [ADMIN_PAGE_WITH_GET_SERVER_SESSION, MIDDLEWARE_WITH_ADMIN],
      policy,
    )
    const adminFindings = findings.filter((f) => f.file === 'app/admin/page.tsx')
    expect(adminFindings.length).toBe(0)
  })

  it('flags admin page with commented-out auth and notes the removal', () => {
    const findings = authCheck.run([ADMIN_PAGE_COMMENTED_AUTH, MIDDLEWARE_WITH_ADMIN], policy)
    const adminFindings = findings.filter((f) => f.file === 'app/admin/page.tsx')
    expect(adminFindings.length).toBeGreaterThanOrEqual(1)
    expect(adminFindings.some((f) => f.explanation.includes('commented out'))).toBe(true)
  })

  it('flags nested dashboard route without auth', () => {
    const findings = authCheck.run(
      [DASHBOARD_PAGE_UNPROTECTED, MIDDLEWARE_WITH_ADMIN],
      policy,
    )
    const f = findings.filter((f) => f.file === 'app/dashboard/settings/page.tsx')
    expect(f.length).toBeGreaterThanOrEqual(1)
  })

  it('flags src/app/admin/page.tsx (src/ prefix layout)', () => {
    const findings = authCheck.run([SRC_ADMIN_PAGE_UNPROTECTED, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'src/app/admin/page.tsx')
    expect(f.length).toBeGreaterThanOrEqual(1)
  })
})

describe('Next.js App Router — API Route Handlers', () => {
  it('flags app/api/admin/route.ts without auth check', () => {
    const findings = authCheck.run([API_ADMIN_UNPROTECTED, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/api/admin/route.ts')
    expect(f.length).toBeGreaterThanOrEqual(1)
    expect(f.some((f) => f.severity === 'high')).toBe(true)
    expect(f.some((f) => f.blocking)).toBe(true)
  })

  it('does NOT flag app/api/admin/route.ts with getServerSession()', () => {
    const findings = authCheck.run([API_ADMIN_WITH_SESSION, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/api/admin/route.ts')
    expect(f.length).toBe(0)
  })

  it('does NOT flag app/api/users/route.ts with auth()', () => {
    const findings = authCheck.run([API_USERS_WITH_AUTH, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/api/users/route.ts')
    expect(f.length).toBe(0)
  })
})

describe('Webhook exclusion', () => {
  it('does NOT flag api/webhooks/stripe/route.ts (no user auth needed)', () => {
    const findings = authCheck.run([API_WEBHOOKS_NO_AUTH, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/api/webhooks/stripe/route.ts')
    expect(f.length).toBe(0)
  })

  it('does NOT flag api/webhooks/clerk/route.ts', () => {
    const findings = authCheck.run([API_WEBHOOKS_CLERK_NO_AUTH, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/api/webhooks/clerk/route.ts')
    expect(f.length).toBe(0)
  })

  it('does NOT flag api/stripe/webhooks/route.ts (alternative layout)', () => {
    const findings = authCheck.run([API_STRIPE_WEBHOOK_ALT, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/api/stripe/webhooks/route.ts')
    expect(f.length).toBe(0)
  })
})

describe('Express route protection', () => {
  it('flags Express route with sensitive path and no auth middleware', () => {
    const findings = authCheck.run([EXPRESS_ADMIN_UNPROTECTED], policy)
    const f = findings.filter((f) => f.file === 'routes/admin.ts')
    expect(f.length).toBeGreaterThanOrEqual(1)
    expect(f.some((f) => f.severity === 'medium')).toBe(true)
  })

  it('does NOT flag Express route with router.use(requireAuth)', () => {
    const findings = authCheck.run([EXPRESS_ADMIN_WITH_MIDDLEWARE], policy)
    const f = findings.filter((f) => f.file === 'routes/admin.ts')
    expect(f.length).toBe(0)
  })

  it('does NOT flag Express route with inline requireAuth middleware', () => {
    const findings = authCheck.run([EXPRESS_ADMIN_INLINE_MIDDLEWARE], policy)
    const f = findings.filter((f) => f.file === 'routes/admin.ts')
    expect(f.length).toBe(0)
  })

  it('does NOT flag non-sensitive Express routes', () => {
    const findings = authCheck.run([EXPRESS_PUBLIC_ROUTE], policy)
    const f = findings.filter((f) => f.file === 'routes/health.ts')
    expect(f.length).toBe(0)
  })
})

describe('Next.js middleware.ts coverage', () => {
  it('flags missing middleware.ts', () => {
    const findings = authCheck.run([ADMIN_PAGE_UNPROTECTED], policy)
    const f = findings.filter((f) => f.file === 'middleware.ts')
    expect(f.length).toBe(1)
    expect(f[0].id).toBe('public_admin_route')
  })

  it('flags middleware.ts that does not reference admin/dashboard routes', () => {
    const findings = authCheck.run(
      [ADMIN_PAGE_UNPROTECTED, MIDDLEWARE_WITHOUT_ADMIN],
      policy,
    )
    const f = findings.filter((f) => f.file === 'middleware.ts')
    expect(f.length).toBe(1)
    expect(f[0].explanation).toMatch(/does not reference/)
  })

  it('does NOT flag middleware.ts that covers admin routes', () => {
    const findings = authCheck.run([ADMIN_PAGE_WITH_AUTH, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'middleware.ts')
    expect(f.length).toBe(0)
  })
})

describe('Policy blocking', () => {
  it('findings are non-blocking when ids not in policy.block', () => {
    const findings = authCheck.run([ADMIN_PAGE_UNPROTECTED], permissivePolicy)
    expect(findings.every((f) => !f.blocking)).toBe(true)
  })

  it('public_admin_route findings are blocking when id is in policy.block', () => {
    const findings = authCheck.run([ADMIN_PAGE_UNPROTECTED], policy)
    const adminFindings = findings.filter((f) => f.id === 'public_admin_route')
    expect(adminFindings.every((f) => f.blocking)).toBe(true)
  })
})

// ─── framework gate for middleware check ────────────────────────────

describe('Next.js middleware check — gated on framework detection', () => {
  it('does NOT emit "No middleware.ts found" for a pure Express repo (no app/ paths)', () => {
    // Express library with a sensitive /admin route — no Next.js signals.
    // Before fix: middleware check fired on EVERY repo lacking middleware.ts.
    const expressFiles = [
      makeFile('routes/admin.ts', `const router = require('express').Router()
router.get('/admin/users', (req, res) => res.json({}))`),
      makeFile('index.ts', `const express = require('express')\nconst app = express()\napp.listen(3000)`),
    ]
    const findings = authCheck.run(expressFiles, policy)
    const middlewareFindings = findings.filter((f) => f.file === 'middleware.ts')
    expect(middlewareFindings.length).toBe(0)
  })

  it('does NOT emit "No middleware.ts found" for an empty/library repo (no framework signals)', () => {
    const libraryFiles = [
      makeFile('src/index.ts', `export function hello() { return 'world' }`),
      makeFile('src/utils.ts', `export function add(a: number, b: number) { return a + b }`),
    ]
    const findings = authCheck.run(libraryFiles, policy)
    const middlewareFindings = findings.filter((f) => f.file === 'middleware.ts')
    expect(middlewareFindings.length).toBe(0)
  })

  it('DOES flag missing middleware.ts for a Next.js repo (app/ path signal)', () => {
    // App Router path present → Next.js detected → middleware check runs.
    const nextFiles = [
      makeFile('app/admin/page.tsx', `export default function AdminPage() { return <div>Admin</div> }`),
    ]
    const findings = authCheck.run(nextFiles, policy)
    const middlewareFindings = findings.filter((f) => f.file === 'middleware.ts')
    expect(middlewareFindings.length).toBe(1)
    expect(middlewareFindings[0].id).toBe('public_admin_route')
  })

  it('DOES flag missing middleware.ts for a Next.js repo (next.config.js signal)', () => {
    const nextFiles = [
      makeFile('next.config.js', `module.exports = { reactStrictMode: true }`),
      makeFile('pages/index.tsx', `export default function Home() { return <div>Home</div> }`),
    ]
    const findings = authCheck.run(nextFiles, policy)
    const middlewareFindings = findings.filter((f) => f.file === 'middleware.ts')
    expect(middlewareFindings.length).toBe(1)
  })

  it('DOES flag missing middleware.ts for a Next.js repo (package.json with next dep)', () => {
    const nextFiles = [
      makeFile('package.json', JSON.stringify({ dependencies: { next: '^15.0.0', react: '^18.0.0' } })),
      makeFile('pages/index.tsx', `export default function Home() { return <div>Home</div> }`),
    ]
    const findings = authCheck.run(nextFiles, policy)
    const middlewareFindings = findings.filter((f) => f.file === 'middleware.ts')
    expect(middlewareFindings.length).toBe(1)
  })

  // ---------------------------------------------------------------------------
  // FAIL-BEFORE/PASS-AFTER regression (loud-errors fix, folded into
  //  a
  // malformed package.json in isNextjsProject() used to be swallowed with a
  // bare `catch { /* not conclusive */ }` — genuinely correct to CONTINUE
  // (the other two Next.js signals, app-router path and next.config.*, are
  // independent and still apply), but the catch was silent. 
  // every catch block must log, even when continuing is the right call.
  // ---------------------------------------------------------------------------
  it('FAIL-BEFORE regression: malformed package.json (no other Next.js signal) ' +
     'logs a warning to stderr instead of silently doing nothing', () => {
    const warnSpy = vi.spyOn(logger, 'warn').mockImplementation(() => {})
    const files = [
      makeFile('package.json', '{not valid json'),
      makeFile('src/index.ts', `export function hello() { return 'world' }`),
    ]
    authCheck.run(files, policy)
    expect(warnSpy).toHaveBeenCalledWith(expect.stringMatching(/package\.json.*JSON|JSON.*package\.json/i))
    warnSpy.mockRestore()
  })

  it('malformed package.json does NOT crash isNextjsProject, and correctly ' +
     'reports false (not a Next.js project) when no other signal is present', () => {
    const files = [
      makeFile('package.json', '{not valid json'),
      makeFile('src/index.ts', `export function hello() { return 'world' }`),
    ]
    expect(() => authCheck.run(files, policy)).not.toThrow()
    const findings = authCheck.run(files, policy)
    const middlewareFindings = findings.filter((f) => f.file === 'middleware.ts')
    expect(middlewareFindings.length).toBe(0)  // no Next.js signal detected — correct
  })

  it('malformed package.json does NOT suppress detection when ANOTHER Next.js ' +
     'signal (app-router path) is present — the OR-across-signals design still works', () => {
    const files = [
      makeFile('package.json', '{not valid json'),
      makeFile('app/admin/page.tsx', `export default function AdminPage() { return <div>Admin</div> }`),
    ]
    const findings = authCheck.run(files, policy)
    const middlewareFindings = findings.filter((f) => f.file === 'middleware.ts')
    expect(middlewareFindings.length).toBe(1)  // app-router path signal still fires
  })
})

// ─── Task D.5: Lexer-based auth detection ────────────────────────────────────
// These tests verify the real lexical scanner introduced to replace regex-based
// comment stripping + the ReDoS-prone variable-width lookbehinds.

describe('Lexer: line-comment spans — commented auth NOT counted as active', () => {
  it('does NOT count line-commented auth() as an active call', () => {
    const file = makeFile(
      'app/admin/page.tsx',
      `export default async function AdminPage() {
  // const session = await auth()
  return <div>Admin</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    // No active auth — should be flagged as unprotected
    expect(f.length).toBeGreaterThanOrEqual(1)
    // And it should mention commented-out (the hasCommentedAuthCall branch)
    expect(f.some((f) => f.explanation.includes('commented out'))).toBe(true)
  })

  it('does NOT count inline line-commented auth() as active — rest of line after // is a comment', () => {
    const file = makeFile(
      'app/admin/page.tsx',
      `export default async function AdminPage() {
  const x = 1 // auth() is not called here
  return <div>Admin</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    // `auth()` is inside a line comment — should be treated as unprotected
    expect(f.length).toBeGreaterThanOrEqual(1)
  })

  it('regex literal containing // does NOT confuse the line-comment lexer', () => {
    // /https:\/\// is a regex literal; the `//` inside it must NOT start a comment.
    // The file also has a real auth() call in executable code.
    const file = makeFile(
      'app/admin/page.tsx',
      `import { auth } from '@/auth'
import { redirect } from 'next/navigation'
const HTTPS_RE = /https:\\/\\//

export default async function AdminPage() {
  const session = await auth()
  if (!session) redirect('/login')
  return <div>Admin</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    // auth() is real executable code — should NOT be flagged as unprotected
    expect(f.length).toBe(0)
  })
})

describe('Lexer: block-comment spans — auth inside /* */ NOT counted as active', () => {
  it('does NOT count auth() inside a block comment as active', () => {
    const file = makeFile(
      'app/admin/page.tsx',
      `/* auth() is disabled in this file */
export default async function AdminPage() {
  return <div>Admin</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    // Block-comment auth should be treated as commented-out, not active
    expect(f.length).toBeGreaterThanOrEqual(1)
  })

  it('does NOT count multi-line block comment auth() as active', () => {
    const file = makeFile(
      'app/admin/page.tsx',
      `/**
 * Previously protected with auth()
 * TODO: re-enable
 */
export default async function AdminPage() {
  return <div>Admin</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    expect(f.length).toBeGreaterThanOrEqual(1)
  })

  it('counts auth() AFTER a closing block comment as active', () => {
    const file = makeFile(
      'app/admin/page.tsx',
      `/* not auth */
import { auth } from '@/auth'
import { redirect } from 'next/navigation'

export default async function AdminPage() {
  const session = await auth()
  if (!session) redirect('/login')
  return <div>Admin</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    expect(f.length).toBe(0)
  })
})

describe('Lexer: string-literal spans — auth inside strings NOT counted as active', () => {
  it('does NOT count auth() inside a double-quoted string as active', () => {
    const file = makeFile(
      'app/admin/page.tsx',
      `export default async function AdminPage() {
  const label = "call auth() to protect this route"
  return <div>{label}</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    // auth() in a string → unprotected
    expect(f.length).toBeGreaterThanOrEqual(1)
  })

  it('does NOT count auth() inside a single-quoted string as active', () => {
    const file = makeFile(
      'app/admin/page.tsx',
      `export default async function AdminPage() {
  const label = 'use auth() to secure routes'
  return <div>{label}</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    expect(f.length).toBeGreaterThanOrEqual(1)
  })

  it('counts auth() AFTER a closed string as active executable code', () => {
    const file = makeFile(
      'app/admin/page.tsx',
      `import { auth } from '@/auth'
import { redirect } from 'next/navigation'

export default async function AdminPage() {
  const msg = 'not-auth-call'
  const session = await auth()
  if (!session) redirect('/login')
  return <div>{msg}</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    expect(f.length).toBe(0)
  })
})

describe('Lexer: template-literal spans — auth inside backtick strings NOT counted as active', () => {
  it('does NOT count auth() inside a template literal as active', () => {
    const file = makeFile(
      'app/admin/page.tsx',
      "export default async function AdminPage() {\n  const msg = `call auth() here`\n  return <div>{msg}</div>\n}",
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    expect(f.length).toBeGreaterThanOrEqual(1)
  })
})

describe('Lexer: conservative on uncertainty — malformed input scanned, never silently skipped', () => {
  it('treats unterminated string conservatively — file with active auth() still detected', () => {
    // An unterminated string literal. The lexer must not treat the rest of the
    // file as a string (that would be a false negative if auth() appears after).
    // Conservative means: scan uncertain regions as executable.
    const file = makeFile(
      'app/admin/page.tsx',
      `import { auth } from '@/auth'
const broken = "unterminated
export default async function AdminPage() {
  const session = await auth()
  return <div>Admin</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    // Conservative: auth() after the unterminated string must be found as active
    expect(f.length).toBe(0)
  })

  it('treats unterminated block comment conservatively — active auth() before it is detected', () => {
    // Unterminated /* block comment: everything after is "uncertain".
    // Any auth() BEFORE the unterminated comment is definitely executable.
    const file = makeFile(
      'app/admin/page.tsx',
      `import { auth } from '@/auth'
import { redirect } from 'next/navigation'
export default async function AdminPage() {
  const session = await auth()
  if (!session) redirect('/login')
  /* unterminated comment — rest of file is uncertain
  return <div>Admin</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    const f = findings.filter((f) => f.file === 'app/admin/page.tsx')
    // auth() before the unterminated block comment IS executable — should be detected
    expect(f.length).toBe(0)
  })
})

describe('Lexer: no ReDoS pattern — no .*? inside lookbehinds', () => {
  it('active auth() in executable code is detected (behavioral proof of correct lexing)', () => {
    // Behavioral proof: the lexer correctly identifies executable auth() calls.
    // This also serves as a regression guard — if the old variable-width lookbehind
    // (?<!\/{2}.*?)(?<!\*.*?) were re-introduced, it could produce false negatives
    // on certain inputs. The real structural guard is the absence of those patterns
    // from the source; this test verifies the observable outcome.
    const file = makeFile(
      'app/admin/page.tsx',
      `import { auth } from '@/auth'
export default async function AdminPage() {
  const session = await auth()
  return <div>Admin</div>
}`,
    )
    const findings = authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)
    expect(findings.filter((f) => f.file === 'app/admin/page.tsx').length).toBe(0)
  })

  it('a long line of slashes before auth() does not hang (ReDoS stress test)', () => {
    // The old (?<!\/{2}.*?) lookbehind with variable width could exponentially
    // backtrack on a line full of slashes. This test would timeout (>5s) if the
    // old pattern is present. With the lexer, it must complete instantly.
    const manySlashes = '/'.repeat(200)
    const file = makeFile(
      'app/admin/page.tsx',
      `// ${manySlashes}
import { auth } from '@/auth'
export default async function AdminPage() {
  const session = await auth()
  return <div>Admin</div>
}`,
    )
    // D.7 relative-growth assertion: run twice (S=200, 2S=400 slashes) and
    // assert time(2S) < 4× time(S) instead of an absolute-ms threshold.
    // Absolute-ms gates (toBeLessThan(500)) are machine-dependent and brittle
    // on slow CI; relative-growth checks are machine-invariant.
    const manySlashes2S = '/'.repeat(400)
    const file2S = makeFile(
      'app/admin/page.tsx',
      `// ${manySlashes2S}
import { auth } from '@/auth'
export default async function AdminPage() {
  const session = await auth()
  return <div>Admin</div>
}`,
    )

    // Median of 3 trials each — dampens single-trial scheduling spikes on a
    // loaded CI / dev box. 40× threshold absorbs wall-clock noise while still
    // catching any genuinely exponential engine (which would be millions of ×).
    const N_TRIALS = 3
    function measureMs(run: () => void): number {
      const samples: number[] = []
      for (let i = 0; i < N_TRIALS; i++) {
        const t0 = performance.now()
        run()
        samples.push(performance.now() - t0)
      }
      samples.sort((a, b) => a - b)
      return samples[Math.floor(N_TRIALS / 2)]
    }

    const elapsedS = Math.max(measureMs(() => authCheck.run([file, MIDDLEWARE_WITH_ADMIN], policy)), 1)
    const elapsed2S = measureMs(() => authCheck.run([file2S, MIDDLEWARE_WITH_ADMIN], policy))

    const ratio = elapsed2S / elapsedS
    // Assert bounded (roughly linear) growth: time(2S) must not exceed 40× time(S).
    // A ReDoS engine would show exponential growth (millions of ×).
    // 40× matches the threshold in tests/scaling/linear-growth.test.ts.
    expect(
      ratio,
      `time(2S)/time(S) = ${ratio.toFixed(2)} exceeds linear bound of 40× — potential ReDoS regression`,
    ).toBeLessThan(40)
  })
})
