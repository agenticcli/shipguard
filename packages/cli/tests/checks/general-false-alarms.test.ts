// Purpose: regression tests for the 0.12 "general false alarm" fixes in the free checks, written so that
// quieting a false alarm never costs a real finding. Three families, each tested BOTH ways:
//   1. public_admin_route on a sensitive page: only a real gate (a session check whose result turns the
//      request away, or an enforcing call such as requireUser()) protects it; a session read for a nav bar,
//      a notFound() for a missing row, a getUser(<id>) data fetch, a comment, a string or a function nothing
//      calls must NOT protect it.
//   2. exposed_env: a tracked .env is reported unless EVERY value is a known-public shape or a whole-value
//      placeholder; any other non-empty value (SMTP_PASS, DB_PASS, JWT, SALT, whsec_, webhook URLs,
//      credential URLs) keeps the finding.
//   3. placeholders are matched against the whole value (or the whole password part of a URL), never as a
//      substring of something that may be a real key.
// Values that look like real keys are built at run time so no key-shaped literal sits in the repo.
import { describe, it, expect } from 'vitest'
import { authCheck } from '../../src/checks/auth.js'
import { secretsCheck, envFileHasSecret, isPlaceholderValue } from '../../src/checks/secrets.js'
import type { FileInfo, Policy } from '@agenticcli/shared'

const POLICY: Policy = {
  version: 1,
  project: { name: 't', framework: 'next', risk_profile: 'standard' },
  scan: { changed_files_only: false, generate_report: false },
  block: ['exposed_env', 'hardcoded_secret', 'public_admin_route'],
  warn: [],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}
const f = (relativePath: string, content: string): FileInfo => ({ path: `/p/${relativePath}`, relativePath, content })
const b64 = (o: object): string => Buffer.from(JSON.stringify(o)).toString('base64url')
const jwt = (role: string): string => `${b64({ alg: 'HS256' })}.${b64({ iss: 'supabase', role })}.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN`
const PAGE = 'export default function Page() { return <div>hi</div> }'
const adminFindings = (files: FileInfo[]) => authCheck.run(files, POLICY).filter((x) => x.id === 'public_admin_route')

describe('public_admin_route: a page is protected only by a real gate', () => {
  it('a plain page with no auth is flagged', () => {
    expect(adminFindings([f('app/dashboard/page.tsx', PAGE)])).toHaveLength(1)
  })

  // ---- bypasses that must still be flagged ----
  it('B1 guard only inside a block comment / line comment is flagged', () => {
    const page = f('app/dashboard/page.tsx', `/* const u = await getUser(); if (!u) redirect('/login') */\n// await requireUser()\nexport default function P() { return <div/> }`)
    expect(adminFindings([page])).toHaveLength(1)
  })
  it('B2 root layout reading the session for a nav bar does not protect the page', () => {
    const root = f('app/layout.tsx', `export default async function L({children}) { const { data } = await supabase.auth.getUser(); if (!data.user) redirect('/login'); return children }`)
    expect(adminFindings([root, f('app/dashboard/page.tsx', PAGE)])).toHaveLength(1)
  })
  it('B3 notFound() for a missing row is not an auth check', () => {
    const page = f('app/dashboard/page.tsx', `export default async function P() { const row = await db.get(); if (!row) notFound(); return <div/> }`)
    expect(adminFindings([page])).toHaveLength(1)
  })
  it('B4 getUser(<id>) is a data fetch, not a session check', () => {
    const page = f('app/dashboard/page.tsx', `export default async function P({ params }) { const u = await getUser(params.id); if (!u) notFound(); return <div>{u.name}</div> }`)
    expect(adminFindings([page])).toHaveLength(1)
  })
  it('B5 a guard function that the page never calls is dead code', () => {
    const page = f('app/dashboard/page.tsx', `async function check() { const u = await getUser(); if (!u) redirect('/login') }\nexport default function P() { return <div/> }`)
    expect(adminFindings([page])).toHaveLength(1)
  })
  it('B6 session read with no guard after it is flagged', () => {
    const page = f('app/dashboard/page.tsx', `export default async function P() { const { data } = await supabase.auth.getUser(); return <div>{data.user?.email}</div> }`)
    expect(adminFindings([page])).toHaveLength(1)
  })
  it('B7 guard text inside a string is flagged', () => {
    const page = f('app/dashboard/page.tsx', "export default function P() { const hint = \"call requireUser() or redirect('/login')\"; return <div>{hint}</div> }")
    expect(adminFindings([page])).toHaveLength(1)
  })
  it('B8 a session hook with no guard is flagged', () => {
    const page = f('app/dashboard/page.tsx', `'use client'\nexport default function P() { const { data } = useSession(); return <div>{data?.user?.name}</div> }`)
    expect(adminFindings([page])).toHaveLength(1)
  })
  it('B9 a guard in a layout that sits ABOVE the sensitive segment does not count', () => {
    const above = f('app/layout.tsx', `export default async function L({children}) { const s = await auth(); if (!s) redirect('/login'); return children }`)
    expect(adminFindings([above, f('app/settings/page.tsx', PAGE)])).toHaveLength(1)
  })

  // ---- real guards that must not be flagged ----
  it('if (!user) redirect() after getUser() is a guard', () => {
    const page = f('app/dashboard/page.tsx', `export default async function P() { const { data: { user } } = await supabase.auth.getUser(); if (!user) { redirect('/login') } return <div/> }`)
    expect(adminFindings([page])).toHaveLength(0)
  })
  it('await requireUser() is a guard', () => {
    expect(adminFindings([f('app/dashboard/page.tsx', `export default async function P() { await requireUser(); return <div/> }`)])).toHaveLength(0)
  })
  it('auth.protect() is a guard', () => {
    expect(adminFindings([f('app/admin/page.tsx', `export default async function P() { await auth.protect(); return <div/> }`)])).toHaveLength(0)
  })
  it('a guard in the layout of the same segment protects the pages below it', () => {
    const layout = f('app/dashboard/layout.tsx', `export default async function L({children}) { const s = await auth(); if (!s) redirect('/login'); return children }`)
    expect(adminFindings([layout, f('app/dashboard/page.tsx', PAGE), f('app/dashboard/team/page.tsx', PAGE)])).toHaveLength(0)
  })
  it('a guard inside a local helper that the page calls counts', () => {
    const page = f('app/dashboard/page.tsx', `async function guard() { const u = await getUser(); if (!u) redirect('/login'); return u }\nexport default async function P() { await guard(); return <div/> }`)
    expect(adminFindings([page])).toHaveLength(0)
  })
  it('helper files inside the folder are not judged as pages', () => {
    const page = f('app/dashboard/page.tsx', `export default async function P() { await requireUser(); return <div/> }`)
    expect(adminFindings([f('app/dashboard/_components/chart.tsx', PAGE), page])).toHaveLength(0)
  })
})

describe('middleware matcher: the Next.js docs matcher is fine', () => {
  const mw = (m: string) => f('middleware.ts', `export { auth as default } from './auth'\nexport const config = { matcher: ['${m}'] }`)
  const findings = (m: string) => adminFindings([mw(m), f('app/page.tsx', PAGE)])
  it('excluding api, _next and static files is not a finding', () => {
    expect(findings('/((?!api|_next/static|_next/image|favicon.ico).*)')).toHaveLength(0)
  })
  it('excluding the dashboard prefix IS a finding', () => {
    expect(findings('/((?!dashboard|_next/static).*)')).toHaveLength(1)
  })
})

describe('exposed_env: any real-looking value keeps the finding', () => {
  const run = (path: string, c: string) => secretsCheck.run([f(path, c)], POLICY)
  const PK = ['pk', 'live', 'A1b2C3d4'.repeat(4)].join('_')

  it('a .env.production with only public keys, URLs and flags is not flagged', () => {
    const c = `NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${jwt('anon')}\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=${PK}\nNODE_ENV=production\nPORT=3000\nNEXT_PUBLIC_APP_ID=app_8f3k2\n`
    expect(run('.env.production', c)).toHaveLength(0)
  })
  it('the same file plus a service_role key is flagged', () => {
    expect(run('.env.production', `NEXT_PUBLIC_SUPABASE_ANON_KEY=${jwt('anon')}\nSUPABASE_SERVICE_ROLE_KEY=${jwt('service_role')}\n`).length).toBeGreaterThan(0)
  })

  const secretValue = 'Zk39dPq81LmNx0Vb'
  const flagged: Array<[string, string]> = [
    ['SMTP_PASS', secretValue],
    ['DB_PASS', secretValue],
    ['MYSQL_PWD', secretValue],
    ['JWT', 'eyJhbGciOiJIUzI1NiJ9.' + secretValue],
    ['SESSION', secretValue],
    ['SALT', secretValue],
    ['WEBHOOK_SIGNING', ['whsec', 'Zk39dPq81LmNx0VbQw7rTy2u'].join('_')],
    ['SLACK_URL', ['https://hooks', 'slack.com/services/T0000/B0000/' + secretValue].join('.')],
    ['CACHE', `redis://:${secretValue}@cache.internal:6379`],
    ['DATABASE_URL', 'postgres://admin:password@db.internal:5432/app'],
    ['LOG_SINK', `https://user:${secretValue}@logs.example.org/ingest`],
  ]
  for (const [key, value] of flagged) {
    it(`${key} with a real value is flagged`, () => {
      expect(envFileHasSecret(`${key}=${value}\n`), key).toBe(true)
      expect(run('.env', `${key}=${value}\n`).length, key).toBeGreaterThan(0)
    })
  }

  it('a credential URL whose password is a whole-token placeholder is not flagged', () => {
    for (const pw of ['<pw>', '<password>', '${DB_PASSWORD}', 'your-password', 'changeme']) {
      expect(envFileHasSecret(`DATABASE_URL=postgres://postgres:${pw}@localhost:5432/app\n`), pw).toBe(false)
    }
  })
  it('<...> is a placeholder only when it is the whole value or the whole password part', () => {
    expect(envFileHasSecret(`DB_PASS=<${secretValue}>x\n`)).toBe(true)
    expect(envFileHasSecret(`DATABASE_URL=postgres://postgres:pre<pw>fix@localhost/app\n`)).toBe(true)
  })
  it('empty values and whole-value placeholders are not flagged', () => {
    expect(envFileHasSecret(`STRIPE_SECRET_KEY=\nAPI_TOKEN=your-token-here\nJWT_SECRET=changeme\nSMTP_PASS=<password>\n`)).toBe(false)
  })
})

describe('placeholders are whole-value, not a substring of a real key', () => {
  it('common placeholder forms', () => {
    for (const v of ['your-key-here', '<YOUR_KEY>', 'changeme', 'sk_live_xxx', 'sk_live_xxxxxxxxxxxxxxxx', 'YOUR_API_KEY', '{{API_KEY}}', '${API_KEY}', 'postgres://postgres:<pw>@localhost:5432/db', 'abc...', 'sk-proj-xxxx', 'sk-proj-REPLACE_ME_REPLACE_ME']) {
      expect(isPlaceholderValue(v), v).toBe(true)
    }
  })
  it('real-looking values are not placeholders', () => {
    for (const v of [
      'Zk39dPq81LmNx0VbQw7rTy2uIo5pAs8d',
      'postgres://admin:pass@localhost:5432/mydb',
      'postgres://admin:password@localhost:5432/mydb',
      ['sk', 'live', 'AbCdxxxxEfGh1234567890abcd'].join('_'),
      ['sk', 'live', 'AbCdplaceholderEfGh1234567890'].join('_'),
      'a1b2<c3>d4e5f6g7h8i9j0k1l2m3',
      'secretvalue123456789012345678',
    ]) {
      expect(isPlaceholderValue(v), v).toBe(false)
    }
  })
  it('README and .env.example placeholders are not findings', () => {
    const files = [
      f('README.md', 'OPENAI_API_KEY=your-key-here\nSTRIPE_SECRET_KEY=<YOUR_STRIPE_KEY>\nJWT_SECRET=changeme-changeme-changeme\n'),
      f('.env.example', 'API_TOKEN=your-token-here-0123456789abcdef0123456789abcdef\nDATABASE_URL=postgres://postgres:<pw>@localhost:5432/db\n'),
    ]
    expect(secretsCheck.run(files, POLICY)).toHaveLength(0)
  })
})
