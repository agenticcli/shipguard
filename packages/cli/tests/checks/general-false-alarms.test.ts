import { describe, it, expect } from 'vitest'
import { authCheck } from '../../src/checks/auth.js'
import { secretsCheck, envFileHasSecret, isPlaceholderValue } from '../../src/checks/secrets.js'
import type { FileInfo, Policy } from '@agenticcli/shared'

// 0.12 Level A general false-alarm fixes (found by an independent proof run, fixed by principle).

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

describe('public_admin_route: page and layout chain', () => {
  it('a page under /dashboard that calls supabase.auth.getUser() is not flagged', () => {
    const page = f('app/dashboard/page.tsx', `export default async function P() { const { data } = await supabase.auth.getUser(); return <div/> }`)
    expect(authCheck.run([page], POLICY).filter((x) => x.id === 'public_admin_route')).toHaveLength(0)
  })
  it('a page with no auth anywhere IS flagged', () => {
    expect(authCheck.run([f('app/dashboard/page.tsx', PAGE)], POLICY).filter((x) => x.id === 'public_admin_route')).toHaveLength(1)
  })
  it('a page is protected when the layout above it checks the session', () => {
    const layout = f('app/dashboard/layout.tsx', `export default async function L({children}) { const s = await auth(); if (!s) redirect('/login'); return children }`)
    expect(authCheck.run([layout, f('app/dashboard/page.tsx', PAGE), f('app/dashboard/team/page.tsx', PAGE)], POLICY).filter((x) => x.id === 'public_admin_route')).toHaveLength(0)
  })
  it('a redirect to the login page counts as a guard', () => {
    const page = f('app/admin/page.tsx', `export default async function P() { if (!user) { redirect('/auth/login') } return <div/> }`)
    expect(authCheck.run([page], POLICY).filter((x) => x.id === 'public_admin_route')).toHaveLength(0)
  })
  it('helper files inside the folder are not judged as pages', () => {
    const helper = f('app/dashboard/_components/chart.tsx', PAGE)
    const page = f('app/dashboard/page.tsx', `export default async function P() { await getUser(); return <div/> }`)
    expect(authCheck.run([helper, page], POLICY).filter((x) => x.id === 'public_admin_route')).toHaveLength(0)
  })
  it('a commented-out auth call does not protect the page', () => {
    const page = f('app/dashboard/page.tsx', `// const s = await auth()\nexport default function P() { return <div/> }`)
    expect(authCheck.run([page], POLICY).filter((x) => x.id === 'public_admin_route')).toHaveLength(1)
  })
})

describe('exposed_env: only public values', () => {
  const run = (path: string, c: string) => secretsCheck.run([f(path, c)], POLICY)
  it('a .env.production with only public keys and URLs is not flagged', () => {
    const c = `NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${jwt('anon')}\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_${'A1b2C3d4'.repeat(4)}\nNODE_ENV=production\n`
    expect(run('.env.production', c)).toHaveLength(0)
  })
  it('the same file with a real secret IS flagged', () => {
    const c = `NEXT_PUBLIC_SUPABASE_ANON_KEY=${jwt('anon')}\nSUPABASE_SERVICE_ROLE_KEY=${jwt('service_role')}\n`
    expect(run('.env.production', c).length).toBeGreaterThan(0)
  })
  it('a secret-named key with a real value IS flagged even when the shape is unknown', () => {
    expect(run('.env', `INTERNAL_API_TOKEN=Zk39dPq81LmNx0Vb\n`).length).toBeGreaterThan(0)
    expect(envFileHasSecret(`DATABASE_URL=postgres://u:Zk39dPq81@db.example.org/x\n`)).toBe(true)
  })
  it('placeholders only is not flagged', () => {
    expect(envFileHasSecret(`STRIPE_SECRET_KEY=\nAPI_TOKEN=your-token-here\nJWT_SECRET=changeme\n`)).toBe(false)
  })
})

describe('placeholders: whole-value anchored', () => {
  it('common placeholder forms', () => {
    for (const v of ['your-key-here', '<YOUR_KEY>', 'changeme', 'sk_live_xxx', 'sk_live_xxxxxxxxxxxxxxxx', 'YOUR_API_KEY', '{{API_KEY}}', '${API_KEY}', 'postgres://user:password@localhost:5432/db', 'abc...', 'sk-proj-xxxx']) {
      expect(isPlaceholderValue(v), v).toBe(true)
    }
  })
  it('real-looking values are not placeholders', () => {
    for (const v of ['Zk39dPq81LmNx0VbQw7rTy2uIo5pAs8d', 'postgres://admin:pass@localhost:5432/mydb', ['sk', 'live', 'AbCdxxxxEfGh1234567890abcd'].join('_'), 'secretvalue123456789012345678']) {
      expect(isPlaceholderValue(v), v).toBe(false)
    }
  })
  it('README and .env.example placeholders are not findings', () => {
    const files = [
      f('README.md', 'OPENAI_API_KEY=your-key-here\nSTRIPE_SECRET_KEY=<YOUR_STRIPE_KEY>\nJWT_SECRET=changeme-changeme-changeme\n'),
      f('.env.example', 'API_TOKEN=your-token-here-0123456789abcdef0123456789abcdef\nDATABASE_URL=postgres://user:password@localhost:5432/db\n'),
    ]
    expect(secretsCheck.run(files, POLICY)).toHaveLength(0)
  })
})

describe('middleware matcher: the Next.js docs matcher is fine', () => {
  const mw = (m: string) => f('middleware.ts', `export { auth as default } from './auth'\nexport const config = { matcher: ['${m}'] }`)
  const findings = (m: string) => authCheck.run([mw(m), f('app/page.tsx', PAGE)], POLICY).filter((x) => x.id === 'public_admin_route')
  it('excluding api, _next and static files is not a finding', () => {
    expect(findings('/((?!api|_next/static|_next/image|favicon.ico).*)')).toHaveLength(0)
  })
  it('excluding the dashboard prefix IS a finding', () => {
    expect(findings('/((?!dashboard|_next/static).*)')).toHaveLength(1)
  })
})
