// The webhook-path skip in the auth check exists for webhook RECEIVERS (a provider calls them with no user session).
// A dashboard PAGE that merely lives under a `webhooks/` segment (the page where a signed-in admin manages webhooks)
// is a page, not a receiver, and must still be judged. Fail-before / pass-after.
import { describe, it, expect } from 'vitest'
import { authCheck } from '../../src/checks/auth.js'
import type { FileInfo, Policy } from '@agenticcli/shared'

const POLICY: Policy = {
  version: 1,
  project: { name: 't', framework: 'next', risk_profile: 'standard' },
  scan: { changed_files_only: false, generate_report: false },
  block: ['public_admin_route'],
  warn: [],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}
const f = (relativePath: string, content: string): FileInfo => ({ path: `/p/${relativePath}`, relativePath, content })
const PAGE = 'export default function Page() { return <div>hi</div> }'
const ids = (files: FileInfo[]) => authCheck.run(files, POLICY).filter((x) => x.id === 'public_admin_route').map((x) => x.file)

describe('auth check: webhook-path skip', () => {
  it('an unprotected admin page under a webhooks/ segment is still flagged', () => {
    expect(ids([f('app/admin/webhooks/page.tsx', PAGE)])).toEqual(['app/admin/webhooks/page.tsx'])
  })
  it('a protected admin page under webhooks/ is not flagged', () => {
    const ok = `import { auth } from '@/auth'\nimport { redirect } from 'next/navigation'\nexport default async function P() { const s = await auth(); if (!s) redirect('/login'); return <div/> }`
    expect(ids([f('app/admin/webhooks/page.tsx', ok)])).toEqual([])
  })
  it('a webhook receiver route stays skipped (no user session by design)', () => {
    const route = `export async function POST(req: Request) { return new Response('ok') }`
    expect(authCheck.run([f('app/api/billing/webhooks/stripe/route.ts', route)], POLICY).filter((x) => x.id === 'auth_route_without_guard')).toEqual([])
  })
})
