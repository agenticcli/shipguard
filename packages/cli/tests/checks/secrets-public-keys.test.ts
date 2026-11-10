import { describe, it, expect } from 'vitest'
import { secretsCheck, isPublicKeyValue, isPlaceholderValue } from '../../src/checks/secrets.js'
import type { FileInfo, Policy } from '@agenticcli/shared'

// 0.12 Level A trust fixes: publishable keys and placeholder text are never "leaked secrets";
// a real secret next to them still is.

const POLICY: Policy = {
  version: 1,
  project: { name: 't', framework: 'next', risk_profile: 'standard' },
  scan: { changed_files_only: false, generate_report: false },
  block: ['exposed_env', 'hardcoded_secret'],
  warn: [],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}

const b64 = (o: object): string => Buffer.from(JSON.stringify(o)).toString('base64url')
const jwt = (role: string): string =>
  `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', ref: 'qwertyuiopasdfghjklz', role, exp: 2015000000 })}.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN`
const ANON = jwt('anon')
const SERVICE = jwt('service_role')
const PK_LIVE = 'pk_live_51HqwErTyUiOpAsDfGhJkLzXcVbNm1234'
const PK_TEST = 'pk_test_51HqwErTyUiOpAsDfGhJkLzXcVbNm1234'
const CLERK_PK = 'pk_live_Y2xlcmsuZXhhbXBsZS5jb20kQWJDZEVmR2hJ'
// built at runtime so no literal key-shaped string sits in the repo (GitHub push protection)
const SK_PLACEHOLDER = ['sk', 'live', 'x'.repeat(24)].join('_')
const SK_LIVE = ['sk', 'live', '51HqwErTyUiOpAsDfGhJkLzXcVbNm1234'].join('_')

const run = (path: string, content: string) => secretsCheck.run([{ path: `/p/${path}`, relativePath: path, content } as FileInfo], POLICY)
// .env files raise the separate "tracked .env" finding; these tests care about SECRET findings only.
const secretFindings = (path: string, content: string) => run(path, content).filter((f) => f.title !== '.env file tracked in git')

describe('public keys are not flagged', () => {
  it('helper: anon JWT, pk_ keys and sb_publishable_ are public; service_role and sk_ are not', () => {
    expect(isPublicKeyValue(ANON)).toBe(true)
    expect(isPublicKeyValue(PK_LIVE)).toBe(true)
    expect(isPublicKeyValue(PK_TEST)).toBe(true)
    expect(isPublicKeyValue(CLERK_PK)).toBe(true)
    expect(isPublicKeyValue('sb_publishable_AbCdEfGhIjKlMnOpQrStUv')).toBe(true)
    expect(isPublicKeyValue(SERVICE)).toBe(false)
    expect(isPublicKeyValue(SK_LIVE)).toBe(false)
    expect(isPublicKeyValue('sb_secret_AbCdEfGhIjKlMnOpQrStUv')).toBe(false)
    expect(isPublicKeyValue('eyJhbGciOiJIUzI1NiJ9.notjson.sig')).toBe(false)
  })

  it('NEXT_PUBLIC_SUPABASE_ANON_KEY in .env.local is not flagged', () => {
    expect(secretFindings('.env.local', `NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON}\n`)).toHaveLength(0)
  })

  it('NEXT_PUBLIC Stripe and Clerk publishable keys in .env.local are not flagged', () => {
    const env = `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=${PK_LIVE}\nNEXT_PUBLIC_STRIPE_TEST_KEY=${PK_TEST}\nNEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=${CLERK_PK}\n`
    expect(secretFindings('.env.local', env)).toHaveLength(0)
  })

  it('anon key and pk_live_ key assigned in an app/ component are not flagged', () => {
    const src = `const NEXT_PUBLIC_SUPABASE_ANON_KEY='${ANON}'\nconst apiKey = '${PK_LIVE}'\n`
    expect(secretFindings('app/page.tsx', src)).toHaveLength(0)
  })
})

describe('real secrets are still flagged', () => {
  it('service_role JWT is flagged', () => {
    const f = secretFindings('lib/admin.ts', `export const admin = createClient(url, '${SERVICE}')\n`)
    expect(f.length).toBeGreaterThan(0)
    expect(f[0].severity).toBe('critical')
  })

  it('NEXT_PUBLIC-prefixed service role key in .env.local is still flagged', () => {
    expect(secretFindings('.env.local', `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${SERVICE}\n`).length).toBeGreaterThan(0)
  })

  it('real sk_live_ key is flagged', () => {
    expect(secretFindings('lib/stripe.ts', `export const s = '${SK_LIVE}'\n`).length).toBeGreaterThan(0)
  })

  it('sk_live_ key and a pk_live_ key on the SAME line: the secret is still flagged', () => {
    const f = secretFindings('lib/pair.ts', `const cfg = { secret: '${SK_LIVE}', publishable: '${PK_LIVE}' }\n`)
    expect(f.some((x) => x.severity === 'critical')).toBe(true)
  })

  it('NEXT_PUBLIC_STRIPE_SECRET_KEY with a real sk_live_ value is flagged', () => {
    expect(secretFindings('.env.local', `NEXT_PUBLIC_STRIPE_SECRET_KEY=${SK_LIVE}\n`).length).toBeGreaterThan(0)
  })
})

describe('placeholder text is not flagged', () => {
  it('helper', () => {
    for (const v of [SK_PLACEHOLDER, 'sk-proj-REPLACE_ME_REPLACE_ME', 'your-api-key-here', 'sk_live_your_key_here', '<your-key>']) {
      expect(isPlaceholderValue(v)).toBe(true)
    }
    expect(isPlaceholderValue(SK_LIVE)).toBe(false)
    // a real key that merely contains a run of x is NOT a placeholder
    expect(isPlaceholderValue(['sk', 'live', 'AbCdxxxxxEfGh1234567890abcd'].join('_'))).toBe(false)
    expect(isPlaceholderValue('re_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxx')).toBe(true)
  })

  it('README and .env.local.example placeholders are not flagged', () => {
    expect(secretFindings('README.md', 'Set STRIPE_SECRET_KEY=' + SK_PLACEHOLDER + ' in .env.local\n')).toHaveLength(0)
    expect(secretFindings('.env.local.example', 'OPENAI_API_KEY=sk-proj-REPLACE_ME_REPLACE_ME_REPLACE_ME\n')).toHaveLength(0)
    expect(secretFindings('README.md', 'RESEND_API_KEY=re_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxx\n')).toHaveLength(0)
  })
})
