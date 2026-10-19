import { describe, it, expect } from 'vitest'
import { secretsCheck } from '../../src/checks/secrets.js'
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
  block: ['exposed_env', 'hardcoded_secret'],
  warn: [],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}

// ---------------------------------------------------------------------------
// Positive tests: should trigger findings
// ---------------------------------------------------------------------------

describe('secretsCheck — positive cases (should trigger)', () => {
  it('detects hardcoded OPENAI_API_KEY with sk-proj- prefix', () => {
    const file = makeFile(
      'lib/ai.ts',
      `const client = new OpenAI({ apiKey: 'sk-proj-abc1234XYZabcXYZabc12345' })`
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.length).toBeGreaterThan(0)
    const f = findings[0]
    expect(f.id).toBe('hardcoded_secret')
    expect(f.severity).toBe('high')
    expect(f.category).toBe('secrets')
    expect(f.blocking).toBe(true)
    // Evidence should be redacted — not expose the full key
    expect(f.evidence).not.toContain('abc1234XYZabcXYZabc12345')
  })

  it('detects hardcoded STRIPE_SECRET_KEY with sk_live_ prefix', () => {
    const file = makeFile(
      'lib/stripe.ts',
      `const stripe = new Stripe('sk_live_abcdefghijklmnopqrstuvwx')`
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.length).toBeGreaterThan(0)
    const f = findings[0]
    expect(f.id).toBe('hardcoded_secret')
    expect(f.severity).toBe('critical')
    expect(f.blocking).toBe(true)
  })

  it('detects .env file tracked in git', () => {
    const file = makeFile('.env', `OPENAI_API_KEY=sk-proj-secret\nSTRIPE_SECRET_KEY=sk_live_foo`)
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const dotEnvFinding = findings.find(f => f.title === '.env file tracked in git')
    expect(dotEnvFinding).toBeDefined()
    expect(dotEnvFinding?.id).toBe('exposed_env')
    expect(dotEnvFinding?.severity).toBe('high')
    expect(dotEnvFinding?.blocking).toBe(true)
  })

  it('detects .env.local file tracked in git', () => {
    const file = makeFile('.env.local', `SECRET=supersecretvalue`)
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const dotEnvFinding = findings.find(f => f.title === '.env file tracked in git')
    expect(dotEnvFinding).toBeDefined()
  })

  it('detects private key block (RSA)', () => {
    const file = makeFile(
      'certs/server.key',
      `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...base64content...\n-----END RSA PRIVATE KEY-----`
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const pkFinding = findings.find(f => f.title === 'Private key block in source')
    expect(pkFinding).toBeDefined()
    expect(pkFinding?.severity).toBe('critical')
    expect(pkFinding?.id).toBe('hardcoded_secret')
    expect(pkFinding?.blocking).toBe(true)
  })

  it('detects NEXT_PUBLIC_ secret exposure in frontend file (critical)', () => {
    const file = makeFile(
      'app/layout.tsx',
      `const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY ?? 'sk_live_defaultfallback123'`
    )
    // The pattern looks for literal assignment in the file content
    const fileWithLiteral = makeFile(
      'app/config.ts',
      `export const stripeKey = 'NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_mypublickeyleak'`
    )
    const fileWithEnvAssignment = makeFile(
      'app/config.ts',
      `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_mypublickeyleak1234`
    )
    const findings = secretsCheck.run([fileWithEnvAssignment], DEFAULT_POLICY)
    const frontendFinding = findings.find(f => f.title === 'Secret exposed via NEXT_PUBLIC_ prefix')
    expect(frontendFinding).toBeDefined()
    expect(frontendFinding?.severity).toBe('critical')
    expect(frontendFinding?.id).toBe('exposed_env')
    expect(frontendFinding?.blocking).toBe(true)
  })

  it('detects private key block (generic PRIVATE KEY)', () => {
    const content = [
      'const pemKey = `',
      '-----BEGIN PRIVATE KEY-----',
      'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...',
      '-----END PRIVATE KEY-----',
      '`',
    ].join('\n')
    const file = makeFile('lib/crypto.ts', content)
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.some(f => f.title === 'Private key block in source')).toBe(true)
  })

  it('detects Stripe sk_live key assigned via variable', () => {
    const file = makeFile(
      'server/payments.ts',
      `const STRIPE_SECRET_KEY = 'sk_live_abcde12345678901234567890'`
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.some(f => f.id === 'hardcoded_secret')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Negative tests: should NOT trigger
// ---------------------------------------------------------------------------

describe('secretsCheck — negative cases (should NOT trigger)', () => {
  it('does NOT flag .env.example file', () => {
    const file = makeFile(
      '.env.example',
      `OPENAI_API_KEY=your-openai-key-here\nSTRIPE_SECRET_KEY=sk_live_your_key`
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const dotEnvFinding = findings.find(f => f.title === '.env file tracked in git')
    expect(dotEnvFinding).toBeUndefined()
  })

  it('does NOT flag .env.sample file', () => {
    const file = makeFile('.env.sample', `DATABASE_URL=postgres://user:pass@host/db`)
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.find(f => f.title === '.env file tracked in git')).toBeUndefined()
  })

  it('does NOT flag process.env.API_KEY reference (no literal value)', () => {
    const file = makeFile(
      'lib/client.ts',
      `const apiKey = process.env.OPENAI_API_KEY\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)`
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    // Should have no hardcoded_secret findings (env references are fine)
    const hardcoded = findings.filter(f => f.id === 'hardcoded_secret')
    expect(hardcoded.length).toBe(0)
  })

  it('does NOT flag regular code with no secrets', () => {
    const file = makeFile(
      'lib/utils.ts',
      `export function formatCurrency(amount: number): string {\n  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount)\n}`
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.length).toBe(0)
  })

  it('does NOT flag .env.template file', () => {
    const file = makeFile('.env.template', `API_KEY=<your-api-key>`)
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.find(f => f.title === '.env file tracked in git')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Blocking behaviour respects policy.block list
// ---------------------------------------------------------------------------

describe('secretsCheck — blocking respects policy', () => {
  it('finding is not blocking when id is absent from policy.block', () => {
    const permissivePolicy: Policy = {
      ...DEFAULT_POLICY,
      block: [], // nothing blocks
    }
    const file = makeFile('lib/ai.ts', `const apiKey = 'sk-proj-abc1234XYZabcXYZabc12345'`)
    const findings = secretsCheck.run([file], permissivePolicy)
    expect(findings.every(f => f.blocking === false)).toBe(true)
  })

  it('finding IS blocking when id is in policy.block', () => {
    const file = makeFile('lib/ai.ts', `const apiKey = 'sk-proj-abc1234XYZabcXYZabc12345'`)
    const findings = secretsCheck.run([file], DEFAULT_POLICY) // block includes 'hardcoded_secret'
    const hardcoded = findings.filter(f => f.id === 'hardcoded_secret')
    expect(hardcoded.length).toBeGreaterThan(0)
    expect(hardcoded.every(f => f.blocking)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Same-pattern matches — two same-pattern secrets on different lines both reported
// ---------------------------------------------------------------------------

describe('secretsCheck — same-pattern matches: all same-pattern matches reported (no early break)', () => {
  it('two AWS access key IDs on separate lines → 2 findings', () => {
    const file = makeFile(
      'config/aws.ts',
      [
        `const key1 = 'AKIAIOSFODNN7EXAMPLE01'`,
        `const key2 = 'AKIAIOSFODNN7EXAMPLE02'`,
      ].join('\n')
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const awsFindings = findings.filter(f => f.title === 'AWS Access Key ID')
    expect(awsFindings.length).toBe(2)
    expect(awsFindings[0].line).not.toBe(awsFindings[1].line)
  })
})

// ---------------------------------------------------------------------------
// Bare DB URI detection — bare DB URI without recognized var-name prefix is still flagged
// ---------------------------------------------------------------------------

describe('secretsCheck — bare DB URI detection: bare DB URI detected regardless of var name', () => {
  it('camelCase var name with mongodb:// credentials → flagged as hardcoded_secret', () => {
    const file = makeFile(
      'lib/db.ts',
      `const uri = "mongodb://admin:s3cr3tPass@host.example.com/mydb"`
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const dbFindings = findings.filter(f => f.title === 'Database URL with Credentials')
    expect(dbFindings.length).toBeGreaterThan(0)
    expect(dbFindings[0].id).toBe('hardcoded_secret')
    expect(dbFindings[0].severity).toBe('critical')
  })

  it('postgres:// URI with credentials in bare assignment → flagged', () => {
    const file = makeFile(
      'server/database.ts',
      `const connectionString = "postgres://dbuser:hunter2@db.prod.internal/appdb"`
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const dbFindings = findings.filter(f => f.title === 'Database URL with Credentials')
    expect(dbFindings.length).toBeGreaterThan(0)
  })

  it('standard DATABASE_URL= assignment still detected after regex change', () => {
    const file = makeFile(
      '.env',
      `DATABASE_URL=postgres://admin:pass@localhost:5432/mydb`
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const dbFindings = findings.filter(f => f.title === 'Database URL with Credentials')
    expect(dbFindings.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// FIX 3: backtick (template literal) secret not skipped by env-ref guard
//
// The bug: the env-ref skip only checked for `'` and `"` in the line.
// A line like:
//   const k = process.env.KEY || `sk_live_abc123...`
// has no `'` or `"`, only backticks — so the entire line was skipped as a
// "pure env reference" and the hardcoded backtick secret was missed (FALSE NEGATIVE).
//
// BEFORE FIX: line with backtick secret + env ref was skipped → secret NOT flagged.
// AFTER FIX:  backtick is included in the guard → line is scanned → secret IS flagged.
// ---------------------------------------------------------------------------

describe('secretsCheck — FIX 3: backtick template-literal secret not skipped by env-ref guard', () => {

  it('FIX 3: process.env.KEY || `sk_live_...` — backtick secret IS flagged', () => {
    // BEFORE FIX: no `'` or `"` on the line → env-ref guard skipped it → FALSE NEGATIVE.
    // AFTER FIX:  backtick check prevents skip → line is scanned → secret IS detected.
    const file = makeFile(
      'lib/payments.ts',
      'const key = process.env.STRIPE_KEY || `sk_live_abcdefghijklmnopqrstuvwx`',
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const stripeFindings = findings.filter(f => f.title === 'Stripe Live Secret Key')
    expect(stripeFindings.length, 'sk_live_ in a backtick literal alongside env ref must be flagged').toBeGreaterThan(0)
  })

  it('FIX 3: pure process.env.SECRET with no quotes/backticks — still NOT flagged', () => {
    // Pure env reference with no string literal of any kind → must still be skipped.
    const file = makeFile(
      'lib/config.ts',
      'const apiKey = process.env.STRIPE_SECRET_KEY',
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const hardcoded = findings.filter(f => f.id === 'hardcoded_secret')
    expect(hardcoded.length, 'pure env reference with no quotes must still be skipped').toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Free-tier secret gaps — Supabase service-role key patterns (seen on real projects). Real values below are
// synthetic (never-issued) values, the same as those used in
// content-pipeline-captures/supabase-rls-ai-built-apps/fixture.env.local.txt.
//
// Precision guard: the legacy-JWT detector decodes the payload and only fires
// when the `role` claim is EXACTLY "service_role" — this is the differentiator
// vs. a generic shape-only `jwt` rule (gitleaks in the article fired identically
// on the anon control key, "a match without a meaning").
// ---------------------------------------------------------------------------

const ANON_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.fakeAnonSignatureForDemoOnlyDoNotUse'
const SERVICE_ROLE_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.fakeServiceRoleSignatureForDemoOnlyDoNotUse'
const AUTHENTICATED_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYXV0aGVudGljYXRlZCJ9.fakeAuthenticatedSigDemoOnly'

describe('secretsCheck — Supabase service-role key (free-tier secret gaps)', () => {
  it('FAIL-BEFORE/PASS-AFTER: legacy-format service-role JWT in .env is flagged critical', () => {
    const file = makeFile(
      '.env.local',
      `NEXT_PUBLIC_SUPABASE_URL=https://spacey-demo.supabase.co\n` +
      `NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON_JWT}\n` +
      `SUPABASE_SERVICE_ROLE_KEY=${SERVICE_ROLE_JWT}\n`,
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const f = findings.find((x) => x.title === 'Supabase Service-Role Key (legacy JWT format)')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('critical')
    expect(f!.line).toBe(3)
    expect(f!.blocking).toBe(true)
    // Evidence must be redacted, never the full key
    expect(f!.evidence).not.toContain('service_role')
  })

  it('precision guard: the anon-role JWT (public by design) is NEVER flagged as service-role', () => {
    const file = makeFile('.env.local', `NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON_JWT}\n`)
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.some((f) => f.title === 'Supabase Service-Role Key (legacy JWT format)')).toBe(false)
  })

  it('precision guard: an "authenticated" role JWT is also not flagged as service-role', () => {
    const file = makeFile('.env.local', `SOME_USER_SESSION_JWT=${AUTHENTICATED_JWT}\n`)
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.some((f) => f.title === 'Supabase Service-Role Key (legacy JWT format)')).toBe(false)
  })

  it('the service-role JWT is caught the same way when hardcoded in a .ts source file, not just .env', () => {
    const file = makeFile(
      'lib/supabase-admin.ts',
      `import { createClient } from '@supabase/supabase-js'\nconst supabaseAdmin = createClient(url, "${SERVICE_ROLE_JWT}")`,
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.some((f) => f.title === 'Supabase Service-Role Key (legacy JWT format)')).toBe(true)
  })

  it('does not throw and does not flag on a malformed/garbage eyJ...eyJ...-shaped string', () => {
    const file = makeFile(
      '.env',
      'RANDOM_LOOKING_VALUE=eyJnb3RjaGEiOnRydWV9.eyJub3RfcmVhbF9qc29uIQ.notvalidsignature123\n',
    )
    expect(() => secretsCheck.run([file], DEFAULT_POLICY)).not.toThrow()
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.some((f) => f.title === 'Supabase Service-Role Key (legacy JWT format)')).toBe(false)
  })

  it('current-format Supabase service-role key (sb_secret_ prefix) is flagged critical', () => {
    const file = makeFile(
      '.env',
      'SUPABASE_SERVICE_ROLE_KEY=sb_secret_abcdefghijklmnopqrstuvwxyz0123456789\n',
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const f = findings.find((x) => x.title === 'Supabase Service-Role Key')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Free-tier secret gaps — secrets INSIDE .env file content were missed even though the
// identical value hardcoded in a source file was caught. Evidenced two distinct
// root causes:
//  (a) NEXT_PUBLIC_ exposure check was gated to app/pages/components paths only
//      (isFrontendFile) and never looked at .env content at all.
//  (b) Two generic-name patterns (JWT Secret, High-Entropy Secret String)
//      required MANDATORY quote characters around the value — true for
//      `const x = "value"` source style, never true for a .env file's
//      unquoted `KEY=value` line. Confirmed via the article's own A/B probe:
//      quoting .env.local values produced identical findings, excluding
//      quoting as a red herring — the real gap was the .env file TYPE.
// ---------------------------------------------------------------------------

describe('secretsCheck — .env content scanning gap (free-tier secret gaps)', () => {
  it('FAIL-BEFORE/PASS-AFTER: NEXT_PUBLIC_ service-role key sitting in .env.local is flagged ' +
     '(not just when hardcoded in a frontend source file)', () => {
    const file = makeFile(
      '.env.local',
      `NEXT_PUBLIC_SUPABASE_URL=https://spacey-demo.supabase.co\n` +
      `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${SERVICE_ROLE_JWT}\n`,
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const f = findings.find((x) => x.title === 'Secret exposed via NEXT_PUBLIC_ prefix')
    expect(f).toBeDefined()
    expect(f!.line).toBe(2)
    expect(f!.severity).toBe('critical')
  })

  it('FAIL-BEFORE/PASS-AFTER: unquoted high-entropy token in .env is flagged — ' +
     'the same token IS already caught (unchanged) when quoted in a source file', () => {
    const token = 'aB3xQ9zK7mN2pR5vT8wY1cD4fG6hJ0kL3nQ5sU7xZ9bE2gH4jM6pS8vW0yA1cF3d'
    const envFile = makeFile('.env', `INTERNAL_DEPLOY_TOKEN=${token}\n`)
    const envFindings = secretsCheck.run([envFile], DEFAULT_POLICY)
    expect(envFindings.some((f) => f.title === 'High-Entropy Secret String')).toBe(true)

    // Control: still detected when quoted in a source file (pre-existing, unbroken behavior)
    const sourceFile = makeFile('config.ts', `export const INTERNAL_DEPLOY_TOKEN = "${token}"`)
    const sourceFindings = secretsCheck.run([sourceFile], DEFAULT_POLICY)
    expect(sourceFindings.some((f) => f.title === 'High-Entropy Secret String')).toBe(true)
  })

  it('unquoted JWT_SECRET in .env is flagged — same value quoted in source is unaffected', () => {
    const secret = 'super-long-random-jwt-signing-secret-value-1234567890'
    const envFile = makeFile('.env', `JWT_SECRET=${secret}\n`)
    const envFindings = secretsCheck.run([envFile], DEFAULT_POLICY)
    expect(envFindings.some((f) => f.title === 'JWT Secret')).toBe(true)

    const sourceFile = makeFile('lib/auth.ts', `const JWT_SECRET = "${secret}"`)
    const sourceFindings = secretsCheck.run([sourceFile], DEFAULT_POLICY)
    expect(sourceFindings.some((f) => f.title === 'JWT Secret')).toBe(true)
  })

  it('unquoted .env value does not over-capture past a trailing comment', () => {
    const token = 'aB3xQ9zK7mN2pR5vT8wY1cD4fG6hJ0kL3nQ5sU7xZ9bE2gH4jM6pS8vW0yA1cF3d'
    const file = makeFile('.env', `INTERNAL_DEPLOY_TOKEN=${token} # rotate quarterly\n`)
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    const f = findings.find((x) => x.title === 'High-Entropy Secret String')
    expect(f).toBeDefined()
    // Redacted evidence is bounded — a gross over-capture would include the
    // comment text; a correct match stops exactly at the token's end.
    expect(f!.evidence).not.toContain('rotate')
  })

  it('the .env-tracked-in-git warning still fires alongside the newly-caught content findings ' +
     '(this fix does not weaken the existing "warn about shipping .env at all" contract)', () => {
    const file = makeFile(
      '.env.local',
      `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${SERVICE_ROLE_JWT}\n`,
    )
    const findings = secretsCheck.run([file], DEFAULT_POLICY)
    expect(findings.some((f) => f.title === '.env file tracked in git')).toBe(true)
    expect(findings.some((f) => f.title === 'Secret exposed via NEXT_PUBLIC_ prefix')).toBe(true)
  })
})
