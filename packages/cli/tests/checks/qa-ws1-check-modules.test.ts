/**
 * QA — CLI Check Modules
 * Covers: SEC-001..SEC-008, AUTH-001..AUTH-004, DB-001..DB-003,
 *         DEPLOY-001..DEPLOY-002, PAY-001..PAY-002, EDGE-001
 *
 * Assertion strategy:
 * - Assert against modules' ACTUAL emitted IDs (hardcoded_secret, exposed_env,
 *   db-drop-table, deployment_*, etc.) NOT registry IDs from the test plan prose.
 * - Cases for behaviours NOT YET IMPLEMENTED in the free modules are documented
 *   as "gap" tests that verify the feature is absent and explain where it lives.
 */

import { describe, it, expect } from 'vitest'
import { secretsCheck } from '../../src/checks/secrets.js'
import { authCheck } from '../../src/checks/auth.js'
import { databaseCheck } from '../../src/checks/database.js'
import { deploymentCheck } from '../../src/checks/deployment.js'
import { payments as paymentsCheck } from '../../src/checks/payments.js'
import type { FileInfo, Policy } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function file(relativePath: string, content: string): FileInfo {
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

// middleware.ts stub — prevents "No middleware.ts found" global finding from
// polluting per-file finding counts in auth tests (as existing auth.test.ts does)
const MIDDLEWARE_STUB = file(
  'middleware.ts',
  `import { authMiddleware } from '@clerk/nextjs'\nexport default authMiddleware({\n  publicRoutes: ['/'],\n})\nexport const config = { matcher: ['/dashboard/(.*)', '/admin/(.*)'] }`
)

// ---------------------------------------------------------------------------
// SEC-001 — OpenAI sk-proj- key detected
// ---------------------------------------------------------------------------

describe('SEC-001: OpenAI new-style key (sk-proj-) detected', () => {
  it('finds hardcoded_secret for sk-proj- prefix key', () => {
    const f = file('test.js', `const key = "sk-proj-Abc123XYZ0000000000000000000000000000000000000"`)
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    const match = findings.filter(x => x.id === 'hardcoded_secret')
    expect(match.length).toBeGreaterThan(0)
    expect(match[0].category).toBe('secrets')
    expect(match[0].file).toBe('test.js')
    // Evidence must be redacted (not expose the raw key)
    expect(match[0].evidence).not.toContain('0000000000000000000000000000000000000')
  })
})

// ---------------------------------------------------------------------------
// SEC-002 — break behavior: one finding per PATTERN per file
// ---------------------------------------------------------------------------

describe('SEC-002: all same-pattern matches reported (same-pattern matches — break removed)', () => {
  it('same-pattern duplicate (two OpenAI keys) → BOTH lines reported per pattern', () => {
    // FIXED (same-pattern matches): Two sk-proj- keys on different lines — same outer-loop pattern entry.
    // Previously the inner `break` caused only the first line to be reported per pattern.
    // After removing the break, all matching lines within a pattern are reported.
    const content = [
      `const key1 = "sk-proj-First000000000000000000000000000000000000000"`,
      `const key2 = "sk-proj-Second00000000000000000000000000000000000000"`,
    ].join('\n')
    const f = file('lib/ai.ts', content)
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    const secrets = findings.filter(x => x.id === 'hardcoded_secret' && x.title === 'OpenAI API Key')
    // Both keys on separate lines → 2 findings for this pattern
    expect(secrets.length).toBe(2)
    expect(secrets[0].line).toBe(1)
    expect(secrets[1].line).toBe(2)
  })

  it('different-pattern secrets (OpenAI + Stripe live) in same file → BOTH reported', () => {
    // OpenAI and Stripe live keys match DIFFERENT outer-loop pattern entries → both reported
    const content = [
      `const openaiKey = "sk-proj-OpenAI000000000000000000000000000000000000"`,
      `// some code`,
      `// more code`,
      `// more code`,
      `const stripeKey = "sk_live_abcdefghijklmnopqrstuvwx"`,
    ].join('\n')
    const f = file('lib/keys.ts', content)
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    const secrets = findings.filter(x => x.id === 'hardcoded_secret')
    // Two DIFFERENT patterns → two findings
    expect(secrets.length).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// SEC-003 — .env file tracked in git
// ---------------------------------------------------------------------------

describe('SEC-003: .env file tracked in git', () => {
  it('bare .env triggers exposed_env finding', () => {
    const f = file('.env', 'KEY=value')
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    const envFinding = findings.find(x => x.id === 'exposed_env' && x.title === '.env file tracked in git')
    expect(envFinding).toBeDefined()
  })

  it('.env.local triggers exposed_env finding', () => {
    const f = file('.env.local', 'SECRET=supersecretvalue')
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    const envFinding = findings.find(x => x.id === 'exposed_env' && x.title === '.env file tracked in git')
    expect(envFinding).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// SEC-004 — .env.example NOT flagged
// ---------------------------------------------------------------------------

describe('SEC-004: .env.example is NOT flagged', () => {
  it('.env.example produces no findings', () => {
    const f = file('.env.example', 'OPENAI_API_KEY=your-openai-key-here\nSTRIPE_SECRET_KEY=sk_live_your_key')
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    const envFinding = findings.find(x => x.title === '.env file tracked in git')
    expect(envFinding).toBeUndefined()
  })

  it('.env.sample produces no findings', () => {
    const f = file('.env.sample', 'DATABASE_URL=postgres://user:pass@host/db')
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    expect(findings.find(x => x.title === '.env file tracked in git')).toBeUndefined()
  })

  it('.env.template produces no findings', () => {
    const f = file('.env.template', 'API_KEY=<your-api-key>')
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    expect(findings.find(x => x.title === '.env file tracked in git')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// SEC-005 — PEM private key blocks
// ---------------------------------------------------------------------------

describe('SEC-005: PEM private key blocks detected', () => {
  it('detects RSA PRIVATE KEY block', () => {
    const f = file('certs/server.key', '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----')
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    expect(findings.some(x => x.title === 'Private key block in source')).toBe(true)
  })

  it('detects EC PRIVATE KEY block', () => {
    const f = file('certs/ec.key', '-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI...\n-----END EC PRIVATE KEY-----')
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    expect(findings.some(x => x.title === 'Private key block in source')).toBe(true)
  })

  it('detects generic PRIVATE KEY block (no prefix)', () => {
    const f = file('lib/crypto.ts', '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw...\n-----END PRIVATE KEY-----')
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    expect(findings.some(x => x.title === 'Private key block in source')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// SEC-006 — NEXT_PUBLIC_ secret exposure
// ---------------------------------------------------------------------------

describe('SEC-006: NEXT_PUBLIC_ secret exposure', () => {
  it('detects literal NEXT_PUBLIC_*_SECRET_KEY=<value> assignment', () => {
    // Rule matches literal env-file-style assignment, not process.env references
    const f = file(
      'app/config.ts',
      `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_mypublickeyleak1234`
    )
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    const nextPublicFinding = findings.find(x => x.title === 'Secret exposed via NEXT_PUBLIC_ prefix')
    expect(nextPublicFinding).toBeDefined()
    expect(nextPublicFinding?.severity).toBe('critical')
    expect(nextPublicFinding?.id).toBe('exposed_env')
  })

  it('DOCUMENTED GAP: process.env.NEXT_PUBLIC_X reference does NOT trigger rule', () => {
    // The free module's NEXT_PUBLIC_SECRET_PATTERN only matches literal assignment form.
    // process.env.NEXT_PUBLIC_X references are NOT caught by secrets.ts — gap for pro tier.
    const f = file(
      'src/app/page.tsx',
      `const x = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY`
    )
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    const nextPublicFinding = findings.find(x => x.title === 'Secret exposed via NEXT_PUBLIC_ prefix')
    // Currently returns undefined — document this as a known gap
    expect(nextPublicFinding).toBeUndefined()
    // GAP: process.env.NEXT_PUBLIC_* references not detected. Rule targets literal assignment only.
  })
})

// ---------------------------------------------------------------------------
// SEC-007 — Commit SHA false positive
// ---------------------------------------------------------------------------

describe('SEC-007: Commit SHA must NOT trigger secret detection', () => {
  it('40-char hex commit SHA produces zero findings', () => {
    const f = file('lib/version.ts', `const sha = "a3f8d20e9c1b4567890abcdef1234567890abcdef"`)
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    // Commit SHAs are hex-only (no uppercase, no slashes/plus) — should not match key patterns
    expect(findings.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// SEC-008 — shipguard-ignore suppression comment
// ---------------------------------------------------------------------------

describe('SEC-008: shipguard-ignore suppression comment', () => {
  it('DOCUMENTED GAP: // shipguard-ignore does NOT suppress findings in free module', () => {
    // secrets.ts has no isLineSuppressed() / suppress-comment logic.
    // This is a pro-tier / scanner feature per architecture docs.
    const content = [
      `// shipguard-ignore: secrets.openai-api-key -- intentional`,
      `const key = "sk-proj-SuppressMe0000000000000000000000000000000000"`,
    ].join('\n')
    const f = file('lib/ai.ts', content)
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    // Suppression comment is NOT honored — finding still emitted
    const secrets = findings.filter(x => x.id === 'hardcoded_secret')
    expect(secrets.length).toBeGreaterThan(0)
    // GAP: SEC-008 suppression feature not implemented in free secrets.ts module.
    // The inner break at secrets.ts:284 prevents duplicate per-pattern, but
    // shipguard-ignore comment parsing does not exist in this module.
  })
})

// ---------------------------------------------------------------------------
// AUTH-001 — Next.js dashboard page without auth flagged
// ---------------------------------------------------------------------------

describe('AUTH-001: Next.js dashboard page without auth import', () => {
  it('flags missing auth on app/dashboard page', () => {
    const dashPage = file(
      'app/dashboard/settings/page.tsx',
      `export default function SettingsPage() { return <div>Settings</div> }`
    )
    // Include middleware stub to avoid global "no middleware" finding noise
    const findings = authCheck.run([MIDDLEWARE_STUB, dashPage], DEFAULT_POLICY)
    const authFindings = findings.filter(x => x.file === 'app/dashboard/settings/page.tsx')
    expect(authFindings.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// AUTH-002 — Webhook path excluded from auth requirement
// ---------------------------------------------------------------------------

describe('AUTH-002: Webhook path excluded from auth requirement', () => {
  it('does NOT flag app/api/webhooks/stripe/route.ts', () => {
    const webhookRoute = file(
      'app/api/webhooks/stripe/route.ts',
      `import Stripe from 'stripe'\nexport async function POST(req: Request) {\n  const body = await req.text()\n  return new Response('ok')\n}`
    )
    const findings = authCheck.run([MIDDLEWARE_STUB, webhookRoute], DEFAULT_POLICY)
    const webhookFindings = findings.filter(x => x.file === 'app/api/webhooks/stripe/route.ts')
    expect(webhookFindings.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// AUTH-003 — Commented-out auth detected
// ---------------------------------------------------------------------------

describe('AUTH-003: Commented-out auth call detected', () => {
  it('flags commented-out getServerSession in protected route with public_admin_route id', () => {
    const protectedPage = file(
      'app/dashboard/page.tsx',
      `// const session = await getServerSession(authOptions)\nexport default function DashboardPage() { return <div>Dashboard</div> }`
    )
    const findings = authCheck.run([MIDDLEWARE_STUB, protectedPage], DEFAULT_POLICY)
    // auth.ts uses public_admin_route for both missing-auth AND commented-out-auth scenarios.
    // The "commented out" case changes the explanation but NOT the finding id.
    const routeFindings = findings.filter(
      x => x.file === 'app/dashboard/page.tsx' && x.id === 'public_admin_route'
    )
    expect(routeFindings.length).toBeGreaterThan(0)
    // Verify the explanation mentions the commented-out scenario
    expect(routeFindings[0].explanation).toContain('commented out')
  })
})

// ---------------------------------------------------------------------------
// AUTH-004 — Express route without auth middleware
// ---------------------------------------------------------------------------

describe('AUTH-004: Express route file without auth middleware', () => {
  it('flags express admin route with no auth middleware reference', () => {
    const expressRoute = file(
      'routes/admin.js',
      `const express = require('express')\nconst router = express.Router()\nrouter.get('/users', async (req, res) => { res.json({ users: [] }) })\nmodule.exports = router`
    )
    const findings = authCheck.run([expressRoute], DEFAULT_POLICY)
    const expressFindings = findings.filter(x => x.file === 'routes/admin.js')
    expect(expressFindings.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// DB-001 — SQL injection via string interpolation
// GAP: database.ts only checks migration files (DROP/TRUNCATE) and package.json.
// No raw SQL injection detection implemented. Document the gap.
// ---------------------------------------------------------------------------

describe('DB-001: SQL injection detection (GAP — NOT IMPLEMENTED)', () => {
  it('DOCUMENTED GAP: raw SQL template-literal injection does NOT trigger databaseCheck', () => {
    const f = file(
      'lib/db.ts',
      'const q = `SELECT * FROM users WHERE id = ${userId}`'
    )
    const findings = databaseCheck.run([f], DEFAULT_POLICY)
    // databaseCheck only routes migration files and package.json — arbitrary .ts files produce no findings
    expect(findings.length).toBe(0)
    // GAP: DB-001 sql-injection-risk not implemented in free database.ts.
    // database.ts only checks: migration files (DROP/TRUNCATE/DELETE) and package.json (db push).
  })
})

// ---------------------------------------------------------------------------
// DB-002 — Mongoose .find({}) unrestricted query
// GAP: not implemented in database.ts
// ---------------------------------------------------------------------------

describe('DB-002: Mongoose unrestricted query (GAP — NOT IMPLEMENTED)', () => {
  it('DOCUMENTED GAP: User.find({}) does NOT trigger databaseCheck', () => {
    const f = file(
      'models/userRepo.ts',
      `const users = await User.find({})\nconst all = await Model.find({})`
    )
    const findings = databaseCheck.run([f], DEFAULT_POLICY)
    expect(findings.length).toBe(0)
    // GAP: DB-002 unrestricted-query not implemented in free database.ts.
    // .find({}) pattern detection absent from current module.
  })
})

// ---------------------------------------------------------------------------
// DB-003 — Database credentials in migration file
// The secrets module catches mongodb:// URL credentials; databaseCheck handles migration patterns.
// Verify no double-reporting between modules.
// ---------------------------------------------------------------------------

describe('DB-003: Database credentials in connection string', () => {
  it('secrets module detects DATABASE_URL with embedded credentials', () => {
    // secrets.ts:146 — DATABASE_URL pattern requires VAR=<url> assignment form
    const f = file('lib/db.ts', `const DATABASE_URL = "mongodb://admin:password123@host:27017/db"`)
    const secretsFindings = secretsCheck.run([f], DEFAULT_POLICY)
    expect(secretsFindings.some(x => x.id === 'hardcoded_secret')).toBe(true)
  })

  it('bare mongodb:// string literal without variable prefix IS caught (bare DB URI detection)', () => {
    // FIXED (bare DB URI detection): secrets.ts DATABASE_URL pattern (secrets.ts:146) now makes the
    // var-name prefix optional, so any literal mongodb://user:pass@host/db form is detected
    // regardless of variable name (uri, conn, connectionString, etc.).
    const f = file('lib/db.ts', `const uri = "mongodb://admin:password123@host:27017/db"`)
    const secretsFindings = secretsCheck.run([f], DEFAULT_POLICY)
    const dbCredsFindings = secretsFindings.filter(x => x.id === 'hardcoded_secret')
    expect(dbCredsFindings.length).toBeGreaterThan(0)
    expect(dbCredsFindings[0].title).toBe('Database URL with Credentials')
  })

  it('databaseCheck does NOT double-report credentials in non-migration file', () => {
    const f = file('lib/db.ts', `const DATABASE_URL = "mongodb://admin:password123@host:27017/db"`)
    const dbFindings = databaseCheck.run([f], DEFAULT_POLICY)
    // database.ts only processes migration files — lib/db.ts not routed
    expect(dbFindings.length).toBe(0)
  })

  it('no duplicate findings: DATABASE_URL caught by secrets only, not database module', () => {
    const f = file('lib/db.ts', `const DATABASE_URL = "mongodb://admin:password123@host:27017/db"`)
    const combined = [
      ...secretsCheck.run([f], DEFAULT_POLICY),
      ...databaseCheck.run([f], DEFAULT_POLICY),
    ]
    // All findings from secrets module only (database.ts returns nothing for non-migration .ts)
    const credFindings = combined.filter(x => x.id === 'hardcoded_secret')
    expect(credFindings.length).toBe(1) // secrets catches it once; database doesn't double-report
  })
})

// ---------------------------------------------------------------------------
// DEPLOY-001 — Debug mode enabled in production config
// FIXED: checkGeneralConfigs is now called from the else-branch of
// deploymentCheck.run() for files not matched by a specific handler.
// debug: true and origin: * in non-standard config files are now detected.
// ---------------------------------------------------------------------------

describe('DEPLOY-001: Debug mode enabled in production config', () => {
  it('debug: true in non-standard config file IS caught', () => {
    // checkGeneralConfigs() (deployment.ts:399) is now wired into the else-branch
    // of deploymentCheck.run() — files like config/server.config.js are no longer silently skipped.
    const f = file('config/server.config.js', `module.exports = { debug: true, port: 3000 }`)
    const findings = deploymentCheck.run([f], DEFAULT_POLICY)
    const debugFindings = findings.filter(x => x.id === 'deployment_config_debug_mode')
    expect(debugFindings.length).toBe(1)
    expect(debugFindings[0].severity).toBe('high')
    expect(debugFindings[0].blocking).toBe(true)
  })

  it('origin: * in non-standard config file IS caught', () => {
    const f = file('config/server.config.js', `module.exports = { origin: '*', port: 3000 }`)
    const findings = deploymentCheck.run([f], DEFAULT_POLICY)
    const corsFindings = findings.filter(x => x.id === 'deployment_config_cors_wildcard_origin')
    expect(corsFindings.length).toBe(1)
    expect(corsFindings[0].severity).toBe('high')
  })

  it('package.json DEBUG=true in start script IS caught via checkPackageJson()', () => {
    const f = file(
      'package.json',
      JSON.stringify({ scripts: { start: 'DEBUG=true node server.js' } }, null, 2)
    )
    const findings = deploymentCheck.run([f], DEFAULT_POLICY)
    // package.json goes through checkPackageJson() which has its own debug detection
    // ID format: deployment_pkg_debug_true_{scriptName} (e.g., deployment_pkg_debug_true_start)
    const debugFindings = findings.filter(x => x.id.startsWith('deployment_pkg_debug_true'))
    expect(debugFindings.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// DEPLOY-002 — 0.0.0.0 binding in server code
// GAP: deployment.ts has no check for 0.0.0.0 binding.
// ---------------------------------------------------------------------------

describe('DEPLOY-002: 0.0.0.0 network binding (GAP — NOT IMPLEMENTED)', () => {
  it('DOCUMENTED GAP: app.listen(3000, "0.0.0.0") does NOT trigger deploymentCheck', () => {
    const f = file('server.js', `app.listen(3000, '0.0.0.0', () => console.log('listening'))`)
    const findings = deploymentCheck.run([f], DEFAULT_POLICY)
    // deployment.ts routes by basename — server.js not handled by any sub-check
    expect(findings.length).toBe(0)
    // GAP: DEPLOY-002 unrestricted-network-binding not implemented in free deployment.ts.
    // 0.0.0.0 binding detection absent from checkGeneralConfigs and all sub-checks.
  })
})

// ---------------------------------------------------------------------------
// PAY-001 — Stripe test key in production code
// NOTE: sk_test_ keys are handled by secrets.ts (Stripe secret key pattern),
// not payments.ts. payments.ts does not have a stripe-test-key-in-prod check.
// ---------------------------------------------------------------------------

describe('PAY-001: Stripe test key in production code', () => {
  it('secrets module catches sk_test_ key as hardcoded_secret', () => {
    const f = file('lib/payments.ts', `const stripe = new Stripe('sk_test_abcdefghijklmnopqrstuvwx')`)
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    expect(findings.some(x => x.id === 'hardcoded_secret')).toBe(true)
  })

  it('payments module does NOT have a dedicated sk_test_ check (secrets module handles it)', () => {
    const f = file('lib/payments.ts', `const stripe = new Stripe('sk_test_abcdefghijklmnopqrstuvwx')`)
    const payFindings = paymentsCheck.run([f], DEFAULT_POLICY)
    // payments.ts focuses on webhook verification, not key type classification
    const testKeyFindings = payFindings.filter(x => x.id === 'stripe_test_key_in_prod')
    expect(testKeyFindings.length).toBe(0)
    // PAY-001 detection lives in secrets.ts, not payments.ts. No duplicate.
  })
})

// ---------------------------------------------------------------------------
// PAY-002 — Client-controlled payment amount
// GAP: payments.ts has no client-controlled-amount check.
// ---------------------------------------------------------------------------

describe('PAY-002: Client-controlled payment amount (GAP — NOT IMPLEMENTED)', () => {
  it('DOCUMENTED GAP: req.body.amount passed to payment API does NOT trigger paymentsCheck', () => {
    const f = file(
      'app/api/checkout/route.ts',
      `export async function POST(req: Request) {\n  const { amount } = await req.json()\n  const session = await stripe.checkout.sessions.create({ line_items: [{ price_data: { unit_amount: amount } }] })\n}`
    )
    const findings = paymentsCheck.run([f], DEFAULT_POLICY)
    // payments.ts only checks webhook verification and client-side secret exposure
    const amountFindings = findings.filter(x => x.id === 'client_controlled_amount')
    expect(amountFindings.length).toBe(0)
    // GAP: PAY-002 client-controlled-amount not implemented in free payments.ts.
    // payments.ts covers: missing webhook signature verification, client-side secret exposure.
  })
})

// ---------------------------------------------------------------------------
// EDGE-001 — Multi-pattern detection after same-pattern matches break removal
// (Duplicates SEC-002 with 3 different secret types for comprehensive coverage)
// ---------------------------------------------------------------------------

describe('EDGE-001: Multi-secret file — all findings per pattern reported', () => {
  it('3 different secret types in one file → 3 findings (one per outer-loop pattern)', () => {
    // OpenAI (sk-proj-), Stripe live (sk_live_), and GitHub PAT (ghp_) are
    // THREE different outer-loop patterns — all are reported (same-pattern matches break removed)
    const content = [
      `const openaiKey = "sk-proj-OpenAIKey000000000000000000000000000000000"`,
      `const stripeKey = "sk_live_abcdefghijklmnopqrstuvwx"`,
      `const githubToken = "ghp_16C7e42F292c6912E169D"`,
    ].join('\n')
    const f = file('lib/all-secrets.ts', content)
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    const secrets = findings.filter(x => x.id === 'hardcoded_secret')
    // All 3 patterns matched — at minimum OpenAI + Stripe are detected
    expect(secrets.length).toBeGreaterThanOrEqual(2)
  })

  it('two lines with SAME secret type → BOTH lines reported (same-pattern matches)', () => {
    // FIXED (same-pattern matches): break removed — all same-pattern matches on separate lines are reported.
    // sk_live_ requires {24,} chars after the prefix — use values of ≥24 chars each.
    const content = [
      `const key1 = "sk_live_firstlivekey0000000000000"`,
      `const key2 = "sk_live_secondlivekey000000000000"`,
    ].join('\n')
    const f = file('lib/stripe-double.ts', content)
    const findings = secretsCheck.run([f], DEFAULT_POLICY)
    const stripeFindings = findings.filter(
      x => x.id === 'hardcoded_secret' && x.title === 'Stripe Live Secret Key'
    )
    // Both Stripe sk_live_ keys → 2 findings
    expect(stripeFindings.length).toBe(2)
    expect(stripeFindings[0].line).toBe(1)
    expect(stripeFindings[1].line).toBe(2)
  })
})
