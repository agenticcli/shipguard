/**
 * Central secret redaction (core/redact.ts) — unit coverage.
 *
 * Every fixture secret is assembled at runtime from fragments so this file itself never
 * contains a scannable key (GitHub push protection / our own self-scan).
 *
 * DISCIPLINE. FAIL-BEFORE: core/redact.ts did not exist and
 * scan() emitted corpus/Pro evidence verbatim.
 */
import { createHash } from 'node:crypto'
import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { Finding, QualityGateRule } from '@agenticcli/shared'
import {
  redactEvidence,
  redactFindingsEvidence,
  redactSecretValue,
  scrubSecretShapes,
  computeFindingKey,
  getFindingKey,
} from '../../src/core/redact.js'
import { scan } from '../../src/core/scanner.js'

const STRIPE = 'sk_' + 'live_Zq8vKm3RtY7pLd2WxN5bHc4J'
const AWS = 'AKIA' + 'Q7WXR2MN4PLK6ZTB'
const GITHUB = 'ghp_' + 'R4tYuI8oPl2KjH6gFd0SaZxC9vBnM3qWeR5t'
const OPENAI = 'sk-' + 'proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGh3'
const ANTHROPIC = 'sk-ant-' + 'api03-Xk3Lm9Pq2Rs5Tv8Wy1Zb4Nc7Hd0Jf3Ga6Ke9Mi2Op5Qr8St1Uv4Wx7Yz0Ab3Cd6Ef9Gh2Ij5Kl8Mn1Pq4Rs7Tu0Vw3Xy6'
const GOOGLE = 'AIza' + 'SyD4kQ7wXr2MnP5vLb9ZtYc3JdHf6GsKe0a'
const DB_PASSWORD = 'S3cr3tPassw0rd' + 'Xyz'
const DB_URL = 'postgres://admin:' + DB_PASSWORD + '@db.internal.corp:5432/app'

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: 'x',
    title: 't',
    severity: 'high',
    category: 'secrets',
    file: 'a.ts',
    explanation: 'e',
    recommendation: 'r',
    blocking: false,
    ...overrides,
  }
}

describe('redactSecretValue — the legacy format', () => {
  it('keeps 8 characters then ***; short values become ***', () => {
    expect(redactSecretValue(STRIPE)).toBe('sk_live_***')
    expect(redactSecretValue('12345678')).toBe('***')
    expect(redactSecretValue('')).toBe('***')
  })
})

describe('redactEvidence — secrets category', () => {
  it.each([
    ['stripe', STRIPE, '...sk_live_***...'],
    ['aws', AWS, '...AKIAQ7WX***...'],
    ['github', GITHUB, '...ghp_R4tY***...'],
    ['openai', OPENAI, '...sk-proj-***...'],
    ['anthropic', ANTHROPIC, '...sk-ant-a***...'],
  ])('%s: the whole evidence is masked in the legacy `...xxxxxxxx***...` shape', (_n, raw, expected) => {
    const out = redactEvidence(raw, 'secrets')
    expect(out).toBe(expected)
    expect(out).not.toContain(raw.slice(9))
  })

  it('masks a database connection string (password never visible)', () => {
    const out = redactEvidence(DB_URL, 'secrets')
    expect(out).not.toContain(DB_PASSWORD)
    expect(out).toBe('...postgres***...')
  })

  it('masks a PEM block that includes body text, but leaves a header-only match readable', () => {
    const body = 'MIIEowIBAAKCAQEA' + 'DistinctivePemBodyLine0123456789'
    const block = '-----BEGIN RSA PRIVATE KEY-----\n' + body
    expect(redactEvidence(block, 'secrets')).not.toContain(body)
    expect(redactEvidence('-----BEGIN RSA PRIVATE KEY-----', 'secrets')).toBe('-----BEGIN RSA PRIVATE KEY-----')
  })

  it('a corpus/Pro lookalike of the legacy shape is NOT waved through (no shape-based pass-through)', () => {
    // 64-char NAME=xxxxxxxx*** used to be accepted as "already redacted" in any category.
    const longName = 'Zk3q9Vb2Lw8Rt5Yp1Nc7Hd4Jf6Gs0Xa2Qe8Uo3Im5Kl9Bv1Cz7Dw4Ey6Fr0Tg2'
    const lookalike = `${longName}=abc***`
    expect(redactEvidence(lookalike, 'secrets')).not.toContain(longName)
    expect(redactEvidence(STRIPE + '***', 'secrets')).not.toContain(STRIPE.slice(9))
  })

  it('leaves non-value evidence readable: PEM header line and "type": "service_account"', () => {
    expect(redactEvidence('-----BEGIN RSA PRIVATE KEY-----', 'secrets')).toBe('-----BEGIN RSA PRIVATE KEY-----')
    expect(redactEvidence('"type": "service_account"', 'secrets')).toBe('"type": "service_account"')
    // ...but a private_key_id VALUE is masked
    const kid = '"private_key_id": "' + 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678' + '"'
    expect(redactEvidence(kid, 'secrets')).not.toContain('a1b2c3d4e5f6071')
  })
})

describe('redactEvidence / scrubSecretShapes — non-secrets categories (documented decision)', () => {
  it('masks a database password inside a package.json script line, keeps the rest', () => {
    const line = `"db:push": "DATABASE_URL=${DB_URL} prisma db push"`
    const out = redactEvidence(line, 'database')
    expect(out).not.toContain(DB_PASSWORD)
    expect(out).toContain('prisma db push')
    expect(out).toContain('postgres://admin:***@db.internal.corp')
  })

  it('masks a secret-named assignment and a token shape on a config line', () => {
    const tok = 'Tq9Zx3Lm8Kp2Wn5V' + 'b7Hc4Jd6Fg1Rs0Yu'
    const out = redactEvidence(`"start": "NODE_ENV=development API_TOKEN=${tok} node server.js"`, 'deployment')
    expect(out).not.toContain(tok)
    expect(out).toContain('NODE_ENV=development')
    expect(out).toContain('API_TOKEN=Tq9Zx3Lm***')
    expect(scrubSecretShapes(`const k = "${GITHUB}"`)).not.toContain(GITHUB.slice(9))
  })

  it('leaves ordinary evidence untouched', () => {
    for (const plain of [
      'Access-Control-Allow-Origin: *',
      'DEBUG = true',
      'res.json(process.env)',
      '"start": "next start"',
      'FROM node:latest',
      "algorithm: 'none'",
    ]) {
      expect(redactEvidence(plain, 'config')).toBe(plain)
    }
  })

  // The six leaks an independent review found in the first cut (the value is built at runtime).
  const R = (n: string): string => n + 'Xq7Lm2Vb9Rt4Ws1Yk6Hd3'
  it.each([
    ['URL password containing a slash', `DATABASE_URL=mysql://root:${R('my/Sl')}@db.example.com/app prisma db push`, R('my/Sl')],
    ['URL with empty user (redis)', `REDIS_URL=redis://:${R('Rd')}@cache.example.com:6379 prisma db push`, R('Rd')],
    ['URL password containing an @', `DATABASE_URL=mysql://u:${R('pa@ss')}@h.example.com/db`, R('pa@ss')],
    ['DB_PASS in a script', `NODE_ENV=development DB_PASS=${R('Np')} node s.js`, R('Np')],
    ['MYSQL_PWD / PGPASSWORD', `MYSQL_PWD=${R('Mp')} PGPASSWORD=${R('Pg')} node s.js`, R('Mp')],
    ['Authorization: Bearer', `curl -H "Authorization: Bearer ${R('Br')}" \${u}`, R('Br')],
    ['mysql -pSECRET', `exec(\`mysql -uroot -p${R('Ex')} \${db}\`)`, R('Ex')],
    ['curl -u user:SECRET', `exec(\`curl -u admin:${R('Cu')} \${u}\`)`, R('Cu')],
    ['docker login --password SECRET', `docker login -u bot --password ${R('Dk')} registry.example.com`, R('Dk')],
    ['--password=SECRET', `deploy --password=${R('Pe')} now`, R('Pe')],
    ['--secret-access-key SECRET', `aws-cli --secret-access-key ${R('Sa')} sync`, R('Sa')],
    ['-token=SECRET', `publish -token=${R('Tk')} --tag latest`, R('Tk')],
    ['--api-key SECRET', `tool --api-key ${R('Ak')} run`, R('Ak')],
    ['SQL PASSWORD literal', `ALTER USER app WITH PASSWORD '${R('Sq')}';`, R('Sq')],
    ['SQL IDENTIFIED BY literal', `CREATE USER a IDENTIFIED BY '${R('Ib')}'`, R('Ib')],
    ['quoted password with spaces', 'password: "correct horse battery staple"', 'horse battery'],
    ['gitlab token', 'x = "' + 'glpat-' + 'AbCdEfGhIjKlMnOpQrSt"', 'AbCdEfGhIjKlMnOpQrSt'],
    ['stripe webhook secret', 'x = "' + 'whsec_' + 'AbCdEfGhIjKlMnOpQrStUvWxYz012345"', 'AbCdEfGhIjKlMnOpQrStUvWxYz012345'],
  ])('masks: %s', (_n, line, mustNotAppear) => {
    const out = redactEvidence(line, 'injection')
    expect(out).not.toContain(mustNotAppear)
    // idempotent: masking masked text changes nothing
    expect(redactEvidence(out, 'injection')).toBe(out)
  })

  it('a bare secret flag with no value is left untouched', () => {
    for (const line of ['docker login -u bot --password', 'run --token']) {
      expect(redactEvidence(line, 'injection')).toBe(line)
    }
    expect(redactEvidence('docker login --password-stdin registry.example.com', 'injection')).toBe(
      'docker login --password-stdin registry.example.com',
    )
  })

  it('keeps the variable name / command shape around a masked value', () => {
    const out = redactEvidence(`NODE_ENV=development DB_PASS=${R('Np')} node s.js`, 'deployment')
    expect(out).toContain('NODE_ENV=development')
    expect(out).toContain('DB_PASS=')
    expect(out).toContain('node s.js')
    expect(redactEvidence('author: "Jane Doe"', 'config')).toBe('author: "Jane Doe"')
  })
})

describe('redactFindingsEvidence + finding identity key', () => {
  it('masks evidence in place, skips findings without evidence, and leaves source-redacted findings byte-identical', () => {
    const a = finding({ evidence: STRIPE })
    const b = finding({ evidence: undefined })
    const legacy = finding({ evidence: 'export NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_***' })
    redactFindingsEvidence([a, b, legacy], new Set([legacy]))
    expect(a.evidence).toBe('...sk_live_***...')
    expect(b.evidence).toBeUndefined()
    // keeps its variable name — not re-masked into `...export N***...`
    expect(legacy.evidence).toBe('export NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_***')
    // without the source-redacted mark the same text IS masked (no shape-based trust)
    const other = finding({ evidence: 'export NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_***' })
    redactFindingsEvidence([other])
    expect(other.evidence).toBe('...export N***...')
  })

  it('stamps the identity key from the RAW evidence BEFORE masking; keys sharing a prefix stay distinct', () => {
    const a = finding({ evidence: STRIPE })
    const other = finding({ evidence: STRIPE.replace('Zq8v', 'Aa1b') })
    redactFindingsEvidence([a, other])
    expect(other.evidence).toBe(a.evidence) // identical masked text...
    expect(getFindingKey(a)).not.toBe(getFindingKey(other)) // ...distinct identities
    // and it is exactly the pre-redaction key, so stored history keys stay valid
    expect(getFindingKey(a)).toBe(createHash('sha256').update(STRIPE).digest('hex').slice(0, 16))
    expect(getFindingKey(a)).toBe(computeFindingKey(finding({ evidence: STRIPE })))
    // no evidence -> title basis, unchanged behaviour
    const t = finding({ evidence: undefined, title: 'Some title' })
    redactFindingsEvidence([t])
    expect(getFindingKey(t)).toBe(createHash('sha256').update('Some title').digest('hex').slice(0, 16))
  })

  it('the serialised finding never carries the identity basis (schema unchanged)', () => {
    const a = finding({ evidence: STRIPE })
    redactFindingsEvidence([a])
    expect(JSON.stringify(a)).not.toContain(STRIPE)
    expect(JSON.stringify(a)).not.toContain('_findingKey')
    expect({ ...a }).not.toHaveProperty('_findingKey')
    expect(Object.keys(a).sort()).toEqual(
      ['blocking', 'category', 'evidence', 'explanation', 'file', 'id', 'recommendation', 'severity', 'title'],
    )
  })
})

describe('scan() — every rule source is redacted at the one central point', () => {
  const dirs: string[] = []
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
  })

  // A Pro rule (fetched at runtime in production) whose matcher captures the secret text.
  const PRO_RULE: QualityGateRule = {
    id: 'pro.secrets.custom-internal-token',
    framework: 'generic',
    category: 'secrets',
    tier: 'pro',
    severity: 'high',
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['corp_tok_[a-zA-Z0-9]{20,}'],
      antiPatterns: [],
    },
    explanation: 'Internal token committed.',
    recommendation: 'Rotate it.',
  }
  const PRO_SECRET = 'corp_' + 'tok_Zk4Pq8Lm2Wn6Vb0Hc3Jd7Fg1'

  it('legacy check + bundled corpus rule + injected Pro rule: no raw value in any finding field', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shipguard-redact-scan-'))
    dirs.push(dir)
    writeFileSync(join(dir, 'package.json'), '{"name":"fx"}', 'utf-8')
    writeFileSync(
      join(dir, 'keys.ts'),
      [`export const stripe = "${STRIPE}"`, `export const aws = "${AWS}"`, `export const corp = "${PRO_SECRET}"`, `export const google = "${GOOGLE}"`, ''].join('\n'),
      'utf-8',
    )
    const cwd = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan(
        { changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' },
        [PRO_RULE],
      )
      const serialised = JSON.stringify(result)
      for (const raw of [STRIPE, AWS, PRO_SECRET, GOOGLE]) expect(serialised).not.toContain(raw)
      const ids = result.findings.map((f) => f.id)
      expect(ids).toContain('generic.secrets.stripe-live-key') // bundled corpus rule
      expect(ids).toContain('hardcoded_secret') // legacy-only check (Google key has no corpus twin)
      expect(ids).toContain('pro.secrets.custom-internal-token') // Pro rule
      const pro = result.findings.find((f) => f.id === 'pro.secrets.custom-internal-token')!
      expect(pro.evidence).toBe('...corp_tok***...')
    } finally {
      process.chdir(cwd)
    }
  })
})
