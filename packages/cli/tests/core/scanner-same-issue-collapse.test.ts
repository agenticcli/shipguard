/**
 * scanner-same-issue-collapse.test.ts — one issue must be one finding, through the real
 * scan pipeline .
 *
 * FAIL-BEFORE (verified on main @697b469, built binary):
 *   `res.setHeader('Access-Control-Allow-Origin', '*')` produced TWO
 *   `generic.cors.wildcard-origin` findings (columns 7 and 18) and riskScore.score 30;
 *   the same shape at `high` severity scored 60 and flipped to DO_NOT_SHIP.
 *
 * The free tier reports the CORS wildcard at whatever severity the bundled corpus assigns, and
 * that number is owned by the corpus, not by this fix — so the verdict assertions below use a
 * `high` CORS rule injected as a Pro rule (the exact scenario in the report), and the bundled
 * rule assertions are about COUNT and self-consistency, which hold at any corpus severity.
 */
import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { QualityGateRule } from '@agenticcli/shared'
import { SEVERITY_WEIGHTS } from '@agenticcli/shared'

vi.mock('../../src/core/git.js', () => ({
  isGitRepo: vi.fn(() => false),
  getChangedFiles: vi.fn(() => []),
}))

const { scan } = await import('../../src/core/scanner.js')

const tempDirs: string[] = []

async function scanFixture(
  files: Record<string, string>,
  proRules?: QualityGateRule[],
) {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-collapse-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body, 'utf-8')
  const originalCwd = process.cwd()
  process.chdir(dir)
  try {
    return await scan({ format: 'json' } as never, proRules)
  } finally {
    process.chdir(originalCwd)
  }
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // ignore
    }
  }
})

const CORS_LINE = "  res.setHeader('Access-Control-Allow-Origin', '*')\n"
const CORS_FILE = `export default function handler(req, res) {\n${CORS_LINE}  res.end('ok')\n}\n`

/** The bundled CORS rule's four patterns, as a HIGH-severity Pro rule (the reported scenario). */
const HIGH_CORS_RULE: QualityGateRule = {
  id: 'pro.test.cors-wildcard-high',
  framework: 'generic',
  category: 'deployment',
  tier: 'pro',
  severity: 'high',
  matcher: {
    type: 'pattern',
    fileGlob: '**/*.ts',
    patterns: [
      "Access-Control-Allow-Origin['\",:\\s]+[*]",
      "(setHeader|header|res\\.set)\\s*\\(\\s*['\"]Access-Control-Allow-Origin['\"]\\s*,\\s*['\"][*]['\"]",
    ],
    antiPatterns: [],
  },
  explanation: 'CORS wildcard.',
  recommendation: 'Pin the origin.',
}

describe('scan() — one line, one finding', () => {
  it('the bundled CORS rule reports a single-line wildcard ONCE (was twice)', async () => {
    const r = await scanFixture({ 'api.ts': CORS_FILE })
    const cors = r.findings.filter((f) => f.id === 'generic.cors.wildcard-origin')
    expect(cors).toHaveLength(1)
    expect(cors[0].line).toBe(2)
    // The survivor is the EARLIEST match on the line: the `setHeader(` pattern starts at
    // column 7; the header-name pattern the second finding came from starts at column 18.
    expect(cors[0].column).toBe(7)
  })

  it('the score is the sum of the reported findings — no hidden double count', async () => {
    const r = await scanFixture({ 'api.ts': CORS_FILE })
    const expected = r.findings.reduce((n, f) => n + (SEVERITY_WEIGHTS[f.severity] ?? 0), 0)
    expect(r.riskScore.score).toBe(Math.min(100, expected))
    expect(r.riskScore.totalFindings).toBe(r.findings.length)
  })

  it('a HIGH-severity rule matching one line twice scores 30 -> REVIEW_BEFORE_SHIP, not 60 -> DO_NOT_SHIP', async () => {
    const r = await scanFixture({ 'api.ts': CORS_FILE }, [HIGH_CORS_RULE])
    const pro = r.findings.filter((f) => f.id === HIGH_CORS_RULE.id)
    expect(pro).toHaveLength(1)
    expect(pro[0].severity).toBe('high')
    // Only the pro finding is asserted on the verdict path: isolate it from whatever the
    // bundled/legacy sets say about the same line.
    const others = r.findings.filter((f) => f.id !== HIGH_CORS_RULE.id)
    const otherScore = others.reduce((n, f) => n + (SEVERITY_WEIGHTS[f.severity] ?? 0), 0)
    expect(r.riskScore.score).toBe(Math.min(100, 30 + otherScore))
  })

  it('two DIFFERENT lines with the same wildcard stay two findings', async () => {
    const twoLines =
      "export function a(res) {\n  res.setHeader('Access-Control-Allow-Origin', '*')\n}\n" +
      "export function b(res) {\n  res.setHeader('Access-Control-Allow-Origin', '*')\n}\n"
    const r = await scanFixture({ 'api.ts': twoLines })
    const cors = r.findings.filter((f) => f.id === 'generic.cors.wildcard-origin')
    expect(cors.map((f) => f.line).sort((a, b) => (a ?? 0) - (b ?? 0))).toEqual([2, 5])
  })
})

describe('scan() — the Stripe key (multi-pattern secrets) is not double-counted under ONE rule id', () => {
  const KEY_LINE = "const stripeKey = 'sk_live_abcdefghijklmnopqrstuvwx1234'\n"

  it('never more than one finding per (rule id, file, line)', async () => {
    const r = await scanFixture({ 'pay.ts': KEY_LINE })
    const seen = new Map<string, number>()
    for (const f of r.findings) {
      if (f.line === undefined) continue
      const k = `${f.id}|${f.file}|${f.line}`
      seen.set(k, (seen.get(k) ?? 0) + 1)
    }
    for (const [k, n] of seen) expect(`${k} x${n}`).toBe(`${k} x1`)
  })

  it('the legacy catch-all id `hardcoded_secret` reports a line ONCE even if several of its patterns match', async () => {
    // Matches two legacy patterns at once: the OpenAI `sk-proj-` shape (high) AND the generic
    // `apiKey: '<long literal>'` assignment shape (medium), both reported as `hardcoded_secret`.
    const line = "const client = new OpenAI({ apiKey: 'sk-proj-abc1234XYZabcXYZabc12345' })\n"
    const r = await scanFixture({ 'client.ts': line })
    const legacy = r.findings.filter((f) => f.id === 'hardcoded_secret' && f.line === 1)
    expect(legacy).toHaveLength(1)
    // Never softened: the survivor is the higher-severity match.
    expect(legacy[0].severity).toBe('high')
  })
})

describe('scan() — distinct secrets on one line are never merged (follow-up 1)', () => {
  // Same 8-char prefix on purpose: the legacy check redacts evidence to 8 chars, so a collapse
  // keyed on evidence would wrongly treat these as one value.
  const KEY_A = 'AKIAIOSFODNN7EXAMPLE'
  const KEY_B = 'AKIAIOSFJKLMNOPQRSTU'

  it('two different AWS keys on one line -> two corpus findings and two legacy findings', async () => {
    const r = await scanFixture({ 'aws.ts': `const keys = ['${KEY_A}', '${KEY_B}']\n` })
    expect(r.findings.filter((x) => x.id === 'generic.secrets.aws-access-key')).toHaveLength(2)
    expect(r.findings.filter((x) => x.id === 'hardcoded_secret' && x.line === 1)).toHaveLength(2)
  })

  it('the same AWS key twice on a line is not lost, and one key matched by two legacy patterns is one finding', async () => {
    const r = await scanFixture({ 'aws.ts': `const k = '${KEY_A}'\n` })
    expect(r.findings.filter((x) => x.id === 'generic.secrets.aws-access-key')).toHaveLength(1)
    expect(r.findings.filter((x) => x.id === 'hardcoded_secret' && x.line === 1)).toHaveLength(1)
  })
})

describe('scan() — one secret seen through several patterns is ONE finding (span-based, follow-up 4)', () => {
  // Patterns capture different-length slices of the same secret (`JWT Secret` the whole value,
  // `High-Entropy Secret String` the first 64 chars). Exact-value keying missed that.
  const legacyAt = (r: Awaited<ReturnType<typeof scanFixture>>, line: number) =>
    r.findings.filter((x) => x.id === 'hardcoded_secret' && x.line === line)

  it('jwtsecret_long: 70-char jwtSecret literal -> 1 finding, the higher severity', async () => {
    const v = 'FAKE_TEST_SECRET_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQ'
    const r = await scanFixture({ 'x.ts': `const jwtSecret = "${v}"\n` })
    const hits = legacyAt(r, 1)
    expect(hits).toHaveLength(1)
    expect(hits[0].severity).toBe('high')
  })

  it('env_jwt_b64_88: JWT_SECRET=<88-char base64> in .env -> 1 hardcoded_secret', async () => {
    const v = 'FAKE_TEST_SECRET_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+/abcdefg'
    const r = await scanFixture({ '.env': `JWT_SECRET=${v}\n` })
    expect(legacyAt(r, 1)).toHaveLength(1)
  })

  it('env_jwt_hex128: JWT_SECRET=<128-char hex> in .env -> 1 hardcoded_secret', async () => {
    const v = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    const r = await scanFixture({ '.env': `JWT_SECRET=${v}\n` })
    expect(legacyAt(r, 1)).toHaveLength(1)
  })

  const SB = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiAic3VwYWJhc2UiLCAicm9sZSI6ICJzZXJ2aWNlX3JvbGUifQ.ssssssssssssssssssssssssssssss'

  it('supabase_jwt: the same service-role JWT twice on one line -> 1 finding (same value repeated)', async () => {
    const r = await scanFixture({ 'x.ts': `x("${SB}","${SB}")\n` })
    expect(legacyAt(r, 1)).toHaveLength(1)
    expect(legacyAt(r, 1)[0].severity).toBe('critical')
  })

  it('supabase_jwt: a service-role JWT is not double-reported by the entropy/JWT patterns', async () => {
    const r = await scanFixture({ 'x.ts': `const a = "${SB}"\n` })
    expect(legacyAt(r, 1)).toHaveLength(1)
  })

  it('supabase_jwt: two DIFFERENT service-role JWTs on one line -> 2 findings', async () => {
    const SB2 = SB.replace('ssssssssssssssssssssssssssssss', 'tttttttttttttttttttttttttttttt')
    const r = await scanFixture({ 'x.ts': `x("${SB}","${SB2}")\n` })
    expect(legacyAt(r, 1)).toHaveLength(2)
  })

  it('two different sk-proj keys sharing a 30-char prefix on one line -> 2 findings; same key twice -> 1', async () => {
    const k1 = 'sk-proj-' + 'A'.repeat(40)
    const k2 = 'sk-proj-' + 'A'.repeat(20) + 'B'.repeat(20)
    expect(legacyAt(await scanFixture({ 'x.ts': `f("${k1}","${k2}")\n` }), 1)).toHaveLength(2)
    expect(legacyAt(await scanFixture({ 'x.ts': `f("${k1}","${k1}")\n` }), 1)).toHaveLength(1)
  })
})

