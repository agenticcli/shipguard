/**
 * Plan W0 file checks: the OpenVEX statement (valid, linked from SECURITY.md, honest against the code),
 * the G-PLAN script (fail closed, exact-phrase allowlist) and the release workflow (no dist-tag step).
 */
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { selfArtifactIgnorePatterns } from '../../src/core/ignore.js'

const CLI = resolve(__dirname, '..', '..')
const ROOT = resolve(CLI, '..', '..')
const GPLAN = join(ROOT, 'scripts', 'g-plan.sh')

describe('OpenVEX statement (docs/security/shipguard.openvex.json)', () => {
  const vex = JSON.parse(readFileSync(join(ROOT, 'docs', 'security', 'shipguard.openvex.json'), 'utf-8'))
  const STATUSES = ['not_affected', 'affected', 'fixed', 'under_investigation']
  const JUSTIFICATIONS = [
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
  ]

  it('is OpenVEX 0.2.0 with the required document fields', () => {
    expect(vex['@context']).toBe('https://openvex.dev/ns/v0.2.0')
    for (const k of ['@id', 'author', 'timestamp', 'version']) expect(vex[k], k).toBeTruthy()
    expect(Number.isInteger(vex.version) && vex.version >= 1).toBe(true)
    expect(Number.isNaN(Date.parse(vex.timestamp))).toBe(false)
    expect(Array.isArray(vex.statements) && vex.statements.length > 0).toBe(true)
  })

  it('every statement has a vulnerability, products, a valid status and, for not_affected, a justification', () => {
    for (const st of vex.statements) {
      expect(st.vulnerability?.name).toMatch(/^GHSA-/)
      expect(st.products.length).toBeGreaterThan(0)
      for (const p of st.products) expect(p['@id'] ?? p.identifiers?.purl).toMatch(/^pkg:npm\//)
      expect(STATUSES).toContain(st.status)
      if (st.status === 'not_affected') expect(JUSTIFICATIONS.includes(st.justification) || Boolean(st.impact_statement)).toBe(true)
      if (st.status === 'affected') expect(st.action_statement).toBeTruthy()
    }
  })

  it('is referenced from SECURITY.md', () => {
    expect(readFileSync(join(ROOT, 'SECURITY.md'), 'utf-8')).toContain('docs/security/shipguard.openvex.json')
  })

  it('the picomatch statement matches what the code does: not_affected only when policy-derived ignore patterns are escaped', () => {
    // report.output comes from the scanned project's policy file and reaches fast-glob's ignore list.
    const hostile = '+(*a)'
    const patterns: string[] = selfArtifactIgnorePatterns({ report: { output: hostile }, history: { path: hostile } } as never)
    const reachable = patterns.some((p) => p.includes(hostile))
    const st = vex.statements.find((s: { vulnerability: { name: string } }) => s.vulnerability.name === 'GHSA-fc5q-39xc-vjpf')
    expect(st).toBeTruthy()
    // Open route -> the file must not claim "not affected". Closed route -> the claim is allowed (and expected).
    expect(st.status).toBe(reachable ? 'under_investigation' : 'not_affected')
    if (st.status === 'not_affected') expect(st.justification).toBe('vulnerable_code_cannot_be_controlled_by_adversary')
  })
})

describe('scripts/g-plan.sh (G-PLAN)', () => {
  const g = (...args: string[]) => spawnSync('bash', [GPLAN, ...args], { encoding: 'utf-8', env: { ...process.env, G_PLAN_ALLOW_FILE: join(tmpdir(), 'sg-no-such-allow-file') } })
  const withFiles = (files: Record<string, string>, fn: (dir: string) => void): void => {
    const dir = mkdtempSync(join(tmpdir(), 'sg-gplan-'))
    try {
      for (const [name, body] of Object.entries(files)) {
        mkdirSync(join(dir, name, '..'), { recursive: true })
        writeFileSync(join(dir, name), body)
      }
      fn(dir)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }

  it('its own self-test passes', () => {
    const r = spawnSync('bash', [GPLAN, '--self-test'], { encoding: 'utf-8' })
    expect(r.status, r.stderr).toBe(0)
  })
  it('a price string fails (exit 1)', () => withFiles({ 'a.ts': 'const a = "Pro costs $29 a month";\n' }, (d) => expect(g(d).status).toBe(1)))
  it('a scan count fails', () => withFiles({ 'a.ts': 'const a = "100 scans a month";\n' }, (d) => expect(g(d).status).toBe(1)))
  it('a trial length and credit packs fail', () => {
    withFiles({ 'a.ts': 'const a = "14-day trial";\n' }, (d) => expect(g(d).status).toBe(1))
    withFiles({ 'a.ts': 'const a = "credit packs";\n' }, (d) => expect(g(d).status).toBe(1))
  })
  it("the banned words 'release gate', 'cloud', 'our servers' fail", () => {
    for (const w of ['the release gate', 'a cloud scan', 'on our servers']) withFiles({ 'a.ts': `// ${w}\n` }, (d) => expect(g(d).status, w).toBe(1))
  })
  it('a clean file passes (exit 0)', () => withFiles({ 'a.ts': 'const c = "Scan finished. Nothing matched.";\n' }, (d) => expect(g(d).status).toBe(0)))
  it('FAILS CLOSED: a missing path is exit 2, never "clean"', () => {
    const r = g('/nonexistent/sg-gplan-path')
    expect(r.status).toBe(2)
    expect(r.stdout).not.toContain('clean')
  })
  it('FAILS CLOSED: one missing path among good ones is still an error', () =>
    withFiles({ 'ok.ts': 'x\n' }, (d) => expect(g(join(d, 'ok.ts'), join(d, 'missing.ts')).status).toBe(2)))
  it('no path at all is an error when called through the function with nothing to scan', () => {
    const r = spawnSync('bash', [GPLAN, '--bogus'], { encoding: 'utf-8' })
    expect(r.status).toBe(2)
  })
  it('the exact-phrase allowlist drops only that phrase in that file', () => {
    withFiles({ 'src/rule.ts': 'x = "access Google Cloud services"\n', 'src/other.ts': 'y = "our cloud"\n' }, (d) => {
      const allow = join(d, 'allow.txt')
      writeFileSync(allow, 'src/rule.ts|access Google Cloud services\n')
      const run = (f: string) => spawnSync('bash', [GPLAN, join(d, f)], { encoding: 'utf-8', env: { ...process.env, G_PLAN_ALLOW_FILE: allow } })
      expect(run('src/rule.ts').status).toBe(0)
      expect(run('src/other.ts').status).toBe(1)
    })
  })
  it('the shipped CLI source is clean: only the two allowlisted rule texts and one comment are excused', () => {
    const r = spawnSync('bash', [GPLAN, join(CLI, 'src')], { encoding: 'utf-8' })
    expect(r.status, r.stdout + r.stderr).toBe(0)
  })
})

describe('.github/workflows/release.yml', () => {
  const wf = readFileSync(join(ROOT, '.github', 'workflows', 'release.yml'), 'utf-8')
  const code = wf.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n')
  it('has no dist-tag step: publishing stays OIDC-only', () => {
    expect(code).not.toMatch(/npm\s+dist-tag/)
    expect(code).not.toMatch(/NODE_AUTH_TOKEN:\s*\$\{\{/)
  })
  it('cites the trusted-publishers doc that explains why', () => {
    expect(wf).toContain('https://docs.npmjs.com/trusted-publishers')
    expect(wf).toContain('Allow npm dist-tag')
  })
  it('runs the release gate before packing', () => {
    expect(wf.indexOf('bash scripts/release-gate.sh')).toBeGreaterThan(0)
    expect(wf.indexOf('bash scripts/release-gate.sh')).toBeLessThan(wf.indexOf('Pack with pnpm'))
  })
})
