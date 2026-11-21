/**
 * W5 scan accuracy (0.13): fail-before/pass-after fixtures for each fix, plus the guards that a real
 * secret / a real vulnerability is still reported.
 *
 *  - the two loud injection rules (child-process-exec, eval-user-input) stop firing on non-shell
 *    methods, constants and test files, and still fire on a real shell call with input
 *  - sign-in pages and credential-checking admin API routes are not "unprotected"
 *  - documented test values are skipped and counted; real secrets are caught
 *  - evidence is type + length only: no 4-character piece of any secret value reaches any output
 *  - git-ignored files are skipped by default (tracked ones never)
 *  - an unreadable tracked binary stays named and flagged
 *  - project-controlled ignore text never reaches the glob library as glob syntax (picomatch VEX)
 *
 * Every secret-shaped value is assembled at runtime so this file holds no scannable key.
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import type { FileInfo, Finding, Policy } from '@agenticcli/shared'
import { loadBundledRules } from '../../src/core/bundled-rules.js'
import { runProRules } from '../../src/core/pro-scanner.js'
import { authCheck } from '../../src/checks/auth.js'
import { checkSecretsWithStats, isTestValue } from '../../src/checks/secrets.js'
import { dropTestPathInjectionNoise, dropTestValueFindings } from '../../src/core/tidy-findings.js'
import { maskSecret } from '../../src/core/redact.js'
import { GIT_IGNORED_PATTERN, literalizeGlobPattern, readFiles } from '../../src/utils/fs.js'
import { scan } from '../../src/core/scanner.js'

const POLICY: Policy = {
  version: 1,
  project: { name: 'w5', framework: 'next', risk_profile: 'standard' },
  scan: { changed_files_only: false, generate_report: false },
  block: ['exposed_env', 'hardcoded_secret'],
  warn: [],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}
const f = (relativePath: string, content: string): FileInfo => ({ path: `/p/${relativePath}`, relativePath, content })
const j = (...parts: string[]): string => parts.join('')
const corpus = (files: FileInfo[]): Finding[] => runProRules(loadBundledRules(), files, POLICY)
const ids = (findings: Finding[], id: string): Finding[] => findings.filter((x) => x.id === id)

const dirs: string[] = []
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true })
})
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'sg-w5-'))
  dirs.push(d)
  return d
}
const write = (root: string, rel: string, content: string | Buffer): void => {
  mkdirSync(dirname(join(root, rel)), { recursive: true })
  writeFileSync(join(root, rel), content)
}

describe('loud rule child-process-exec', () => {
  it('does not fire on db.exec / regex.exec (a method of another object is not a shell)', () => {
    const out = corpus([
      f('a.ts', 'export function add(db: any, c: string) { db.exec(`ALTER TABLE t ADD COLUMN ${c} TEXT`) }\n'),
      f('b.ts', 'const m = re.exec(`${a}-${b}`)\nconst n = pool.execSync(`x ${y}`)\n'),
    ])
    expect(ids(out, 'generic.injection.child-process-exec')).toEqual([])
  })
  it('still fires on a real child_process call built from input (concat and template), at the right line', () => {
    const out = ids(
      corpus([
        f('c.ts', "import { exec, execSync } from 'child_process'\nexport const a = (base: string, d: string) => exec(base + d)\nexport const b = (d: string) => execSync(`rm ${d}`)\n"),
        f('d.js', "const cp = require('child_process')\ncp.exec(`ls ${dir}`)\n"),
      ]),
      'generic.injection.child-process-exec',
    )
    expect(out.map((x) => `${x.file}:${x.line}`).sort()).toEqual(['c.ts:2', 'c.ts:3', 'd.js:2'])
  })
})

describe('loud rule eval-user-input', () => {
  it('does not fire on new Function of a SCREAMING_CASE constant or on a method called eval', () => {
    const out = corpus([f('a.ts', 'export const run = new Function(EARLY_CLICK_SCRIPT)\nconst r = redis.eval(script)\nconst z = retrieval(x)\n')])
    expect(ids(out, 'generic.injection.eval-user-input')).toEqual([])
  })
  it('still fires on eval / new Function of a variable, at the right line', () => {
    const out = ids(
      corpus([f('b.ts', 'export function a(userCode: string) {\n  return eval(userCode)\n}\nexport const g = (body: string) => new Function(body)\n')]),
      'generic.injection.eval-user-input',
    )
    expect(out.map((x) => x.line)).toEqual([2, 4])
  })
  it('both loud rules in a test file are removed by the test-path filter; the same code elsewhere is kept', () => {
    const src = "import { execSync } from 'child_process'\nexport const o = execSync(`node ${s}`)\n"
    const out = corpus([f('tests/cmd.test.ts', src), f('src/__tests__/x.ts', src), f('lib/cmd.ts', src)])
    expect(ids(out, 'generic.injection.child-process-exec')).toHaveLength(3)
    expect(dropTestPathInjectionNoise(out)).toBe(2)
    expect(ids(out, 'generic.injection.child-process-exec').map((x) => x.file)).toEqual(['lib/cmd.ts'])
  })
  it('the test-path filter never touches another rule in a test file', () => {
    const out: Finding[] = [{ id: 'hardcoded_secret', title: 't', severity: 'high', category: 'secrets', file: 'tests/a.test.ts', explanation: '', recommendation: '', blocking: false }]
    expect(dropTestPathInjectionNoise(out)).toBe(0)
    expect(out).toHaveLength(1)
  })
})

describe('auth: sign-in pages and credential-checking admin routes', () => {
  const run = (files: FileInfo[]): Finding[] => authCheck.run([f('middleware.ts', "export const config = { matcher: ['/admin/:path*'] }\n"), ...files], POLICY)
  it('a sign-in page under /admin is public by design', () => {
    expect(run([f('app/admin/sign-in/page.tsx', 'export default function P() { return <form /> }\n')])).toEqual([])
  })
  it('an unguarded admin page is still reported', () => {
    expect(run([f('app/admin/dashboard/page.tsx', 'export default function P() { return <div /> }\n')]).map((x) => x.id)).toEqual(['public_admin_route'])
  })
  it('an admin API route that reads the credential and answers 401 is guarded', () => {
    const guarded = "export async function GET(req: Request) {\n  if (req.headers.get('authorization') !== `Bearer ${process.env.T}`) return new Response('no', { status: 401 })\n  return Response.json({})\n}\n"
    expect(run([f('app/api/admin/stats/route.ts', guarded)])).toEqual([])
  })
  it('a route that only mentions 401 without reading any credential is still reported', () => {
    const fake = "export async function GET() {\n  const code = 401\n  return Response.json({ note: 'x' }, { status: 200 })\n}\n"
    expect(run([f('app/api/admin/users/route.ts', fake)]).map((x) => x.id)).toEqual(['auth_route_without_guard'])
  })
  it('a 401 written only in a comment does not count as a guard', () => {
    const commented = "// if (!token) return new Response('no', { status: 401 })\nexport async function GET() { return Response.json({}) }\n"
    expect(run([f('app/api/admin/users/route.ts', commented)]).map((x) => x.id)).toEqual(['auth_route_without_guard'])
  })
})

describe('test values skipped and counted; real secrets caught', () => {
  const REAL_STRIPE = j('sk_', 'live_Zq8vKm3RtY7pLd2WxN5bHc4J')
  const REAL_AWS = j('AKIA', 'Q7WXR2MN4PLK6ZTB')
  const TEST_STRIPE = j('sk_', 'test_Zq8vKm3RtY7pLd2WxN5bHc4J')
  const DOC_AWS = j('AKIA', 'IOSFODNN7EXAMPLE')

  it('sk_test_ and the documented AWS example key are skipped and counted, not reported', () => {
    const r = checkSecretsWithStats([f('lib/k.ts', `export const a = "${TEST_STRIPE}"\nexport const b = "${DOC_AWS}"\n`)], POLICY)
    expect(r.findings).toEqual([])
    expect(r.ignoredTestValues).toBe(2)
  })
  it('real-looking live keys are still caught (and not counted as test values)', () => {
    const r = checkSecretsWithStats([f('lib/k.ts', `export const a = "${REAL_STRIPE}"\nexport const b = "${REAL_AWS}"\n`)], POLICY)
    expect(r.findings.map((x) => x.line).sort()).toEqual([1, 2])
    expect(r.ignoredTestValues).toBe(0)
  })
  it('a real secret in a .md file or in a test file is still caught', () => {
    for (const path of ['docs/notes.md', 'tests/k.test.ts']) {
      const r = checkSecretsWithStats([f(path, `key: "${REAL_STRIPE}"\n`)], POLICY)
      expect(r.findings, path).toHaveLength(1)
    }
  })
  it('"example" in a connection URL host does not hide a real password', () => {
    expect(isTestValue('postgres://app:Xk93mQ7LpR2vTz81@sample-db.example.net/prod')).toBe(false)
    expect(isTestValue('postgres://app:your-password-here@db.example.net/prod')).toBe(true)
  })
  it('dropTestValueFindings removes a corpus finding whose matched text is a test value, keeps a real one', () => {
    const mk = (evidence: string): Finding => ({
      id: 'generic.secrets.stripe-live-key', title: 't', severity: 'high', category: 'secrets', file: 'a.ts', line: 1, column: 1,
      evidence, explanation: '', recommendation: '', blocking: true,
    })
    const list = [mk(TEST_STRIPE), mk(REAL_STRIPE), mk(DOC_AWS)]
    expect(dropTestValueFindings(list)).toBe(2)
    expect(list.map((x) => x.evidence)).toEqual([REAL_STRIPE])
  })
})

describe('masked evidence shows type and length only', () => {
  const SECRETS: Array<[string, string]> = [
    ['stripe-live-key', j('sk_', 'live_Zq8vKm3RtY7pLd2WxN5bHc4J')],
    ['aws-access-key', j('AKIA', 'Q7WXR2MN4PLK6ZTB')],
    ['github-token', j('ghp_', 'R4tYuI8oPl2KjH6gFd0SaZxC9vBnM3qWeR5t')],
    ['openai-api-key', j('sk-', 'proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGh3')],
  ]
  /** The part of a key after its public provider prefix (`sk_live_`, `AKIA`, `ghp_`, `sk-proj-`). */
  const body = (v: string): string => v.replace(/^(?:sk_live_|AKIA|ghp_|sk-proj-)/, '')

  it('maskSecret output holds no 4-character piece of the value body', () => {
    for (const [type, raw] of SECRETS) {
      const masked = maskSecret(type, raw)
      const b = body(raw)
      for (let i = 0; i + 4 <= b.length; i++) expect(masked, `${type} @${i}`).not.toContain(b.slice(i, i + 4))
    }
  })
  it('a full scan of planted secrets never prints a 4-character piece of any value, in any finding field', async () => {
    const root = tmp()
    write(root, 'package.json', '{"name":"fx"}')
    write(root, 'keys.ts', SECRETS.map(([t, v], i) => `export const k${i} = "${v}" // ${t}\n`).join(''))
    const cwd = process.cwd()
    process.chdir(root)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(result.findings.length).toBeGreaterThanOrEqual(SECRETS.length)
      const serialised = JSON.stringify(result)
      for (const [t, raw] of SECRETS) {
        const b = body(raw)
        for (let i = 0; i + 4 <= b.length; i++) expect(serialised, `${t} @${i}`).not.toContain(b.slice(i, i + 4))
      }
    } finally {
      process.chdir(cwd)
    }
  })
})

describe('git-ignored files are skipped by default', () => {
  const gitRepo = (): string => {
    const root = tmp()
    execFileSync('git', ['init', '-q'], { cwd: root })
    write(root, '.gitignore', '.env.local\nsecret-dir/\nforced.ts\n')
    write(root, 'src/app.ts', 'export const a = 1\n')
    write(root, '.env.local', `STRIPE_SECRET_KEY=${j('sk_', 'live_Zq8vKm3RtY7pLd2WxN5bHc4J')}\n`)
    write(root, 'secret-dir/x.ts', 'export const x = 1\n')
    write(root, 'forced.ts', 'export const f = 1\n')
    execFileSync('git', ['add', '-f', 'forced.ts'], { cwd: root }) // tracked although a pattern matches it
    return root
  }
  const names = (r: Awaited<ReturnType<typeof readFiles>>): string[] => [...new Set(r.files.map((x) => x.relativePath))].sort()

  it('skips an ignored file and folder, counts them, keeps tracked files', async () => {
    const root = gitRepo()
    const r = await readFiles(root, ['**/*'], [])
    expect(names(r)).toEqual(['.gitignore', 'forced.ts', 'src/app.ts'])
    expect(r.ignoredByDefault.find((e) => e.pattern === GIT_IGNORED_PATTERN)?.files).toBe(2)
  })
  it('includeGitIgnored scans them again', async () => {
    const r = await readFiles(gitRepo(), ['**/*'], [], { includeGitIgnored: true })
    expect(names(r)).toEqual(['.env.local', '.gitignore', 'forced.ts', 'secret-dir/x.ts', 'src/app.ts'])
  })
  it('outside a git work tree nothing is skipped', async () => {
    const root = tmp()
    write(root, '.gitignore', '.env.local\n')
    write(root, '.env.local', 'A=1\n')
    expect(names(await readFiles(root, ['**/*'], []))).toEqual(['.env.local', '.gitignore'])
  })
  it('a full scan reports no exposed_env / secret for a git-ignored .env.local', async () => {
    const root = gitRepo()
    const cwd = process.cwd()
    process.chdir(root)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(result.findings.filter((x) => x.file === '.env.local')).toEqual([])
    } finally {
      process.chdir(cwd)
    }
  })
})

describe('an unreadable tracked binary stays named and flagged', () => {
  it('NUL/control data with no known format is counted, named, and degrades the scan (never auto-skipped)', async () => {
    const root = tmp()
    write(root, 'src/a.ts', 'export const a = 1\n')
    const blob = Buffer.alloc(2048)
    for (let i = 0; i < blob.length; i++) blob[i] = (i * 7) % 29
    write(root, 'assets/blob.dat', blob)
    const r = await readFiles(root, ['**/*'], [])
    expect(r.skippedUnknownBinary).toBe(1)
    expect(r.skippedUnknownBinaryFiles).toEqual(['assets/blob.dat'])
    const cwd = process.cwd()
    process.chdir(root)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(result.degradedReasons?.map((d) => d.code)).toContain('UNSCANNED_UNKNOWN_BINARY')
      expect(result.degradedReasons?.find((d) => d.code === 'UNSCANNED_UNKNOWN_BINARY')?.detail).toContain('assets/blob.dat')
    } finally {
      process.chdir(cwd)
    }
  })
})

describe('picomatch "not reachable": project text is never glob syntax', () => {
  it('built-in ignore patterns pass through; a policy-derived path has its glob characters escaped', () => {
    expect(literalizeGlobPattern('node_modules/**')).toBe('node_modules/**')
    expect(literalizeGlobPattern('+(a|a)*b/(c)/[d]/{e,f}/!g/@h/?i')).toBe('\\+\\(a|a\\)*b/\\(c\\)/\\[d\\]/\\{e,f\\}/\\!g/\\@h/\\?i')
    expect(literalizeGlobPattern('.shipguard/reports/runs/**')).toBe('.shipguard/reports/runs/**')
  })
  it('a policy report.output with extglob text still scans fine (it is a literal path, ignored only if it names a real file)', async () => {
    const root = tmp()
    write(root, 'package.json', '{"name":"fx"}')
    write(root, 'a.ts', 'export const a = 1\n')
    write(root, 'shipguard.policy.yml', 'version: 1\nreport:\n  output: "+(a|a|a|a|a|a|a)*(a|a)b/latest.md"\n  format: markdown\n')
    const cwd = process.cwd()
    process.chdir(root)
    const started = Date.now()
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(result.filesScanned).toBeGreaterThan(0)
      expect(Date.now() - started).toBeLessThan(20_000)
    } finally {
      process.chdir(cwd)
    }
  })
})
