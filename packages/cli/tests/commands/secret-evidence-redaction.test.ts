/**
 * Secret redaction across EVERY output surface — spawns the BUILT binary with an isolated
 * HOME and asserts no raw secret value appears anywhere ShipGuard emits or writes.
 *
 * INCIDENT (SEC-EVID-1): findings from the governed corpus rules (`generic.secrets.*`)
 * carried the matched text verbatim in `evidence`, while the legacy `hardcoded_secret`
 * check redacted correctly (`...sk_live_***...`). The raw key therefore landed in `--json`
 * stdout, the default text view, `.shipguard/reports/latest.md` and the run-scoped
 * reports, and the `--strict` hook dump (which prints the whole JSON to stderr) — i.e. in
 * CI logs, agent transcripts and committed/uploaded report files.
 *
 * FAIL-BEFORE: with the `redactFindingsEvidence()` call removed from core/scanner.ts, the
 * raw-value sweep below fails for --json, text, --strict, latest.md and runs/<id>.{md,json}.
 * (SARIF, --quiet and the history DB were already clean and stay asserted clean.)
 *
 * Every secret is assembled from fragments at runtime so this source file holds no
 * scannable key. DISCIPLINE: behavioral test.
 */
import { spawnSync, execSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { existsSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join, relative } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { keyFindingIdentity, loadOrCreateSalt } from '../../src/core/history/finding-key.js'

const require = createRequire(import.meta.url)

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

const SECRETS = {
  stripe: 'sk_' + 'live_Zq8vKm3RtY7pLd2WxN5bHc4J',
  aws: 'AKIA' + 'Q7WXR2MN4PLK6ZTB',
  github: 'ghp_' + 'R4tYuI8oPl2KjH6gFd0SaZxC9vBnM3qWeR5t',
  openai: 'sk-' + 'proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGh3',
  anthropic:
    'sk-ant-' + 'api03-Xk3Lm9Pq2Rs5Tv8Wy1Zb4Nc7Hd0Jf3Ga6Ke9Mi2Op5Qr8St1Uv4Wx7Yz0Ab3Cd6Ef9Gh2Ij5Kl8Mn1Pq4Rs7Tu0Vw3Xy6',
  dbPassword: 'S3cr3tPassw0rd' + 'Xyz',
  generic: 'Tq9Zx3Lm8Kp2Wn5V' + 'b7Hc4Jd6Fg1Rs0Yu',
  pemBody: 'MIIEowIBAAKCAQEA' + 'DistinctivePemBodyLine0123456789',
  // Leaks found by the independent review of the first cut (non-secrets rules echoing a line).
  mysqlSlashPw: 'mySl' + 'W0w28eJt/YxHaECgiIJ',
  redisPw: 'Rd' + 'EnZRxcrAwikB9Kj3B4Pp',
  execPw: 'Ex' + 'ghZ5ia1Eyd3F6Qkdsu',
  bearer: 'Br' + '9tajbDFG4HlF4TOHBhDIl00JrSTcZL',
  nodeEnvPw: 'Np' + 'ZliEgHcJsnClfTp0ha',
  curlPw: 'Cu' + 'JryfZOWxYUW4W7lVvD',
  sqlPw: 'Sq' + 'L9xKf3TmR7vPw2Yb',
  dockerPw: 'Dk' + 'vWq8Zt3Lm9Rx2Yb',
  flagEq: 'Fe' + 'Qm4Kt8Vn2Lp',
  flagAwsSecret: 'Fa' + 'Xr7Bw3Zc9Nj',
  flagTokenEq: 'Ft' + 'Hy5Gd1Sk6Mu',
}
const DB_URL = 'postgres://admin:' + SECRETS.dbPassword + '@db.internal.corp:5432/app'

let root: string
let project: string
let home: string
const captured: Record<string, string> = {}

function run(args: string[]): { code: number; stdout: string; stderr: string } {
  const res = spawnSync('node', [distCli, ...args], {
    cwd: project,
    encoding: 'utf-8',
    timeout: 60_000,
    env: {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: join(home, '.config'),
      SHIPGUARD_TELEMETRY: '0',
      DO_NOT_TRACK: '1',
    },
  })
  return { code: res.status ?? -1, stdout: res.stdout ?? '', stderr: res.stderr ?? '' }
}

/** Every regular file under `dir`, skipping the given absolute directory prefixes/files. */
function walk(dir: string, skip: (abs: string) => boolean, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const abs = join(dir, name)
    if (skip(abs)) continue
    const st = statSync(abs)
    if (st.isDirectory()) walk(abs, skip, out)
    else if (st.isFile()) out.push(abs)
  }
  return out
}

function newestMtime(dir: string): number {
  let newest = 0
  for (const name of readdirSync(dir)) {
    const abs = join(dir, name)
    const st = statSync(abs)
    newest = Math.max(newest, st.isDirectory() ? newestMtime(abs) : st.mtimeMs)
  }
  return newest
}

function distIsStale(): boolean {
  if (!existsSync(distCli)) return true
  const built = statSync(distCli).mtimeMs
  return [join(pkgRoot, 'src'), join(pkgRoot, 'rules'), resolve(pkgRoot, '../shared/src'), resolve(pkgRoot, '../matcher-contract/src')]
    .filter((d) => existsSync(d))
    .some((d) => newestMtime(d) > built)
}

beforeAll(() => {
  // Rebuild when dist is missing OR older than any source/rule file — a stale binary would
  // let this test pass or fail against code that is not the code under review.
  if (distIsStale()) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })

  root = mkdtempSync(join(tmpdir(), 'shipguard-redaction-'))
  project = join(root, 'project')
  home = join(root, 'home')
  mkdirSync(join(project, 'src'), { recursive: true })
  mkdirSync(home, { recursive: true })

  const src = (name: string, body: string): void => writeFileSync(join(project, 'src', name), body, 'utf-8')
  src('stripe.ts', `export const stripeKey = "${SECRETS.stripe}"\n`)
  src('aws.ts', `export const awsKey = "${SECRETS.aws}"\n`)
  src('gh.ts', `export const ghToken = "${SECRETS.github}"\n`)
  src('openai.ts', `export const openai = "${SECRETS.openai}"\n`)
  src('anthropic.ts', `export const anthropic = "${SECRETS.anthropic}"\n`)
  src('db.ts', `export const url = "${DB_URL}"\n`)
  const BT = '`'
  src('mysql.ts', `export const mySl = "mysql://root:${SECRETS.mysqlSlashPw}@db.example.com/app"\n`)
  src('redis.ts', `export const redis = "redis://:${SECRETS.redisPw}@cache.example.com:6379"\n`)
  src(
    'exec.ts',
    [
      `export function a(db: string) { exec(${BT}mysql -uroot -p${SECRETS.execPw} \${db}${BT}) }`,
      `export function b(u: string) { exec(${BT}curl -H "Authorization: Bearer ${SECRETS.bearer}" \${u}${BT}) }`,
      `export function c(u: string) { exec(${BT}curl -u admin:${SECRETS.curlPw} \${u}${BT}) }`,
      `export function d(r: string) { exec(${BT}docker login -u bot --password ${SECRETS.dockerPw} \${r}${BT}) }`,
      `export function e(r: string) { exec(${BT}deploy --password=${SECRETS.flagEq} \${r}${BT}) }`,
      `export function f(r: string) { exec(${BT}aws-cli --secret-access-key ${SECRETS.flagAwsSecret} \${r}${BT}) }`,
      `export function g(r: string) { exec(${BT}publish -token=${SECRETS.flagTokenEq} \${r}${BT}) }`,
      '',
    ].join('\n'),
  )
  src('generic.ts', `const apiToken = "${SECRETS.generic}"\n`)
  src('pem.ts', `const k = \`-----BEGIN RSA PRIVATE KEY-----\n${SECRETS.pemBody}\n-----END RSA PRIVATE KEY-----\`\n`)
  // Non-secrets-category rules whose evidence is a raw config line containing a secret.
  writeFileSync(
    join(project, 'package.json'),
    JSON.stringify({
      name: 'fx',
      scripts: {
        start: `NODE_ENV=development API_TOKEN=${SECRETS.generic} node server.js`,
        'db:push': `DATABASE_URL=${DB_URL} prisma db push`,
        'db:push2': `DATABASE_URL=mysql://u:${SECRETS.mysqlSlashPw}@h.example.com/db prisma db push`,
        'db:push3': `REDIS_URL=redis://:${SECRETS.redisPw}@h prisma db push`,
        'db:push4': `psql -c "ALTER USER app WITH PASSWORD '${SECRETS.sqlPw}'" && prisma db push`,
        migrate: `NODE_ENV=development DB_PASS=${SECRETS.nodeEnvPw} node migrate.js`,
      },
    }),
    'utf-8',
  )

  captured.json = run(['scan', '.', '--json', '--report']).stdout
  captured.text = (() => {
    const r = run(['scan', '.'])
    return r.stdout + '\n--stderr--\n' + r.stderr
  })()
  captured.sarif = run(['scan', '.', '--sarif']).stdout
  captured.quiet = (() => {
    const r = run(['scan', '.', '--quiet'])
    return r.stdout + r.stderr
  })()
  // The exact invocation every installed hook runs; on a block it dumps the JSON to stderr.
  captured.strict = (() => {
    const r = run(['scan', '.', '--json', '--strict'])
    return r.stdout + '\n--stderr--\n' + r.stderr
  })()
  captured.history = run(['history', '.', '--json']).stdout + run(['history', '.']).stdout
}, 240_000)

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true })
})

const RAW_VALUES = (): Array<[string, string]> => [
  ['stripe key', SECRETS.stripe],
  ['aws key', SECRETS.aws],
  ['github token', SECRETS.github],
  ['openai key', SECRETS.openai],
  ['anthropic key', SECRETS.anthropic],
  // Long keys must not leak in part either (the text view truncates at 100 chars, which
  // would otherwise still expose ~90 characters of the anthropic key).
  ['anthropic key (tail)', SECRETS.anthropic.slice(20)],
  ['db password', SECRETS.dbPassword],
  ['db url', DB_URL],
  ['generic token', SECRETS.generic],
  ['pem body', SECRETS.pemBody],
  ['mysql url password with a slash', SECRETS.mysqlSlashPw],
  ['redis url password (empty user)', SECRETS.redisPw],
  ['exec -p password', SECRETS.execPw],
  ['bearer token', SECRETS.bearer],
  ['NODE_ENV script DB_PASS', SECRETS.nodeEnvPw],
  ['curl -u password', SECRETS.curlPw],
  ['SQL PASSWORD literal', SECRETS.sqlPw],
  ['docker login --password SECRET', SECRETS.dockerPw],
  ['--password=SECRET', SECRETS.flagEq],
  ['--secret-access-key SECRET', SECRETS.flagAwsSecret],
  ['-token=SECRET', SECRETS.flagTokenEq],
]

describe('SEC-EVID-1 — no raw secret on any output surface', () => {
  it('precondition: the scan really found the planted secrets (a clean scan would pass vacuously)', () => {
    const json = JSON.parse(captured.json)
    const ids: string[] = json.findings.map((f: { id: string }) => f.id)
    for (const id of [
      'generic.secrets.stripe-live-key',
      'generic.secrets.aws-access-key',
      'generic.secrets.github-token',
      'generic.secrets.openai-api-key',
      'generic.secrets.anthropic-api-key',
      'generic.secrets.db-connection-string',
      'generic.secrets.private-key-pem',
      'hardcoded_secret',
      'db-push-in-scripts',
      'generic.injection.child-process-exec',
    ]) {
      expect(ids, `expected finding ${id}`).toContain(id)
    }
  })

  for (const surface of ['json', 'text', 'sarif', 'quiet', 'strict', 'history'] as const) {
    it(`stdout/stderr surface "${surface}" holds no raw value`, () => {
      expect(captured[surface].length).toBeGreaterThan(0)
      for (const [label, raw] of RAW_VALUES()) {
        expect(captured[surface], `${label} leaked into ${surface}`).not.toContain(raw)
      }
    })
  }

  it('the --json evidence uses the legacy redacted shape for corpus findings', () => {
    const json = JSON.parse(captured.json)
    const byId = (id: string): string =>
      json.findings.find((f: { id: string }) => f.id === id)?.evidence
    expect(byId('generic.secrets.stripe-live-key')).toBe('...sk_live_***...')
    expect(byId('generic.secrets.aws-access-key')).toBe('...AKIAQ7WX***...')
    expect(byId('generic.secrets.github-token')).toBe('...ghp_R4tY***...')
    expect(byId('generic.secrets.anthropic-api-key')).toBe('...sk-ant-a***...')
    // The corpus PEM rule matches the header AND the first line of key body, so the evidence
    // holds real key material and is masked whole (the bare header alone would stay readable).
    expect(byId('generic.secrets.private-key-pem')).toBe('...-----BEG***...')
  })

  it('the --json schema is unchanged: exact top-level key set and per-finding key set are pinned', () => {
    const json = JSON.parse(captured.json)
    // Pinned from origin/main's output on this fixture's first scan (no Pro, no baseline).
    // Adding or removing a field must be a deliberate edit here, not a side effect of redaction.
    expect(Object.keys(json).sort()).toEqual([
      'cliVersion', 'creditsWarning', 'degraded', 'filesScanned', 'findings', 'policyUsed',
      'recommendation', 'regressionCheckSkipped', 'regressionCheckSkippedReason', 'riskScore',
      'runId', 'scanIdReused', 'schemaVersion', 'stateStatus', 'timestamp', 'treeDigest',
    ])
    const ALLOWED_FINDING_KEYS = [
      'aiCodeTarget', 'blocking', 'category', 'column', 'confidence', 'cwe', 'evidence',
      'explanation', 'file', 'fix', 'id', 'line', 'matcherType', 'recommendation', 'severity',
      'suppressed', 'suppressionState', 'title',
    ]
    const REQUIRED_FINDING_KEYS = ['blocking', 'category', 'explanation', 'file', 'id', 'recommendation', 'severity', 'title']
    const seen = new Set<string>()
    for (const f of json.findings) {
      const keys = Object.keys(f)
      keys.forEach((k) => seen.add(k))
      for (const k of REQUIRED_FINDING_KEYS) expect(keys, `finding ${f.id} lacks ${k}`).toContain(k)
      expect(keys.filter((k) => !ALLOWED_FINDING_KEYS.includes(k)), `unexpected key on ${f.id}`).toEqual([])
      if (f.evidence !== undefined) expect(typeof f.evidence).toBe('string')
      expect(typeof f.id).toBe('string')
      expect(typeof f.file).toBe('string')
    }
    // and the internal identity stamp is not one of them
    expect(seen.has('_findingKey')).toBe(false)
    // corpus findings still carry every optional field they carried before redaction
    expect([...seen].sort()).toEqual(ALLOWED_FINDING_KEYS)
  })

  it('no file ShipGuard wrote (reports, run-scoped reports, history DB, HOME) holds a raw value', () => {
    // The planted source files are the fixture itself and legitimately contain the keys;
    // everything ELSE under the project, plus the whole isolated HOME, must be clean.
    const sourceFixtures = new Set([join(project, 'package.json'), join(project, 'src')])
    const files = [
      ...walk(project, (abs) => sourceFixtures.has(abs)),
      ...walk(home, () => false),
    ]
    // Guard against a vacuous sweep: the reports and the history DB must actually exist.
    const rel = files.map((f) => relative(root, f))
    expect(rel.some((f) => f.endsWith('.shipguard/reports/latest.md'))).toBe(true)
    expect(rel.some((f) => /\.shipguard\/reports\/runs\/.+\.json$/.test(f))).toBe(true)
    expect(rel.some((f) => f.endsWith('.shipguard/history.db'))).toBe(true)

    for (const file of files) {
      const bytes = readFileSync(file)
      for (const [label, raw] of RAW_VALUES()) {
        expect(bytes.includes(Buffer.from(raw)), `${label} found in ${relative(root, file)}`).toBe(false)
      }
    }
  })

  it('SARIF still names every finding (redaction removes values, not findings)', () => {
    const sarif = JSON.parse(captured.sarif)
    expect(sarif.runs[0].results.length).toBeGreaterThan(5)
  })

  it('history keeps two different keys that share a prefix as DISTINCT finding_keys (identity computed before masking)', () => {
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite')
    const keyA = 'sk_' + 'live_AaAaAaAaAaAaAaAaAaAaAaAa'
    const keyB = 'sk_' + 'live_BbBbBbBbBbBbBbBbBbBbBbBb'
    const proj = join(root, 'project-identity')
    mkdirSync(join(proj, 'src'), { recursive: true })
    writeFileSync(join(proj, 'package.json'), '{"name":"idfx"}', 'utf-8')
    const runIn = (args: string[]): void => {
      spawnSync('node', [distCli, ...args], {
        cwd: proj,
        encoding: 'utf-8',
        timeout: 60_000,
        env: { ...process.env, HOME: home, SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1' },
      })
    }
    writeFileSync(join(proj, 'src', 'k.ts'), `export const k = "${keyA}"\n`, 'utf-8')
    runIn(['scan', '.', '--json'])
    writeFileSync(join(proj, 'src', 'k.ts'), `export const k = "${keyB}"\n`, 'utf-8')
    runIn(['scan', '.', '--json'])

    const db = new DatabaseSync(join(proj, '.shipguard', 'history.db'))
    const rows = db
      .prepare("SELECT finding_key FROM findings WHERE rule_id = 'generic.secrets.stripe-live-key' ORDER BY rowid")
      .all() as Array<{ finding_key: string }>
    db.close()
    const sha = (v: string): string => createHash('sha256').update(v).digest('hex').slice(0, 16)
    const salt = loadOrCreateSalt(join(proj, '.shipguard', 'history.db'))
    if (!salt.ok) throw new Error(salt.reason)
    // Both scans emit the SAME masked evidence (`...sk_live_***...`) yet get different keys. Each key
    // is the keyed digest (HMAC with the history salt) of the raw value: never the plain hash.
    expect(rows.map((r) => r.finding_key)).toEqual([keyFindingIdentity(salt.salt, sha(keyA)), keyFindingIdentity(salt.salt, sha(keyB))])
    expect(rows.map((r) => r.finding_key)).not.toContain(sha(keyA))
  })
})
