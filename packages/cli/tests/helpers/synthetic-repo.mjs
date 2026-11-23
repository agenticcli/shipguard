// Deterministic synthetic repository generator for scan speed/memory checks and the golden-equality
// test. Nothing it writes is committed: tests and benchmarks call it with a temp dir.
//
//   node tests/helpers/synthetic-repo.mjs <dir> <fileCount> [seed]
//
// The same (fileCount, seed) always yields byte-identical trees. A small share of lines is
// deliberately risky so the scan has real findings to report, and every risky line also appears
// in a "safe" twin (anti-pattern exemptions, comments) so suppression paths run too.
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

function mulberry32(seed) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// Fake credential shapes are assembled at runtime so no token-shaped literal sits in the source
// (GitHub push protection rejects those, and secret scanners would flag this file).
const j = (...parts) => parts.join('')

const SAFE_TS = [
  "import { useState } from 'react'",
  "export const config = { retries: 3, timeout: 5000 }",
  'const total = items.reduce((sum, item) => sum + item.price * item.qty, 0)',
  'function formatDate(d: Date): string { return d.toISOString().slice(0, 10) }',
  "if (!user) { throw new Error('not signed in') }",
  'const res = await fetch(`${BASE_URL}/api/items?page=${page}`)',
  'export default function Page({ params }: { params: { id: string } }) {',
  "  return <div className=\"card\">{params.id}</div>",
  'const parsed = schema.parse(await req.json())',
  "logger.info('request handled', { path: req.url })",
  '// TODO: tighten this once the design settles',
  'const cache = new Map<string, number>()',
  'export async function GET(req: Request) { return Response.json({ ok: true }) }',
  "const token = req.headers.get('authorization')",
  'for (const row of rows) { out.push(row.id) }',
]
const RISKY_TS = [
  'const agent = new https.Agent({ rejectUnauthorized: false })',
  "res.setHeader('Access-Control-Allow-Origin', '*')",
  "const c = crypto.createCipheriv('aes-128-ecb', key, null)",
  'const out = eval(userInput)',
  "const db = 'postgres://app:hunter2pass@db.internal:5432/app'",
  `const key = '${j('AKI', 'AABCDEFGHIJKLMNOP')}'`,
  `const stripe = "${j('sk_', 'live_abcdefghijklmnopqrstuvwx')}"`,
  'const session = Math.random().toString(36)',
  "const t = jwt.verify(tok, k, { algorithms: ['none'] })",
  'el.dangerouslySetInnerHTML = { __html: userHtml }',
  '// shipguard-ignore: generic.tls.reject-unauthorized-disabled -- test\nconst a2 = { rejectUnauthorized: false }',
]
const SAFE_PY = [
  'import os',
  'def handler(event, context):',
  '    return {"ok": True}',
  'DEBUG = os.environ.get("DEBUG", "") == "1"',
  'items = [i for i in range(10) if i % 2 == 0]',
  'print("done")',
]
const RISKY_PY = ['DEBUG = True', 'subprocess.run(cmd, shell=True)', 'data = pickle.loads(blob)', 'requests.get(u, verify=False)']
const SAFE_JSON = ['  "name": "pkg",', '  "version": "1.0.0",', '  "private": true,', '  "scripts": { "build": "tsc" },']
const SAFE_YML = ['services:', '  web:', '    image: node:22', '    ports: ["3000:3000"]', 'name: ci', 'on: [push]']
const SAFE_SQL = ['create table items (id int primary key, name text);', 'select id, name from items where id = 1;', 'create index idx_name on items (name);']
const RISKY_SQL = ['create policy p on items for all using (true) with check (true);']
const SAFE_MD = ['# Notes', 'Some prose about the module and how to run it.', '- item one', '- item two']

const KINDS = [
  { ext: 'ts', dir: 'src/lib', w: 30, safe: SAFE_TS, risky: RISKY_TS },
  { ext: 'tsx', dir: 'src/components', w: 20, safe: SAFE_TS, risky: RISKY_TS },
  { ext: 'js', dir: 'scripts', w: 8, safe: SAFE_TS, risky: RISKY_TS },
  { ext: 'py', dir: 'services', w: 10, safe: SAFE_PY, risky: RISKY_PY },
  { ext: 'json', dir: 'data', w: 10, safe: SAFE_JSON, risky: [] },
  { ext: 'yml', dir: 'deploy', w: 6, safe: SAFE_YML, risky: [] },
  { ext: 'sql', dir: 'db/migrations', w: 6, safe: SAFE_SQL, risky: RISKY_SQL },
  { ext: 'md', dir: 'docs', w: 10, safe: SAFE_MD, risky: [] },
]

/**
 * Hand-written files that hit many bundled rules on purpose, with case and Unicode-fold variants of
 * the case-insensitive ones (U+017F long s and U+212A Kelvin sign fold to ASCII s and k under RE2's
 * simple case folding). Written under extra/ in every generated repo.
 */
export const EXTRA_FILES = {
  'extra/jwt.ts': "const o = { ALGORITHMS: ['HS256', 'NONE'] }\njwt.verify(t, '')\nconst a = { Algorithm: 'None' }\n",
  'extra/cors.ts': "app.use(cors({ origin: true }))\nres.setHeader('Access-Control-Allow-Origin', req.headers.origin)\nconst corsOptions = { origin: ['*'] }\n",
  'extra/crypto.ts': "const c = createCipheriv('aes-256-ecb', k, null)\nconst d = createCipheriv('des-ede3', k, iv)\nconst iv = Buffer.alloc(16, 0)\nconst tok = Math.random().toString(36)\nconst SESSION = Math.random()\n",
  'extra/exec.js': "exec(cmd + ' ' + arg)\nexecSync(`ls ${dir}`)\nexec(command, cb)\neval(userInput)\nconst f = new Function(body)\nvm.runInNewContext(code)\n",
  'extra/sql.ts': 'const q = "select id from users where id = " + id\nconst r = "DELETE FROM users where x = " + x\nconst e = "\\u017felect id from users where id = " + id\n',
  'extra/secrets.ts': `const a = '${j('AKI', 'AABCDEFGHIJKLMNOP')}'\nconst g = '${j('gh', 'p_abcdefghijklmnopqrstuvwx')}'\nconst s = '${j('xo', 'xb-1234567890-abcdefghij')}'\nconst k = '${j('sk_', 'live_abcdefghijklmnopqrstu')}'\nconst r = '${j('r', 'e_abcdefgh_abcdefghijklmnopqrstuvwxyz')}'\nconst h = '${j('h', 'f_abcdefghijklmnopqrstuvwxyzabcdefgh')}'\n`,
  'extra/db.env': 'DATABASE_URL=POSTGRES://user:p4ssw0rd@db.example.org/app\nDEBUG=TRUE\nNEXT_PUBLIC_SECRET_KEY=abc\nNEXT_PUBLIC_SECRET_KEY=zzz\nnext_public_jwt_secret=1\n',
  'extra/settings.py': 'DEBUG = True\nsubprocess.run(cmd, shell=True)\nx = yaml.load(s)\nr = requests.get(u, verify=False)\neval(input())\nresp = jsonify(os.environ)\nfrom Crypto.Cipher import DES\n',
  'extra/tls.go': 'cfg := &tls.Config{InsecureSkipVerify: true}\nvar x = {"type": "service_account"}\n',
  'extra/docker-compose.yml': 'POSTGRES_HOST_AUTH_METHOD: trust\nhost all all 0.0.0.0/0 trust\ndebug: true\nallow_origins=["*"]\n',
  'extra/page.tsx': 'export const P = ({ h }) => <div dangerouslySetInnerHTML={{ __html: h }} />\nconst z = { __html: `a${b}` }\nconst ok = { __html: DOMPurify.sanitize(x) }\n',
  'extra/policy.sql': 'CREATE POLICY p ON t FOR ALL USING (TRUE);\ncreate policy q on t using ( true );\n-- public catalog\ncreate policy r on t with check (true);\n',
  'extra/unicode.ts': 'const é = "café"; // 中文 😀\nconst k = { rejectUnauthorized: false } // 😀 emoji before the finding\n',
  'extra/crlf.ts': 'const a = 1\r\nconst b = { rejectUnauthorized: false }\r\nexec(cmd + x)\r\n',
  'extra/suppressed.ts': '// shipguard-ignore: generic.injection.vm-runcontext -- reviewed\nvm.runInThisContext(code)\nvm.runInThisContext(other)\n',
  'extra/ai.py': "k1 = '" + j('s', 'k-') + 'a'.repeat(48) + "'\nk2 = '" + j('sk-', 'ant-api03-') + 'b'.repeat(85) + "'\naz = 'AccountKey=" + 'c'.repeat(44) + "=='\n",
  'extra/pem.ts': 'const pem = `-----BEGIN RSA PRIVATE KEY-----\n' + 'A'.repeat(60) + '\n-----END RSA PRIVATE KEY-----`\n',
  'extra/trust.env': 'POSTGRES_HOST_AUTH_METHOD=trust\nDEBUG=true\n',
  'extra/empty.ts': '',
}

/** Write `fileCount` files under `dir`. Returns the number of bytes written. */
export function generateRepo(dir, fileCount, seed = 1) {
  const rnd = mulberry32(seed)
  const total = KINDS.reduce((s, k) => s + k.w, 0)
  let bytes = 0
  for (let i = 0; i < fileCount; i++) {
    let pick = rnd() * total
    let kind = KINDS[0]
    for (const k of KINDS) {
      if (pick < k.w) { kind = k; break }
      pick -= k.w
    }
    const lines = 20 + Math.floor(rnd() * 380)
    const out = []
    for (let l = 0; l < lines; l++) {
      if (kind.risky.length > 0 && rnd() < 0.004) out.push(kind.risky[Math.floor(rnd() * kind.risky.length)])
      else out.push(kind.safe[Math.floor(rnd() * kind.safe.length)] + (rnd() < 0.3 ? ` // ${l}` : ''))
    }
    const sub = `${kind.dir}/m${i % 40}`
    const rel = `${sub}/file${i}.${kind.ext}`
    const body = out.join('\n') + '\n'
    const abs = join(dir, rel)
    mkdirSync(dirname(abs), { recursive: true })
    writeFileSync(abs, body)
    bytes += body.length
  }
  writeFileSync(join(dir, 'package.json'), '{"name":"synthetic","version":"1.0.0","private":true}\n')
  for (const [rel, body] of Object.entries(EXTRA_FILES)) {
    const abs = join(dir, rel)
    mkdirSync(dirname(abs), { recursive: true })
    writeFileSync(abs, body)
  }
  // Limits high enough that the 11k-file size is not truncated at the 5000-file default.
  writeFileSync(join(dir, 'shipguard.policy.yml'), 'limits:\n  maxFiles: 50000\n  maxTotalBytes: 1073741824\n')
  return bytes
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [dir, n, seed] = process.argv.slice(2)
  if (!dir || !n) {
    console.error('usage: node synthetic-repo.mjs <dir> <fileCount> [seed]')
    process.exit(2)
  }
  const bytes = generateRepo(dir, Number(n), seed ? Number(seed) : 1)
  console.log(`wrote ${n} files, ${bytes} bytes to ${dir}`)
}
