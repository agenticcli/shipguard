/**
 * The "812-file app" for the W5 expected-diff golden (tests/golden/expected-diff-0130.json):
 * the deterministic generated tree (791 files + 21 hand-written extras = 812 files, seed 1) plus a
 * small overlay of files that exercise exactly what W5 changed, each in a vulnerable and a safe form.
 * Nothing here is committed as a tree: the test writes it to a temp dir.
 *
 * Secret-shaped strings are assembled at runtime so no token-shaped literal sits in this source.
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { generateRepo } from '../helpers/synthetic-repo.mjs'

export const APP_FILE_COUNT = 791
export const APP_SEED = 1
const j = (...parts: string[]): string => parts.join('')

/** Real-looking secrets: must be caught. */
export const REAL_STRIPE = j('sk_', 'live_Zq8vKm3RtY7pLd2WxN5bHc4J')
export const REAL_AWS = j('AKIA', 'Q7WXR2MN4PLK6ZTB')
/** Documented test values: skipped and counted. */
export const TEST_STRIPE = j('sk_', 'test_Zq8vKm3RtY7pLd2WxN5bHc4J')
export const DOC_AWS = j('AKIA', 'IOSFODNN7EXAMPLE')

export const OVERLAY: Record<string, string> = {
  // loud rule 1: db.exec is not a shell (removed); a real child_process call with input stays (TP)
  'overlay/db-exec.ts': 'export function addColumn(db: any, col: string) { db.exec(`ALTER TABLE t ADD COLUMN ${col} TEXT`) }\n',
  'overlay/run-shell.ts': "import { exec } from 'child_process'\nexport function clean(dir: string) { exec(`rm -rf ${dir}`) }\n",
  // loud rule 2: a constant is not user input (removed); a variable stays (TP)
  'overlay/inline-script.ts': 'const EARLY_SCRIPT = "window.x = 1"\nexport const run = new Function(EARLY_SCRIPT)\n',
  'overlay/eval-var.ts': 'export function calc(userCode: string) { return eval(userCode) }\n',
  // loud rules inside a test file (removed)
  'overlay/__tests__/cmd.test.ts': "import { execSync } from 'child_process'\nexport const out = execSync(`node ${SCRIPT} --root=${dir}`)\n",
  // test values (removed) and real secrets (kept)
  'overlay/keys.ts': [
    `export const testStripe = "${TEST_STRIPE}"`,
    `export const docAws = "${DOC_AWS}"`,
    `export const liveStripe = "${REAL_STRIPE}"`,
    `export const liveAws = "${REAL_AWS}"`,
    '',
  ].join('\n'),
  // git-ignored files (removed): the secret inside is real-looking, but the file is not committed
  '.gitignore': '.env.local\nignored-secrets/\n',
  '.env.local': `STRIPE_SECRET_KEY=${REAL_STRIPE}\n`,
  'ignored-secrets/note.ts': `export const k = "${REAL_STRIPE}"\n`,
  // auth: a sign-in page is public by design (removed); an unguarded admin page stays (TP)
  'middleware.ts': "export const config = { matcher: ['/admin/:path*', '/dashboard/:path*'] }\n",
  'app/admin/sign-in/page.tsx': 'export default function SignIn() { return <form action="/api/session" /> }\n',
  'app/admin/dashboard/page.tsx': 'export default function Page() { return <div>admin</div> }\n',
  // auth: an API route that reads the credential and answers 401/403 is guarded (removed); one with no guard stays (TP)
  'app/api/admin/stats/route.ts': [
    "export async function GET(req: Request) {",
    "  if (req.headers.get('authorization') !== `Bearer ${process.env.ADMIN_TOKEN}`) {",
    "    return new Response('no', { status: 401 })",
    '  }',
    '  return Response.json({ ok: true })',
    '}',
    '',
  ].join('\n'),
  'app/api/admin/users/route.ts': 'export async function GET() { return Response.json({ users: [] }) }\n',
}

/** Bytes with NULs and control data and no known magic: an unreadable tracked binary (stays named, flagged). */
export function unknownBinary(): Buffer {
  const b = Buffer.alloc(2048)
  for (let i = 0; i < b.length; i++) b[i] = (i * 7) % 29 // 0..28: NULs and control bytes, no printable text
  return b
}

export function buildApp(dir: string): void {
  generateRepo(dir, APP_FILE_COUNT, APP_SEED)
  for (const [rel, content] of Object.entries(OVERLAY)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true })
    writeFileSync(join(dir, rel), content)
  }
  mkdirSync(join(dir, 'assets'), { recursive: true })
  writeFileSync(join(dir, 'assets', 'blob.dat'), unknownBinary())
  execFileSync('git', ['init', '-q'], { cwd: dir })
}
