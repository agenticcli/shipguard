/**
 * init / logout / status smoke tests.
 *
 * Mutation-probing exposed that these three commands had NO behavioral test:
 *   - init: must create the policy file + .shipguard/ dir, and NOT silently
 *     clobber an existing policy on re-run.
 *   - logout: must clear stored credentials.
 *   - status: must report "not authenticated" with no creds, and reflect a
 *     stored (valid) credential when present.
 *
 * DISCIPLINE: behavioral, SPAWNED. Credential state is isolated by
 * overriding HOME for the child process (getCredentialsPath() derives from
 * os.homedir(), which honors HOME on Linux), so the real user's credentials are
 * never touched. init runs in a throwaway cwd.
 */
import { spawnSync, execSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync, chmodSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'

// Real-process e2e file: every test spawns the built CLI (each spawn ~0.3-1s idle, several x
// under load). Vitest's 5s default is below the cost of a 3-4 spawn test on a shared box, so
// state the budget explicitly (same 30s as the per-spawn kill timeout), file-scoped - not global.
vi.setConfig({ testTimeout: 30_000 })

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

const tempDirs: string[] = []
function mkTemp(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
})

interface RunOpts {
  cwd?: string
  /** Isolated HOME for credential-path isolation. */
  home?: string
}
function runCli(args: string[], opts: RunOpts = {}): { code: number; stdout: string; stderr: string } {
  const env = { ...process.env }
  if (opts.home) {
    env.HOME = opts.home
    // Some environments also read XDG/USERPROFILE; align them for safety.
    env.USERPROFILE = opts.home
  }
  const res = spawnSync('node', [distCli, ...args], {
    cwd: opts.cwd ?? pkgRoot,
    encoding: 'utf-8',
    timeout: 30_000,
    env,
  })
  const code = res.status === null ? -1 : res.status
  return { code, stdout: res.stdout ?? '', stderr: res.stderr ?? '' }
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 120_000)

// ── init ─────────────────────────────────────────────────────────────────────

describe('init smoke', () => {
  it('init creates shipguard.policy.yml and the .shipguard/ dir → exit 0', () => {
    const project = mkTemp('shipguard-init-')
    const { code } = runCli(['init'], { cwd: project })
    expect(code).toBe(0)
    expect(existsSync(join(project, 'shipguard.policy.yml'))).toBe(true)
    expect(existsSync(join(project, '.shipguard'))).toBe(true)
  })

  it('init when the policy already exists does NOT silently clobber it', () => {
    const project = mkTemp('shipguard-init-exists-')
    const policyPath = join(project, 'shipguard.policy.yml')
    const sentinel = '# CUSTOM USER POLICY — must survive re-init\nversion: 1\n'
    writeFileSync(policyPath, sentinel, 'utf-8')

    const { code, stdout, stderr } = runCli(['init'], { cwd: project })
    expect(code).toBe(0)
    // The existing file content must be untouched (not overwritten with defaults).
    expect(readFileSync(policyPath, 'utf-8')).toBe(sentinel)
    // And it should say so (skip/exists), not pretend it created a fresh one.
    expect(`${stdout}${stderr}`.toLowerCase()).toMatch(/exist|skip/)
  })
})

// ── logout ─────────────────────────────────────────────────────────────────────

describe('logout smoke', () => {
  it('logout removes a stored credentials file → exit 0', () => {
    const home = mkTemp('shipguard-home-')
    const credPath = join(home, '.config', 'shipguard', 'credentials.json')
    mkdirSync(dirname(credPath), { recursive: true })
    writeFileSync(
      credPath,
      JSON.stringify({
        accessToken: 'tok',
        refreshToken: 'ref',
        expiresAt: Date.now() + 3_600_000,
        apiUrl: 'https://example.test',
      }),
      'utf-8',
    )
    expect(existsSync(credPath)).toBe(true)

    const { code, stdout, stderr } = runCli(['logout'], { home })
    expect(code).toBe(0)
    // The credentials file must be gone after logout.
    expect(existsSync(credPath)).toBe(false)
    expect(`${stdout}${stderr}`.toLowerCase()).toMatch(/log/)
  })

  it('logout with no stored credentials still exits 0 (idempotent)', () => {
    const home = mkTemp('shipguard-home-empty-')
    const { code } = runCli(['logout'], { home })
    expect(code).toBe(0)
  })
})

// ── status ─────────────────────────────────────────────────────────────────────

describe('status smoke', () => {
  it('status with no credentials reports "not authenticated" → exit 0', () => {
    const home = mkTemp('shipguard-home-noauth-')
    const { code, stdout, stderr } = runCli(['status'], { home })
    expect(code).toBe(0)
    expect(`${stdout}${stderr}`.toLowerCase()).toMatch(/not authenticated|login/)
  })

  it('status with a stored (expired) credential reports its state → exit 0', () => {
    const home = mkTemp('shipguard-home-expired-')
    const credPath = join(home, '.config', 'shipguard', 'credentials.json')
    mkdirSync(dirname(credPath), { recursive: true })
    writeFileSync(
      credPath,
      JSON.stringify({
        accessToken: 'tok',
        refreshToken: 'ref',
        expiresAt: Date.now() - 1000, // already expired
        apiUrl: 'https://example.test',
      }),
      'utf-8',
    )
    // Harden the file to 0600 so auth.ts's permission-guard doesn't refuse it
    // (hardening: files with group/other-readable bits are rejected).
    if (process.platform !== 'win32') {
      chmodSync(dirname(credPath), 0o700)
      chmodSync(credPath, 0o600)
    }
    const { code, stdout, stderr } = runCli(['status'], { home })
    expect(code).toBe(0)
    // Should surface the API url and the expired state (no network call needed
    // for an expired token).
    expect(`${stdout}${stderr}`).toMatch(/example\.test/)
    expect(`${stdout}${stderr}`.toLowerCase()).toMatch(/expired/)
  })
})
