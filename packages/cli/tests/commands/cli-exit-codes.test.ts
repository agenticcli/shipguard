/**
 * Spawned-binary exit-code regression tests.
 *
 * Incident 373dd8da: `shipguard --version` exited non-zero (exit 3) on a
 * mid-build state because the cli.ts exitOverride catch only handled
 * exitCode !== 0 cleanly for unknown commands, but the `--version` /
 * `--help` informational paths (Commander emits a CommanderError with
 * exitCode 0) were not always routed to a clean exit. The release-gate's
 * VERSION-GATE was de-bandaided to assert exit 0 separately from the value
 * (no more `--version 2>/dev/null; true`).
 *
 * Related: and
 *.
 *
 * KEY DISCIPLINE: these assertions SPAWN THE BUILT BINARY
 * (dist/cli.js). Unit tests that call parseAsync() in-process never exercise
 * the real process exit path — exactly why such bugs ship. Every
 * public command's exit code MUST be a spawned-binary assertion.
 */
import { execSync } from 'node:child_process'
import { spawnNode, type SpawnResult } from '../helpers/spawn-cli.js'
import { existsSync, readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest'

// Real-process e2e file: every test spawns the built CLI (each spawn ~0.3-1s idle, several x
// under load). Vitest's 5s default is below the cost of a 3-4 spawn test on a shared box, so
// state the budget explicitly (same 30s as the per-spawn kill timeout), file-scoped - not global.
vi.setConfig({ testTimeout: 30_000 })

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')
const pkgVersion = JSON.parse(
  readFileSync(resolve(pkgRoot, 'package.json'), 'utf-8')
).version as string

/**
 * Run the BUILT binary with given args from a neutral cwd (pkgRoot).
 * Returns { code, stdout, stderr }. No shell — argv passed directly.
 */
function runCli(args: string[], opts: { cwd?: string } = {}): Promise<SpawnResult> {
  return spawnNode(distCli, args, { cwd: opts.cwd ?? pkgRoot })
}


// The built binary must exist for these tests. Build it if missing so the
// suite is self-contained (the release-gate also builds before running tests).
beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 120_000)

describe('spawned-binary exit-code contract ', () => {
  it('dist/cli.js exists (build produced the binary)', async () => {
    expect(existsSync(distCli)).toBe(true)
  })

  it('`--version` → exit 0 AND prints package.json version', async () => {
    const { code, stdout } = await runCli(['--version'])
    // Exit code is asserted SEPARATELY from the value — the exact thing the
    // old gate swallowed with `2>/dev/null; true` .
    expect(code).toBe(0)
    expect(stdout.trim()).toBe(pkgVersion)
  })

  it('`--help` → exit 0', async () => {
    const { code, stdout } = await runCli(['--help'])
    expect(code).toBe(0)
    expect(stdout.length).toBeGreaterThan(0)
  })

  it('bare invocation (no args) → exit 0 (branded quickstart)', async () => {
    const { code, stdout } = await runCli([])
    expect(code).toBe(0)
    expect(stdout.toLowerCase()).toMatch(/shipguard|scan|quickstart/)
  })

  it('`?` alias → exit 0 (routes to help)', async () => {
    const { code } = await runCli(['?'])
    expect(code).toBe(0)
  })

  it('unknown command → exit 2 (config/usage error, not 0)', async () => {
    const { code, stderr } = await runCli(['totallyunknowncmd'])
    // unknown command MUST exit 2, never 0.
    expect(code).toBe(2)
    expect(stderr.toLowerCase()).toContain('unknown command')
  })

  it('unknown command close to a real one → exit 2 with a suggestion', async () => {
    const { code, stderr } = await runCli(['scna'])
    expect(code).toBe(2)
    expect(stderr.toLowerCase()).toMatch(/did you mean|scan/)
  })

  it('`help` subcommand → exit 0', async () => {
    const { code } = await runCli(['help'])
    expect(code).toBe(0)
  })
})

// A tiny clean project. These tests used to scan `pkgRoot` (the whole package incl. node_modules
// and dist: ~18s idle, >30s under load - the source of default-timeout flakes). The exit-code
// contract under test does not depend on tree size; scan-size/linear-time is covered by
// tests/scaling/linear-growth.test.ts.
const cleanFixtures: string[] = []
function mkCleanFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-clean-'))
  cleanFixtures.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"clean-fixture"}', 'utf-8')
  writeFileSync(join(dir, 'index.js'), 'module.exports = 1\n', 'utf-8')
  return dir
}
afterAll(() => {
  for (const d of cleanFixtures.splice(0)) rmSync(d, { recursive: true, force: true })
})

describe('spawned-binary scan exit codes (documented contract 0/1/2/3)', () => {
  it('scan a clean project fixture → exit 0 (safe)', async () => {
    const { code } = await runCli(['scan', mkCleanFixture(), '--quiet'])
    expect(code).toBe(0)
  })

  it('scan a non-project directory (no path, scope guard) → exit 2', async () => {
    // Run from a tmp dir with no package.json/.git and no path arg.
    const tmp = execSync('mktemp -d', { encoding: 'utf-8' }).trim()
    const { code } = await runCli(['scan', '--quiet'], { cwd: tmp })
    expect(code).toBe(2)
  })
})

describe('spawned-binary A1 exit-code contract: verdict-neutral by default (2026-07-13)', () => {
  // RCA (review/fable/2026-07-06-prelaunch-code-review/raw-fable/06-cli-repo.md
  // P0, commands/scan.ts:54-67): a default `shipguard scan` against a fixture with
  // a hardcoded live secret exited 0 while the written contract claimed "0=safe".
  // A1 makes this the INTENDED, documented behavior: exit 0 = "scan completed,
  // read the JSON `recommendation`" — --strict is the opt-in hard gate.
  const tmp: string[] = []

  function mkSecretFixture(): string {
    const dir = mkdtempSync(join(tmpdir(), 'shipguard-a1-secret-'))
    tmp.push(dir)
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture-a1"}', 'utf-8')
    // A live Stripe secret key — matches secrets.ts's sk_live_ HIGH-confidence
    // detector (compileDetectorRegex pattern at src/checks/secrets.ts:131).
    // This is a synthetic fixture value, never a real credential.
    writeFileSync(
      join(dir, 'config.js'),
      `const stripeKey = "sk_live_${'a'.repeat(24)}";\nmodule.exports = { stripeKey };\n`,
      'utf-8',
    )
    return dir
  }

  afterEach(() => {
    for (const d of tmp.splice(0)) {
      try {
        rmSync(d, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })

  it('FAIL-BEFORE regression: default scan on a fixture with a blocking secret ' +
     '→ exit 0 (verdict-neutral), JSON recommendation is DO_NOT_SHIP', async () => {
    const fixture = mkSecretFixture()
    const { code, stdout } = await runCli(['scan', fixture, '--json'])
    expect(code).toBe(0)
    const parsed = JSON.parse(stdout)
    expect(parsed.recommendation).toBe('DO_NOT_SHIP')
    expect(parsed.riskScore.blockingCount).toBeGreaterThan(0)
  })

  it('--strict on the SAME fixture → exit 1 (opt-in hard gate)', async () => {
    const fixture = mkSecretFixture()
    const { code, stdout } = await runCli(['scan', fixture, '--json', '--strict'])
    expect(code).toBe(1)
    const parsed = JSON.parse(stdout)
    expect(parsed.recommendation).toBe('DO_NOT_SHIP')
  })

  it('--quiet on the blocking fixture WITHOUT --strict prints an informational ' +
     'caveat next to the verdict (exit 0, no misleading "hard failure" implication)', async () => {
    const fixture = mkSecretFixture()
    const { code, stdout } = await runCli(['scan', fixture, '--quiet'])
    expect(code).toBe(0)
    expect(stdout.toLowerCase()).toMatch(/informational|exit 0/)
  })
})

describe('spawned-binary subcommand unknown-option exit codes ', () => {
  // RCA: program.exitOverride() on the ROOT Command was not inherited by the
  // subcommand Command objects, so Commander's default handler called
  // process.exit(1) (BLOCKED) on an unknown subcommand option — before cli.ts's
  // own catch could map it to exit 2 (CONFIG_ERROR). Each subcommand must carry
  // its own exitOverride and unknown-option/command errors must map to exit 2.

  it('root --badopt → exit 2 (config/usage error) — control, already correct', async () => {
    const { code } = await runCli(['--badopt'])
    expect(code).toBe(2)
  })

  it('scan --badopt → exit 2 (was 1)', async () => {
    const { code, stderr } = await runCli(['scan', '--badopt'])
    expect(code).toBe(2)
    expect(stderr.toLowerCase()).toMatch(/unknown option|--badopt/)
  })

  it('init --badopt → exit 2 (was 1)', async () => {
    const { code } = await runCli(['init', '--badopt'])
    expect(code).toBe(2)
  })

  it('status --badopt → exit 2 (was 1)', async () => {
    const { code } = await runCli(['status', '--badopt'])
    expect(code).toBe(2)
  })

  it('login --badopt → exit 2 (every subcommand, not just the named three)', async () => {
    const { code } = await runCli(['login', '--badopt'])
    expect(code).toBe(2)
  })

  it('a VALID scan still works → exit 0 (fix did not break the happy path)', async () => {
    // Timeout raised to 30s (same reason as above — see D.4 migration note).
    const { code } = await runCli(['scan', mkCleanFixture(), '--quiet'])
    expect(code).toBe(0)
  })
})

describe('spawned-binary runtime-error exit code 3 ', () => {
  // Coverage gap (mutation-probing): exit 3 was only ever asserted via the
  // in-process handler unit test — never through a SPAWNED binary on a real
  // scan() throw. We force a genuine runtime error inside scan(): a policy whose
  // `ignore.paths` is a non-iterable scalar. It is valid YAML and a valid object
  // (so loadPolicy succeeds), but scanner.ts spreads `...policy.ignore.paths`,
  // which throws `TypeError: … is not iterable` at runtime — caught by the
  // scan-command try/catch that maps it to EXIT_CODES.RUNTIME_ERROR (3).
  const tmp: string[] = []
  function mkBadPolicyFixture(): string {
    const dir = mkdtempSync(join(tmpdir(), 'shipguard-exit3-'))
    tmp.push(dir)
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
    // ignore.paths as a NUMBER → not iterable → spread throws inside scan().
    writeFileSync(join(dir, 'shipguard.policy.yml'), 'version: 1\nignore:\n  paths: 42\n', 'utf-8')
    return dir
  }
  afterEach(() => {
    for (const d of tmp.splice(0)) {
      try {
        rmSync(d, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })

  it('scan() runtime throw (human mode) → exit 3 with a clean error line', async () => {
    const { code, stdout, stderr } = await runCli(['scan', mkBadPolicyFixture(), '--quiet'])
    expect(code).toBe(3)
    // A clean human error, never a raw V8 stack / core dump.
    expect(`${stdout}${stderr}`.toLowerCase()).toMatch(/scan failed|not iterable|unexpected/)
  })

  it('scan() runtime throw (--json) → exit 3 AND stdout is still valid JSON', async () => {
    const { code, stdout } = await runCli(['scan', mkBadPolicyFixture(), '--json'])
    expect(code).toBe(3)
    // --json must stay parseable even on a runtime error.
    expect(() => JSON.parse(stdout)).not.toThrow()
    expect(JSON.parse(stdout)).toHaveProperty('error')
  })

  // ---------------------------------------------------------------------------
  // P1 regression (review/fable/2026-07-06-prelaunch-code-review/raw-fable/
  // 06-cli-repo.md, git.ts:45-47): a genuine `git` failure during `--changed`
  // collection must surface as exit 3 with the git stderr in the message —
  // never silently as exit 0 "0 files scanned, SAFE." This is the FULL
  // end-to-end spawned-binary version of the git.ts/scanner.ts unit coverage.
  // ---------------------------------------------------------------------------
  it('FAIL-BEFORE regression: `--changed` against a git repo with a corrupted ' +
     'index → exit 3 (runtime error), NOT exit 0/"safe"', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shipguard-git-fail-'))
    tmp.push(dir)
    execSync('git init -q', { cwd: dir })
    execSync('git config user.email test@example.com', { cwd: dir })
    execSync('git config user.name test', { cwd: dir })
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
    writeFileSync(join(dir, 'a.ts'), 'const a = 1\n', 'utf-8')
    execSync('git add -A', { cwd: dir })
    execSync('git commit -q -m init', { cwd: dir })
    // Corrupt the index file so any `git diff --cached` / `git diff` call fails.
    writeFileSync(join(dir, '.git', 'index'), 'not a real git index', 'utf-8')

    const { code, stdout, stderr } = await runCli(['scan', dir, '--changed', '--json'])
    expect(code).toBe(3)
    // The git failure detail must be visible, not swallowed.
    expect(`${stdout}${stderr}`.toLowerCase()).toMatch(/git|index/)
  })
})
