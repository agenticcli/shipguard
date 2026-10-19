/**
 * --json / --sarif stdout purity.
 *
 * Symptom: when `--pro` degrades (e.g. API unreachable / not authenticated),
 * `logger.warn()` printed the "⚠ Pro rules unavailable…" line to STDOUT via
 * console.log, corrupting the `--json` payload. `scan --pro … --json | jq .`
 * failed to parse.
 *
 * Fix: all non-data human/status output (logger.warn/info/success/divider/etc.)
 * goes to STDERR. STDOUT carries ONLY the machine payload in --json/--sarif mode.
 *
 * DISCIPLINE: the bug is behavioral — only a SPAWNED binary exercises
 * the real stdout/stderr split. These assertions spawn dist/cli.js and parse the
 * captured stdout with JSON.parse (the jq equivalent).
 *
 * UPDATE: the default behavior for an explicit --pro request
 * whose rule fetch fails changed (see scan.ts resolveExitCode doc comment,
 * amended A1)
 * PREVIOUSLY every pro-fetch failure silently degraded to a free scan with
 * exit 0 (a false-green: the caller asked for the pro gate and didn't get it,
 * but saw success). NOW the default is exit 3 with a structured JSON error;
 * the OLD fallback behavior is opt-in via --allow-degraded. Both paths must
 * still keep stdout pure JSON — that is the invariant this file guards, and
 * it is unaffected by which of the two behaviors is active.
 */
import { spawnSync, execSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
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
function mkProjectFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-json-purity-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(join(dir, 'app.js'), 'const x = 1\n', 'utf-8')
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

function runCli(args: string[]): { code: number; stdout: string; stderr: string } {
  const res = spawnSync('node', [distCli, ...args], {
    cwd: pkgRoot,
    encoding: 'utf-8',
    timeout: 30_000,
  })
  const code = res.status === null ? -1 : res.status
  return { code, stdout: res.stdout ?? '', stderr: res.stderr ?? '' }
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 120_000)

describe('--json stdout purity under --pro degrade ', () => {
  // Which ProFetchErrorCode this spawned binary produces is environment-dependent:
  // if the machine running this test has a real `shipguard login` credentials file,
  // the unreachable --api-url is reached and the network failure classifies as
  // SERVER_ERROR; with no stored credentials (the common case, e.g. CI), fetchProRules
  // never reaches the network at all and classifies as AUTH_FAILED. Both are exercised
  // exhaustively and deterministically (mocked) in pro-scanner-error-codes.test.ts and
  // scan-pro-fetch-failure.test.ts — this file's job is ONLY to prove the stdout/stderr
  // purity invariant holds for the real spawned binary, so it accepts either class.
  const KNOWN_PRO_FETCH_ERROR_CODES = ['AUTH_FAILED', 'INSUFFICIENT_CREDITS', 'RATE_LIMITED', 'SERVER_ERROR', 'BUNDLE_INVALID']

  it('FAIL-BEFORE/PASS-AFTER : default --pro fetch failure ' +
     '→ exit 3, structured JSON error on stdout, human warning on stderr', () => {
    const fixture = mkProjectFixture()
    // Unreachable API forces the pro-fetch failure path.
    const { code, stdout, stderr } = runCli([
      'scan',
      fixture,
      '--pro',
      '--api-url',
      'http://127.0.0.1:19999',
      '--json',
    ])

    // an explicit --pro request whose fetch failed is now a
    // RUNTIME ERROR (exit 3) by default — the requested gate did not run, so
    // this can never silently read as exit 0/"safe". See scan.ts
    // resolveExitCode doc comment (amended A1, explicit-Pro-failure path only).
    expect(code).toBe(3)

    // STDOUT must be exactly one JSON document — no warning lines prepended.
    expect(() => JSON.parse(stdout)).not.toThrow()
    const parsed = JSON.parse(stdout)
    expect(parsed.degraded).toBe(false)
    expect(KNOWN_PRO_FETCH_ERROR_CODES).toContain(parsed.code)
    expect(typeof parsed.error).toBe('string')
    expect(typeof parsed.action).toBe('string')

    // The warning must STILL be emitted — to STDERR, where it belongs.
    expect(stderr).toMatch(/pro rules request failed/i)
    // And it must NOT be on stdout.
    expect(stdout).not.toMatch(/pro rules request failed/i)
    expect(stdout.trimStart().startsWith('{')).toBe(true)
  })

  it('--allow-degraded restores the pre-fix fallback: exit 0, degraded:true, clean JSON', () => {
    const fixture = mkProjectFixture()
    const { code, stdout, stderr } = runCli([
      'scan',
      fixture,
      '--pro',
      '--allow-degraded',
      '--api-url',
      'http://127.0.0.1:19999',
      '--json',
    ])

    // Opt-in fallback: verdict-neutral, exit 0, degraded:true (old behavior).
    expect(code).toBe(0)

    expect(() => JSON.parse(stdout)).not.toThrow()
    const parsed = JSON.parse(stdout)
    expect(parsed).toHaveProperty('findings')
    expect(parsed).toHaveProperty('schemaVersion', '5')
    expect(parsed.degraded).toBe(true)

    expect(stderr).toMatch(/degrading to free scan/i)
    expect(stdout).not.toMatch(/degrading to free scan/i)
    expect(stdout.trimStart().startsWith('{')).toBe(true)
  })

  it('stdout parses as clean JSON on a normal (non-pro) scan', () => {
    const fixture = mkProjectFixture()
    const { stdout } = runCli(['scan', fixture, '--json'])
    expect(() => JSON.parse(stdout)).not.toThrow()
    expect(stdout.trimStart().startsWith('{')).toBe(true)
  })

  it('--sarif: default --pro fetch failure → exit 3, clean JSON error (not a SARIF doc)', () => {
    const fixture = mkProjectFixture()
    const { code, stdout } = runCli([
      'scan',
      fixture,
      '--pro',
      '--api-url',
      'http://127.0.0.1:19999',
      '--sarif',
    ])
    expect(code).toBe(3)
    expect(() => JSON.parse(stdout)).not.toThrow()
    const parsed = JSON.parse(stdout)
    expect(parsed.degraded).toBe(false)
    expect(KNOWN_PRO_FETCH_ERROR_CODES).toContain(parsed.code)
  })

  it('--sarif + --allow-degraded stdout still parses as a valid SARIF document under degrade', () => {
    const fixture = mkProjectFixture()
    const { code, stdout } = runCli([
      'scan',
      fixture,
      '--pro',
      '--allow-degraded',
      '--api-url',
      'http://127.0.0.1:19999',
      '--sarif',
    ])
    expect(code).toBe(0)
    expect(() => JSON.parse(stdout)).not.toThrow()
    const sarif = JSON.parse(stdout)
    expect(sarif).toHaveProperty('version') // SARIF 2.1.0 document
  })
})
