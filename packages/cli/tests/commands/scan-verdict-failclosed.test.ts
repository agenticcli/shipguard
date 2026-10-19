/**
 * Fail-closed verdict, on the REAL binary — recommendations #1 and #2.
 *
 * FAIL-BEFORE (verified on main @3b2a99b): `shipguard scan <dir-with-oversized-file> --json`
 * printed `"recommendation": "SAFE_TO_SHIP"` in the same document as `"degraded": true`.
 * That is the H4 false-safe: a truthful field and a false headline, side by side.
 *
 * PASS-AFTER: the same scan reports DO_NOT_SHIP in BOTH the top-level field and the
 * deprecated `riskScore.recommendation` mirror, while STILL exiting 0 — because ShipGuard
 * is passive by default and only `--strict` blocks (
 * covered by tests/commands/strict-degraded-blocks.test.ts).
 *
 * DISCIPLINE: behavioral — spawns the built binary, asserts the serialized
 * contract, not an in-process object.
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

/** A CLEAN project whose only problem is that one file was too big to read. */
function mkDegradedButCleanFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-failclosed-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(join(dir, 'small.js'), 'const ok = 1\n', 'utf-8')
  // 1 MB > the 512 KB per-file cap → skipped unread → the scan is INCOMPLETE.
  writeFileSync(join(dir, 'huge-bundle.js'), 'x'.repeat(1_000_000), 'utf-8')
  return dir
}

/** A completely clean project — the control case that must still say SAFE_TO_SHIP. */
function mkCleanFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-failclosed-clean-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(join(dir, 'small.js'), 'const ok = 1\n', 'utf-8')
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
    timeout: 60_000,
  })
  return { code: res.status === null ? -1 : res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' }
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 180_000)

describe('#1 — a degraded scan never says SAFE_TO_SHIP', () => {
  it('--json: degraded:true → recommendation DO_NOT_SHIP, exit still 0 (passive default)', () => {
    const { code, stdout } = runCli(['scan', mkDegradedButCleanFixture(), '--json'])
    const json = JSON.parse(stdout)
    expect(json.degraded).toBe(true)
    expect(json.recommendation).toBe('DO_NOT_SHIP')
    // Passive by default: the report says DO_NOT_SHIP; the PROCESS still exits 0.
    expect(code).toBe(0)
  })

  it('--json: the degraded verdict names WHY in degradedReasons', () => {
    const { stdout } = runCli(['scan', mkDegradedButCleanFixture(), '--json'])
    const json = JSON.parse(stdout)
    expect(Array.isArray(json.degradedReasons)).toBe(true)
    expect(json.degradedReasons.map((r: { code: string }) => r.code)).toContain('FILE_TOO_LARGE')
  })

  it('--json: a genuinely clean scan is untouched — still SAFE_TO_SHIP, exit 0', () => {
    const { code, stdout } = runCli(['scan', mkCleanFixture(), '--json'])
    const json = JSON.parse(stdout)
    expect(json.degraded).toBeFalsy()
    expect(json.recommendation).toBe('SAFE_TO_SHIP')
    expect(code).toBe(0)
  })

  it('human mode: the panel says INCOMPLETE, not "fix the criticals first"', () => {
    const { stdout } = runCli(['scan', mkDegradedButCleanFixture()])
    expect(stdout).toContain('INCOMPLETE')
    expect(stdout).toContain('FILE_TOO_LARGE')
    expect(stdout).not.toContain('SHIP IT')
  })

  it('--quiet: the one-line verdict admits the scan was incomplete', () => {
    const { stdout } = runCli(['scan', mkDegradedButCleanFixture(), '--quiet'])
    expect(stdout).toContain('DO NOT SHIP')
    expect(stdout).toContain('incomplete=yes')
  })
})

describe('#2 — the duplicate verdict field can never disagree', () => {
  it('--json: riskScore.recommendation mirrors the top-level recommendation (degraded)', () => {
    const { stdout } = runCli(['scan', mkDegradedButCleanFixture(), '--json'])
    const json = JSON.parse(stdout)
    expect(json.riskScore.recommendation).toBe(json.recommendation)
    expect(json.riskScore.recommendation).toBe('DO_NOT_SHIP')
  })

  it('--json: the two copies also agree on a clean scan', () => {
    const { stdout } = runCli(['scan', mkCleanFixture(), '--json'])
    const json = JSON.parse(stdout)
    expect(json.riskScore.recommendation).toBe(json.recommendation)
  })
})
