/**
 * `--strict` blocks on an unfinished scan.
 *
 * Specification:
 *   "Regression test: `--strict` on the maxfiles fixture must exit 1
 *    (fail-before/pass-after)"
 *
 * WHY IT IS THE HIGHEST-STAKES CASE: `--strict` is
 * the product's ONLY hard stop, and the `shipguard hook` feature (#5) installs exactly that
 * invocation at the merge boundary. If `--strict` exits 0 on a truncated scan, the hard stop is
 * not delivering what it is understood to deliver.
 *
 * FAIL-BEFORE (verified on the pre-change source): `resolveExitCode` keyed on
 * `blockingCount` alone, so a scan truncated at the maxFiles cap whose read files happened
 * to be clean exited 0 under `--strict`.
 *
 * DISCIPLINE: behavioral — a spawned binary on a generated
 * over-the-cap fixture, plus the unit-level truth table on resolveExitCode.
 */
import { spawnSync, execSync } from 'node:child_process'
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'

// Real-process e2e file: every test spawns the built CLI (each spawn ~0.3-1s idle, several x
// under load). Vitest's 5s default is below the cost of a 3-4 spawn test on a shared box, so
// state the budget explicitly (same 30s as the per-spawn kill timeout), file-scoped - not global.
vi.setConfig({ testTimeout: 30_000 })
import { resolveExitCode } from '../../src/commands/scan.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

const tempDirs: string[] = []

/**
 * The "maxfiles fixture": a project with a small `limits.maxFiles` policy and more files
 * than that, so collection stops early → OUTPUT_TRUNCATED → degraded. Every file is
 * innocuous, so `blockingCount` is 0 and the ONLY reason to block is the truncation.
 */
function mkMaxFilesFixture(fileCount = 40, maxFiles = 5): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-maxfiles-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(
    join(dir, 'shipguard.policy.yml'),
    `version: 1\nlimits:\n  maxFiles: ${maxFiles}\n`,
    'utf-8',
  )
  mkdirSync(join(dir, 'src'), { recursive: true })
  for (let i = 0; i < fileCount; i++) {
    writeFileSync(join(dir, 'src', `mod${i}.js`), `export const n${i} = ${i}\n`, 'utf-8')
  }
  return dir
}

/** A complete, clean project — the control: `--strict` must still exit 0 here. */
function mkCleanFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-strict-clean-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(join(dir, 'ok.js'), 'const ok = 1\n', 'utf-8')
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

describe('#3 — --strict on the maxfiles fixture must exit 1', () => {
  it('the fixture really is degraded by truncation (precondition)', () => {
    const { stdout } = runCli(['scan', mkMaxFilesFixture(), '--json'])
    const json = JSON.parse(stdout)
    expect(json.degraded).toBe(true)
    expect(json.degradedReasons.map((r: { code: string }) => r.code)).toContain('OUTPUT_TRUNCATED')
    // The point of the case: nothing blocking was FOUND — only the scan was unfinished.
    expect(json.riskScore.blockingCount).toBe(0)
  })

  it('--strict on a truncated scan exits 1', () => {
    const { code } = runCli(['scan', mkMaxFilesFixture(), '--strict', '--json'])
    expect(code).toBe(1)
  })

  it('WITHOUT --strict the same truncated scan still exits 0 (passivity preserved)', () => {
    const { code } = runCli(['scan', mkMaxFilesFixture(), '--json'])
    expect(code).toBe(0)
  })

  it('--strict on a complete clean scan still exits 0 (no over-blocking)', () => {
    const { code } = runCli(['scan', mkCleanFixture(), '--strict', '--json'])
    expect(code).toBe(0)
  })

  it('human mode names the unfinished scan as the reason for the hard stop', () => {
    const { code, stderr } = runCli(['scan', mkMaxFilesFixture(), '--strict'])
    expect(code).toBe(1)
    expect(stderr).toContain('did not finish')
    expect(stderr).toContain('OUTPUT_TRUNCATED')
  })
})

describe('#3 — resolveExitCode truth table', () => {
  it('degraded blocks only under --strict', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 0, degraded: true })).toBe(1)
    expect(resolveExitCode({ strict: false, blockingCount: 0, degraded: true })).toBe(0)
  })

  it('blocking findings still block under --strict', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 3, degraded: false })).toBe(1)
    expect(resolveExitCode({ strict: false, blockingCount: 3, degraded: false })).toBe(0)
  })

  it('a complete clean scan never blocks', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 0, degraded: false })).toBe(0)
    expect(resolveExitCode({ strict: true, blockingCount: 0 })).toBe(0)
  })
})
