/**
 * Degraded-on-oversized-skip regression (S2, HIGH).
 *
 * Symptom: a file larger than the per-file size cap is silently skipped. The
 * scan reported degraded:false, exited 0, and rendered SAFE_TO_SHIP — masking
 * that a (potentially secret-bearing, e.g. 180 MB) file was never scanned. A
 * skip-due-to-size is an INCOMPLETE scan and must degrade.
 *
 * Fix: scanner.ts includes skippedTooLarge > 0 in the degraded condition (NOT
 * skippedBinary — binary skip is normal/expected). The command emits a loud
 * human warning naming the skipped file(s).
 *
 * UPDATED (A1, 2026-07-13): exit code is now
 * verdict-neutral — degradation is surfaced ONLY via `degraded`/
 * `degradedReasons` in --json, never by moving the exit code off 0. The old
 * "degraded → exit 2" assertions here are superseded: exit 2 is reserved
 * strictly for config errors now (see resolveExitCode() in commands/scan.ts).
 * `degraded:true` + `degradedReasons` remain exactly as before — still the
 * machine-detectable signal a consumer must key on, just via JSON, not exit code.
 *
 * DISCIPLINE: behavioral — a SPAWNED binary on a dir with an
 * oversized file. Asserts degraded:true in --json (exit 0, per A1), and
 * (human mode) a stderr warning that NAMES the skipped file.
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

/** Build a project fixture containing one oversized file (> 512 KB default cap). */
function mkOversizedFixture(oversizedName = 'huge-generated.js'): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-degraded-skip-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(join(dir, 'small.js'), 'const ok = 1\n', 'utf-8')
  // 1 MB > the 512 KB DEFAULT_MAX_FILE_SIZE_BYTES → skipped as too large.
  writeFileSync(join(dir, oversizedName), 'x'.repeat(1_000_000), 'utf-8')
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

describe('scan degrades on oversized-file skip', () => {
  it('--json: oversized file → degraded:true, exit 0 (A1: verdict-neutral — ' +
     'degradation is JSON-only, exit 2 is reserved for config errors)', () => {
    const fixture = mkOversizedFixture()
    const { code, stdout } = runCli(['scan', fixture, '--json'])

    expect(() => JSON.parse(stdout)).not.toThrow()
    const parsed = JSON.parse(stdout)
    // The contract for an incomplete scan: degraded:true is what callers MUST
    // key on — a consumer that trusts only `recommendation` (findings-based,
    // here SAFE_TO_SHIP because no blocking finding was seen) is buggy, but
    // `degraded:true` (+ degradedReasons, see next test) makes the
    // incompleteness unambiguous and machine-detectable via JSON. Under A1
    // the exit code itself stays 0 — it is verdict/degradation-neutral.
    expect(parsed.degraded).toBe(true)
    expect(code).toBe(0)
  })

  it('human mode: loud warning NAMES the skipped oversized file (stderr); exit 0 per A1', () => {
    const fixture = mkOversizedFixture('secret-bundle.js')
    const { code, stderr } = runCli(['scan', fixture])
    expect(code).toBe(0)
    // The warning must name the file so the user knows WHAT was not scanned.
    expect(stderr).toMatch(/secret-bundle\.js/)
    expect(stderr.toLowerCase()).toMatch(/skip|too large|incomplete|not scanned/)
  })

  it('--json: oversized-file degrade carries degradedReasons with FILE_TOO_LARGE code ', () => {
    // Regression for: degraded:true in --json carried no machine-readable reason.
    // RCA: scan.ts:349-352 stripped _fields (internal metadata) but degradedReasons
    // (the WHY) was never populated — types.ts:91 had no such field.
    //
    // RED before fix: `parsed.degradedReasons` was undefined.
    // GREEN after fix: degradedReasons array present with at least one entry whose
    // `code` is 'FILE_TOO_LARGE', including the skipped filename in `detail`.
    const fixture = mkOversizedFixture('giant-bundle.js')
    const { code, stdout } = runCli(['scan', fixture, '--json'])

    expect(() => JSON.parse(stdout)).not.toThrow()
    const parsed = JSON.parse(stdout) as {
      degraded: boolean
      degradedReasons?: Array<{ code: string; detail?: string }>
    }

    // Confirm the outer degrade contract still holds (A1: exit 0, not 2 — see above)
    expect(parsed.degraded).toBe(true)
    expect(code).toBe(0)

    // NEW: degradedReasons must be present and machine-readable
    expect(Array.isArray(parsed.degradedReasons)).toBe(true)
    expect(parsed.degradedReasons!.length).toBeGreaterThan(0)

    const fileTooLarge = parsed.degradedReasons!.find((r) => r.code === 'FILE_TOO_LARGE')
    expect(fileTooLarge, 'expected FILE_TOO_LARGE entry in degradedReasons').toBeDefined()
    // detail must name the skipped file so agents can surface it without parsing stderr
    expect(fileTooLarge!.detail).toMatch(/giant-bundle\.js/)
  })

  it('a binary-only skip does NOT degrade (binary skip is normal)', () => {
    // Control: a NUL-byte (binary) file is skipped but is NOT a degradation.
    const dir = mkdtempSync(join(tmpdir(), 'shipguard-binary-skip-'))
    tempDirs.push(dir)
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
    writeFileSync(join(dir, 'ok.js'), 'const z = 3\n', 'utf-8')
    // Small binary file (contains NUL) — under the size cap, skipped as binary.
    writeFileSync(join(dir, 'data.bin'), Buffer.from([0x00, 0x01, 0x02, 0x00, 0x03]))

    const { code, stdout } = runCli(['scan', dir, '--json'])
    const parsed = JSON.parse(stdout)
    // Binary skip alone must NOT degrade and must NOT bump the exit code.
    expect(parsed.degraded).toBeFalsy()
    expect(code).toBe(0)
  })
})
