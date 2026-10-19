/**
 * Free-tier inline-suppression regression.
 *
 * Symptom: the 5 free CheckModules (secrets/auth/database/payments/deployment)
 * ignored `// shipguard-ignore: <ruleId> -- <reason>` comments. Only
 * pro-scanner.ts honored them (its own SUPPRESS_RE). So a user could suppress a
 * PRO finding but NOT a free finding — `// shipguard-ignore: hardcoded_secret`
 * was silently ineffective, the finding stayed blocking, and `scan --strict`
 * exited 1.
 *
 * Fix: factor the suppression logic into a shared helper and apply it to
 * free-tier findings too. Pro semantics: a suppressed finding is still COUNTED
 * and RECORDED (suppressed:true), just not blocking (blocking:false).
 *
 * DISCIPLINE: behavioral — a SPAWNED binary on a fixture with an
 * inline suppression over a REAL free rule id (hardcoded_secret). Asserts the
 * finding is suppressed (not blocking) and a strict scan no longer exits 1.
 * A unit test on the shared helper backs it up.
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

function mkFixture(fileBody: string, fileName = 'config.js'): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-free-suppress-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(join(dir, fileName), fileBody, 'utf-8')
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

// A real free rule id is `hardcoded_secret` (checks/secrets.ts). An AWS access
// key triggers it with HIGH confidence (blocking by default).
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'

describe('free-tier inline suppression ', () => {
  it('suppression comment ON THE SAME LINE marks the free finding suppressed (not blocking)', () => {
    const fixture = mkFixture(
      `const key = '${AWS_KEY}' // shipguard-ignore: hardcoded_secret -- qa, reviewed\n`,
    )
    const { stdout } = runCli(['scan', fixture, '--json'])
    const parsed = JSON.parse(stdout)
    const secretFindings = parsed.findings.filter(
      (f: { id: string }) => f.id === 'hardcoded_secret',
    )
    expect(secretFindings.length).toBeGreaterThan(0)
    // Pro semantics: still RECORDED, marked suppressed, and NOT blocking.
    for (const f of secretFindings) {
      expect(f.suppressed).toBe(true)
      expect(f.blocking).toBe(false)
    }
  })

  it('suppression comment ON THE LINE ABOVE also suppresses (matches pro behavior)', () => {
    const fixture = mkFixture(
      `// shipguard-ignore: hardcoded_secret -- qa, accepted\nconst key = '${AWS_KEY}'\n`,
    )
    const { stdout } = runCli(['scan', fixture, '--json'])
    const parsed = JSON.parse(stdout)
    const secretFindings = parsed.findings.filter(
      (f: { id: string }) => f.id === 'hardcoded_secret',
    )
    expect(secretFindings.length).toBeGreaterThan(0)
    expect(secretFindings.every((f: { suppressed?: boolean }) => f.suppressed === true)).toBe(true)
  })

  // UPDATED 2026-08-05 (CLI-2/J-3, strict-exit-verdict-divergence — see
  // tests/commands/strict-verdict-divergence-blocks.test.ts and the resolveExitCode()
  // doc comment in src/commands/scan.ts). This exact fixture is now a CLI-2 case, not a
  // counter-example to it: `AKIAIOSFODNN7EXAMPLE` fires BOTH the legacy free-tier rule
  // (`hardcoded_secret`) AND its as-yet-unreconciled corpus twin
  // (`generic.secrets.aws-access-key`) — two `severity: 'high'` findings, both suppressed
  // by the SAME comment (both `blocking: false`), but their combined risk score (60) still
  // crosses the DO_NOT_SHIP threshold. The narrower claim this test originally protected —
  // that suppression alone, at a genuinely LOW resulting score, must not force --strict to
  // block — is unaffected and re-asserted in isolation immediately below with a
  // single-finding, score-15 fixture that stays SAFE_TO_SHIP/REVIEW_BEFORE_SHIP.
  it('a suppressed free finding does NOT score: verdict is SAFE_TO_SHIP and --strict exits 0 (design decision), yet it is still reported', () => {
    // `AKIAIOSFODNN7EXAMPLE` fires the legacy `hardcoded_secret` (suppressed by the comment) and its
    // corpus twin `generic.secrets.aws-access-key` (suppressed by the rule's own EXAMPLE antiPattern).
    // Both used to score (2 x high = 60 = DO_NOT_SHIP, CLI-2). Suppressed findings no longer count.
    const fixture = mkFixture(
      `const key = '${AWS_KEY}' // shipguard-ignore: hardcoded_secret -- qa\n`,
    )
    const { stdout: json } = runCli(['scan', fixture, '--json'])
    const parsed = JSON.parse(json)
    expect(parsed.riskScore.score).toBe(0)
    expect(parsed.recommendation).toBe('SAFE_TO_SHIP')
    expect(parsed.riskScore.blockingCount).toBe(0)
    // Still REPORTED and counted separately: findings[] keeps them (suppressed:true) and
    // totalFindings exceeds the (active-only) severity counts by exactly the suppressed count.
    expect(parsed.findings.length).toBeGreaterThan(0)
    expect(parsed.findings.every((f: { suppressed?: boolean }) => f.suppressed === true)).toBe(true)
    expect(parsed.riskScore.totalFindings).toBe(parsed.findings.length)
    expect(parsed.riskScore.highCount).toBe(0)

    const { code } = runCli(['scan', fixture, '--strict', '--quiet'])
    expect(code).toBe(0)
  })

  it('a suppressed free finding whose resulting score stays BELOW DO_NOT_SHIP does not block --strict (the original claim, isolated from CLI-2)', () => {
    // A single medium-severity secret (Stripe TEST key, weight 15) — no corpus twin fires
    // for this pattern, so this is a clean score-15/REVIEW_BEFORE_SHIP case, unlike the AWS
    // fixture above.
    const fixture = mkFixture(
      `const key = 'sk_test_abcdefghijklmnopqrstuvwx' // shipguard-ignore: hardcoded_secret -- qa\n`,
    )
    const { stdout: json } = runCli(['scan', fixture, '--json'])
    const parsed = JSON.parse(json)
    expect(parsed.recommendation).not.toBe('DO_NOT_SHIP')
    expect(parsed.riskScore.blockingCount).toBe(0)

    const { code } = runCli(['scan', fixture, '--strict', '--quiet'])
    expect(code).toBe(0)
  })

  it('NO suppression comment → free finding still blocks --strict (exit 1) — control', () => {
    const fixture = mkFixture(`const key = '${AWS_KEY}'\n`)
    const { code } = runCli(['scan', fixture, '--strict', '--quiet'])
    expect(code).toBe(1)
  })

  it('a suppression for a DIFFERENT rule id does NOT suppress this finding', () => {
    const fixture = mkFixture(
      `const key = '${AWS_KEY}' // shipguard-ignore: some_other_rule -- nope\n`,
    )
    const { stdout } = runCli(['scan', fixture, '--json'])
    const parsed = JSON.parse(stdout)
    const secretFindings = parsed.findings.filter(
      (f: { id: string }) => f.id === 'hardcoded_secret',
    )
    expect(secretFindings.length).toBeGreaterThan(0)
    // Mismatched rule id → NOT suppressed, still blocking.
    expect(secretFindings.some((f: { blocking?: boolean }) => f.blocking === true)).toBe(true)
  })
})
