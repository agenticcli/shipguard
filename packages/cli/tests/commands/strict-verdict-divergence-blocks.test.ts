/**
 * `--strict` must never disagree with the printed verdict — CLI-2 / J-3
 *
 * ROOT CAUSE (evidenced on the pre-fix source, commit 85ff828):
 *   `resolveExitCode()` (src/commands/scan.ts:111-124) keyed the --strict hard stop
 *   ONLY on `blockingCount`/`degraded`. `computeRiskScore()` (src/core/risk-score.ts:14-25)
 *   sums severity weight for EVERY finding, including ones marked `suppressed:true` —
 *   suppression (src/core/suppression.ts:14-18) only forces `blocking:false`, it does
 *   NOT remove the finding from the score ("a suppressed finding is NOT dropped. It is
 *   still RECORDED and COUNTED"). So a scan whose only findings are suppressed-but-severe
 *   secrets can cross the `computeVerdict()` DO_NOT_SHIP threshold (score >= 50) while
 *   `blockingCount` stays 0 — the printed panel/`--json` says "DO NOT SHIP" and the
 *   pre-fix `--strict` exit code said 0. Every installed hook
 *   (`shipguard scan --json --strict` — src/core/hook-templates.ts GATE_COMMAND) shells
 *   out to exactly this invocation, so a pre-push/CI/Claude hook waved a DO_NOT_SHIP
 *   scan through the merge boundary it exists to guard.
 *
 * FIX (fail-closed — see resolveExitCode doc
 * comment in src/commands/scan.ts for the full rationale): resolveExitCode() now ALSO
 * blocks under --strict when the effective recommendation (verdict.ts
 * `effectiveRecommendation()` — the exact value the panel/`--json` prints) is
 * DO_NOT_SHIP. This is an ADDITIVE OR term — blockingCount>0 and degraded===true still
 * block exactly as before (see tests/commands/strict-degraded-blocks.test.ts, which this
 * file does not duplicate or replace).
 *
 * UPDATED: suppressed findings no longer count toward the risk
 * score or verdict (risk-score.ts), so the "suppressed-but-severe" fixture below is now
 * SAFE_TO_SHIP and `--strict` exits 0 - the exit code and the printed verdict still agree,
 * which is the invariant this file protects. The `resolveExitCode` recommendation OR-term stays
 * (a DO_NOT_SHIP reached by ACTIVE non-blocking findings must still block under --strict).
 *
 * FAIL-BEFORE (verified on the pre-fix source): the frozen fixture below reliably
 * produces `recommendation: "DO_NOT_SHIP"`, `riskScore.score: 60`,
 * `riskScore.blockingCount: 0` — and `--strict --json` exited 0.
 *
 * DISCIPLINE:
 * behavioral — a spawned binary against a frozen fixture repo, plus the unit-level truth
 * table on resolveExitCode().
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
 * FROZEN fixture: two hardcoded secrets, each on a line covered by a
 * `// shipguard-ignore: hardcoded_secret -- <reason>` comment on the line above (the
 * documented suppression syntax — src/core/suppression.ts SUPPRESS_RE). Both patterns are
 * unambiguous, unrelated to any bundled-corpus rule that could double-count the same
 * secret under a second id (verified empirically: findings.length === 2, not 3), and each
 * is `severity: 'high'` (SEVERITY_WEIGHTS.high = 30 — src/checks/secrets.ts 'OpenAI API
 * Key' / 'Anthropic API Key' patterns), so the two together sum to a risk score of
 * exactly 60 — over the DO_NOT_SHIP threshold (>= 50) on their own. Suppression forces
 * `blocking: false` on both (src/core/suppression.ts applySuppressions), so
 * `blockingCount` stays 0 — the ONLY way to reach DO_NOT_SHIP here is via the score,
 * exactly the CLI-2/J-3 gap.
 */
function mkSuppressedButSevereFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-strict-verdict-divergence-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  mkdirSync(join(dir, 'src'), { recursive: true })
  writeFileSync(
    join(dir, 'src', 'keys.js'),
    [
      "// shipguard-ignore: hardcoded_secret -- test fixture placeholder, accepted risk",
      "const openaiKey = process.env.OPENAI_KEY || 'sk-proj-abcdefghijklmnopqrstuvwxyz12'",
      "// shipguard-ignore: hardcoded_secret -- test fixture placeholder, accepted risk",
      "const anthropicKey = process.env.ANTHROPIC_KEY || 'sk-ant-api03-abcdefghijklmnopqrstuvwx'",
      '',
    ].join('\n'),
    'utf-8',
  )
  return dir
}

/** A complete, clean project — the control: `--strict` must still exit 0 here. */
function mkCleanFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-strict-verdict-divergence-clean-'))
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

/** Control: an ACTIVE (unsuppressed) severe secret. */
function mkActiveSevereFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-strict-verdict-active-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(join(dir, 'k.js'), "const a = 'AKIAIOSFODNN7REALKEY'\n", 'utf-8')
  return dir
}

describe('suppressed findings do not score (design decision) and --strict agrees with the verdict', () => {
  it('the fully-suppressed fixture is reported but scores 0 / SAFE_TO_SHIP with zero blocking (precondition)', () => {
    const { stdout } = runCli(['scan', mkSuppressedButSevereFixture(), '--json'])
    const json = JSON.parse(stdout)
    expect(json.recommendation).toBe('SAFE_TO_SHIP')
    expect(json.riskScore.score).toBe(0)
    expect(json.riskScore.blockingCount).toBe(0)
    // still REPORTED and counted separately: 2 findings, both suppressed, active severity counts are 0
    expect(json.findings).toHaveLength(2)
    expect(json.findings.every((f: { suppressed?: boolean; blocking: boolean }) => f.suppressed === true && f.blocking === false)).toBe(true)
    expect(json.riskScore.totalFindings).toBe(2)
    expect(json.riskScore.highCount).toBe(0)
  })

  it('--strict on the fully-suppressed scan exits 0 (verdict SAFE_TO_SHIP, exit agrees)', () => {
    const { code } = runCli(['scan', mkSuppressedButSevereFixture(), '--strict', '--json'])
    expect(code).toBe(0)
  })

  it('WITHOUT --strict the same scan also exits 0', () => {
    const { code } = runCli(['scan', mkSuppressedButSevereFixture(), '--json'])
    expect(code).toBe(0)
  })

  it('--strict on a complete clean scan still exits 0 (no over-blocking)', () => {
    const { code } = runCli(['scan', mkCleanFixture(), '--strict', '--json'])
    expect(code).toBe(0)
  })

  it('control: an ACTIVE (unsuppressed) severe finding still blocks --strict ', () => {
    const { code, stdout } = runCli(['scan', mkActiveSevereFixture(), '--strict', '--json'])
    const json = JSON.parse(stdout)
    expect(json.riskScore.blockingCount).toBeGreaterThan(0)
    expect(json.riskScore.score).toBeGreaterThan(0)
    expect(code).toBe(1)
  })
})

describe('CLI-2/J-3 — resolveExitCode truth table (recommendation is an OR term, never a replacement)', () => {
  it('DO_NOT_SHIP recommendation blocks on its own under --strict, even with zero blocking findings', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 0, degraded: false, recommendation: 'DO_NOT_SHIP' })).toBe(1)
    expect(resolveExitCode({ strict: false, blockingCount: 0, degraded: false, recommendation: 'DO_NOT_SHIP' })).toBe(0)
  })

  it('a non-DO_NOT_SHIP recommendation does not block on its own', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 0, degraded: false, recommendation: 'REVIEW_BEFORE_SHIP' })).toBe(0)
    expect(resolveExitCode({ strict: true, blockingCount: 0, degraded: false, recommendation: 'SAFE_TO_SHIP' })).toBe(0)
  })

  it('blocking findings still block under --strict regardless of recommendation (existing behavior preserved)', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 3, degraded: false, recommendation: 'SAFE_TO_SHIP' })).toBe(1)
  })

  it('degraded still blocks under --strict regardless of recommendation (existing behavior preserved)', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 0, degraded: true, recommendation: 'SAFE_TO_SHIP' })).toBe(1)
  })

  it('omitting recommendation entirely never blocks on its own (backward-compatible default)', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 0, degraded: false })).toBe(0)
  })

  it('a complete clean scan never blocks', () => {
    expect(resolveExitCode({ strict: true, blockingCount: 0, degraded: false, recommendation: 'SAFE_TO_SHIP' })).toBe(0)
  })
})
