/**
 * --json ScanResult schema-freeze contract.
 *
 * The `--json` shape is a PUBLIC API contract for downstream agents/CI. A field
 * added, removed, or renamed silently breaks every consumer. Mutation-probing
 * exposed that no test pinned the exhaustive key set or the schemaVersion.
 *
 * This test FAILS if:
 *   - a NEW top-level key appears that is not in the allow-list (added field),
 *   - a REQUIRED key disappears (removed/renamed field),
 *   - schemaVersion is not exactly '5',
 *   - the internal `_skipped*` / `_truncated` metadata leaks into --json,
 *   - a Finding or riskScore key set drifts.
 *
 * It spawns the BUILT binary so it asserts the REAL serialized contract, not an
 * in-process object. When the schema is intentionally evolved, bump the version
 * and update BOTH the allow-list here AND this file's documented contract — that
 * is the whole point of a freeze test.
 */
import { execSync } from 'node:child_process'
import { spawnNode, type SpawnResult } from '../helpers/spawn-cli.js'
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

// ── The FROZEN contract ──────────────────────────────────────────────────────

/** Keys that MUST always be present on a free (non-pro) scan's --json result. */
const REQUIRED_TOP_LEVEL = [
  'findings',
  'riskScore',
  'filesScanned',
  'timestamp',
  'policyUsed',
  'recommendation',
  'schemaVersion',
  'degraded',
  'creditsWarning',
  // schemaVersion 2 → 3: the local history store's persistence outcome and whether the
  // regression comparison ran are always populated, success or failure — see history/index.ts.
  'stateStatus',
  'regressionCheckSkipped',
  // ScanId reuse (schemaVersion 3 → 4): whether THIS scan's scanId was reused from a prior local
  // reservation (retry idempotency) — always populated true/false, see history/scan-id.ts.
  'scanIdReused',
  // Receipt fields (schemaVersion 4 → 5): who produced this verdict
  // and about which bytes. Always populated on a real scan — see core/verdict.ts + scanner.ts.
  'runId',
  'cliVersion',
] as const

/** Additional OPTIONAL top-level keys allowed (present only with --pro or on degraded scans). */
const OPTIONAL_TOP_LEVEL = [
  'rulesApplied',
  'rulesBreakdown',
  'rulesVersion',
  'aiCodeIssues',
  'degradedReasons',
  // Present only when regressionCheckSkipped is true (reason) or false (the two lists).
  'regressionCheckSkippedReason',
  'regressions',
  'coverageChanged',
  // Receipt (rec #8) — absent only when the scan read zero files.
  'treeDigest',
] as const

const ALLOWED_TOP_LEVEL = new Set<string>([...REQUIRED_TOP_LEVEL, ...OPTIONAL_TOP_LEVEL])

/** riskScore is a frozen sub-object — exhaustive key set. */
const RISK_SCORE_KEYS = [
  'score',
  'recommendation',
  'totalFindings',
  'criticalCount',
  'highCount',
  'mediumCount',
  'lowCount',
  'infoCount',
  'blockingCount',
].sort()

/** Finding keys that may appear (superset; not all are always present). */
const ALLOWED_FINDING_KEYS = new Set<string>([
  'id',
  'title',
  'severity',
  'category',
  'file',
  'line',
  'evidence',
  'explanation',
  'recommendation',
  'blocking',
  'fix',
  'confidence',
  'aiCodeTarget',
  'suppressed',
  'cwe',
  // Added 2026-08-04. These three are NOT new schema — they have always been declared
  // optional fields of `Finding` (packages/shared/src/types.ts) and a `--pro` scan has
  // always emitted them. This allow-list simply never listed them, because until the
  // bundled corpus started running on every scan, no FREE scan could produce them. The
  // list was incomplete relative to the declared type, not deliberately narrower.
  //
  // No schemaVersion bump: the change is purely additive (three optional keys that the
  // published type already permits), so nothing an agent parses today stops working.
  'column',
  'suppressionState',
  'matcherType',
])

/** Internal metadata that must NEVER appear in the frozen --json schema. */
const FORBIDDEN_KEYS = [
  '_skippedTooLarge',
  '_skippedTooLargeFiles',
  '_skippedBinary',
  '_skippedBinaryFiles',
  '_skippedSymlinks',
  '_skippedSymlinkFiles',
  '_truncated',
]

const tempDirs: string[] = []
function mkFixtureWithFinding(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-schema-freeze-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  // An AWS key → at least one finding so the findings array is non-empty.
  writeFileSync(join(dir, 'config.js'), "const k = 'AKIAIOSFODNN7EXAMPLE'\n", 'utf-8')
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

async function scanJson(fixture: string): Promise<Record<string, unknown>> {
  const res = await spawnNode(distCli, ['scan', fixture, '--json'], { cwd: pkgRoot, timeoutMs: 25_000 })
  return JSON.parse(res.stdout)
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 120_000)

describe('--json ScanResult schema freeze ', () => {
  it('schemaVersion is exactly "5" (bumped for CLI recommendations #1/#2/#8 — see core/verdict.ts)', async () => {
    const result = (await scanJson(mkFixtureWithFinding()))
    expect(result.schemaVersion).toBe('5')
  })

  it('all required top-level keys are present', async () => {
    const result = (await scanJson(mkFixtureWithFinding()))
    for (const key of REQUIRED_TOP_LEVEL) {
      expect(result, `missing required --json key: ${key}`).toHaveProperty(key)
    }
  })

  it('NO unexpected top-level key appears (added-field guard)', async () => {
    const result = (await scanJson(mkFixtureWithFinding()))
    const unexpected = Object.keys(result).filter((k) => !ALLOWED_TOP_LEVEL.has(k))
    expect(
      unexpected,
      `UNFROZEN --json key(s) appeared: ${unexpected.join(', ')}. ` +
        'If intentional, bump schemaVersion and update the freeze allow-list.',
    ).toEqual([])
  })

  it('internal _skipped*/_truncated metadata never leaks into --json', async () => {
    const result = (await scanJson(mkFixtureWithFinding()))
    for (const forbidden of FORBIDDEN_KEYS) {
      expect(result, `internal key leaked into --json: ${forbidden}`).not.toHaveProperty(forbidden)
    }
  })

  it('riskScore has the exact frozen key set', async () => {
    const result = (await scanJson(mkFixtureWithFinding()))
    const riskScore = result.riskScore as Record<string, unknown>
    expect(Object.keys(riskScore).sort()).toEqual(RISK_SCORE_KEYS)
  })

  it('every finding key is within the frozen Finding allow-list', async () => {
    const result = (await scanJson(mkFixtureWithFinding()))
    const findings = result.findings as Array<Record<string, unknown>>
    expect(findings.length).toBeGreaterThan(0)
    for (const finding of findings) {
      const unexpected = Object.keys(finding).filter((k) => !ALLOWED_FINDING_KEYS.has(k))
      expect(unexpected, `UNFROZEN Finding key(s): ${unexpected.join(', ')}`).toEqual([])
      // Core finding fields must always be present.
      for (const core of ['id', 'title', 'severity', 'category', 'file', 'blocking']) {
        expect(finding).toHaveProperty(core)
      }
    }
  })

  it('field TYPES are stable (contract is shape AND type)', async () => {
    const result = (await scanJson(mkFixtureWithFinding()))
    expect(Array.isArray(result.findings)).toBe(true)
    expect(typeof result.filesScanned).toBe('number')
    expect(typeof result.timestamp).toBe('string')
    expect(typeof result.policyUsed).toBe('string')
    expect(typeof result.schemaVersion).toBe('string')
    expect(typeof result.scanIdReused).toBe('boolean')
    const riskScore = result.riskScore as Record<string, unknown>
    expect(typeof riskScore.score).toBe('number')
    expect(typeof riskScore.blockingCount).toBe('number')
  })
})
