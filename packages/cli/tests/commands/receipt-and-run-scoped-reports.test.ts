/**
 * Receipt fields + run-scoped reports.
 *
 * Specification:
 *   "Receipt fields in the JSON: tree digest, run ID, CLI + ruleset versions; run-scoped
 *    report files with atomic temp-then-rename, `latest.json` demoted to a pointer"
 *
 * WHY: (a) a verdict nobody can re-derive is a claim, not a receipt — with the tree digest,
 * two scans that report differently can be told apart as "the code changed" vs "ShipGuard
 * changed"; (b) `latest.json` was one mutable file every scan overwrote in place, so two
 * concurrent scans raced and a reader could get a torn document or the wrong run's result
 *.
 *
 * SCOPE, honestly: this makes ShipGuard attestation-READY (the fields map onto an in-toto
 * verification predicate / SLSA VSA). It builds NO signing pipeline — the design kills that
 * until verifiers exist in the wild.
 *
 * FAIL-BEFORE: `runId`, `treeDigest` and `cliVersion` did not exist in the JSON; the report
 * writer produced only `latest.md`/`latest.json` with plain non-atomic writes.
 *
 * DISCIPLINE.
 */
import { execSync } from 'node:child_process'
import { spawnNode, type SpawnResult } from '../helpers/spawn-cli.js'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'

// Real-process e2e file: every test spawns the built CLI (each spawn ~0.3-1s idle, several x
// under load). Vitest's 5s default is below the cost of a 3-4 spawn test on a shared box, so
// state the budget explicitly (same 30s as the per-spawn kill timeout), file-scoped - not global.
vi.setConfig({ testTimeout: 30_000 })
import { computeTreeDigest } from '../../src/core/scanner.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

const tempDirs: string[] = []

function mkFixture(content = "const k = 'AKIAIOSFODNN7EXAMPLE'\n"): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-receipt-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(join(dir, 'config.js'), content, 'utf-8')
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

function runCli(args: string[]): Promise<SpawnResult> {
  return spawnNode(distCli, args, { cwd: pkgRoot, timeoutMs: 25_000 })
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 180_000)

describe('#8 — the JSON carries a receipt', () => {
  it('reports runId, treeDigest and cliVersion', async () => {
    const json = JSON.parse((await runCli(['scan', mkFixture(), '--json'])).stdout)
    expect(typeof json.runId).toBe('string')
    expect(json.runId.length).toBeGreaterThan(0)
    expect(json.treeDigest).toMatch(/^[0-9a-f]{64}$/)
    expect(typeof json.cliVersion).toBe('string')
  })

  it('the same tree digests the same, and different content digests differently', async () => {
    const same = mkFixture()
    // Warm-up: the first scan writes ShipGuard's own .gitignore into the project, which is
    // a genuine change to the tree — so measure from the second run onward.
    await runCli(['scan', same, '--json'])
    const a = JSON.parse((await runCli(['scan', same, '--json'])).stdout)
    const b = JSON.parse((await runCli(['scan', same, '--json'])).stdout)
    expect(a.treeDigest).toBe(b.treeDigest)

    const otherDir = mkFixture("const k = 'AKIAIOSFODNN7EXAMPLX'\n")
    await runCli(['scan', otherDir, '--json'])
    const other = JSON.parse((await runCli(['scan', otherDir, '--json'])).stdout)
    expect(other.treeDigest).not.toBe(a.treeDigest)
    // Wall-clock allowance, not a loosened assertion — same reasoning as the documented 30s
    // budget in cli-exit-codes.test.ts. This case SPAWNS THE BINARY FIVE TIMES, and from
    // 2026-08-04 each spawn also applies the 30 bundled corpus rules, so a run that used to
    // fit inside the 5s default now sits right on it and tips over whenever the shared box
    // is busy. Every assertion above is unchanged; only the clock is.
  })

  it('every run gets its own runId', async () => {
    const dir = mkFixture()
    const a = JSON.parse((await runCli(['scan', dir, '--json'])).stdout)
    // Change the tree so the scanId reuse window (retry idempotency) does not apply.
    writeFileSync(join(dir, 'extra.js'), 'const x = 2\n', 'utf-8')
    const b = JSON.parse((await runCli(['scan', dir, '--json'])).stdout)
    expect(a.runId).not.toBe(b.runId)
  })

  it('computeTreeDigest is order-independent and empty-safe', async () => {
    const files = [
      { path: '/x/b.js', relativePath: 'b.js', content: 'b' },
      { path: '/x/a.js', relativePath: 'a.js', content: 'a' },
    ]
    expect(computeTreeDigest(files)).toBe(computeTreeDigest([...files].reverse()))
    // Nothing read is NOT the same claim as "I looked and found nothing".
    expect(computeTreeDigest([])).toBeUndefined()
  })
})

describe('#8 — run-scoped reports, latest.json demoted to a pointer', () => {
  it('writes an immutable <runId>.md and <runId>.json alongside latest.*', async () => {
    const dir = mkFixture()
    const json = JSON.parse((await runCli(['scan', dir, '--report', '--json'])).stdout)
    const reportDir = join(dir, '.shipguard', 'reports')
    // Run-scoped files live in a `runs/` subdirectory so the scan surface can exclude
    // them by name (see the artifact-creep case in self-scan-and-determinism.test.ts).
    expect(existsSync(join(reportDir, 'runs', `${json.runId}.json`))).toBe(true)
    expect(existsSync(join(reportDir, 'runs', `${json.runId}.md`))).toBe(true)
    expect(existsSync(join(reportDir, 'latest.md'))).toBe(true)
    expect(existsSync(join(reportDir, 'latest.json'))).toBe(true)
  })

  it('latest.json is a pointer, not a scan result', async () => {
    const dir = mkFixture()
    const json = JSON.parse((await runCli(['scan', dir, '--report', '--json'])).stdout)
    const pointer = JSON.parse(readFileSync(join(dir, '.shipguard', 'reports', 'latest.json'), 'utf-8'))
    expect(pointer.pointer).toBe(true)
    expect(pointer.pointerVersion).toBe(1)
    expect(pointer.runId).toBe(json.runId)
    expect(pointer.runJson).toBe(`runs/${json.runId}.json`)
    expect(pointer.recommendation).toBe(json.recommendation)
    // A pointer is deliberately NOT a result — it must not carry findings.
    expect(pointer.findings).toBeUndefined()
  })

  it('the run-scoped JSON is the full result, identical to --json stdout', async () => {
    const dir = mkFixture()
    const stdout = JSON.parse((await runCli(['scan', dir, '--report', '--json'])).stdout)
    const onDisk = JSON.parse(
      readFileSync(join(dir, '.shipguard', 'reports', 'runs', `${stdout.runId}.json`), 'utf-8'),
    )
    // The report is written before the history/regression fields are known to stdout's copy,
    // so compare the verdict-bearing core rather than requiring byte equality.
    expect(onDisk.recommendation).toBe(stdout.recommendation)
    expect(onDisk.treeDigest).toBe(stdout.treeDigest)
    expect(onDisk.runId).toBe(stdout.runId)
    expect(onDisk.findings.length).toBe(stdout.findings.length)
  })

  it('a second scan adds a NEW run file and never rewrites the old one', async () => {
    const dir = mkFixture()
    const first = JSON.parse((await runCli(['scan', dir, '--report', '--json'])).stdout)
    const reportDir = join(dir, '.shipguard', 'reports')
    const firstRunFile = join(reportDir, 'runs', `${first.runId}.json`)
    const firstBytes = readFileSync(firstRunFile, 'utf-8')

    writeFileSync(join(dir, 'extra.js'), 'const x = 2\n', 'utf-8')
    const second = JSON.parse((await runCli(['scan', dir, '--report', '--json'])).stdout)

    expect(second.runId).not.toBe(first.runId)
    // The earlier run's receipt is untouched — that is the whole point of run-scoping.
    expect(readFileSync(firstRunFile, 'utf-8')).toBe(firstBytes)
    expect(existsSync(join(reportDir, 'runs', `${second.runId}.json`))).toBe(true)
    // And the pointer now names the new run.
    const pointer = JSON.parse(readFileSync(join(reportDir, 'latest.json'), 'utf-8'))
    expect(pointer.runId).toBe(second.runId)
  })

  it('leaves no temp files behind (atomic write, then rename)', async () => {
    const dir = mkFixture()
    await runCli(['scan', dir, '--report', '--json'])
    const reportDir = join(dir, '.shipguard', 'reports')
    const entries = [...readdirSync(reportDir), ...readdirSync(join(reportDir, 'runs'))]
    expect(entries.filter((e) => e.endsWith('.tmp'))).toHaveLength(0)
  })
})
