/**
 * Self-scan exclusion + deterministic traversal — recommendations #6 and #7.
 *
 * #6 verbatim: "Exclude `.shipguard/` from ShipGuard's own scan surface + degrade loudly
 *               (never crash) on read-only trees"
 * #7 verbatim: "Sort-before-cap deterministic traversal (documented cross-platform ordering
 *               before the 5,000-file ceiling applies)"
 *
 * WHAT WAS ALREADY TRUE, and is pinned here rather than rebuilt: `.shipguard/**` was already
 * in both ignore lists, and a read-only tree already degraded loudly without crashing. Those
 * invariants had no test, so one refactor could have silently removed them.
 *
 * WHAT WAS ACTUALLY BROKEN (#6): `report.output` and `history.path` are user-configurable. With
 * `report.output: reports/latest.md`, a two-file project reported `filesScanned: 6` on its
 * SECOND run — ShipGuard reading its own artifacts back in. It failed to produce phantom
 * findings only because report evidence happens to be masked.
 *
 * WHAT WAS ACTUALLY BROKEN (#7): traversal order came from fast-glob/the filesystem. Once the
 * file cap truncates collection, order stops being an implementation detail and becomes policy
 * — same repo, different machine, different subset scanned, potentially different verdict.
 *
 * DISCIPLINE.
 */
import { execSync } from 'node:child_process'
import { spawnNode, type SpawnResult } from '../helpers/spawn-cli.js'
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'

// Real-process e2e file: every test spawns the built CLI (each spawn ~0.3-1s idle, several x
// under load). Vitest's 5s default is below the cost of a 3-4 spawn test on a shared box, so
// state the budget explicitly (same 30s as the per-spawn kill timeout), file-scoped - not global.
vi.setConfig({ testTimeout: 30_000 })
import { compareScanPaths } from '../../src/utils/fs.js'
import { selfArtifactIgnorePatterns } from '../../src/core/scanner.js'
import { DEFAULT_POLICY } from '../../src/core/policy.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

const tempDirs: string[] = []

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      chmodSync(dir, 0o755)
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
})

function mkDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  tempDirs.push(dir)
  return dir
}

function runCli(args: string[], cwd = pkgRoot): Promise<SpawnResult> {
  return spawnNode(distCli, args, { cwd: cwd, timeoutMs: 25_000 })
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 180_000)

describe('#6 — ShipGuard never scans its own output', () => {
  it('a secret planted in .shipguard/ is not scanned (the default location)', async () => {
    const dir = mkDir('shipguard-selfscan-')
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
    writeFileSync(join(dir, 'app.js'), 'const ok = 1\n', 'utf-8')
    mkdirSync(join(dir, '.shipguard', 'reports'), { recursive: true })
    writeFileSync(join(dir, '.shipguard', 'reports', 'latest.json'), "{\"k\":\"AKIAIOSFODNN7EXAMPLE\"}", 'utf-8')

    const json = JSON.parse((await runCli(['scan', dir, '--json'])).stdout)
    expect(json.findings).toHaveLength(0)
    expect(json.findings.map((f: { file: string }) => f.file)).not.toContain('.shipguard/reports/latest.json')
  })

  it('a RELOCATED report is excluded too — where the policy sends it, not just .shipguard/', async () => {
    const dir = mkDir('shipguard-selfscan-relocated-')
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
    writeFileSync(join(dir, 'app.js'), 'const ok = 1\n', 'utf-8')
    writeFileSync(
      join(dir, 'shipguard.policy.yml'),
      'version: 1\nreport:\n  output: reports/latest.md\n  format: markdown\n',
      'utf-8',
    )
    // Pre-plant a report at the RELOCATED path carrying a raw secret. Before the fix this
    // was scanned like any other file; a report format that stopped masking evidence would
    // have made ShipGuard report a finding about its own output.
    mkdirSync(join(dir, 'reports'), { recursive: true })
    writeFileSync(join(dir, 'reports', 'latest.md'), "key: AKIAIOSFODNN7EXAMPLE\n", 'utf-8')
    writeFileSync(join(dir, 'reports', 'latest.json'), '{"k":"AKIAIOSFODNN7EXAMPLE"}\n', 'utf-8')

    const json = JSON.parse((await runCli(['scan', dir, '--json'])).stdout)
    const files = json.findings.map((f: { file: string }) => f.file)
    expect(files).not.toContain('reports/latest.md')
    expect(files).not.toContain('reports/latest.json')
    expect(json.findings).toHaveLength(0)
  })

  it('scanning the same tree twice reads the same number of files (no artifact creep)', async () => {
    const dir = mkDir('shipguard-selfscan-stable-')
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
    writeFileSync(join(dir, 'app.js'), 'const ok = 1\n', 'utf-8')
    writeFileSync(
      join(dir, 'shipguard.policy.yml'),
      'version: 1\nreport:\n  output: reports/latest.md\n  format: markdown\n',
      'utf-8',
    )
    // Warm-up so ShipGuard's own side files exist before either measured run.
    await runCli(['scan', dir, '--report', '--json'])
    const first = JSON.parse((await runCli(['scan', dir, '--report', '--json'])).stdout)
    const second = JSON.parse((await runCli(['scan', dir, '--report', '--json'])).stdout)
    expect(existsSync(join(dir, 'reports', 'latest.md'))).toBe(true)
    expect(second.filesScanned).toBe(first.filesScanned)
  })

  it('selfArtifactIgnorePatterns covers the report, its json sibling, and the history store', async () => {
    const patterns = selfArtifactIgnorePatterns({
      ...DEFAULT_POLICY,
      report: { output: 'reports/latest.md', format: 'markdown' },
      history: { path: 'audit/history.db' },
    })
    expect(patterns).toContain('reports/latest.md')
    expect(patterns).toContain('reports/latest.json')
    expect(patterns).toContain('audit/history.db')
    // ...and the per-run report directory, which holds unpredictable run-id filenames.
    expect(patterns).toContain('reports/runs/**')
  })
})

describe('#6 — a read-only project degrades loudly and never crashes', () => {
  it('exits 0, emits valid JSON, and names every write it could not make', async () => {
    const dir = mkDir('shipguard-readonly-')
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
    writeFileSync(join(dir, 'app.js'), 'const ok = 1\n', 'utf-8')
    chmodSync(dir, 0o555)

    const { code, stdout, stderr } = (await runCli(['scan', dir, '--report', '--json']))
    expect(code).toBe(0)
    expect(() => JSON.parse(stdout)).not.toThrow()
    // Loud: every failed write is reported on stderr, never swallowed.
    expect(stderr).toContain('Report generation failed')
    expect(stderr).toContain('history')
    // And the machine channel says the audit store did not persist.
    expect(JSON.parse(stdout).stateStatus).not.toBe('complete')
  })

  it('human mode on a read-only project also exits 0 rather than crashing', async () => {
    const dir = mkDir('shipguard-readonly-human-')
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
    writeFileSync(join(dir, 'app.js'), 'const ok = 1\n', 'utf-8')
    chmodSync(dir, 0o555)
    expect((await runCli(['scan', dir])).code).toBe(0)
  })
})

describe('#7 — sort before the cap, so the same repo scans the same files everywhere', () => {
  it('compareScanPaths is a byte-wise, locale-independent ordering', async () => {
    const input = ['b.js', 'A.js', 'a.js', 'Z/x.js', 'a/b.js']
    expect([...input].sort(compareScanPaths)).toEqual(['A.js', 'Z/x.js', 'a.js', 'a/b.js', 'b.js'])
    // Not localeCompare: that would sort 'a.js' before 'A.js' in most locales.
    expect(compareScanPaths('A.js', 'a.js')).toBeLessThan(0)
  })

  it('a truncated scan collects the FIRST files in sorted order, not filesystem order', async () => {
    const dir = mkDir('shipguard-sortcap-')
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
    writeFileSync(join(dir, 'shipguard.policy.yml'), 'version: 1\nlimits:\n  maxFiles: 5\n', 'utf-8')
    mkdirSync(join(dir, 'src'), { recursive: true })
    // Created in DESCENDING order on purpose, so filesystem order and sorted order differ.
    for (let i = 60; i >= 10; i--) {
      writeFileSync(join(dir, 'src', `m${i}.js`), `export const n = ${i}\n`, 'utf-8')
    }
    // A secret in the FIRST file by sorted order — it must always be found, cap or no cap.
    writeFileSync(join(dir, 'src', 'm10.js'), "const k = 'AKIAIOSFODNN7EXAMPLE'\n", 'utf-8')

    const json = JSON.parse((await runCli(['scan', dir, '--json'])).stdout)
    expect(json.degraded).toBe(true)
    expect(json.findings.map((f: { file: string }) => f.file)).toContain('src/m10.js')
  })

  it('two runs over a capped tree scan the SAME files (determinism)', async () => {
    const dir = mkDir('shipguard-sortcap-determinism-')
    writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
    writeFileSync(join(dir, 'shipguard.policy.yml'), 'version: 1\nlimits:\n  maxFiles: 8\n', 'utf-8')
    mkdirSync(join(dir, 'src'), { recursive: true })
    for (let i = 40; i >= 10; i--) {
      // Every file carries a secret, so the finding set reveals exactly which files were read.
      writeFileSync(join(dir, 'src', `m${i}.js`), `const k${i} = 'AKIAIOSFODNN7EXAMPL${i % 10}'\n`, 'utf-8')
    }
    // Warm-up: let ShipGuard write its own side files first, so the two measured runs
    // see an identical tree and any difference is traversal order, not new files.
    await runCli(['scan', dir, '--json'])
    const a = JSON.parse((await runCli(['scan', dir, '--json'])).stdout)
    const b = JSON.parse((await runCli(['scan', dir, '--json'])).stdout)
    const files = (j: { findings: Array<{ file: string }> }) => j.findings.map((f) => f.file).sort()
    expect(files(a)).toEqual(files(b))
    expect(files(a).length).toBeGreaterThan(0)
  })

  it('the traversal order is documented in the code that implements it', async () => {
    const src = readFileSync(join(pkgRoot, 'src', 'utils', 'fs.ts'), 'utf-8')
    expect(src).toContain('compareScanPaths')
    expect(src).toContain('localeCompare')
  })
})
