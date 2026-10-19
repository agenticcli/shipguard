/**
 * SLOW LANE - shipped-tree self-scan ("the published package must not block itself").
 *
 * Restores coverage that was lost when cli-exit-codes stopped scanning the package root
 * (that scan cost ~18s idle, so it lived in the fast suite as a flake source, and it only
 * asserted exit 0, which is always the exit code for a default scan). This test asserts the
 * real property: scanning what `npm pack` ships yields NO blocking, unsuppressed finding and
 * `--strict` exits 0 (default layout), AND every packed file is actually scanned (dist/ is
 * default-ignored, so it is re-staged under another name and filesScanned must equal the packed
 * count); dist/ itself legitimately contains the scanner's own detector text and is exempt from
 * the blocker assertion.
 *
 * Not in the default `pnpm test` (see vitest.config.ts exclude). Run by scripts/release-gate.sh
 * (gate G8) and by `pnpm --filter @agenticcli/shipguard test:slow`.
 *
 * It first caught a real false positive: rules/free-bundle.json's prose
 * "(Access-Control-Allow-Origin: *)" tripped the legacy generic-config CORS check.
 */
import { execFileSync } from 'node:child_process'
import { appendFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { spawnNode } from '../helpers/spawn-cli.js'
import { diffAgainstBaseline, summarizeDistBlockers, type BaselineEntry } from './dist-baseline.js'

vi.setConfig({ testTimeout: 120_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')
const BASELINE_PATH = resolve(dirname(fileURLToPath(import.meta.url)), 'dist-blockers.baseline.json')
let stage: string | undefined

afterAll(() => {
  if (stage) rmSync(stage, { recursive: true, force: true })
})

describe('shipped tree self-scan (slow lane)', () => {
  it('scanning exactly the files `npm pack` ships raises no blocking finding; --strict exits 0', async () => {
    expect(existsSync(distCli), 'build first: pnpm --filter @agenticcli/shipguard build').toBe(true)

    // The authoritative shipped-file list, straight from npm (respects package.json "files").
    const raw = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
      cwd: pkgRoot,
      encoding: 'utf-8',
    })
    const shipped = (JSON.parse(raw)[0].files as Array<{ path: string }>).map((f) => f.path)
    expect(shipped.length).toBeGreaterThan(5)
    expect(shipped).toContain('dist/cli.js')
    expect(shipped).toContain('rules/free-bundle.json')

    stage = mkdtempSync(join(tmpdir(), 'shipguard-shipped-'))
    const stageCopy = (root: string, mapRel: (rel: string) => string) => {
      for (const rel of shipped) {
        const dest = join(root, mapRel(rel))
        mkdirSync(dirname(dest), { recursive: true })
        cpSync(join(pkgRoot, rel), dest)
      }
    }
    type Out = {
      filesScanned: number
      findings: Array<{ id: string; file: string; line?: number; blocking?: boolean; suppressed?: boolean }>
    }
    const run = async (root: string, args: string[]) => {
      const res = await spawnNode(distCli, ['scan', root, '--json', ...args], { cwd: root, timeoutMs: 100_000 })
      return { res, json: JSON.parse(res.stdout) as Out }
    }
    const blockersOf = (o: Out) => o.findings.filter((f) => f.blocking && !f.suppressed)

    // Scan A - the tree as a user would scan it (original layout, default ignores).
    const asShipped = join(stage, 'as-shipped')
    stageCopy(asShipped, (rel) => rel)
    const a = await run(asShipped, ['--strict'])
    expect(blockersOf(a.json), `shipped tree blocks itself: ${JSON.stringify(blockersOf(a.json))}`).toEqual([])
    expect(a.res.code, a.res.stderr).toBe(0)

    // Scan B - EVERY packed file, none skipped. The default ignore list drops `dist/**` (10 of
    // the 17 shipped files incl. dist/cli.js), so stage dist/ under a non-ignored name (bytes
    // identical). dist/ legitimately contains the scanner's own detector patterns and embedded
    // rule text (e.g. "Access-Control-Allow-Origin: *", Razorpay/GCP key regexes), so it WILL
    // trip its own rules - that self-reference is not a defect and is excluded from the blocker
    // assertion. Everything else must be clean, and nothing may be silently skipped.
    const everything = join(stage, 'everything')
    stageCopy(everything, (rel) => (rel.startsWith('dist/') ? `shipped-${rel}` : rel))
    const b = await run(everything, [])
    expect(b.json.filesScanned, 'a packed file was skipped by the scanner').toBe(shipped.length)
    const nonDistBlockers = blockersOf(b.json).filter((f) => !f.file.startsWith('shipped-dist/'))
    expect(nonDistBlockers, `non-dist shipped file blocks: ${JSON.stringify(nonDistBlockers)}`).toEqual([])

    // dist/ is not exempt: its blockers are PINNED. Anything new or changed (a bundled real secret,
    // an edited detector line, an extra occurrence) fails. Refresh deliberately with
    // UPDATE_DIST_BASELINE=1 after reviewing the diff.
    const readLine = (root: string) => (file: string, line: number) =>
      readFileSync(join(root, file), 'utf-8').split('\n')[line - 1]
    const current = summarizeDistBlockers(b.json.findings, readLine(everything))
    if (process.env.UPDATE_DIST_BASELINE) {
      writeFileSync(BASELINE_PATH, JSON.stringify(current, null, 2) + '\n', 'utf-8')
    }
    const baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf-8')) as BaselineEntry[]
    expect(baseline.length, 'baseline is empty').toBeGreaterThan(0)
    expect(
      diffAgainstBaseline(current, baseline),
      'dist/ has a blocking finding that is not in tests/slow/dist-blockers.baseline.json (new or changed)',
    ).toEqual([])

    // Planted-key proof: a real-looking secret bundled into dist/cli.js must be caught by the baseline.
    // (Assembled at runtime so this test file never contains a scannable key literal.)
    const planted = join(stage, 'planted')
    stageCopy(planted, (rel) => (rel.startsWith('dist/') ? `shipped-${rel}` : rel))
    appendFileSync(
      join(planted, 'shipped-dist/cli.js'),
      `\nconst leaked = "${['sk', 'live', 'PLANTEDabcdefghijklmnopqrstuvwx'].join('_')}";\nconst aws = "${'AKIA' + 'IOSFODNN7REALKEY'}";\n`,
      'utf-8',
    )
    const p = await run(planted, [])
    const plantedNew = diffAgainstBaseline(summarizeDistBlockers(p.json.findings, readLine(planted)), baseline)
    expect(plantedNew.length, 'a secret planted in dist/cli.js was NOT caught by the baseline').toBeGreaterThan(0)
  })
})
