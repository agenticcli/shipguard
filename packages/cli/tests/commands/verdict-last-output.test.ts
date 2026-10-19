/**
 * Verdict-last human output.
 *
 * Specification:
 *   "Verdict-last human output: tips move above the panel, report path inside it,
 *    final glyph matches the verdict (✗ on DO_NOT_SHIP)"
 *
 * WHY: the verdict sat ~70 lines into a 93-line screen, so a scrolled or
 * truncated terminal dropped the one line the tool exists to print — and the last glyph
 * on a do-not-ship run was a green ✓ from the `Report: …` success line that printed after
 * the panel. With the exit code deliberately silent by default, the
 * printed verdict carries the entire default-mode signal.
 *
 * FAIL-BEFORE (verified on the pre-change source): the "What now?" tips appeared AFTER the
 * verdict panel, and the report path was printed outside the panel by `logger.success`.
 *
 * DISCIPLINE: behavioral — spawned binary, positional assertions on
 * the real rendered screen.
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

/** A project with enough blocking secrets to score a DO_NOT_SHIP verdict. */
function mkFindingFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-verdict-last-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(
    join(dir, 'config.js'),
    "const k = 'AKIAIOSFODNN7EXAMPLE'\nconst s = 'sk_live_51H8xQwEXAMPLEKEYabcdefghijklmnop'\n",
    'utf-8',
  )
  return dir
}

function mkCleanFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-verdict-last-clean-'))
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

// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;]*m/g
function stripAnsi(s: string): string {
  return s.replace(ANSI, '')
}

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

describe('#4 — the verdict is the last thing you see', () => {
  it('tips print ABOVE the verdict panel', () => {
    const out = stripAnsi(runCli(['scan', mkFindingFixture()]).stdout)
    const tipsIdx = out.indexOf('What now?')
    const verdictIdx = out.lastIndexOf('DO NOT SHIP')
    expect(tipsIdx).toBeGreaterThan(-1)
    expect(verdictIdx).toBeGreaterThan(-1)
    expect(tipsIdx).toBeLessThan(verdictIdx)
  })

  it('the verdict is in the LAST quarter of the screen, not buried mid-scroll', () => {
    const out = stripAnsi(runCli(['scan', mkFindingFixture()]).stdout)
    const verdictIdx = out.lastIndexOf('DO NOT SHIP')
    expect(verdictIdx / out.length).toBeGreaterThan(0.75)
  })

  it('the report path is INSIDE the panel, not printed after it', () => {
    const { stdout, stderr } = runCli(['scan', mkFindingFixture(), '--report'])
    const out = stripAnsi(stdout)
    expect(out).toContain('Report written')
    // The old trailing `logger.success('Report: …')` line (green ✓, stderr) is gone.
    expect(stripAnsi(stderr)).not.toContain('Report:')
  })

  it('the final glyph on screen matches the verdict — never a green ✓ after DO NOT SHIP', () => {
    const out = stripAnsi(runCli(['scan', mkFindingFixture(), '--report']).stdout)
    const tail = out.slice(out.lastIndexOf('DO NOT SHIP'))
    // Nothing that reads as "all good" may follow the negative verdict.
    expect(tail).not.toContain('✅')
    expect(tail).not.toContain('SHIP IT')
    // The verdict's own glyph is the last glyph rendered in the panel.
    expect(out.lastIndexOf('🛑')).toBeGreaterThan(out.lastIndexOf('What now?'))
  })

  it('a clean run still ends on its own positive verdict', () => {
    const out = stripAnsi(runCli(['scan', mkCleanFixture()]).stdout)
    const tipsIdx = out.indexOf('What now?')
    const verdictIdx = out.lastIndexOf('SAFE TO SHIP')
    expect(tipsIdx).toBeLessThan(verdictIdx)
    expect(out.slice(verdictIdx)).toContain('SHIP IT')
  })

  it('the panel still renders every context section it did before', () => {
    const out = stripAnsi(runCli(['scan', mkFindingFixture()]).stdout)
    for (const section of ['Severity breakdown', 'Run summary', 'How ShipGuard helped', 'Learn more']) {
      expect(out).toContain(section)
    }
  })
})
