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
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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

describe('verdict first (spec 01)', () => {
  it('line 1 of stdout is the verdict line; nothing is printed before it', () => {
    const { stdout } = runCli(['scan', mkFindingFixture()])
    expect(stripAnsi(stdout).split('\n')[0]).toMatch(/^DO NOT SHIP · \d+ blocking of \d+ findings · \d+ files?, \d+ general rules, [\d.]+s$/)
  })

  it('the whole screen is at most 25 lines and has no box art, emoji, tips or links box', () => {
    const out = stripAnsi(runCli(['scan', mkFindingFixture()]).stdout)
    expect(out.trimEnd().split('\n').length).toBeLessThanOrEqual(25)
    expect(out).not.toMatch(/[╭╮╰╯│├┤█🛑⛔🐛✅]/u)
    for (const gone of ['What now?', 'Learn more', 'Severity breakdown', 'Confidence legend', 'shipguard feedback']) {
      expect(out).not.toContain(gone)
    }
  })

  it('the report path is a plain Report: line, and nothing positive follows a negative verdict', () => {
    const { stdout, stderr } = runCli(['scan', mkFindingFixture()])
    const out = stripAnsi(stdout)
    expect(out).toMatch(/^Report: \S+latest\.md/m)
    expect(out).not.toContain('SHIP IT')
    expect(stripAnsi(stderr)).not.toContain('Report:')
    expect(out.trimEnd().split('\n').pop()).toMatch(/^Rules ran: /)
  })

  it('a clean run starts with SAFE TO SHIP and states what "safe" means on line 2', () => {
    const lines = stripAnsi(runCli(['scan', mkCleanFixture()]).stdout).split('\n')
    expect(lines[0]).toMatch(/^SAFE TO SHIP · 0 findings · /)
    expect(lines[1]).toBe('"Safe" here means no rule matched. It is not a security audit.')
  })

  it('--strict ends with the one Exit 1 line and exits 1; --quiet and --json print none', () => {
    const strict = runCli(['scan', mkFindingFixture(), '--strict'])
    expect(strict.code).toBe(1)
    expect(stripAnsi(strict.stdout).trimEnd().split('\n').pop()).toMatch(/^Exit 1: --strict stops on DO NOT SHIP\./)
    const quiet = runCli(['scan', mkFindingFixture(), '--strict', '--quiet'])
    expect(quiet.code).toBe(1)
    expect(quiet.stdout.trimEnd().split('\n')).toHaveLength(1)
    expect(quiet.stdout).toMatch(/^shipguard: verdict=DO_NOT_SHIP blocking=\d+ findings=\d+ incomplete=no agentAction=\S+ run=[0-9a-f]{8}/)
    expect(quiet.stdout).not.toContain('Exit 1')
    const json = runCli(['scan', mkFindingFixture(), '--strict', '--json'])
    expect(json.stdout).not.toContain('Exit 1:')
    expect(() => JSON.parse(json.stdout)).not.toThrow()
  })

  it('no secret text reaches the screen or the report', () => {
    const dir = mkFindingFixture()
    const { stdout } = runCli(['scan', dir])
    expect(stdout).not.toContain('sk_live_51H8xQw')
    expect(stdout).not.toContain('AKIAIOSFOD')
    const report = readFileSync(join(dir, '.shipguard', 'reports', 'latest.md'), 'utf-8')
    expect(report).not.toContain('sk_live_51H8xQw')
    expect(report).not.toContain('AKIAIOSFOD')
    expect(report).toContain('value hidden')
  })
})
