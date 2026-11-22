/**
 * E-01 (2026-11-22 e2e): setup's self-test must run the planted blocker (must block, exit 2) and the clean
 * tree (must pass, exit 0) through the installed hook script, not only the "binary hidden" check (spec 07, R11).
 * Real files, real `sh`, real git, the real built CLI as the only ShipGuard the hook can find.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { runSetup, type SetupDeps } from '../../src/commands/setup.js'

vi.setConfig({ testTimeout: 120_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')
beforeAll(() => {
  if (!existsSync(distCli)) execFileSync('npx', ['tsup'], { cwd: pkgRoot, stdio: 'inherit' })
}, 240_000)

const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'sg-selftest-'))
  roots.push(d)
  return d
}

async function setup(cliEntry: string | undefined): Promise<{ code: number; text: string; lines: string[] }> {
  const cwd = tmp()
  execFileSync('git', ['init', '-q'], { cwd })
  const lines: string[] = []
  const deps: SetupDeps = {
    cwd, out: (l) => lines.push(l), isTty: false, confirm: async () => true, env: { PATH: process.env['PATH'] ?? '' },
    now: () => 1_800_000_000_000, configDir: tmp(), cliVersion: '0.13.0', claudeVersion: () => '2.1.326',
    findCli: () => ({ where: 'local', version: '0.13.0', path: 'x' }), installDependency: () => undefined,
    prime: async () => ({ attempted: false }), signedIn: () => false, sandbox: true, cliEntry,
  }
  const code = await runSetup({ agent: 'claude', yes: true }, deps)
  return { code, text: lines.join('\n'), lines }
}

describe('setup --agent claude: the gate self-test', () => {
  it('runs the planted blocker (blocks, exit 2) and the clean tree (passes, exit 0) and prints it', async () => {
    const r = await setup(distCli)
    expect(r.code).toBe(0)
    expect(r.text).toContain('✓ with the ShipGuard binary hidden, a test `git push` was blocked (exit 2)')
    expect(r.text).toContain('✓ gate self-test: a push with a planted blocker is blocked (exit 2), a clean tree passes (exit 0)')
  })

  it('a hook that lets the planted blocker through fails setup with SETUP_VERIFY_FAILED (exit 3)', async () => {
    // A stand-in ShipGuard whose gate always passes: the planted push is not blocked.
    const fake = join(tmp(), 'cli.js')
    mkdirSync(dirname(fake), { recursive: true })
    writeFileSync(fake, 'process.exit(0)\n')
    const r = await setup(fake)
    expect(r.code).toBe(3)
    expect(r.text).toContain('✗ SETUP_VERIFY_FAILED: the hook did not block the test push (exit 0, expected 2). Nothing is protected yet.')
  })

  it('a hook that blocks a clean tree fails setup too (it would stop real work)', async () => {
    const fake = join(tmp(), 'cli.js')
    mkdirSync(dirname(fake), { recursive: true })
    // `gate --supports` answers; every real gate run blocks with the gate's own code 2.
    writeFileSync(fake, "if (process.argv.includes('--supports')) process.exit(0)\nprocess.stderr.write('blocked\\n')\nprocess.exit(2)\n")
    const r = await setup(fake)
    expect(r.code).toBe(3)
    expect(r.text).toContain('SETUP_VERIFY_FAILED: the hook blocked a clean test push (exit 2, expected 0)')
  })

  it('no built CLI to run: the self-test says so, it never claims a pass', async () => {
    const r = await setup(undefined)
    expect(r.code).toBe(0)
    expect(r.text).toContain('Not run: the gate self-test')
    expect(r.text).not.toContain('✓ gate self-test')
  })
})
