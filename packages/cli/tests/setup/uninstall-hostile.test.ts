/**
 * Test-strategy judge (2026-11-22), finding 2: a clone brings its own `.shipguard/installed.json` and its own folders.
 * Uninstall must never change or delete anything outside the project and never trust a record it did not write:
 * hostile records (paths outside, absolute, ~, symlinks, odd createdDirs) and committed symlinks (.claude, .github,
 * .shipguard pointing out of the project). Real files, real git.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { runSetup, type SetupDeps } from '../../src/commands/setup.js'
import { runUninstall, type UninstallDeps, type UninstallOptions } from '../../src/commands/uninstall.js'
import { readInstallState } from '../../src/core/install-state.js'
import { claudeShimScript } from '../../src/core/hook-templates.js'

const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))

const mk = (prefix: string): string => {
  const d = mkdtempSync(join(tmpdir(), prefix))
  roots.push(d)
  return d
}

function repo(files: Record<string, string>): string {
  const dir = mk('sg-un-')
  execFileSync('git', ['init', '-q'], { cwd: dir })
  for (const [f, t] of Object.entries(files)) {
    mkdirSync(join(dir, f, '..'), { recursive: true })
    writeFileSync(join(dir, f), t)
  }
  return dir
}

/** Every file and folder under dir (relative), skipping .git internals except the hooks folder, and git's sample hooks. */
function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {}
  const walk = (d: string): void => {
    for (const name of readdirSync(d)) {
      const abs = join(d, name)
      const rel = relative(dir, abs)
      if (rel.startsWith('.git/') && rel !== '.git/hooks' && !rel.startsWith('.git/hooks/')) continue
      if (rel.endsWith('.sample')) continue
      if (rel === '.git') {
        walk(abs)
        continue
      }
      if (lstatSync(abs).isDirectory()) {
        out[rel + '/'] = ''
        walk(abs)
      } else out[rel] = readFileSync(abs, 'utf-8')
    }
  }
  walk(dir)
  return out
}

async function setup(dir: string, agent: string): Promise<void> {
  const config = mk('sg-un-cfg-')
  const deps: SetupDeps = {
    cwd: dir,
    out: () => undefined,
    isTty: true,
    confirm: async () => true,
    env: { PATH: process.env['PATH'] ?? '' },
    now: () => 1_800_000_000_000,
    configDir: config,
    cliVersion: '0.13.0',
    claudeVersion: () => '2.1.326',
    findCli: () => ({ where: 'local', version: '0.13.0', path: './node_modules/.bin/shipguard' }),
    installDependency: () => undefined,
    signedIn: () => false,
    sandbox: false,
    prime: async () => ({ attempted: false }) as never,
  }
  expect(await runSetup({ agent }, deps)).toBe(0)
}

function harness(dir: string, over: Partial<UninstallDeps> = {}): { deps: UninstallDeps; lines: string[]; config: string } {
  const config = mk('sg-un-home-')
  writeFileSync(join(config, 'telemetry.json'), '{}')
  const lines: string[] = []
  return { deps: { cwd: dir, out: (l) => lines.push(l), isTty: true, confirm: async () => true, configDir: config, ...over }, lines, config }
}
const un = (dir: string, o: UninstallOptions, over: Partial<UninstallDeps> = {}): Promise<{ code: number; text: string; config: string }> => {
  const h = harness(dir, over)
  return runUninstall(o, h.deps).then((code) => ({ code, text: h.lines.join('\n'), config: h.config }))
}
const USER_SETTINGS = JSON.stringify({ model: 'x', hooks: { PreToolUse: [{ matcher: 'Edit', hooks: [{ type: 'command', command: 'echo mine' }] }] } }, null, 2) + '\n'
const FILES = {
  '.claude/settings.json': USER_SETTINGS,
  'CLAUDE.md': '# My project\n\nRules of mine.\n',
  'AGENTS.md': '# Agents\n\nMine too.\n',
  '.github/workflows/ci.yml': 'name: mine\n',
  'shipguard.policy.yml': 'version: 1\n',
}

describe('uninstall: hostile committed record and symlinks', () => {
  it('a record that lists ../x, absolute, ~ and symlink paths (and odd createdDirs) touches nothing outside the project', async () => {
    const outside = mk('sg-un-out-')
    writeFileSync(join(outside, 'x'), 'outside x')
    writeFileSync(join(outside, 'victim.txt'), 'victim')
    mkdirSync(join(outside, 'emptydir'))
    const fakeHome = mk('sg-un-home2-')
    mkdirSync(join(fakeHome, '.ssh'))
    writeFileSync(join(fakeHome, '.ssh', 'id_x'), 'private')
    const dir = repo({ 'src/app.js': 'x\n', 'precious.txt': 'keep me' })
    symlinkSync(join(outside, 'victim.txt'), join(dir, 'link-to-victim'))
    mkdirSync(join(dir, '.shipguard'))
    const hostile = {
      version: 1,
      shipguardVersion: '0.13.0',
      hookVersion: 2,
      agents: ['claude', 'git'],
      entries: [
        { path: '../x', kind: 'file', sha256: 'x' },
        { path: join(outside, 'victim.txt'), kind: 'file', sha256: 'x' },
        { path: `${fakeHome}/.ssh/id_x`, kind: 'file', sha256: 'x' },
        { path: '~/.ssh/id_x', kind: 'block', sha256: 'x' },
        { path: 'link-to-victim', kind: 'file', sha256: 'x' },
        { path: 'precious.txt', kind: 'block', sha256: 'x' },
      ],
      createdDirs: ['../emptydir', outside + '/emptydir', 'src', '.'],
    }
    writeFileSync(join(dir, '.shipguard/installed.json'), JSON.stringify(hostile))
    // The record is read, but its entries are not places setup writes: they are dropped, not followed.
    expect(readInstallState(dir)?.entries).toEqual([])
    const before = snapshot(outside)
    const beforeHome = snapshot(fakeHome)
    const r = await un(dir, { yes: true })
    expect(r.code).toBe(0)
    expect(snapshot(outside)).toEqual(before)
    expect(snapshot(fakeHome)).toEqual(beforeHome)
    expect(readFileSync(join(dir, 'precious.txt'), 'utf-8')).toBe('keep me')
    expect(readFileSync(join(dir, 'src/app.js'), 'utf-8')).toBe('x\n')
    expect(lstatSync(join(dir, 'link-to-victim')).isSymbolicLink()).toBe(true)
  })

  it('.claude committed as a symlink out of the project: its settings and hook script are kept, named, unchanged', async () => {
    const dir = repo({ ...FILES })
    await setup(dir, 'claude')
    const outside = mk('sg-un-out-')
    renameSync(join(dir, '.claude'), join(outside, 'claude'))
    symlinkSync(join(outside, 'claude'), join(dir, '.claude'))
    const before = snapshot(outside)
    expect(before['claude/hooks/shipguard-gate.sh']).toBe(claudeShimScript())
    const r = await un(dir, { yes: true })
    expect(r.text).toContain('not safely inside the project')
    expect(snapshot(outside)).toEqual(before)
  })

  it('.github committed as a symlink out of the project: the workflow behind it is not deleted', async () => {
    const dir = repo({ ...FILES })
    await setup(dir, 'ci')
    const outside = mk('sg-un-out-')
    renameSync(join(dir, '.github'), join(outside, 'github'))
    symlinkSync(join(outside, 'github'), join(dir, '.github'))
    const before = snapshot(outside)
    expect(Object.keys(before).some((k) => k.endsWith('shipguard.yml'))).toBe(true)
    const r = await un(dir, { yes: true })
    expect(r.text).toContain('not safely inside the project')
    expect(snapshot(outside)).toEqual(before)
  })

  it('.shipguard committed as a symlink out of the project: its installed.json is not read or deleted, --purge leaves the target', async () => {
    const dir = repo({ ...FILES })
    await setup(dir, 'claude')
    const outside = mk('sg-un-out-')
    renameSync(join(dir, '.shipguard'), join(outside, 'sg'))
    symlinkSync(join(outside, 'sg'), join(dir, '.shipguard'))
    writeFileSync(join(outside, 'sg', 'history.db'), 'precious history')
    const before = snapshot(outside)
    for (const o of [{ yes: true }, { yes: true, purge: true }]) {
      await un(dir, o)
      expect(snapshot(outside)).toEqual(before)
    }
  })
})
