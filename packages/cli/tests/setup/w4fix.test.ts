/** W4fix: setup never writes through symlinks, never drops a user's own hook, uninstall tidies only folders setup made. */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { dependencyCommand, runSetup, type SetupDeps } from '../../src/commands/setup.js'
import { runUninstall } from '../../src/commands/uninstall.js'
import { classifyClaudeHookCommand } from '../../src/core/hook-templates.js'
import { readInstallState } from '../../src/core/install-state.js'

const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'sg-w4fix-'))
  roots.push(d)
  return d
}
const repo = (files: Record<string, string> = {}): string => {
  const d = tmp()
  execFileSync('git', ['init', '-q'], { cwd: d })
  for (const [f, t] of Object.entries(files)) {
    mkdirSync(join(d, f, '..'), { recursive: true })
    writeFileSync(join(d, f), t)
  }
  return d
}
function setup(cwd: string, agent: string, over: Partial<SetupDeps> = {}): Promise<{ code: number; text: string }> {
  const lines: string[] = []
  const deps: SetupDeps = {
    cwd, out: (l) => lines.push(l), isTty: false, confirm: async () => true, env: { PATH: process.env['PATH'] ?? '' },
    now: () => 1_800_000_000_000, configDir: tmp(), cliVersion: '0.13.0', claudeVersion: () => '2.1.326',
    findCli: () => ({ where: 'local', version: '0.13.0', path: 'x' }), installDependency: () => undefined,
    prime: async () => ({ attempted: false }), signedIn: () => false, sandbox: true, ...over,
  }
  return runSetup({ agent, yes: true }, deps).then((code) => ({ code, text: lines.join('\n') }))
}
const uninstall = (cwd: string): Promise<number> =>
  runUninstall({ agent: 'all', yes: true }, { cwd, out: () => undefined, isTty: false, confirm: async () => true, configDir: tmp() })

describe('1. symlinks are never written through', () => {
  it('CLAUDE.md -> a file outside the project: refused and named, the outside file is untouched', async () => {
    const outside = join(tmp(), 'victim.txt')
    writeFileSync(outside, 'secret\n')
    const d = repo({ '.claude/settings.json': '{}' })
    symlinkSync(outside, join(d, 'CLAUDE.md'))
    const r = await setup(d, 'claude')
    expect(r.code).toBe(3)
    expect(readFileSync(outside, 'utf-8')).toBe('secret\n')
    expect(r.text).toContain('CLAUDE.md is a symbolic link')
  })

  it('a dangling shim symlink is not created through; a linked parent folder is refused', async () => {
    const out = tmp()
    const d = repo({ '.claude/settings.json': '{}' })
    mkdirSync(join(d, '.claude', 'hooks'))
    symlinkSync(join(out, 'gone.sh'), join(d, '.claude', 'hooks', 'shipguard-gate.sh'))
    const r = await setup(d, 'claude')
    expect(r.code).toBe(3)
    expect(existsSync(join(out, 'gone.sh'))).toBe(false)

    const d2 = repo()
    symlinkSync(out, join(d2, '.claude'))
    const r2 = await setup(d2, 'claude')
    expect(r2.code).toBe(3)
    expect(existsSync(join(out, 'settings.json'))).toBe(false)
    expect(r2.text).toContain('.claude is a symbolic link')
  })

  it('a linked .shipguard folder stops setup before any write', async () => {
    const out = tmp()
    const d = repo({ '.claude/settings.json': '{}' })
    symlinkSync(out, join(d, '.shipguard'))
    expect((await setup(d, 'claude')).code).toBe(3)
    expect(existsSync(join(out, 'installed.json'))).toBe(false)
    expect(existsSync(join(d, 'CLAUDE.md'))).toBe(false)
  })
})

describe('2. a user hook that merely says scan --json --strict is not ours', () => {
  it('classification needs shipguard in the command', () => {
    expect(classifyClaudeHookCommand('trivy fs scan --json --strict .')).toBe('foreign')
    expect(classifyClaudeHookCommand('./node_modules/.bin/shipguard scan --json --strict')).toBe('legacy')
  })
  it('setup keeps the trivy hook and adds ours', async () => {
    const d = repo({ '.claude/settings.json': JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'trivy fs scan --json --strict .' }] }] } }) })
    expect((await setup(d, 'claude')).code).toBe(0)
    const s = JSON.parse(readFileSync(join(d, '.claude', 'settings.json'), 'utf-8')) as { hooks: { PreToolUse: Array<{ hooks: Array<{ command: string }> }> } }
    expect(s.hooks.PreToolUse.flatMap((e) => e.hooks.map((h) => h.command))).toContain('trivy fs scan --json --strict .')
    expect(s.hooks.PreToolUse).toHaveLength(2)
  })
})

describe('3. uninstall tidies only folders setup created', () => {
  it('a pre-existing empty .github stays; folders setup made go', async () => {
    const d = repo()
    mkdirSync(join(d, '.github'))
    await setup(d, 'ci')
    expect(readInstallState(d)?.createdDirs).toEqual(['.github/workflows', '.shipguard'])
    expect(await uninstall(d)).toBe(0)
    expect(existsSync(join(d, '.github'))).toBe(true)
    expect(existsSync(join(d, '.github', 'workflows'))).toBe(false)

    const d2 = repo()
    await setup(d2, 'ci')
    expect(readInstallState(d2)?.createdDirs).toEqual(['.github', '.github/workflows', '.shipguard'])
    await uninstall(d2)
    expect(existsSync(join(d2, '.github'))).toBe(false)
  })
})

describe('4-5. record and settings details', () => {
  it('claude is not recorded when the settings entry was refused', async () => {
    const d = repo({ '.claude/settings.json': '{ nope' })
    expect((await setup(d, 'claude')).code).toBe(3)
    expect(readInstallState(d)?.agents ?? []).not.toContain('claude')
  })
  it('new entry is "add"; existing JSON indentation and trailing-newline are kept; a non-object hooks value is refused', async () => {
    const d = repo({ '.claude/settings.json': '{\n    "model": "x"\n}' })
    const r = await setup(d, 'claude')
    expect(r.text).toMatch(/\.claude\/settings\.json\s+add 1 PreToolUse hook/)
    const t = readFileSync(join(d, '.claude', 'settings.json'), 'utf-8')
    expect(t).toContain('\n    "model": "x"')
    expect(t.endsWith('\n')).toBe(false)
    const d2 = repo({ '.claude/settings.json': '{"hooks": []}' })
    const r2 = await setup(d2, 'claude')
    expect(r2.code).toBe(3)
    expect(readFileSync(join(d2, '.claude', 'settings.json'), 'utf-8')).toBe('{"hooks": []}')
    expect(r2.text).toContain('"hooks" is not an object')
  })
})

describe('6. package manager calls', () => {
  it('pnpm workspace root gets -w; yarn berry gets a manual command; plain yarn and npm keep --ignore-scripts', () => {
    const v = '0.13.0'
    const pnpm = repo({ 'pnpm-lock.yaml': '', 'pnpm-workspace.yaml': 'packages: []' })
    expect(dependencyCommand(pnpm, v)).toEqual({ pm: 'pnpm', args: ['add', '-D', '-E', '--ignore-scripts', '-w', '@agenticcli/shipguard@0.13.0'] })
    const berry = repo({ 'yarn.lock': '', '.yarnrc.yml': '' })
    expect(dependencyCommand(berry, v)).toEqual({ manual: 'yarn add -D -E @agenticcli/shipguard@0.13.0' })
    const berry2 = repo({ 'yarn.lock': '', 'package.json': '{"packageManager":"yarn@4.1.0"}' })
    expect('manual' in dependencyCommand(berry2, v)).toBe(true)
    expect(dependencyCommand(repo({ 'yarn.lock': '' }), v)).toMatchObject({ pm: 'yarn' })
    expect(dependencyCommand(repo(), v)).toMatchObject({ pm: 'npm' })
  })
  it('yarn berry: setup prints the manual command and does not try to install', async () => {
    const d = repo({ 'package.json': '{}', 'yarn.lock': '', '.yarnrc.yml': '' })
    let called = false
    const r = await setup(d, 'claude', { findCli: () => null, installDependency: () => { called = true } })
    expect(called).toBe(false)
    expect(r.text).toContain('yarn add -D -E @agenticcli/shipguard@0.13.0')
    expect(r.code).toBe(0)
  })
})
