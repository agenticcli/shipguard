/**
 * `shipguard uninstall` (W4b, spec 07): setup then uninstall leaves the tree as it was, user-edited content is kept
 * and named, a preview writes nothing, a tampered record cannot reach another file. Real files, real git.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { runSetup, type SetupDeps } from '../../src/commands/setup.js'
import { runUninstall, type UninstallDeps, type UninstallOptions } from '../../src/commands/uninstall.js'
import { readInstallState } from '../../src/core/install-state.js'

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

describe('uninstall: round trip', () => {
  it('setup --agent all then uninstall --yes leaves the tree as it was (files and folders)', async () => {
    const dir = repo(FILES)
    const before = snapshot(dir)
    await setup(dir, 'all')
    expect(existsSync(join(dir, '.claude/hooks/shipguard-gate.sh'))).toBe(true)
    expect(existsSync(join(dir, '.git/hooks/pre-push'))).toBe(true)
    const r = await un(dir, { yes: true })
    expect(r.code).toBe(0)
    expect(r.text).toContain('no ShipGuard hook or block is left')
    expect(r.text).toContain('Still to do by hand: npm uninstall @agenticcli/shipguard')
    const after = snapshot(dir)
    expect(Object.keys(after).sort()).toEqual(Object.keys(before).sort())
    for (const k of Object.keys(before)) {
      if (k === '.claude/settings.json') expect(JSON.parse(after[k])).toEqual(JSON.parse(before[k]))
      else expect(after[k], k).toBe(before[k])
    }
    expect(readInstallState(dir)).toBeNull()
  })

  it('a project that had none of those files goes back to empty (CLAUDE.md, hooks, workflow, .shipguard all gone)', async () => {
    const dir = repo({ '.claude/keep.txt': 'x' })
    const before = snapshot(dir)
    await setup(dir, 'claude')
    await setup(dir, 'ci')
    expect((await un(dir, { yes: true })).code).toBe(0)
    expect(snapshot(dir)).toEqual(before)
  })

  it('the second run says nothing is set up and exits 0', async () => {
    const dir = repo(FILES)
    await setup(dir, 'claude')
    await un(dir, { yes: true })
    const r = await un(dir, { yes: true })
    expect(r.code).toBe(0)
    expect(r.text).toBe('ShipGuard is not set up in this project. Nothing to remove.')
  })
})

describe('uninstall: preview and confirmation', () => {
  it('--dry-run writes nothing and exits 0; it names removals, the kept policy and what it does not touch', async () => {
    const dir = repo(FILES)
    await setup(dir, 'all')
    const before = snapshot(dir)
    const r = await un(dir, { dryRun: true })
    expect(r.code).toBe(0)
    expect(snapshot(dir)).toEqual(before)
    expect(r.text).toContain('Dry run, nothing will be changed')
    expect(r.text).toContain('.claude/hooks/shipguard-gate.sh')
    expect(r.text).toContain('.git/hooks/pre-push')
    expect(r.text).toContain('.shipguard/installed.json')
    expect(r.text).toContain('shipguard.policy.yml')
    expect(r.text).toContain('npm uninstall @agenticcli/shipguard')
    expect(r.text).toContain('~/.config/shipguard/')
  })

  it('not a terminal without --yes: prints the plan, exit 2 CONFIRMATION_REQUIRED, changes nothing', async () => {
    const dir = repo(FILES)
    await setup(dir, 'claude')
    const before = snapshot(dir)
    const r = await un(dir, { agent: 'claude' }, { isTty: false })
    expect(r.code).toBe(2)
    expect(r.text).toContain('Run: shipguard uninstall --agent claude --yes')
    expect(snapshot(dir)).toEqual(before)
  })

  it('answering no changes nothing', async () => {
    const dir = repo(FILES)
    await setup(dir, 'claude')
    const before = snapshot(dir)
    const r = await un(dir, {}, { confirm: async () => false })
    expect(r.code).toBe(0)
    expect(r.text).toContain('Nothing was changed.')
    expect(snapshot(dir)).toEqual(before)
  })

  it('unknown agent and --purge with --keep-reports are config errors (exit 2)', async () => {
    const dir = repo(FILES)
    expect((await un(dir, { agent: 'vim' })).code).toBe(2)
    expect((await un(dir, { purge: true, keepReports: true })).code).toBe(2)
    expect((await un(dir, { purge: true, agent: 'claude' })).code).toBe(2)
  })
})

describe('uninstall: edited content is kept and named', () => {
  it('an edited hook script is kept and named; the rest is removed', async () => {
    const dir = repo(FILES)
    await setup(dir, 'claude')
    const shim = join(dir, '.claude/hooks/shipguard-gate.sh')
    writeFileSync(shim, readFileSync(shim, 'utf-8') + '\n# my own line\n')
    const r = await un(dir, { yes: true })
    expect(r.code).toBe(0)
    expect(existsSync(shim)).toBe(true)
    expect(r.text).toContain('Will keep (edited since install')
    expect(r.text).toContain('Still active')
    expect(r.text).not.toContain('no ShipGuard hook or block is left')
    expect(readFileSync(join(dir, 'CLAUDE.md'), 'utf-8')).toBe('# My project\n\nRules of mine.\n')
  })

  it('an edited settings.json hook entry is kept (and so is the script it runs)', async () => {
    const dir = repo(FILES)
    await setup(dir, 'claude')
    const f = join(dir, '.claude/settings.json')
    const s = JSON.parse(readFileSync(f, 'utf-8'))
    s.hooks.PreToolUse[1].hooks[0].timeout = 999
    writeFileSync(f, JSON.stringify(s, null, 2))
    const r = await un(dir, { yes: true })
    expect(r.code).toBe(0)
    expect(JSON.stringify(JSON.parse(readFileSync(f, 'utf-8')))).toContain('shipguard-gate.sh')
    expect(existsSync(join(dir, '.claude/hooks/shipguard-gate.sh'))).toBe(true)
    expect(r.text).toContain('Do this yourself')
  })

  it('an edited managed block in CLAUDE.md is kept with its line numbers', async () => {
    const dir = repo(FILES)
    await setup(dir, 'claude')
    const f = join(dir, 'CLAUDE.md')
    writeFileSync(f, readFileSync(f, 'utf-8').replace('## ShipGuard', '## ShipGuard (my words)'))
    const r = await un(dir, { yes: true })
    expect(r.code).toBe(0)
    expect(readFileSync(f, 'utf-8')).toContain('my words')
    expect(r.text).toMatch(/delete lines \d+-\d+ yourself/)
  })

  it('user lines in a git hook stay; only the ShipGuard block goes', async () => {
    const dir = repo(FILES)
    await setup(dir, 'git')
    const f = join(dir, '.git/hooks/pre-push')
    writeFileSync(f, readFileSync(f, 'utf-8') + 'echo mine\necho also mine\n')
    const r = await un(dir, { yes: true })
    expect(r.code).toBe(0)
    const t = readFileSync(f, 'utf-8')
    expect(t).toContain('echo mine')
    expect(t).not.toContain('shipguard managed block')
    expect(existsSync(join(dir, '.git/hooks/pre-merge-commit'))).toBe(false)
    expect(r.text).toContain('2 lines of yours stay')
  })

  it('a workflow file edited by the user is kept', async () => {
    const dir = repo(FILES)
    await setup(dir, 'ci')
    const f = join(dir, '.github/workflows/shipguard.yml')
    writeFileSync(f, readFileSync(f, 'utf-8').replace('ubuntu-latest', 'ubuntu-22.04'))
    const r = await un(dir, { yes: true })
    expect(r.code).toBe(0)
    expect(existsSync(f)).toBe(true)
    expect(r.text).toContain('.github/workflows/shipguard.yml')
  })
})

describe('uninstall: scope and safety', () => {
  it('--agent claude leaves the git hooks, the CI workflow and the record for the others', async () => {
    const dir = repo(FILES)
    await setup(dir, 'all')
    expect((await un(dir, { agent: 'claude', yes: true })).code).toBe(0)
    expect(existsSync(join(dir, '.claude/hooks/shipguard-gate.sh'))).toBe(false)
    expect(readFileSync(join(dir, 'CLAUDE.md'), 'utf-8')).toBe('# My project\n\nRules of mine.\n')
    expect(existsSync(join(dir, '.git/hooks/pre-push'))).toBe(true)
    expect(existsSync(join(dir, '.github/workflows/shipguard.yml'))).toBe(true)
    const rec = readInstallState(dir)
    expect(rec?.agents).not.toContain('claude')
    expect(rec?.agents).toContain('ci')
    expect(rec?.entries.some((e) => e.path === '.claude/hooks/shipguard-gate.sh')).toBe(false)
  })

  it('a repo with reports keeps .shipguard/ (named); --purge deletes it after naming it', async () => {
    const dir = repo(FILES)
    await setup(dir, 'claude')
    mkdirSync(join(dir, '.shipguard/reports'), { recursive: true })
    writeFileSync(join(dir, '.shipguard/reports/a.json'), '{}')
    const r = await un(dir, { yes: true })
    expect(r.text).toContain('Kept: shipguard.policy.yml, .shipguard/ (reports, history, its .gitignore)')
    expect(existsSync(join(dir, '.shipguard/reports/a.json'))).toBe(true)
    expect(existsSync(join(dir, '.shipguard/installed.json'))).toBe(false)
    const dry = await un(dir, { purge: true, dryRun: true })
    expect(dry.text).toContain('the whole folder')
    expect(existsSync(join(dir, '.shipguard/reports/a.json'))).toBe(true)
  })

  it('--purge removes reports; --purge-home removes only the config folder named shipguard', async () => {
    const dir = repo(FILES)
    await setup(dir, 'claude')
    mkdirSync(join(dir, '.shipguard/reports'), { recursive: true })
    writeFileSync(join(dir, '.shipguard/reports/a.json'), '{}')
    const home = mk('sg-un-h-')
    const cfg = join(home, '.config', 'shipguard')
    mkdirSync(cfg, { recursive: true })
    writeFileSync(join(cfg, 'telemetry.json'), '{}')
    const r = await un(dir, { yes: true, purge: true, purgeHome: true }, { configDir: cfg })
    expect(r.code).toBe(0)
    expect(existsSync(join(dir, '.shipguard'))).toBe(false)
    expect(existsSync(cfg)).toBe(false)
    expect(existsSync(home)).toBe(true)
    const bad = await un(dir, { yes: true, purgeHome: true }, { configDir: home })
    expect(bad.code).toBe(2)
    expect(existsSync(home)).toBe(true)
  })

  it('a tampered record cannot point uninstall at another file', async () => {
    const dir = repo({ ...FILES, 'precious.txt': 'keep me' })
    await setup(dir, 'claude')
    const f = join(dir, '.shipguard/installed.json')
    const rec = JSON.parse(readFileSync(f, 'utf-8'))
    rec.entries.push({ path: 'precious.txt', kind: 'file', sha256: 'x' }, { path: '../outside.txt', kind: 'file', sha256: 'x' })
    writeFileSync(f, JSON.stringify(rec))
    expect((await un(dir, { yes: true })).code).toBe(0)
    expect(readFileSync(join(dir, 'precious.txt'), 'utf-8')).toBe('keep me')
  })

  it('0.12 install with no record: found by markers; the inline hook entry and the hook block go, a user hook entry stays', async () => {
    const legacy = {
      hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'npx @agenticcli/shipguard scan --json --strict' }, { type: 'command', command: 'echo mine' }] }] },
    }
    const dir = repo({ '.claude/settings.json': JSON.stringify(legacy, null, 2) })
    const r = await un(dir, { yes: true })
    expect(r.text).toContain('Found by markers (no install record).')
    expect(r.code).toBe(0)
    const after = JSON.parse(readFileSync(join(dir, '.claude/settings.json'), 'utf-8'))
    expect(after.hooks.PreToolUse[0].hooks).toEqual([{ type: 'command', command: 'echo mine' }])
  })

  it('a file that merely mentions shipguard but has no marker is never touched', async () => {
    const dir = repo({ 'CLAUDE.md': 'Use shipguard before pushing.\n', '.github/workflows/shipguard.yml': 'name: mine\n' })
    const before = snapshot(dir)
    const r = await un(dir, { yes: true })
    expect(r.text).toBe('ShipGuard is not set up in this project. Nothing to remove.')
    expect(snapshot(dir)).toEqual(before)
  })
})
