/**
 * `shipguard setup` (W4a, spec 07): each agent target on a temp repo, dry-run and confirmation, announced writes
 * equal actual writes, the Claude hook flags by Claude Code version, the CI template, offer-cache priming gates.
 * Real files and a real `sh` (the fail-closed check); no network (the priming fetch is a stub).
 */
import { execFileSync } from 'node:child_process'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import { parse } from 'yaml'
import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { runSetup, versionAtLeast, type SetupDeps, type SetupOptions } from '../../src/commands/setup.js'
import { readInstallState, sha256 } from '../../src/core/install-state.js'
import { CLAUDE_HOOK_COMMAND, SHIM_RELATIVE_PATH, claudeShimScript } from '../../src/core/hook-templates.js'
import { agentsMdBlock, claudeMdBlock, extractMdBlock } from '../../src/core/setup-templates.js'
import { primeOfferCache } from '../../src/core/offer-cache.js'
import { probeGate } from '../../src/core/screen-context.js'

const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))

function repo(opts: { git?: boolean; files?: Record<string, string> } = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'sg-setup-'))
  roots.push(dir)
  if (opts.git !== false) execFileSync('git', ['init', '-q'], { cwd: dir })
  for (const [f, t] of Object.entries(opts.files ?? {})) {
    mkdirSync(join(dir, f, '..'), { recursive: true })
    writeFileSync(join(dir, f), t)
  }
  return dir
}

/** Every file under dir (relative), skipping .git internals except hooks. */
function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {}
  const walk = (d: string): void => {
    for (const name of readdirSync(d)) {
      const abs = join(d, name)
      const rel = relative(dir, abs)
      if (rel.startsWith('.git/') && rel !== '.git/hooks' && !rel.startsWith('.git/hooks/')) continue
      if (rel === '.git') {
        walk(abs)
        continue
      }
      if (lstatSync(abs).isDirectory()) walk(abs)
      else if (!rel.endsWith('.sample')) out[rel] = readFileSync(abs, 'utf-8')
    }
  }
  walk(dir)
  return out
}

const changed = (a: Record<string, string>, b: Record<string, string>): string[] =>
  Object.keys({ ...a, ...b }).filter((k) => a[k] !== b[k]).sort()

interface Harness {
  deps: SetupDeps
  lines: string[]
  primeCalls: Array<{ url: string }>
  installs: string[]
  config: string
}

function harness(cwd: string, over: Partial<SetupDeps> = {}, fetchStatus = 500): Harness {
  const config = mkdtempSync(join(tmpdir(), 'sg-setup-cfg-'))
  roots.push(config)
  const lines: string[] = []
  const primeCalls: Array<{ url: string }> = []
  const installs: string[] = []
  const deps: SetupDeps = {
    cwd,
    out: (l) => lines.push(l),
    isTty: true,
    confirm: async () => true,
    env: { PATH: process.env['PATH'] ?? '' },
    now: () => 1_800_000_000_000,
    configDir: config,
    cliVersion: '0.13.0',
    claudeVersion: () => '2.1.326',
    findCli: () => ({ where: 'local', version: '0.13.0', path: './node_modules/.bin/shipguard' }),
    installDependency: (_d, v) => void installs.push(v),
    signedIn: () => false,
    sandbox: true,
    prime: (g, now) =>
      primeOfferCache({ configDir: config, now, safeMode: g.safeMode }, g, {
        fetchImpl: (async (url: string) => {
          primeCalls.push({ url: String(url) })
          return new Response('no', { status: fetchStatus })
        }) as unknown as typeof fetch,
      }),
    ...over,
  }
  return { deps, lines, primeCalls, installs, config }
}

const run = (o: SetupOptions, h: Harness): Promise<number> => runSetup(o, h.deps)
const text = (h: Harness): string => h.lines.join('\n')
const settings = (dir: string): { hooks: { PreToolUse: Array<{ matcher?: string; hooks: Array<Record<string, unknown>> }> } } =>
  JSON.parse(readFileSync(join(dir, '.claude', 'settings.json'), 'utf-8'))

let dir: string
beforeEach(() => {
  dir = repo({ files: { '.claude/settings.json': JSON.stringify({ model: 'x', hooks: { PreToolUse: [{ matcher: 'Edit', hooks: [{ type: 'command', command: 'echo mine' }] }], Stop: [] } }) } })
})

describe('setup --agent claude', () => {
  it('writes the hook entry (timeout 180, onFailure block on 2.1.295+), the script, the CLAUDE.md block and the record; keeps the rest', async () => {
    const h = harness(dir)
    const before = snapshot(dir)
    expect(await run({ agent: 'claude' }, h)).toBe(0)
    const s = settings(dir)
    expect(s.hooks.PreToolUse).toHaveLength(2)
    expect(s.hooks.PreToolUse[0].hooks[0].command).toBe('echo mine')
    expect((s as unknown as Record<string, unknown>)['model']).toBe('x')
    const ours = s.hooks.PreToolUse[1]
    expect(ours.matcher).toBe('Bash')
    expect(ours.hooks[0]).toEqual({ type: 'command', command: CLAUDE_HOOK_COMMAND, timeout: 180, onFailure: 'block' })
    expect(readFileSync(join(dir, SHIM_RELATIVE_PATH), 'utf-8')).toBe(claudeShimScript())
    expect(lstatSync(join(dir, SHIM_RELATIVE_PATH)).mode & 0o111).not.toBe(0)
    expect(readFileSync(join(dir, 'CLAUDE.md'), 'utf-8')).toContain(claudeMdBlock())
    expect(readFileSync(join(dir, '.shipguard', '.gitignore'), 'utf-8')).toBe('*\n')
    expect(changed(before, snapshot(dir))).toEqual(['.claude/hooks/shipguard-gate.sh', '.claude/settings.json', '.shipguard/.gitignore', '.shipguard/installed.json', 'CLAUDE.md'])
    expect(text(h)).toContain('with the ShipGuard binary hidden, a test `git push` was blocked (exit 2)')
  })

  it('announced writes equal actual writes', async () => {
    const h = harness(dir)
    const before = snapshot(dir)
    await run({ agent: 'claude' }, h)
    const plan = h.lines.slice(h.lines.findIndex((l) => l.startsWith('This will change')) + 1)
    const announced = plan.filter((l) => /^ {2}\S/.test(l)).map((l) => l.trim().split(/\s+/)[0]).filter((p) => p.includes('.') || p.includes('/') || p === 'CLAUDE.md').slice(0, 5)
    expect(h.lines.find((l) => l.startsWith('This will change'))).toBe('This will change 5 files:')
    expect(announced.sort()).toEqual(changed(before, snapshot(dir)))
  })

  it('the record holds a content hash per write and the scan screen reads it', async () => {
    const h = harness(dir)
    await run({ agent: 'claude' }, h)
    const rec = readInstallState(dir)
    expect(rec).not.toBeNull()
    expect(rec?.agents).toEqual(['claude'])
    expect(rec?.hookVersion).toBe(2)
    const shim = rec?.entries.find((e) => e.path === SHIM_RELATIVE_PATH)
    expect(shim).toMatchObject({ kind: 'file', sha256: sha256(claudeShimScript()) })
    const md = rec?.entries.find((e) => e.path === 'CLAUDE.md')
    expect(md?.sha256).toBe(sha256(extractMdBlock(readFileSync(join(dir, 'CLAUDE.md'), 'utf-8')) as string))
    expect(probeGate(dir).state).toBe('current')
  })

  it('is idempotent: a second run changes nothing', async () => {
    await run({ agent: 'claude' }, harness(dir))
    const before = snapshot(dir)
    const h = harness(dir)
    expect(await run({ agent: 'claude' }, h)).toBe(0)
    expect(text(h)).toContain('Already installed, no change.')
    expect(snapshot(dir)).toEqual(before)
  })

  it('onFailure only on Claude Code 2.1.295 or later; unknown or older version says so and sets none', async () => {
    for (const v of ['2.1.294', '2.0.9', null]) {
      const d = repo({ files: { '.claude/settings.json': '{}' } })
      const h = harness(d, { claudeVersion: () => v })
      expect(await run({ agent: 'claude' }, h)).toBe(0)
      const hook = settings(d).hooks.PreToolUse[0].hooks[0]
      expect(hook.timeout).toBe(180)
      expect(hook).not.toHaveProperty('onFailure')
      expect(text(h)).toContain('onFailure block not set')
    }
    const d295 = repo({ files: { '.claude/settings.json': '{}' } })
    await run({ agent: 'claude' }, harness(d295, { claudeVersion: () => '2.1.295' }))
    expect(settings(d295).hooks.PreToolUse[0].hooks[0].onFailure).toBe('block')
    expect(versionAtLeast('2.1.295', '2.1.295')).toBe(true)
    expect(versionAtLeast('2.1.294', '2.1.295')).toBe(false)
    expect(versionAtLeast('3.0.0', '2.1.295')).toBe(true)
    expect(versionAtLeast(null, '2.1.295')).toBe(false)
  })

  it('keeps an existing onFailure and timeout on our own entry', async () => {
    await run({ agent: 'claude' }, harness(dir))
    const s = settings(dir)
    s.hooks.PreToolUse[1].hooks[0].onFailure = 'continue'
    s.hooks.PreToolUse[1].hooks[0].timeout = 300
    writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify(s))
    const h = harness(dir)
    await run({ agent: 'claude' }, h)
    const hook = settings(dir).hooks.PreToolUse[1].hooks[0]
    expect(hook.onFailure).toBe('continue')
    expect(hook.timeout).toBe(300)
  })

  it('updates the 0.12 inline hook in place and names it', async () => {
    const legacy = `sh -c '_sg_in=$(cat); ./node_modules/.bin/shipguard scan --json --strict'`
    const d = repo({ files: { '.claude/settings.json': JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: legacy }] }] } }) } })
    const h = harness(d)
    await run({ agent: 'claude' }, h)
    expect(text(h)).toContain('Hook is v1 (0.11 or 0.12, can skip the gate silently): will be updated to v2')
    const s = settings(d)
    expect(s.hooks.PreToolUse).toHaveLength(1)
    expect(s.hooks.PreToolUse[0].hooks).toHaveLength(1)
    expect(s.hooks.PreToolUse[0].hooks[0].command).toBe(CLAUDE_HOOK_COMMAND)
  })

  it('never touches a settings file it cannot parse, a script of yours, or hand-edited blocks', async () => {
    const bad = repo({ files: { '.claude/settings.json': '{ nope' } })
    const hb = harness(bad)
    expect(await run({ agent: 'claude' }, hb)).toBe(3)
    expect(readFileSync(join(bad, '.claude', 'settings.json'), 'utf-8')).toBe('{ nope')
    expect(text(hb)).toContain('NOT changed')
    expect(text(hb)).toContain('Do this yourself')

    const mine = repo({ files: { [SHIM_RELATIVE_PATH]: '#!/bin/sh\necho mine\n' } })
    const hm = harness(mine)
    expect(await run({ agent: 'claude' }, hm)).toBe(3)
    expect(readFileSync(join(mine, SHIM_RELATIVE_PATH), 'utf-8')).toBe('#!/bin/sh\necho mine\n')

    // a hand-edited CLAUDE.md block is kept
    await run({ agent: 'claude' }, harness(dir))
    const md = join(dir, 'CLAUDE.md')
    writeFileSync(md, readFileSync(md, 'utf-8').replace('Never use', 'Please do not use'))
    const edited = readFileSync(md, 'utf-8')
    const h2 = harness(dir)
    await run({ agent: 'claude' }, h2)
    expect(readFileSync(md, 'utf-8')).toBe(edited)
  })

  it('appends the block to an existing CLAUDE.md and keeps the rest', async () => {
    const d = repo({ files: { 'CLAUDE.md': '# My rules\n\n- be nice\n' } })
    await run({ agent: 'claude' }, harness(d))
    const t = readFileSync(join(d, 'CLAUDE.md'), 'utf-8')
    expect(t.startsWith('# My rules\n\n- be nice\n\n')).toBe(true)
    expect(t).toContain(claudeMdBlock())
  })
})

describe('confirmation and dry run', () => {
  it('--dry-run writes nothing and exits 0', async () => {
    const before = snapshot(dir)
    const h = harness(dir, { isTty: false })
    expect(await run({ agent: 'claude', dryRun: true }, h)).toBe(0)
    expect(snapshot(dir)).toEqual(before)
    expect(text(h)).toContain('Dry run: nothing was changed.')
    expect(text(h)).toContain('This will change 5 files:')
  })

  it('not a terminal and no --yes: prints the plan, exits 2 CONFIRMATION_REQUIRED, writes nothing', async () => {
    const before = snapshot(dir)
    const h = harness(dir, { isTty: false })
    expect(await run({ agent: 'claude' }, h)).toBe(2)
    expect(snapshot(dir)).toEqual(before)
    expect(text(h)).toContain('Run: shipguard setup --agent claude --yes')
    const again = harness(dir, { isTty: false })
    expect(await run({ agent: 'claude', yes: true }, again)).toBe(0)
  })

  it('answering no changes nothing', async () => {
    const before = snapshot(dir)
    const h = harness(dir, { confirm: async () => false })
    expect(await run({ agent: 'claude' }, h)).toBe(0)
    expect(snapshot(dir)).toEqual(before)
    expect(text(h)).toContain('Nothing was changed.')
  })

  it('an unknown agent is a config error; no --agent detects from the files', async () => {
    expect(await run({ agent: 'vim' }, harness(dir))).toBe(2)
    const h = harness(dir, { isTty: false })
    await run({ dryRun: true }, h)
    expect(text(h)).toContain('Detected: Claude Code (.claude/ found); git hooks (.git/ found).')
    const none = repo({ git: false })
    expect(await run({}, harness(none))).toBe(2)
  })
})

describe('setup --agent codex | cursor | git', () => {
  it('codex: AGENTS.md block + both git hooks, the hooks fail closed when ShipGuard is hidden', async () => {
    const d = repo({ files: { 'AGENTS.md': '# Agents\n' } })
    const h = harness(d)
    const before = snapshot(d)
    expect(await run({ agent: 'codex' }, h)).toBe(0)
    expect(readFileSync(join(d, 'AGENTS.md'), 'utf-8')).toContain(agentsMdBlock())
    for (const n of ['pre-push', 'pre-merge-commit']) {
      expect(lstatSync(join(d, '.git', 'hooks', n)).mode & 0o111).not.toBe(0)
      expect(readFileSync(join(d, '.git', 'hooks', n), 'utf-8')).toContain('shipguard managed block >>> v2')
    }
    expect(changed(before, snapshot(d))).toEqual(['.git/hooks/pre-merge-commit', '.git/hooks/pre-push', '.shipguard/.gitignore', '.shipguard/installed.json', 'AGENTS.md'])
    expect(text(h)).toContain('Hooks folder: git config core.hooksPath is not set')
    expect(text(h)).toMatch(/pre-push: with the ShipGuard binary hidden, the hook blocks \(exit 1\)/)
    expect(readInstallState(d)?.agents).toEqual(['codex'])
  })

  it('cursor is the same route and says Cursor', async () => {
    const d = repo({ files: { '.cursor/rules': 'x' } })
    const h = harness(d, { isTty: false })
    expect(await run({ agent: 'cursor', yes: true }, h)).toBe(0)
    expect(existsSync(join(d, 'AGENTS.md'))).toBe(true)
    expect(readInstallState(d)?.agents).toEqual(['cursor'])
  })

  it('a git hook of yours is never overwritten: named, exit 3, the other hook still installs', async () => {
    const d = repo({ files: { '.git/hooks/pre-push': '#!/bin/sh\necho mine\n' } })
    const h = harness(d)
    expect(await run({ agent: 'git' }, h)).toBe(3)
    expect(readFileSync(join(d, '.git', 'hooks', 'pre-push'), 'utf-8')).toBe('#!/bin/sh\necho mine\n')
    expect(text(h)).toContain('add `shipguard gate --host git` to .git/hooks/pre-push yourself')
    expect(existsSync(join(d, '.git', 'hooks', 'pre-merge-commit'))).toBe(true)
  })

  it('core.hooksPath: a normal folder is used and named; a generated husky folder is refused in words', async () => {
    const d = repo()
    mkdirSync(join(d, '.githooks'))
    execFileSync('git', ['config', 'core.hooksPath', '.githooks'], { cwd: d })
    const h = harness(d)
    expect(await run({ agent: 'git' }, h)).toBe(0)
    expect(existsSync(join(d, '.githooks', 'pre-push'))).toBe(true)
    expect(text(h)).toContain('core.hooksPath is .githooks')

    const hu = repo()
    mkdirSync(join(hu, '.husky', '_'), { recursive: true })
    execFileSync('git', ['config', 'core.hooksPath', '.husky/_'], { cwd: hu })
    const h2 = harness(hu)
    await run({ agent: 'git' }, h2)
    expect(text(h2)).toContain('core.hooksPath=.husky/_ is managed by husky')
    expect(existsSync(join(hu, '.husky', '_', 'pre-push'))).toBe(false)
  })

  it('updates an old git block in place and keeps the lines of yours', async () => {
    const d = repo({ files: { '.git/hooks/pre-push': '#!/bin/sh\necho before\n# >>> shipguard managed block >>> v1 (pre-push)\nold\n# <<< shipguard managed block <<<\necho after\n' } })
    const h = harness(d, { isTty: false })
    await run({ agent: 'git', yes: true }, h)
    const t = readFileSync(join(d, '.git', 'hooks', 'pre-push'), 'utf-8')
    expect(t.startsWith('#!/bin/sh\necho before\n')).toBe(true)
    expect(t.endsWith('echo after\n')).toBe(true)
    expect(t).toContain('shipguard managed block >>> v2')
    expect(t).not.toContain('\nold\n')
    expect(t.match(/#!\/bin\/sh/g)).toHaveLength(1)
  })
})

describe('setup --agent ci', () => {
  it('writes a workflow that is valid YAML, Node 22, pins the package to this version, has the optional key line', async () => {
    const d = repo({ files: { '.github/keep': '' } })
    const h = harness(d)
    expect(await run({ agent: 'ci' }, h)).toBe(0)
    const t = readFileSync(join(d, '.github', 'workflows', 'shipguard.yml'), 'utf-8')
    const doc = parse(t) as { name: string; jobs: Record<string, { name: string; steps: Array<Record<string, unknown>> }> }
    expect(doc.jobs['shipguard'].name).toBe('ShipGuard')
    const node = doc.jobs['shipguard'].steps.find((s) => String(s['uses']).startsWith('actions/setup-node'))
    expect((node?.['with'] as Record<string, string>)['node-version']).toBe('22')
    expect(t).toContain('npx --yes @agenticcli/shipguard@0.13.0 scan --strict')
    expect(t).toContain('SHIPGUARD_API_KEY: ${{ secrets.SHIPGUARD_API_KEY }}')
    expect(t).not.toMatch(/node-version: '20'/)
    expect(text(h)).toContain('workflow file is valid YAML and calls shipguard')
    expect(text(h)).toContain('require status check "ShipGuard"')
  })

  it('a workflow of yours is not overwritten', async () => {
    const d = repo({ files: { '.github/workflows/shipguard.yml': 'name: mine\n' } })
    expect(await run({ agent: 'ci' }, harness(d))).toBe(3)
    expect(readFileSync(join(d, '.github', 'workflows', 'shipguard.yml'), 'utf-8')).toBe('name: mine\n')
  })
})

describe('the CLI the hook runs', () => {
  const noCli = { findCli: () => null }

  it('not installed: the plan names the exact-pinned devDependency; it is added after the yes', async () => {
    const d = repo({ files: { 'package.json': '{}' } })
    const h = harness(d, noCli)
    await run({ agent: 'claude' }, h)
    expect(text(h)).toContain('adds @agenticcli/shipguard@0.13.0 as an exact-pinned devDependency')
    expect(h.installs).toEqual(['0.13.0'])
    expect(text(h)).toContain('This will change 7 files:')
  })

  it('--no-install: nothing is added and the npx fallback is stated', async () => {
    const d = repo({ files: { 'package.json': '{}' } })
    const h = harness(d, noCli)
    await run({ agent: 'claude', noInstall: true }, h)
    expect(h.installs).toEqual([])
    expect(text(h)).toContain('needs the network')
    expect(text(h)).toContain('This will change 5 files:')
  })

  it('dry run and a refused confirmation add nothing', async () => {
    const d = repo({ files: { 'package.json': '{}' } })
    const h = harness(d, { ...noCli, confirm: async () => false })
    await run({ agent: 'claude' }, h)
    await run({ agent: 'claude', dryRun: true }, harness(d, noCli))
    expect(h.installs).toEqual([])
  })

  it('a failed install stops before any other write and says how to go on', async () => {
    const d = repo({ files: { 'package.json': '{}' } })
    const before = snapshot(d)
    const h = harness(d, { ...noCli, installDependency: () => { throw new Error('offline') } })
    expect(await run({ agent: 'claude' }, h)).toBe(3)
    expect(snapshot(d)).toEqual(before)
    expect(text(h)).toContain('--no-install')
  })

  it('an older ShipGuard cannot be added here: no install is attempted', async () => {
    const d = repo({ files: { 'package.json': '{}' } })
    const h = harness(d, { ...noCli, cliVersion: '0.12.1' })
    await run({ agent: 'claude' }, h)
    expect(h.installs).toEqual([])
    expect(text(h)).toContain('older than 0.13')
  })
})

describe('offer-cache priming (spec 07, G1)', () => {
  it('after the yes: one generic fetch, no stack data in the request, named in the preview', async () => {
    const h = harness(dir)
    await run({ agent: 'claude' }, h)
    expect(h.primeCalls).toHaveLength(1)
    expect(h.primeCalls[0].url).toMatch(/\/api\/cli\/v1\/offer$/)
    expect(h.primeCalls[0].url).not.toContain('?')
    expect(text(h)).toContain('Also: fetches one public offer document (no project data, no login)')
    // the same 7-day counter: a second setup within the week does not fetch again
    const h2 = harness(dir, { configDir: h.config })
    h2.deps.prime = h.deps.prime
    await run({ agent: 'claude' }, h2)
    expect(h.primeCalls).toHaveLength(1)
    expect(text(h2)).not.toContain('Also: fetches')
  })

  it('a failed fetch is silent: exit code unchanged, no error line', async () => {
    const h = harness(dir, {}, 500)
    expect(await run({ agent: 'claude' }, h)).toBe(0)
    expect(text(h)).not.toMatch(/offer.*(failed|error)/i)
  })

  const excluded: Array<[string, Partial<SetupDeps>, SetupOptions]> = [
    ['signed in', { signedIn: () => true }, {}],
    ['safe mode', { env: { PATH: process.env['PATH'] ?? '', SHIPGUARD_SAFE_MODE: '1' } }, {}],
    ['DO_NOT_TRACK', { env: { PATH: process.env['PATH'] ?? '', DO_NOT_TRACK: '1' } }, {}],
    ['SHIPGUARD_TELEMETRY=0', { env: { PATH: process.env['PATH'] ?? '', SHIPGUARD_TELEMETRY: '0' } }, {}],
    ['CI', { env: { PATH: process.env['PATH'] ?? '', CI: 'true' } }, {}],
    ['not a terminal (an agent running it)', { isTty: false }, { yes: true }],
  ]
  for (const [name, over, opts] of excluded) {
    it(`skipped: ${name} (no fetch, preview does not promise one)`, async () => {
      const h = harness(dir, over)
      expect(await run({ agent: 'claude', ...opts }, h)).toBe(0)
      expect(h.primeCalls).toHaveLength(0)
      expect(text(h)).not.toContain('Also: fetches')
    })
  }

  it('skipped: --dry-run (the preview still names it, nothing is fetched)', async () => {
    const h = harness(dir)
    await run({ agent: 'claude', dryRun: true }, h)
    expect(h.primeCalls).toHaveLength(0)
    expect(text(h)).toContain('Also: fetches')
  })

  it('skipped: answering no', async () => {
    const h = harness(dir, { confirm: async () => false })
    await run({ agent: 'claude' }, h)
    expect(h.primeCalls).toHaveLength(0)
  })
})

describe('no plugin text and no disabled file (0.14, not built)', () => {
  it('output and written files never mention a plugin or .shipguard/disabled', async () => {
    const h = harness(dir)
    await run({ agent: 'all' }, h)
    const all = text(h) + Object.values(snapshot(dir)).join('\n')
    expect(all).not.toMatch(/plugin/i)
    expect(all).not.toContain('shipguard/disabled')
    expect(all).not.toMatch(/release gate|our servers|cloud/i)
    expect(existsSync(join(dir, '.shipguard', 'disabled'))).toBe(false)
  })
})
