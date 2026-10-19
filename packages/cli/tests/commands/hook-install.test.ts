/**
 * `shipguard hook`.
 *
 * Specification:
 *   "`shipguard hook` — one command installing the merge-boundary gate (design in §4)"
 *
 * Design constraints asserted here, all from the design:
 *   - every target installs `shipguard scan --json --strict` (a non---strict hook is a no-op,
 *     because ShipGuard is passive by default and --strict is its only hard stop);
 *   - idempotent — re-running updates in place, never duplicates;
 *   - refuses politely if a foreign hook exists, printing the manual line instead of
 *     overwriting;
 *   - says which layer binds whom in its OWN output, not just in the docs.
 *
 * FAIL-BEFORE: the command did not exist — `shipguard hook` exited 2 as an unknown command.
 *
 * DISCIPLINE: behavioral — spawned binary writing into real temp repos.
 */
import { spawnSync, execSync, execFileSync } from 'node:child_process'
import { spawnNode, type SpawnResult } from '../helpers/spawn-cli.js'
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
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

function mkRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-hook-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  execFileSync('git', ['init', '-q'], { cwd: dir, stdio: 'pipe' })
  return dir
}

/** A project dir that is deliberately NOT a git repo. */
function mkNonRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-hook-nogit-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
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

function runCli(args: string[], cwd: string): Promise<SpawnResult> {
  return spawnNode(distCli, args, { cwd, timeoutMs: 25_000 })
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 180_000)

describe('#5 — shipguard hook --target git', () => {
  it('installs pre-push and pre-merge-commit, both executable', async () => {
    const repo = mkRepo()
    const { code } = (await runCli(['hook'], repo))
    expect(code).toBe(0)
    for (const name of ['pre-push', 'pre-merge-commit']) {
      const path = join(repo, '.git', 'hooks', name)
      expect(existsSync(path)).toBe(true)
      // eslint-disable-next-line no-bitwise
      expect(statSync(path).mode & 0o111).toBeGreaterThan(0)
    }
  })

  it('the installed hook runs the ratified gate invocation', async () => {
    const repo = mkRepo()
    await runCli(['hook'], repo)
    const body = readFileSync(join(repo, '.git', 'hooks', 'pre-push'), 'utf-8')
    expect(body).toContain('scan --json --strict')
  })

  it('a missing shipguard binary makes the hook BLOCK, never silently pass', async () => {
    const repo = mkRepo()
    await runCli(['hook'], repo)
    const body = readFileSync(join(repo, '.git', 'hooks', 'pre-push'), 'utf-8')
    // Fail-closed: a gate that did not run must not report a pass (same rule as rec #1).
    expect(body).toContain('the release gate did not run')
    expect(body).toMatch(/exit 1/)
  })

  it('is idempotent — re-running updates in place, never duplicates the block', async () => {
    const repo = mkRepo()
    await runCli(['hook'], repo)
    const first = readFileSync(join(repo, '.git', 'hooks', 'pre-push'), 'utf-8')
    const second = (await runCli(['hook'], repo))
    const after = readFileSync(join(repo, '.git', 'hooks', 'pre-push'), 'utf-8')
    expect(after).toBe(first)
    expect(after.match(/shipguard managed block >>>/g)?.length).toBe(1)
    expect(after.match(/#!\/bin\/sh/g)?.length).toBe(1)
    expect(second.stderr).toContain('Already up to date')
  })

  it('refuses to overwrite a hook somebody else wrote, and prints the line to add', async () => {
    const repo = mkRepo()
    const path = join(repo, '.git', 'hooks', 'pre-push')
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, '#!/bin/sh\necho "my own hook"\n', 'utf-8')
    const { code, stderr } = (await runCli(['hook'], repo))
    expect(code).toBe(0)
    expect(readFileSync(path, 'utf-8')).toContain('my own hook')
    expect(readFileSync(path, 'utf-8')).not.toContain('shipguard managed block')
    expect(stderr).toContain('written by something else')
    expect(stderr).toContain('shipguard scan --json --strict')
  })

  it('says out loud that a git hook does NOT bind an agent', async () => {
    const repo = mkRepo()
    const { stderr } = (await runCli(['hook'], repo))
    expect(stderr).toContain('--no-verify')
    expect(stderr).toContain('--target claude')
    expect(stderr).toContain('--target ci')
  })

  it('outside a git repository it is a config error (exit 2), not a crash', async () => {
    const { code, stderr } = (await runCli(['hook'], mkNonRepo()))
    expect(code).toBe(2)
    expect(stderr).toContain('Not a git repository')
  })
})

describe('#5 — the installed git hook actually gates (executed, not just written)', () => {
  /** Run the generated pre-push hook with a stub `shipguard` on PATH. */
  function runInstalledHook(repo: string, stubExitCode: number): number {
    const binDir = join(repo, 'stub-bin')
    mkdirSync(binDir, { recursive: true })
    const stub = join(binDir, 'shipguard')
    writeFileSync(stub, `#!/bin/sh\necho '{"recommendation":"DO_NOT_SHIP"}'\nexit ${stubExitCode}\n`, 'utf-8')
    chmodSync(stub, 0o755)
    const res = spawnSync('sh', [join(repo, '.git', 'hooks', 'pre-push')], {
      cwd: repo,
      encoding: 'utf-8',
      timeout: 30_000,
      env: { ...process.env, PATH: `${binDir}:${process.env.PATH ?? ''}` },
    })
    return res.status === null ? -1 : res.status
  }

  it('passes the push through when the gate passes', async () => {
    const repo = mkRepo()
    await runCli(['hook'], repo)
    expect(runInstalledHook(repo, 0)).toBe(0)
  })

  it('blocks the push when the gate blocks', async () => {
    const repo = mkRepo()
    await runCli(['hook'], repo)
    expect(runInstalledHook(repo, 1)).toBe(1)
  })
})

describe('#5 — shipguard hook --target claude', () => {
  it('creates a PreToolUse Bash hook that blocks with exit 2', async () => {
    const repo = mkRepo()
    const { code } = (await runCli(['hook', '--target', 'claude'], repo))
    expect(code).toBe(0)
    const settings = JSON.parse(readFileSync(join(repo, '.claude', 'settings.json'), 'utf-8'))
    const entry = settings.hooks.PreToolUse[0]
    expect(entry.matcher).toBe('Bash')
    expect(entry.hooks[0].command).toContain('scan --json --strict')
    expect(entry.hooks[0].command).toContain('git merge')
    expect(entry.hooks[0].command).toContain('git push')
    expect(entry.hooks[0].command).toContain('exit 2')
  })

  it('merges into an existing settings.json without destroying other keys', async () => {
    const repo = mkRepo()
    mkdirSync(join(repo, '.claude'), { recursive: true })
    writeFileSync(
      join(repo, '.claude', 'settings.json'),
      JSON.stringify({ model: 'opus', hooks: { PreToolUse: [{ matcher: 'Write', hooks: [{ type: 'command', command: 'echo hi' }] }] } }, null, 2),
      'utf-8',
    )
    await runCli(['hook', '--target', 'claude'], repo)
    const settings = JSON.parse(readFileSync(join(repo, '.claude', 'settings.json'), 'utf-8'))
    expect(settings.model).toBe('opus')
    expect(settings.hooks.PreToolUse).toHaveLength(2)
    expect(settings.hooks.PreToolUse[0].matcher).toBe('Write')
  })

  it('is idempotent — a second run adds no second entry', async () => {
    const repo = mkRepo()
    await runCli(['hook', '--target', 'claude'], repo)
    await runCli(['hook', '--target', 'claude'], repo)
    const settings = JSON.parse(readFileSync(join(repo, '.claude', 'settings.json'), 'utf-8'))
    expect(settings.hooks.PreToolUse).toHaveLength(1)
  })

  it('refuses to touch an unparseable settings.json', async () => {
    const repo = mkRepo()
    mkdirSync(join(repo, '.claude'), { recursive: true })
    writeFileSync(join(repo, '.claude', 'settings.json'), '{ not json', 'utf-8')
    const { stderr } = (await runCli(['hook', '--target', 'claude'], repo))
    expect(readFileSync(join(repo, '.claude', 'settings.json'), 'utf-8')).toBe('{ not json')
    expect(stderr).toContain('Refusing to touch it')
  })

  it('says out loud that this layer DOES bind the agent', async () => {
    const { stderr } = (await runCli(['hook', '--target', 'claude'], mkRepo()))
    expect(stderr).toContain('outside the model')
  })
})

describe('#5 — shipguard hook --target ci', () => {
  it('writes a GitHub Actions verdict job running the gate', async () => {
    const repo = mkRepo()
    const { code } = (await runCli(['hook', '--target', 'ci'], repo))
    expect(code).toBe(0)
    const yml = readFileSync(join(repo, '.github', 'workflows', 'shipguard.yml'), 'utf-8')
    expect(yml).toContain('scan --json --strict')
    expect(yml).toContain('runs-on: ubuntu-latest')
  })

  it('says out loud that CI is the layer that binds everyone', async () => {
    const { stderr } = (await runCli(['hook', '--target', 'ci'], mkRepo()))
    expect(stderr.toLowerCase()).toContain('binds everyone')
    expect(stderr.toLowerCase()).toContain('branch protection')
  })

  it('is idempotent', async () => {
    const repo = mkRepo()
    await runCli(['hook', '--target', 'ci'], repo)
    const first = readFileSync(join(repo, '.github', 'workflows', 'shipguard.yml'), 'utf-8')
    await runCli(['hook', '--target', 'ci'], repo)
    expect(readFileSync(join(repo, '.github', 'workflows', 'shipguard.yml'), 'utf-8')).toBe(first)
  })
})

describe('#5 — hook argument handling', () => {
  it('an unknown target is a config error (exit 2)', async () => {
    const { code, stderr } = (await runCli(['hook', '--target', 'jenkins'], mkRepo()))
    expect(code).toBe(2)
    expect(stderr).toContain('Unknown --target')
  })

  it('`hook` is a known command — no "unknown command" suggestion path', async () => {
    const { stderr } = (await runCli(['hook', '--target', 'ci'], mkRepo()))
    expect(stderr).not.toContain('unknown command')
  })
})
