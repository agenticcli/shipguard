/**
 * The full rulebook runs on push and in CI, not on every local check.
 *
 * - pre-push hook and the CI workflow add `--pro` when the machine is signed in (a saved login or
 *   SHIPGUARD_API_KEY); pre-merge-commit and the Claude Code hook stay plain.
 * - NOT signed in: the hook and CI degrade to a plain scan with ONE notice line. Never a new failure.
 * - Signed in but `--pro` cannot run (exit 3: no credits left, rulebook unreachable): fall back to
 *   the plain scan with one notice line. A block (exit 1) is never retried or hidden.
 *
 * The generated shell is EXECUTED here with a stub `shipguard`/`npx` that records its arguments.
 */
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { CLAUDE_HOOK_COMMAND, ciWorkflowYaml, gitHookBlock, gitHookScript } from '../../src/core/hook-templates.js'

const dirs: string[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

function mkdir(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix))
  dirs.push(d)
  return d
}

interface Run {
  status: number
  stderr: string
  stdout: string
  /** One line per stub call: the arguments it received. */
  calls: string[]
}

/**
 * Run `script` with stub binaries on PATH. The stub exits with STUB_EXIT_PRO when `--pro` is among
 * its arguments, else with STUB_EXIT_PLAIN, and appends its arguments to a log file.
 */
function runScript(script: string, opts: { stubs: string[]; signedIn: boolean | 'key'; pro: number; plain: number }): Run {
  const root = mkdir('sg-hook-pro-')
  const bin = join(root, 'bin')
  const home = join(root, 'home')
  mkdirSync(bin)
  mkdirSync(home)
  const log = join(root, 'calls.log')
  for (const name of opts.stubs) {
    const stub = join(bin, name)
    writeFileSync(
      stub,
      '#!/bin/sh\necho "$*" >> "$STUB_LOG"\ncase " $* " in *" --pro "*) exit "$STUB_EXIT_PRO";; esac\nexit "$STUB_EXIT_PLAIN"\n',
    )
    chmodSync(stub, 0o755)
  }
  if (opts.signedIn === true) {
    mkdirSync(join(home, '.config', 'shipguard'), { recursive: true })
    writeFileSync(join(home, '.config', 'shipguard', 'credentials.json'), '{}')
  }
  const scriptPath = join(root, 'script.sh')
  writeFileSync(scriptPath, script)
  const env: NodeJS.ProcessEnv = {
    PATH: `${bin}:/usr/bin:/bin`,
    HOME: home,
    STUB_LOG: log,
    STUB_EXIT_PRO: String(opts.pro),
    STUB_EXIT_PLAIN: String(opts.plain),
  }
  if (opts.signedIn === 'key') env.SHIPGUARD_API_KEY = 'test-key'
  const res = spawnSync('sh', [scriptPath], { cwd: root, encoding: 'utf-8', timeout: 30_000, env })
  let calls: string[] = []
  try {
    calls = readFileSync(log, 'utf-8').split('\n').filter(Boolean)
  } catch {
    calls = []
  }
  return { status: res.status ?? -1, stderr: res.stderr ?? '', stdout: res.stdout ?? '', calls }
}

const PRE_PUSH = gitHookScript('pre-push')

describe('templates: where --pro goes', () => {
  it('pre-push uses --pro; pre-merge-commit and the Claude hook do not', () => {
    expect(gitHookBlock('pre-push')).toContain('--pro')
    expect(gitHookBlock('pre-merge-commit')).not.toContain('--pro')
    expect(CLAUDE_HOOK_COMMAND).not.toContain('--pro')
  })

  it('the CI workflow uses --pro, reads the key from a repository secret, and still has the plain command', () => {
    const yml = ciWorkflowYaml()
    expect(yml).toContain('--pro')
    expect(yml).toContain('secrets.SHIPGUARD_API_KEY')
    expect(yml).toContain('scan --json --strict')
  })

  it('no user-facing line uses the banned words', () => {
    const text = [gitHookBlock('pre-push'), ciWorkflowYaml()].join('\n')
    const added = text.split('\n').filter((l) => /not signed in|falls back|SHIPGUARD_API_KEY/i.test(l)).join('\n')
    expect(added).not.toMatch(/cloud|release gate/i)
  })
})

describe('pre-push hook (executed)', () => {
  it('not signed in: plain scan only, one notice line, push allowed', () => {
    const r = runScript(PRE_PUSH, { stubs: ['shipguard'], signedIn: false, pro: 3, plain: 0 })
    expect(r.status).toBe(0)
    expect(r.calls).toEqual(['scan --json --strict'])
    expect(r.stderr.match(/not signed in/gi)?.length).toBe(1)
  })

  it('signed in (saved login): runs with --pro, no notice', () => {
    const r = runScript(PRE_PUSH, { stubs: ['shipguard'], signedIn: true, pro: 0, plain: 0 })
    expect(r.status).toBe(0)
    expect(r.calls).toEqual(['scan --json --strict --pro'])
    expect(r.stderr).not.toMatch(/not signed in/i)
  })

  it('signed in (SHIPGUARD_API_KEY): runs with --pro', () => {
    const r = runScript(PRE_PUSH, { stubs: ['shipguard'], signedIn: 'key', pro: 0, plain: 0 })
    expect(r.status).toBe(0)
    expect(r.calls).toEqual(['scan --json --strict --pro'])
  })

  it('signed in but --pro cannot run (exit 3): falls back to the plain scan with one notice, never a new failure', () => {
    const r = runScript(PRE_PUSH, { stubs: ['shipguard'], signedIn: true, pro: 3, plain: 0 })
    expect(r.status).toBe(0)
    expect(r.calls).toEqual(['scan --json --strict --pro', 'scan --json --strict'])
    expect(r.stderr.match(/falls back to the local rules/gi)?.length).toBe(1)
  })

  it('signed in, --pro runs and BLOCKS (exit 1): the push is blocked, no retry', () => {
    const r = runScript(PRE_PUSH, { stubs: ['shipguard'], signedIn: true, pro: 1, plain: 0 })
    expect(r.status).toBe(1)
    expect(r.calls).toEqual(['scan --json --strict --pro'])
  })

  it('fallback plain scan that blocks still blocks the push', () => {
    const r = runScript(PRE_PUSH, { stubs: ['shipguard'], signedIn: true, pro: 3, plain: 1 })
    expect(r.status).toBe(1)
    expect(r.calls).toEqual(['scan --json --strict --pro', 'scan --json --strict'])
  })

  it('not signed in and the plain scan blocks: blocked, as before', () => {
    const r = runScript(PRE_PUSH, { stubs: ['shipguard'], signedIn: false, pro: 0, plain: 1 })
    expect(r.status).toBe(1)
  })
})

describe('pre-merge-commit hook (executed)', () => {
  it('stays plain even when signed in, and prints no sign-in notice', () => {
    const r = runScript(gitHookScript('pre-merge-commit'), { stubs: ['shipguard'], signedIn: true, pro: 0, plain: 0 })
    expect(r.status).toBe(0)
    expect(r.calls).toEqual(['scan --json --strict'])
    expect(r.stderr).not.toMatch(/not signed in/i)
  })
})

/** The `run: |` body of the CI step, de-indented, ready to run as a shell script. */
function ciRunBody(): string {
  const lines = ciWorkflowYaml().split('\n')
  const start = lines.findIndex((l) => /^\s+run: \|\s*$/.test(l))
  expect(start).toBeGreaterThan(-1)
  const indent = (lines[start + 1].match(/^\s*/) ?? [''])[0].length
  const body: string[] = []
  for (const l of lines.slice(start + 1)) {
    if (l.trim() !== '' && (l.match(/^\s*/) ?? [''])[0].length < indent) break
    body.push(l.slice(indent))
  }
  return body.join('\n') + '\n'
}

describe('CI workflow step (executed)', () => {
  it('no SHIPGUARD_API_KEY: plain scan, one notice line, job passes', () => {
    const r = runScript(ciRunBody(), { stubs: ['npx'], signedIn: false, pro: 3, plain: 0 })
    expect(r.status).toBe(0)
    expect(r.calls).toEqual(['--yes @agenticcli/shipguard scan --json --strict'])
    expect(r.stdout.match(/SHIPGUARD_API_KEY is not set/g)?.length).toBe(1)
  })

  it('SHIPGUARD_API_KEY set: runs with --pro', () => {
    const r = runScript(ciRunBody(), { stubs: ['npx'], signedIn: 'key', pro: 0, plain: 0 })
    expect(r.status).toBe(0)
    expect(r.calls).toEqual(['--yes @agenticcli/shipguard scan --json --strict --pro'])
  })

  it('key set but --pro cannot run (exit 3): falls back to the plain scan', () => {
    const r = runScript(ciRunBody(), { stubs: ['npx'], signedIn: 'key', pro: 3, plain: 0 })
    expect(r.status).toBe(0)
    expect(r.calls).toEqual(['--yes @agenticcli/shipguard scan --json --strict --pro', '--yes @agenticcli/shipguard scan --json --strict'])
  })

  it('a block (exit 1) fails the job', () => {
    const r = runScript(ciRunBody(), { stubs: ['npx'], signedIn: 'key', pro: 1, plain: 0 })
    expect(r.status).toBe(1)
    expect(r.calls).toHaveLength(1)
  })
})
