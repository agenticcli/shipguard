/**
 * Test-strategy judge (2026-11-22), finding 4: the gate must fail CLOSED on its own configuration errors, through the
 * REAL built CLI (not a fake scan): a broken or wrongly shaped shipguard.policy.yml in the pushed commit, a folder that
 * is not a git repository, a folder that does not exist, one that cannot be read. Each is a block (Claude exit 2, git
 * exit 1) with the gate's own text ("did not run ... so nothing was scanned"), the machine line
 * `code=INVALID_POLICY` or `code=NOT_A_PROJECT`, never a pass and never the plain-CLI error. Before this, a policy that
 * parsed as YAML but was a list, a number or had `ignore: nope` either crashed the child scan (INTERNAL_ERROR, "the scan
 * crashed") or was silently ignored (a pass).
 */
import { execFileSync, spawn } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

vi.setConfig({ testTimeout: 90_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const cli = process.env.SHIPGUARD_CLI ?? resolve(pkgRoot, 'dist/cli.js')
beforeAll(() => {
  if (!existsSync(cli)) execFileSync('npx', ['tsup'], { cwd: pkgRoot, stdio: 'inherit' })
}, 240_000)

const dirs: string[] = []
afterAll(() => {
  for (const d of dirs.splice(0)) {
    try {
      chmodSync(d, 0o755)
    } catch {
      /* gone already */
    }
    rmSync(d, { recursive: true, force: true })
  }
})
const tmp = (p: string): string => {
  const d = mkdtempSync(join(tmpdir(), p))
  dirs.push(d)
  return d
}
const home = tmp('sg-gate-cfg-home-')

/** A repo with one commit holding `policy` as its shipguard.policy.yml. */
function repoWithPolicy(policy: string): string {
  const d = tmp('sg-gate-cfg-')
  const g = (...a: string[]): void => void execFileSync('git', a, { cwd: d, stdio: 'ignore' })
  g('init', '-q')
  g('config', 'user.email', 't@example.com')
  g('config', 'user.name', 't')
  writeFileSync(join(d, 'a.js'), 'console.log(1)\n')
  writeFileSync(join(d, 'shipguard.policy.yml'), policy)
  g('add', '-A')
  g('commit', '-q', '-m', 'c')
  return d
}

function gate(args: string[], cwd: string, stdin: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((res) => {
    const child = spawn(process.execPath, [cli, 'gate', ...args], {
      cwd,
      env: { ...process.env, HOME: home, SHIPGUARD_TELEMETRY: 'off', NODE_OPTIONS: '' },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf-8').on('data', (d: string) => (stdout += d))
    child.stderr.setEncoding('utf-8').on('data', (d: string) => (stderr += d))
    child.on('close', (code) => res({ code: code ?? -1, stdout, stderr }))
    child.stdin.end(stdin)
  })
}
const claude = (command: string, cwd: string, runIn: string): ReturnType<typeof gate> =>
  gate(['--host', 'claude'], runIn, JSON.stringify({ tool_input: { command }, cwd }))
const lastLine = (t: string): string => t.trimEnd().split('\n').pop() ?? ''

describe('gate config errors fail closed (real CLI)', () => {
  const BAD: Array<[string, string, string]> = [
    ['broken YAML', 'version: 1\nproject:\n  name: x\n   bad: [\n', 'line 3'],
    ['a list at the top level', '- just\n- a list\n', 'must be a list of "key: value"'],
    ['a bare number', '42\n', 'must be a list of "key: value"'],
    ['ignore: nope', 'ignore: nope\n', '"ignore" must have indented'],
    ['ignore.paths is a number', 'ignore:\n  paths: 5\n', '"ignore.paths" must be a list'],
    ['limits: 7', 'limits: 7\n', '"limits" must have indented'],
    ['block: x', 'block: x\n', '"block" must be a list of names'],
    ['gate.timeoutSeconds: abc', 'gate:\n  timeoutSeconds: abc\n', 'gate.timeoutSeconds must be a number'],
  ]
  for (const [name, policy, cause] of BAD) {
    it(`${name} in the pushed commit: INVALID_POLICY, nothing pushed (Claude exit 2, git exit 1)`, async () => {
      const d = repoWithPolicy(policy)
      const c = await claude('git push origin main', d, d)
      expect(c.code, c.stdout + c.stderr).toBe(2)
      expect(c.stdout).toBe('')
      expect(c.stderr).toContain('did not run')
      expect(c.stderr).toContain('so nothing was scanned')
      expect(c.stderr).toContain(cause)
      expect(c.stderr).not.toContain('the scan crashed')
      expect(lastLine(c.stderr)).toBe('shipguard-gate: code=INVALID_POLICY agentAction=fix_and_rerun run=none')
      const g = await gate(['--host', 'git', '--hook', 'pre-push'], d, '')
      expect(g.code, g.stdout + g.stderr).toBe(1)
      expect(lastLine(g.stderr)).toBe('shipguard-gate: code=INVALID_POLICY agentAction=fix_and_rerun run=none')
    })
  }

  it('an empty policy file is "use the defaults", not an error: the gate runs and passes a clean commit', async () => {
    const d = repoWithPolicy('')
    const c = await claude('git push origin main', d, d)
    expect(c.code, c.stderr).toBe(0)
    expect(JSON.parse(c.stdout).hookSpecificOutput.additionalContext).toContain('Verdict: SAFE TO SHIP')
  })

  it('a folder that is not a git repository, one that does not exist and a bare push there: NOT_A_PROJECT', async () => {
    const plain = tmp('sg-gate-cfg-plain-')
    const gone = join(plain, 'does-not-exist')
    for (const [command, runIn] of [
      [`git -C ${plain} push`, plain],
      [`git -C ${gone} push`, plain],
      ['git push', plain],
    ] as const) {
      const c = await claude(command, plain, runIn)
      expect(c.code, command).toBe(2)
      expect(c.stdout, command).toBe('')
      expect(c.stderr, command).toContain('so nothing was scanned')
      expect(lastLine(c.stderr), command).toBe('shipguard-gate: code=NOT_A_PROJECT agentAction=fix_and_rerun run=none')
    }
    const g = await gate(['--host', 'git', '--hook', 'pre-push'], plain, '')
    expect(g.code).toBe(1)
    expect(lastLine(g.stderr)).toBe('shipguard-gate: code=NOT_A_PROJECT agentAction=fix_and_rerun run=none')
  })

  it.skipIf(process.getuid?.() === 0)('a target folder that cannot be entered is a block, never a pass', async () => {
    const outer = tmp('sg-gate-cfg-noaccess-')
    const target = join(outer, 'locked')
    mkdirSync(target)
    chmodSync(target, 0o000)
    const c = await claude(`git -C ${target} push`, outer, outer)
    chmodSync(target, 0o755)
    expect(c.code, c.stdout + c.stderr).toBe(2)
    expect(c.stdout).toBe('')
    expect(lastLine(c.stderr)).toMatch(/^shipguard-gate: code=(NOT_A_PROJECT|INTERNAL_ERROR) agentAction=/)
  })
})
