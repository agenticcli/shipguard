/**
 * The POSIX shim every hook runs (spec 03): fail closed, one clock, texts that say why.
 *
 * Behavioural: the generated script is run with a restricted PATH and stub `shipguard` binaries.
 * Nothing here needs the real CLI. Stalled-probe cases take about 5 s (the real probe cap).
 */
import { spawn } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import {
  CLAUDE_HOOK_COMMAND,
  CLAUDE_HOOK_TIMEOUT_SECONDS,
  GATE_DEADLINE_SECONDS,
  NPX_SPEC,
  claudeShimScript,
  gitHookScript,
  shimFileVersion,
} from '../../src/core/hook-templates.js'

vi.setConfig({ testTimeout: 40_000 })

const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))

interface Sandbox {
  root: string
  bin: string
  work: string
  log: string
}

/** A work dir and a bin dir holding only the stubs asked for. `local` goes to work/node_modules/.bin. */
function sandbox(stubs: { npx?: string; shipguard?: string; local?: string } = {}): Sandbox {
  const root = mkdtempSync(join(tmpdir(), 'sg-shim-'))
  roots.push(root)
  const bin = join(root, 'bin')
  const work = join(root, 'work')
  mkdirSync(bin)
  mkdirSync(join(work, 'node_modules', '.bin'), { recursive: true })
  const put = (path: string, body: string): void => {
    writeFileSync(path, `#!/bin/sh\n${body}\n`)
    chmodSync(path, 0o755)
  }
  if (stubs.npx) put(join(bin, 'npx'), stubs.npx)
  if (stubs.shipguard) put(join(bin, 'shipguard'), stubs.shipguard)
  if (stubs.local) put(join(work, 'node_modules', '.bin', 'shipguard'), stubs.local)
  return { root, bin, work, log: join(root, 'calls.log') }
}

interface Run {
  code: number | null
  stdout: string
  stderr: string
  ms: number
}

function runScript(sb: Sandbox, script: string, input: string, opts: { path?: string; env?: Record<string, string>; shell?: string } = {}): Promise<Run> {
  const file = join(sb.root, 'shim.sh')
  writeFileSync(file, script)
  return new Promise((resolve) => {
    const t0 = Date.now()
    const child = spawn(opts.shell ?? '/bin/sh', [file], {
      cwd: sb.work,
      env: { PATH: opts.path ?? `${sb.bin}:/usr/bin:/bin`, HOME: sb.root, CLAUDE_PROJECT_DIR: sb.work, ...opts.env },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (b) => (stdout += b))
    child.stderr.on('data', (b) => (stderr += b))
    child.on('close', (code) => resolve({ code, stdout, stderr, ms: Date.now() - t0 }))
    child.stdin.end(input)
  })
}

const push = (command = 'git push origin main', cwd?: string): string => JSON.stringify({ cwd, tool_input: { command } })
const lastLine = (t: string): string => t.trimEnd().split('\n').pop() ?? ''

describe('the files the shim is written to', () => {
  it('claude: a short readable script with the version marker on line 2, the hook entry names it', () => {
    const s = claudeShimScript()
    expect(s.split('\n')[0]).toBe('#!/bin/sh')
    expect(s.split('\n')[1]).toMatch(/^# shipguard-hook v2 \(managed by ShipGuard/)
    expect(shimFileVersion(s)).toBe(2)
    expect(s.split('\n').length).toBeLessThan(60)
    expect(CLAUDE_HOOK_COMMAND).toBe('sh "$CLAUDE_PROJECT_DIR/.claude/hooks/shipguard-gate.sh"')
  })

  it('every resolver names the scoped package, never the unscoped one, and never --pro', () => {
    for (const t of [claudeShimScript(), gitHookScript('pre-push'), gitHookScript('pre-merge-commit')]) {
      expect(t).toContain(`npx --yes ${NPX_SPEC}`)
      expect(t).not.toMatch(/npx (--yes |--no-install )?shipguard\b/)
      expect(t).not.toContain('--pro')
    }
  })

  it('the numbers in the text are the numbers the code uses', () => {
    expect(CLAUDE_HOOK_TIMEOUT_SECONDS).toBe(180)
    expect(GATE_DEADLINE_SECONDS).toBe(150)
    const s = claudeShimScript()
    expect(s).toContain('SHIPGUARD_HOST_TIMEOUT=180')
    expect(s).toContain('DEADLINE=150')
    expect(s).toContain('cap 5')
  })
})

describe('claude shim: the hook sees EVERY Bash command', () => {
  it('a command that names neither git nor gh is not gated: exit 0, silent, ShipGuard never started (and never blocked when it is missing)', async () => {
    const sb = sandbox({ shipguard: 'echo started >> "$LOG"; exit 2' })
    for (const command of ['ls -la', 'npm test', 'echo highway weigh', 'cat digit.txt', 'node scripts/build.js --flag=1']) {
      const r = await runScript(sb, claudeShimScript(), push(command), { env: { LOG: sb.log } })
      expect(r.code, command).toBe(0)
      expect(r.stderr + r.stdout, command).toBe('')
    }
    expect(existsSync(sb.log)).toBe(false)
    const none = await runScript(sandbox(), claudeShimScript(), push('ls'))
    expect(none.code).toBe(0)
  })

  it('every command that names git or gh goes on (including paths, chains and subshells)', async () => {
    for (const command of ['git push', '/usr/bin/git push', 'cd x && git merge y', '(git push)', 'FOO=1 gh pr merge 3', 'git -C ../wt push']) {
      const r = await runScript(sandbox(), claudeShimScript(), push(command))
      expect(r.code, command).toBe(2)
      expect(lastLine(r.stderr), command).toContain('code=GATE_NOT_STARTED')
    }
  })
})

describe('claude shim: the pre-filter is never narrower than the parser (no way to hide a push from it)', () => {
  it('quotes, backslashes, variables, substitutions, globs and braces always go to the gate', async () => {
    for (const command of [
      "g''it push origin main",
      'g\\it push origin main',
      '/usr/bin/g[i]t push',
      '/usr/bin/g?t push',
      '/usr/bin/g*t push',
      'G=git; $G push',
      '${G:-git} push',
      '$(echo git) push',
      '`echo git` push',
      '{g,x}it push',
      'echo hi\nls',
      '"git" push',
      "'git' push",
    ]) {
      const r = await runScript(sandbox(), claudeShimScript(), push(command))
      expect(r.code, command).toBe(2)
      expect(lastLine(r.stderr), command).toContain('code=GATE_NOT_STARTED')
    }
  })

  it('a command with no such character and no git or gh word is the only thing that is not gated', async () => {
    for (const command of ['ls -la', 'npm run build', 'echo done']) {
      expect((await runScript(sandbox(), claudeShimScript(), push(command))).code, command).toBe(0)
    }
  })
})

describe('claude shim: the program that decides comes from the project root, never from the hook cwd', () => {
  it('a node_modules/.bin/shipguard in the folder the agent is in is NOT run (no code execution, no bypass)', async () => {
    const sb = sandbox({ shipguard: 'if [ "$2" = --supports ]; then exit 0; fi; echo "SAFE-PATH" >&2; exit 2' })
    const evil = join(sb.root, 'evil')
    mkdirSync(join(evil, 'node_modules', '.bin'), { recursive: true })
    writeFileSync(join(evil, 'node_modules', '.bin', 'shipguard'), `#!/bin/sh\ntouch "${join(sb.root, 'PWNED')}"\nexit 0\n`)
    chmodSync(join(evil, 'node_modules', '.bin', 'shipguard'), 0o755)
    const r = await runScript(sb, claudeShimScript(), push('git push', evil))
    expect(existsSync(join(sb.root, 'PWNED'))).toBe(false)
    expect(r.code).toBe(2)
    expect(r.stderr).toContain('SAFE-PATH')
  })

  it('without CLAUDE_PROJECT_DIR no local binary is used at all: PATH shipguard (or npx) only', async () => {
    const sb = sandbox({
      local: `touch "${'$'}LOG.local"; if [ "${'$'}2" = --supports ]; then exit 0; fi; exit 0`,
      shipguard: 'if [ "$2" = --supports ]; then exit 0; fi; echo path >> "$LOG"; exit 0',
    })
    const r = await runScript(sb, claudeShimScript(), push('git push'), { env: { CLAUDE_PROJECT_DIR: '', LOG: sb.log } })
    expect(r.code).toBe(0)
    expect(existsSync(`${sb.log}.local`)).toBe(false)
    expect(readFileSync(sb.log, 'utf-8').trim()).toBe('path')
    // and with nothing else installed it fails closed, it does not pick up ./node_modules/.bin
    const only = sandbox({ local: 'if [ "$2" = --supports ]; then exit 0; fi; exit 0' })
    const r2 = await runScript(only, claudeShimScript(), push('git push'), { env: { CLAUDE_PROJECT_DIR: '' } })
    expect(r2.code).toBe(2)
    expect(lastLine(r2.stderr)).toContain('code=GATE_NOT_STARTED')
  })

  it('the project-root binary is used even when the hook cwd is somewhere else', async () => {
    const sb = sandbox({ local: 'if [ "$2" = --supports ]; then exit 0; fi; echo "$0" > "$LOG"; exit 0' })
    const elsewhere = join(sb.root, 'elsewhere')
    mkdirSync(elsewhere)
    const r = await runScript(sb, claudeShimScript(), push('git push', elsewhere), { env: { LOG: sb.log } })
    expect(r.code).toBe(0)
    expect(readFileSync(sb.log, 'utf-8').trim()).toBe(`${sb.work}/node_modules/.bin/shipguard`)
  })
})

describe('claude shim: fail closed when ShipGuard cannot run the gate', () => {
  it('a gate that was stopped (exit 124) is a deadline text, not "could not start"', async () => {
    const sb = sandbox({ shipguard: 'if [ "$2" = --supports ]; then exit 0; fi; exit 124' })
    const r = await runScript(sb, claudeShimScript(), push())
    expect(r.code).toBe(2)
    expect(lastLine(r.stderr)).toContain('code=GATE_TIMEOUT')
  })

  it('nothing installed: exit 2, GATE_NOT_STARTED text with the fix and the manual removal, the command named', async () => {
    const sb = sandbox()
    const r = await runScript(sb, claudeShimScript(), push('git push origin main'), { path: `${sb.bin}:/usr/bin:/bin` })
    expect(r.code).toBe(2)
    expect(r.stderr).toContain('SHIPGUARD BLOCKED: `git push origin main` did not run. ShipGuard could not start')
    expect(r.stderr).toContain('npm i -D @agenticcli/shipguard')
    expect(r.stderr).toContain('npm i -g @agenticcli/shipguard')
    expect(r.stderr).toContain('delete the file .claude/hooks/shipguard-gate.sh')
    expect(r.stderr).not.toContain('shipguard uninstall')
    expect(lastLine(r.stderr)).toBe('shipguard-gate: code=GATE_NOT_STARTED agentAction=fix_and_rerun run=none')
  })

  it('an old ShipGuard (the probe fails with "unknown command", exit 2) is skipped, never read as a block it did not decide', async () => {
    const sb = sandbox({ shipguard: 'echo "unknown command gate" >&2; exit 2' })
    const r = await runScript(sb, claudeShimScript(), push())
    expect(r.code).toBe(2)
    expect(lastLine(r.stderr)).toContain('code=GATE_NOT_STARTED')
    expect(r.stderr).not.toContain('unknown command')
  })

  it('a local binary that answers the probe is run and a pass is a plain exit 0 with its stdout kept', async () => {
    const sb = sandbox({ local: 'if [ "$1" = gate ] && [ "$2" = --supports ]; then exit 0; fi; echo \'{"ok":1}\'; exit 0' })
    const r = await runScript(sb, claudeShimScript(), push())
    expect(r.code).toBe(0)
    expect(r.stdout).toContain('{"ok":1}')
    expect(r.stderr).toBe('')
  })

  it('a gate block (exit 2) passes through as exit 2 with the gate text untouched', async () => {
    const sb = sandbox({ shipguard: 'if [ "$2" = --supports ]; then exit 0; fi; echo "GATE TEXT" >&2; exit 2' })
    const r = await runScript(sb, claudeShimScript(), push())
    expect(r.code).toBe(2)
    expect(r.stderr).toBe('GATE TEXT\n')
  })

  it('a crash (exit 1, 127, 139) is not a pass and not a gate block: fail closed with the cannot-start text', async () => {
    for (const rc of [1, 127, 139]) {
      const sb = sandbox({ shipguard: `if [ "$2" = --supports ]; then exit 0; fi; exit ${rc}` })
      const r = await runScript(sb, claudeShimScript(), push())
      expect(r.code, `rc ${rc}`).toBe(2)
      expect(lastLine(r.stderr)).toContain('code=GATE_NOT_STARTED')
    }
  })

  it('the local binary wins over PATH and npx; npx is the scoped package with the gate arguments', async () => {
    const sb = sandbox({ local: 'echo local >> "$LOG"; exit 0', shipguard: 'echo path >> "$LOG"; exit 0', npx: 'echo npx >> "$LOG"; exit 0' })
    let r = await runScript(sb, claudeShimScript(), push(), { env: { LOG: sb.log } })
    expect(r.code).toBe(0)
    expect(readFileSync(sb.log, 'utf-8').split('\n').filter(Boolean)).toEqual(['local', 'local'])

    const only = sandbox({ npx: 'echo "$@" >> "$LOG"; exit 0' })
    r = await runScript(only, claudeShimScript(), push(), { env: { LOG: only.log } })
    expect(r.code).toBe(0)
    expect(readFileSync(only.log, 'utf-8').trim()).toBe(`--yes ${NPX_SPEC} gate --host claude`)
  })

  it('the stdin of the hook reaches the gate untouched; the gate runs from the project root; the clock and version are exported', async () => {
    const sb = sandbox({ shipguard: 'if [ "$2" = --supports ]; then exit 0; fi; cat > "$LOG"; pwd >> "$LOG"; env | grep ^SHIPGUARD_ >> "$LOG"; exit 0' })
    const elsewhere = join(sb.root, 'elsewhere')
    mkdirSync(elsewhere)
    const input = push('git push', elsewhere)
    const r = await runScript(sb, claudeShimScript(), input, { env: { LOG: sb.log } })
    expect(r.code).toBe(0)
    const log = readFileSync(sb.log, 'utf-8')
    expect(log).toContain(input)
    expect(log).toContain(elsewhere) // the gate reads the hook cwd from the JSON itself
    expect(log).toContain(`${input}${sb.work}\n`)
    expect(log).toMatch(/SHIPGUARD_GATE_START=\d+/)
    expect(log).toContain('SHIPGUARD_HOST_TIMEOUT=180')
    expect(log).toContain('SHIPGUARD_SHIM_VERSION=2')
  })

  it('a project folder that cannot be entered blocks with NOT_A_PROJECT', async () => {
    const sb = sandbox()
    const r = await runScript(sb, claudeShimScript(), push('git push', '/no/such/dir'), { env: { CLAUDE_PROJECT_DIR: '/no/such/project' } })
    expect(r.code).toBe(2)
    expect(lastLine(r.stderr)).toBe('shipguard-gate: code=NOT_A_PROJECT agentAction=fix_and_rerun run=none')
  })
})

describe('claude shim: the clock', () => {
  it('a stalled startup probe costs 5 s at most, is remembered, and blocks with GATE_STARTUP_STALLED when nothing else can run', async () => {
    const sb = sandbox({ local: 'sleep 30' })
    const r = await runScript(sb, claudeShimScript(), push('git push origin main'))
    expect(r.code).toBe(2)
    expect(r.ms).toBeGreaterThanOrEqual(4_500)
    expect(r.ms).toBeLessThan(15_000)
    expect(r.stderr).toContain('did not answer its 5 s startup check')
    expect(r.stderr).toContain(`${sb.work}/node_modules/.bin/shipguard`)
    expect(lastLine(r.stderr)).toBe('shipguard-gate: code=GATE_STARTUP_STALLED agentAction=ask_human run=none')
  })

  it('another working candidate is still tried after a stalled one', async () => {
    const sb = sandbox({ local: 'sleep 30', shipguard: 'echo path >> "$LOG"; exit 0' })
    const r = await runScript(sb, claudeShimScript(), push(), { env: { LOG: sb.log } })
    expect(r.code).toBe(0)
    expect(readFileSync(sb.log, 'utf-8')).toContain('path')
  })

  // E-06 / E-18: npx always sits next to node, so a stalled local binary used to fall through to `npx --yes ...@0.13 gate`,
  // which offline ate the whole 150 s deadline (GATE_TIMEOUT with "raise timeoutSeconds") instead of GATE_STARTUP_STALLED in ~5 s.
  for (const shell of ['/bin/sh', '/bin/dash']) {
    it(`a stalled local binary with npx on PATH blocks with GATE_STARTUP_STALLED in about 5 s and never runs npx (${shell})`, async () => {
      const sb = sandbox({ local: 'sleep 30', npx: 'echo npx >> "$LOG"; sleep 30' })
      const r = await runScript(sb, claudeShimScript(), push('git push origin main'), { env: { LOG: sb.log }, shell })
      expect(r.code).toBe(2)
      expect(r.ms).toBeGreaterThanOrEqual(4_500)
      expect(r.ms).toBeLessThan(9_000)
      expect(r.stderr).toContain('did not answer its 5 s startup check')
      expect(r.stderr).not.toContain('raise gate.timeoutSeconds')
      expect(lastLine(r.stderr)).toBe('shipguard-gate: code=GATE_STARTUP_STALLED agentAction=ask_human run=none')
      expect(existsSync(sb.log)).toBe(false)
    })
  }

  it('the same without a timeout tool (plain-shell watchdog) and with dash', async () => {
    const sb = sandbox({ local: 'sleep 30', npx: 'echo npx >> "$LOG"; sleep 30' })
    const tools = join(sb.root, 'tools')
    mkdirSync(tools)
    for (const t of ['sh', 'dash', 'cat', 'sed', 'head', 'date', 'mktemp', 'rm', 'sleep', 'grep']) {
      for (const dir of ['/usr/bin', '/bin']) {
        if (existsSync(join(dir, t))) {
          symlinkSync(join(dir, t), join(tools, t))
          break
        }
      }
    }
    symlinkSync(join(sb.bin, 'npx'), join(tools, 'npx'))
    const r = await runScript(sb, claudeShimScript(), push(), { path: tools, env: { LOG: sb.log }, shell: '/bin/dash' })
    expect(r.code).toBe(2)
    expect(r.ms).toBeLessThan(9_000)
    expect(lastLine(r.stderr)).toContain('code=GATE_STARTUP_STALLED')
    expect(existsSync(sb.log)).toBe(false)
  })

  it('a healthy local binary with npx on PATH never reaches the stalled text; npx is still the fallback when nothing stalled', async () => {
    const sb = sandbox({ npx: 'echo npx >> "$LOG"; exit 0' })
    rmSync(join(sb.work, 'node_modules'), { recursive: true, force: true })
    const r = await runScript(sb, claudeShimScript(), push(), { env: { LOG: sb.log } })
    expect(r.code).toBe(0)
    expect(readFileSync(sb.log, 'utf-8')).toContain('npx')
  })

  it('without coreutils timeout the plain-shell watchdog still bounds the probe', async () => {
    const sb = sandbox({ local: 'sleep 30' })
    const tools = join(sb.root, 'tools')
    mkdirSync(tools)
    for (const t of ['sh', 'cat', 'sed', 'head', 'date', 'mktemp', 'rm', 'sleep', 'grep']) {
      for (const dir of ['/usr/bin', '/bin']) {
        if (existsSync(join(dir, t))) {
          symlinkSync(join(dir, t), join(tools, t))
          break
        }
      }
    }
    const r = await runScript(sb, claudeShimScript(), push(), { path: tools })
    expect(r.code).toBe(2)
    expect(r.ms).toBeLessThan(15_000)
    expect(lastLine(r.stderr)).toContain('code=GATE_STARTUP_STALLED')
  })

  it('the deadline covers the whole shim: a gate that runs past it is stopped and blocks with GATE_TIMEOUT', async () => {
    const sb = sandbox({ shipguard: 'if [ "$2" = --supports ]; then exit 0; fi; sleep 30; exit 0' })
    // the same text, a 2 s clock instead of 150 s
    const script = claudeShimScript().replace('DEADLINE=150', 'DEADLINE=2')
    const r = await runScript(sb, script, push('git push origin main'))
    expect(r.code).toBe(2)
    expect(r.ms).toBeLessThan(12_000)
    expect(r.stderr).toContain('This is not a finding.')
    expect(r.stderr).toContain('raise gate.timeoutSeconds in shipguard.policy.yml')
    expect(lastLine(r.stderr)).toBe('shipguard-gate: code=GATE_TIMEOUT agentAction=fix_and_rerun run=none rerun="shipguard scan --strict"')
  })

  it('a pass is never reported when the deadline has passed (no exit 0 from a stopped step)', async () => {
    const sb = sandbox({ shipguard: 'if [ "$2" = --supports ]; then exit 0; fi; sleep 30; exit 0' })
    const r = await runScript(sb, claudeShimScript().replace('DEADLINE=150', 'DEADLINE=2'), push())
    expect(r.code).not.toBe(0)
  })
})

describe('git shim: exit 1 on a block, same texts', () => {
  it('nothing installed: exit 1 with GATE_NOT_STARTED and the git removal line', async () => {
    const sb = sandbox()
    const r = await runScript(sb, gitHookScript('pre-push'), 'refs/heads/main abc refs/heads/main 000\n')
    expect(r.code).toBe(1)
    expect(r.stderr).toContain('SHIPGUARD BLOCKED: `git push` did not run.')
    expect(r.stderr).toContain('delete the block between the two "shipguard managed block" lines')
    expect(lastLine(r.stderr)).toContain('code=GATE_NOT_STARTED')
  })

  it('pre-merge-commit names git merge and passes the hook name to the gate', async () => {
    const sb = sandbox({ shipguard: 'if [ "$2" = --supports ]; then exit 0; fi; echo "$@" > "$LOG"; exit 0' })
    const r = await runScript(sb, gitHookScript('pre-merge-commit'), '', { env: { LOG: sb.log } })
    expect(r.code).toBe(0)
    expect(readFileSync(sb.log, 'utf-8').trim()).toBe('gate --host git --hook pre-merge-commit')
    const none = await runScript(sandbox(), gitHookScript('pre-merge-commit'), '')
    expect(none.stderr).toContain('`git merge` did not run')
  })

  it('a gate block (exit 1) stays exit 1; the refs git sends reach the gate on stdin', async () => {
    const sb = sandbox({ shipguard: 'if [ "$2" = --supports ]; then exit 0; fi; cat > "$LOG"; echo BLOCK >&2; exit 1' })
    const refs = 'refs/heads/main 1111111111111111111111111111111111111111 refs/heads/main 0000000000000000000000000000000000000000\n'
    const r = await runScript(sb, gitHookScript('pre-push'), refs, { env: { LOG: sb.log } })
    expect(r.code).toBe(1)
    expect(readFileSync(sb.log, 'utf-8')).toBe(refs)
  })
})
