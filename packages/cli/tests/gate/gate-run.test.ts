/**
 * `shipguard gate` end to end through runGate(): real git repos and worktrees, the real commit
 * extraction, a scan stand-in that reads the extracted tree. (spec 03; plan W3 acceptance tests)
 *
 *  - worktree push scans the worktree, not main (the false-SAFE regression, owner decision A1);
 *  - deadline: a slow or late scan fails closed inside the deadline, never passes;
 *  - machine line format; loop-stop on rule + file; host kill leaves a `running` record;
 *  - no plan line except the weekly clean-pass line; the gate never fetches.
 */
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { runGate } from '../../src/commands/gate.js'
import { readGateRecord } from '../../src/core/gate-state.js'
import {
  SECRET_MARKER,
  addWorktree,
  claudeInput,
  cleanup,
  commitFile,
  fakeScan,
  git,
  mkDeps,
  mkRepo,
} from './gate-fixtures.js'

afterEach(cleanup)

const lastLine = (text: string): string => text.trimEnd().split('\n').pop() ?? ''
const MACHINE = /^shipguard-gate: code=[A-Z_]+ agentAction=(proceed|fix_and_rerun|retry|ask_human|stop) run=([0-9a-f]{8}|none)( rerun=".*")?$/

describe('A1: the gate scans the directory the command targets, not the hook cwd', () => {
  function setup() {
    const main = mkRepo()
    const wt = addWorktree(main, 'wt', 'feature')
    const bad = commitFile(wt, 'lib/stripe.ts', `const k = "${SECRET_MARKER}"\n`, 'add key')
    return { main, wt, bad, mainSha: git(main, 'rev-parse', 'HEAD') }
  }

  for (const command of ['cd ../wt && git push origin feature', 'git -C ../wt push origin feature', 'cd ../wt && git push']) {
    it(`${command}: blocks on the worktree commit while main is clean (false SAFE if the hook cwd were scanned)`, async () => {
      const { main, wt, bad, mainSha } = setup()
      const seen: string[] = []
      const { deps, out } = mkDeps(main, claudeInput(command, main), { runScan: fakeScan({ seen }) })
      const code = await runGate({ host: 'claude' }, deps)
      expect(code).toBe(2)
      expect(out.stdout).toBe('')
      expect(out.stderr).toContain('SHIPGUARD BLOCKED:')
      expect(out.stderr).toContain(`Checked: ${wt} @ ${bad.slice(0, 7)}`)
      expect(out.stderr).not.toContain(mainSha.slice(0, 7))
      expect(out.stderr).toContain('lib/stripe.ts:2')
      // The scan ran on an extraction of that commit, not on either checkout.
      expect(seen).toHaveLength(1)
      expect(seen[0]).not.toBe(main)
      expect(seen[0]).not.toBe(wt)
    })
  }

  it('the same push from main itself (clean commit) passes: the directory decides, not luck', async () => {
    const { main } = setup()
    const { deps, out } = mkDeps(main, claudeInput('git push origin main', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(0)
    const json = JSON.parse(out.stdout)
    expect(json.hookSpecificOutput.hookEventName).toBe('PreToolUse')
    expect(json.hookSpecificOutput.additionalContext).toContain('Verdict: SAFE TO SHIP')
  })

  it('an unreadable target directory blocks with NOT_A_PROJECT and scans nothing', async () => {
    const { main } = setup()
    let scanned = 0
    const runScan = async () => { scanned++; return fakeScan()({ dir: main, budgetMs: 1, host: 'claude' }) }
    for (const command of ['cd /does/not/exist && git push', 'cd "$WT" && git push', 'git -C /does/not/exist push']) {
      const { deps, out } = mkDeps(main, claudeInput(command, main), { runScan })
      expect(await runGate({ host: 'claude' }, deps), command).toBe(2)
      expect(out.stderr, command).toContain('code=NOT_A_PROJECT')
      expect(out.stderr, command).toContain('did not run')
    }
    expect(scanned).toBe(0)
  })

  it('a folder that is not a git repository blocks with NOT_A_PROJECT', async () => {
    const { main } = setup()
    const { deps, out } = mkDeps(main, claudeInput('cd /tmp && git push', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(out.stderr).toContain('code=NOT_A_PROJECT')
  })
})

describe('what is checked: the commit the command names, never the working tree', () => {
  it('git push <ref> scans that ref, not HEAD', async () => {
    const main = mkRepo()
    git(main, 'branch', 'clean-branch')
    commitFile(main, 'a.env.ts', `x = "${SECRET_MARKER}"\n`, 'oops on main')
    const { deps, out } = mkDeps(main, claudeInput('git push origin clean-branch', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(0)
    expect(out.stdout).toContain('Checked:')
  })

  it('git merge <ref> checks the incoming commit only and says the merged result is not checked', async () => {
    const main = mkRepo()
    git(main, 'checkout', '-q', '-b', 'incoming')
    const bad = commitFile(main, 'x.ts', `s = "${SECRET_MARKER}"\n`)
    git(main, 'checkout', '-q', 'main')
    const { deps, out } = mkDeps(main, claudeInput('git merge incoming', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(out.stderr).toContain('git merge incoming')
    expect(out.stderr).toContain(`@ ${bad.slice(0, 7)}`)
    expect(out.stderr).toContain('Not checked: the merged result.')
  })

  it('a PR merge checks local HEAD and says what it did not check', async () => {
    const main = mkRepo()
    const { deps, out } = mkDeps(main, claudeInput('gh pr merge 12 --squash', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(0)
    const ctx = JSON.parse(out.stdout).hookSpecificOutput.additionalContext as string
    expect(ctx).toContain('NOT checked: the PR head on GitHub or the merged result')
    expect(ctx).toContain('Merge command allowed')
  })

  it('uncommitted changes are named and are not scanned; a clean tree says so', async () => {
    const main = mkRepo()
    writeFileSync(join(main, 'src', 'a.ts'), `edited ${SECRET_MARKER}\n`)
    const { deps, out } = mkDeps(main, claudeInput('git push', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(0)
    const ctx = JSON.parse(out.stdout).hookSpecificOutput.additionalContext as string
    expect(ctx).toContain('Working tree: 1 file changed, not committed. They are not pushed and were not checked.')
    git(main, 'checkout', '--', 'src/a.ts')
    const again = mkDeps(main, claudeInput('git push', main))
    await runGate({ host: 'claude' }, again.deps)
    expect(JSON.parse(again.out.stdout).hookSpecificOutput.additionalContext).toContain('Working tree: clean')
  })

  it('a block names the uncommitted file whose fix is not pushed yet', async () => {
    const main = mkRepo()
    commitFile(main, 'lib/stripe.ts', `k = "${SECRET_MARKER}"\n`)
    writeFileSync(join(main, 'lib', 'stripe.ts'), 'fixed but not committed\n')
    const { deps, out } = mkDeps(main, claudeInput('git push', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(out.stderr).toContain('Working tree: 1 file changed, not committed (lib/stripe.ts): a fix there is not pushed until you commit it.')
  })

  it('a ref that cannot be read with a dirty tree blocks with UNCOMMITTED_CHANGES; with a clean tree HEAD is used', async () => {
    const main = mkRepo()
    writeFileSync(join(main, 'src', 'a.ts'), 'dirty\n')
    const dirty = mkDeps(main, claudeInput('git push origin no-such-ref', main))
    expect(await runGate({ host: 'claude' }, dirty.deps)).toBe(2)
    expect(dirty.out.stderr).toContain('code=UNCOMMITTED_CHANGES')
    git(main, 'checkout', '--', 'src/a.ts')
    const clean = mkDeps(main, claudeInput('git push origin no-such-ref', main))
    expect(await runGate({ host: 'claude' }, clean.deps)).toBe(0)
  })

  it('a committed file marked export-ignore is still scanned (git archive would hide it)', async () => {
    const main = mkRepo({ 'package.json': '{}', '.gitattributes': 'hidden.txt export-ignore\n', 'hidden.txt': `s = ${SECRET_MARKER}\n` })
    const { deps, out } = mkDeps(main, claudeInput('git push', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(out.stderr).toContain('hidden.txt')
  })

  it('a push that only deletes a branch sends no commit: silent', async () => {
    const main = mkRepo()
    const { deps, out } = mkDeps(main, claudeInput('git push origin :old-branch', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(0)
    expect(out.stdout + out.stderr).toBe('')
  })

  it('commands that are not gated stay silent and never run a scan', async () => {
    const main = mkRepo()
    let scanned = 0
    const { deps, out } = mkDeps(main, claudeInput('git status', main), { runScan: async () => { scanned++; throw new Error('no') } })
    expect(await runGate({ host: 'claude' }, deps)).toBe(0)
    expect(out.stdout + out.stderr).toBe('')
    expect(scanned).toBe(0)
    expect(readGateRecord(main)).toBeNull()
  })

  it('git host (pre-push): the refs git sends on stdin are the commits that are scanned', async () => {
    const main = mkRepo()
    const first = git(main, 'rev-parse', 'HEAD')
    commitFile(main, 'x.ts', `s = "${SECRET_MARKER}"\n`)
    const stdin = `refs/heads/main ${first} refs/heads/main 0000000000000000000000000000000000000000\n`
    const { deps, out } = mkDeps(main, stdin)
    expect(await runGate({ host: 'git', hook: 'pre-push' }, deps)).toBe(0)
    expect(out.stderr).toContain(`@ ${first.slice(0, 7)}`)
    const bad = git(main, 'rev-parse', 'HEAD')
    const bad2 = mkDeps(main, `refs/heads/main ${bad} refs/heads/main ${first}\n`)
    expect(await runGate({ host: 'git', hook: 'pre-push' }, bad2.deps)).toBe(1)
    expect(bad2.out.stderr).toContain('SHIPGUARD BLOCKED:')
  })

  it('git host: a pre-push that only deletes refs is silent', async () => {
    const main = mkRepo()
    const { deps, out } = mkDeps(main, `(delete) ${'0'.repeat(40)} refs/heads/old ${git(main, 'rev-parse', 'HEAD')}\n`)
    expect(await runGate({ host: 'git', hook: 'pre-push' }, deps)).toBe(0)
    expect(out.stdout + out.stderr).toBe('')
  })
})

describe('exit codes and channels', () => {
  it('claude: block = exit 2 + stderr only; pass = exit 0 + ONE JSON object on stdout and nothing on stderr', async () => {
    const main = mkRepo()
    const pass = mkDeps(main, claudeInput('git push', main))
    expect(await runGate({ host: 'claude' }, pass.deps)).toBe(0)
    expect(pass.out.stderr).toBe('')
    const json = JSON.parse(pass.out.stdout)
    expect(Object.keys(json).sort()).toEqual(['hookSpecificOutput', 'systemMessage'])
    expect(json.systemMessage).toContain('SAFE TO SHIP')
    expect(json.systemMessage).toContain('not a security audit')
    expect(json.hookSpecificOutput).not.toHaveProperty('permissionDecision')

    commitFile(main, 'x.ts', `s = "${SECRET_MARKER}"\n`)
    const block = mkDeps(main, claudeInput('git push', main))
    expect(await runGate({ host: 'claude' }, block.deps)).toBe(2)
    expect(block.out.stdout).toBe('')
  })

  it('git, ci, codex and cursor: block = exit 1 + stderr; pass = exit 0 + stderr', async () => {
    const main = mkRepo()
    for (const host of ['git', 'ci', 'codex', 'cursor']) {
      const ok = mkDeps(main, '')
      expect(await runGate({ host }, ok.deps), host).toBe(0)
      expect(ok.out.stdout, host).toBe('')
      expect(ok.out.stderr, host).toContain('Verdict: SAFE TO SHIP')
    }
    commitFile(main, 'x.ts', `s = "${SECRET_MARKER}"\n`)
    for (const host of ['git', 'ci', 'codex', 'cursor']) {
      const bad = mkDeps(main, '')
      expect(await runGate({ host }, bad.deps), host).toBe(1)
      expect(bad.out.stderr, host).toContain('SHIPGUARD BLOCKED:')
    }
  })

  it('an unknown or missing host is a block with a text, never a crash', async () => {
    const main = mkRepo()
    for (const host of [undefined, 'jenkins']) {
      const { deps, out } = mkDeps(main, '')
      expect(await runGate({ host }, deps)).toBe(2)
      expect(out.stderr).toContain('code=UNKNOWN_OPTION')
    }
  })

  it('--supports answers 0 and prints nothing', async () => {
    const { deps, out } = mkDeps('/', '')
    expect(await runGate({ supports: true }, deps)).toBe(0)
    expect(out.stdout + out.stderr).toBe('')
  })

  it('an unexpected error is a block, never a pass', async () => {
    const main = mkRepo()
    const { deps, out } = mkDeps(main, claudeInput('git push', main), { extractCommit: () => { throw new Error('boom') } })
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(out.stderr).toContain('SHIPGUARD BLOCKED')
    expect(out.stderr).toContain('code=INTERNAL_ERROR')
  })
})

describe('machine line: every text ends with ONE fixed last line', () => {
  it('format on every outcome', async () => {
    const main = mkRepo()
    const texts: string[] = []
    const pass = mkDeps(main, claudeInput('git push', main))
    await runGate({ host: 'claude' }, pass.deps)
    texts.push(JSON.parse(pass.out.stdout).hookSpecificOutput.additionalContext)

    const nonBlocking = mkDeps(main, claudeInput('git push', main), { runScan: fakeScan({ nonBlocking: 2 }) })
    await runGate({ host: 'claude' }, nonBlocking.deps)
    texts.push(JSON.parse(nonBlocking.out.stdout).hookSpecificOutput.additionalContext)

    mkdirSync(join(main, 'lib'), { recursive: true })
    commitFile(main, 'lib/stripe.ts', `k = "${SECRET_MARKER}"\n`)
    const bad = mkDeps(main, claudeInput('git push', main))
    await runGate({ host: 'claude' }, bad.deps)
    texts.push(bad.out.stderr)

    writeFileSync(join(main, 'shipguard.policy.yml'), 'ignore: [oops\n')
    git(main, 'add', '-A'); git(main, 'commit', '-q', '-m', 'bad policy')
    const policy = mkDeps(main, claudeInput('git push', main))
    await runGate({ host: 'claude' }, policy.deps)
    texts.push(policy.out.stderr)

    for (const t of texts) expect(lastLine(t), t).toMatch(MACHINE)
    expect(lastLine(texts[0])).toBe('shipguard-gate: code=SAFE_TO_SHIP agentAction=proceed run=247f9045')
    expect(lastLine(texts[1])).toBe('shipguard-gate: code=REVIEW_BEFORE_SHIP agentAction=proceed run=247f9045')
    expect(lastLine(texts[2])).toBe('shipguard-gate: code=BLOCKING_FINDINGS agentAction=fix_and_rerun run=247f9045 rerun="shipguard scan --strict"')
    expect(lastLine(texts[3])).toBe('shipguard-gate: code=INVALID_POLICY agentAction=fix_and_rerun run=none')
  })

  it('the rerun value is ONE JSON string: a target with spaces and quotes round-trips', async () => {
    const main = mkRepo()
    const wt = addWorktree(main, 'my "app"', 'q')
    commitFile(wt, 'x.ts', `k = "${SECRET_MARKER}"\n`)
    const { deps, out } = mkDeps(main, claudeInput(`git -C '../my "app"' push`, main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    const line = lastLine(out.stderr)
    expect(line).toMatch(MACHINE)
    const decoded = JSON.parse(line.slice(line.indexOf(' rerun=') + ' rerun='.length)) as string
    expect(decoded).toBe(`shipguard scan '../my "app"' --strict`)
  })
})

describe('the block text', () => {
  it('names verdict, what was and was not done, the checked commit, the top fixes and the way forward (about 20 lines)', async () => {
    const main = mkRepo()
    commitFile(main, 'lib/stripe.ts', `k = "${SECRET_MARKER}"\n`)
    const { deps, out } = mkDeps(main, claudeInput('git push origin main', main))
    await runGate({ host: 'claude' }, deps)
    const t = out.stderr
    expect(t.split('\n')[0]).toMatch(/^SHIPGUARD BLOCKED: `git push origin main` did not run\. DO NOT SHIP: 1 blocking finding in \d+ files\.$/)
    expect(t).toContain('Nothing was pushed. Do not retry with --no-verify or another route; fix, commit, then push again.')
    expect(t).toContain('Fix these 1 (')
    expect(t).toMatch(/ 1\. CRITICAL {1}lib\/stripe\.ts:2 {2}live Stripe secret key in source/)
    expect(t).toContain('    fix: Rotate it first, then read the new one from process.env.STRIPE_SECRET_KEY.')
    expect(t).toContain('Check: shipguard scan --strict')
    expect(t).toContain('If a finding is wrong for this repo: shipguard ignore <finding-id> --file <path> --reason "<why>"')
    expect(t).toContain('Ask the user before ignoring a critical finding.')
    expect(t.split('\n').length).toBeLessThanOrEqual(24)
    expect(t.length).toBeLessThan(2500)
  })

  it('more than 3 blockers: the top 3 are shown, then a count', async () => {
    const main = mkRepo()
    const many = fakeScan()
    const runScan: typeof many = async (o) => {
      const r = await many(o)
      const j = JSON.parse(r.stdout)
      j.findings = Array.from({ length: 5 }, (_, i) => ({ id: `r${i}`, title: `t${i}`, severity: 'high', file: `f${i}.ts`, line: 1, blocking: true }))
      return { ...r, exitCode: 1, stdout: JSON.stringify({ ...j, recommendation: 'DO_NOT_SHIP' }) }
    }
    const { deps, out } = mkDeps(main, claudeInput('git push', main), { runScan })
    await runGate({ host: 'claude' }, deps)
    expect(out.stderr).toContain('Fix these 3 first')
    expect(out.stderr).toContain('+2 more blocking: see the report')
    expect(out.stderr).toContain('5 blocking findings')
  })

  it('an incomplete scan is a coverage stop, not a finding: files named, ask the user', async () => {
    const main = mkRepo()
    const runScan = async () => ({
      exitCode: 1,
      timedOut: false,
      stderrTail: '',
      stdout: JSON.stringify({
        recommendation: 'DO_NOT_SHIP',
        degraded: true,
        filesScanned: 10,
        runId: '651c826a-0000-0000-0000-000000000000',
        findings: [],
        coverage: { discovered: 12, scanned: 10, files: { tooLarge: ['data-dump.txt'], unknownBinary: ['mystery.dat'] } },
        degradedReasons: [{ code: 'FILE_TOO_LARGE', detail: 'x' }, { code: 'UNSCANNED_UNKNOWN_BINARY', detail: 'y' }],
      }),
    })
    const { deps, out } = mkDeps(main, claudeInput('git push origin main', main), { runScan })
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    const t = out.stderr
    expect(t.split('\n')[0]).toBe('SHIPGUARD BLOCKED: `git push origin main` did not run. The scan is incomplete: 2 of 12 files were not scanned (0 findings in the other 10).')
    expect(t).toContain('This is a coverage stop, not a finding. Nothing was pushed.')
    expect(t).toContain(' - data-dump.txt  too large')
    expect(t).toContain(' - mystery.dat  binary data, unknown format')
    expect(t).toContain('Ask the user before excluding any unscanned file')
    expect(lastLine(t)).toBe('shipguard-gate: code=INCOMPLETE_SCAN agentAction=ask_human run=651c826a rerun="shipguard scan --strict"')
  })
})

describe('loop-stop: rule id + file, three runs in a row ask the human', () => {
  it('first block fixes and re-runs; second shows the repeat string; third asks the human; a changed line does not reset it', async () => {
    const main = mkRepo()
    commitFile(main, 'lib/stripe.ts', `k = "${SECRET_MARKER}"\n`)
    const run = async (line: number) => {
      const { deps, out } = mkDeps(main, claudeInput('git push', main), { runScan: fakeScan({ line }) })
      expect(await runGate({ host: 'claude' }, deps)).toBe(2)
      return out.stderr
    }
    const one = await run(2)
    expect(lastLine(one)).toContain('agentAction=fix_and_rerun')
    expect(one).not.toContain('Same blocking result')

    const two = await run(2)
    expect(two).toContain('Same blocking result on the same commit. If you changed a file, commit it, then push.')
    expect(lastLine(two)).toContain('agentAction=fix_and_rerun')

    const three = await run(77)
    expect(three).toContain('Repeated blocking result. Stop and ask the user; do not ignore or bypass it (shipguard ignore, --no-verify) on your own.')
    expect(lastLine(three)).toContain('agentAction=ask_human')
  })

  it('after a new commit the repeat string asks to re-read the Verify step; a clean pass clears the count', async () => {
    const main = mkRepo()
    commitFile(main, 'lib/stripe.ts', `k = "${SECRET_MARKER}"\n`)
    const first = mkDeps(main, claudeInput('git push', main))
    await runGate({ host: 'claude' }, first.deps)
    commitFile(main, 'other.ts', 'unrelated\n', 'another commit')
    const second = mkDeps(main, claudeInput('git push', main))
    await runGate({ host: 'claude' }, second.deps)
    expect(second.out.stderr).toContain('Same blocking result. Re-read the Verify step of this finding in the report')

    commitFile(main, 'lib/stripe.ts', 'fixed\n', 'fix')
    const ok = mkDeps(main, claudeInput('git push', main))
    expect(await runGate({ host: 'claude' }, ok.deps)).toBe(0)
    expect(readGateRecord(main)?.status).toBe('passed')
    expect(readGateRecord(main)?.blocking).toEqual({})
  })
})

describe('deadline: one clock, fail closed, never a pass', () => {
  it('a scan that is still running at the deadline is killed and the gate blocks with GATE_TIMEOUT', async () => {
    const main = mkRepo()
    const budgets: number[] = []
    const runScan = async ({ budgetMs }: { budgetMs: number }) => {
      budgets.push(budgetMs)
      return { exitCode: null, stdout: '', timedOut: true, stderrTail: '' }
    }
    const { deps, out } = mkDeps(main, claudeInput('git push origin main', main), { runScan })
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(out.stderr).toContain('The gate did not finish inside its 150 s deadline (startup checks, download and scan), so nothing was cleared. This is not a finding.')
    expect(lastLine(out.stderr)).toBe('shipguard-gate: code=GATE_TIMEOUT agentAction=fix_and_rerun run=none rerun="shipguard scan --strict"')
    expect(budgets[0]).toBeLessThanOrEqual(120_000)
    expect(readGateRecord(main)?.status).toBe('timeout')
  })

  it('startup steps that already used the deadline leave no budget: no scan is started', async () => {
    const main = mkRepo()
    let scanned = 0
    const startedAgo = Math.floor(Date.now() / 1000) - 160
    const { deps, out } = mkDeps(
      main,
      claudeInput('git push', main),
      { runScan: async () => { scanned++; throw new Error('must not run') } },
      { SHIPGUARD_GATE_START: String(startedAgo), SHIPGUARD_HOST_TIMEOUT: '180' },
    )
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(scanned).toBe(0)
    expect(out.stderr).toContain('code=GATE_TIMEOUT')
  })

  it('the scan budget is the smaller of gate.timeoutSeconds and what is left of the deadline', async () => {
    const main = mkRepo()
    const startedAgo = Math.floor(Date.now() / 1000) - 100
    const budgets: number[] = []
    const { deps } = mkDeps(
      main,
      claudeInput('git push', main),
      { runScan: async (o) => { budgets.push(o.budgetMs); return fakeScan()(o) } },
      { SHIPGUARD_GATE_START: String(startedAgo), SHIPGUARD_HOST_TIMEOUT: '180' },
    )
    await runGate({ host: 'claude' }, deps)
    expect(budgets[0]).toBeGreaterThan(40_000)
    expect(budgets[0]).toBeLessThanOrEqual(50_000)
  })

  it('gate.timeoutSeconds longer than the hook allows blocks before any scan (GATE_CONFIG_INVALID)', async () => {
    const main = mkRepo({ 'package.json': '{}', 'shipguard.policy.yml': 'version: 1\ngate:\n  timeoutSeconds: 300\n' })
    let scanned = 0
    const { deps, out } = mkDeps(main, claudeInput('git push origin main', main), { runScan: async () => { scanned++; throw new Error('no') } })
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(scanned).toBe(0)
    expect(out.stderr).toContain('gate.timeoutSeconds is 300 s, but the hook is stopped at 180 s')
    expect(lastLine(out.stderr)).toBe('shipguard-gate: code=GATE_CONFIG_INVALID agentAction=ask_human run=none')
  })

  it('a broken policy file blocks with its line and a plain cause, nothing scanned', async () => {
    const main = mkRepo({ 'package.json': '{}', 'shipguard.policy.yml': 'version: 1\nignore: [oops\n' })
    const { deps, out } = mkDeps(main, claudeInput('git push origin main', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(out.stderr).toMatch(/shipguard\.policy\.yml could not be read \(line \d+\), so nothing was scanned\./)
    expect(out.stderr).toContain('Cause:')
    expect(out.stderr).not.toMatch(/YAMLParseError|Flow sequence/)
  })
})

describe('a host kill leaves the proof', () => {
  it('the running record exists before the scan, and a scan that never returns leaves it as `running`', async () => {
    const main = mkRepo()
    let during: string | undefined
    const runScan = async () => {
      during = readGateRecord(main)?.status
      throw new Error('host killed us')
    }
    const { deps } = mkDeps(main, claudeInput('git push origin main', main), { runScan })
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(during).toBe('running')
    const rec = readGateRecord(main)
    expect(rec?.status).toBe('running')
    expect(rec?.command).toBe('git push origin main')
    expect(typeof rec?.startedAt).toBe('string')
  })

  it('the next gate run reports the unfinished one, once it is older than a live gate can be', async () => {
    const main = mkRepo()
    const old = new Date(Date.now() - 600_000).toISOString()
    mkdirSync(join(main, '.shipguard'), { recursive: true })
    writeFileSync(
      join(main, '.shipguard', 'gate-last.json'),
      JSON.stringify({ schema: 1, status: 'running', host: 'claude', command: 'git push origin main', startedAt: old }),
    )
    const { deps, out } = mkDeps(main, claudeInput('git push', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(0)
    const ctx = JSON.parse(out.stdout).hookSpecificOutput.additionalContext as string
    expect(ctx).toContain('WARNING: the last gate check (git push origin main')
    expect(ctx).toContain('never finished')
    expect(readGateRecord(main)?.status).toBe('passed')
  })

  it('the finished record carries what ignore and status need: findings, run id, ignores used, rules fallback', async () => {
    const main = mkRepo()
    commitFile(main, 'lib/stripe.ts', `k = "${SECRET_MARKER}"\n`)
    const { deps } = mkDeps(main, claudeInput('git push', main), { runScan: fakeScan({ extra: { rules: { corpus: 'general', fallback: { code: 'RULEBOOK_UNREACHABLE' } } } }) })
    await runGate({ host: 'claude' }, deps)
    const rec = readGateRecord(main)
    expect(rec?.status).toBe('blocked')
    expect(rec?.code).toBe('BLOCKING_FINDINGS')
    expect(rec?.run).toBe('247f9045')
    expect(rec?.findings?.[0]).toMatchObject({ id: 'generic.secrets.stripe-live-key', severity: 'critical', file: 'lib/stripe.ts' })
    expect(rec?.rules?.fallback?.code).toBe('RULEBOOK_UNREACHABLE')
  })
})

describe('plan lines: the gate prints at most the weekly "Not run here" line on a clean pass', () => {
  const GAP = 'Not run here (checks, not problems found): Supabase row-level security. Pro adds more rules for Next.js + Supabase; the general-rule results above stay as they are.'

  it('printed at the end of a clean pass (SAFE and REVIEW), before the machine line', async () => {
    const main = mkRepo()
    for (const nonBlocking of [0, 2]) {
      const { deps, out } = mkDeps(main, claudeInput('git push', main), { gapLine: () => GAP, runScan: fakeScan({ nonBlocking }) })
      expect(await runGate({ host: 'claude' }, deps)).toBe(0)
      const lines = (JSON.parse(out.stdout).hookSpecificOutput.additionalContext as string).split('\n')
      expect(lines.at(-2)).toBe(GAP)
      expect(MACHINE.test(lines.at(-1) ?? '')).toBe(true)
    }
  })

  it('never on a block, in CI, in safe mode, with the promotion mute, or on an incomplete scan', async () => {
    const main = mkRepo()
    const gap = () => GAP
    const asked: string[] = []
    const counting = () => { asked.push('x'); return GAP }
    const ci = mkDeps(main, '', { gapLine: counting })
    await runGate({ host: 'ci' }, ci.deps)
    expect(ci.out.stderr).not.toContain('Not run here')

    const safe = mkDeps(main, claudeInput('git push', main), { gapLine: counting, isSafeMode: () => true })
    await runGate({ host: 'claude' }, safe.deps)
    expect(safe.out.stdout).not.toContain('Not run here')

    const muted = mkDeps(main, claudeInput('git push', main), { gapLine: counting }, { SHIPGUARD_NO_PROMO: '1' })
    await runGate({ host: 'claude' }, muted.deps)
    expect(muted.out.stdout).not.toContain('Not run here')
    expect(asked).toEqual([])

    commitFile(main, 'x.ts', `k = "${SECRET_MARKER}"\n`)
    const bad = mkDeps(main, claudeInput('git push', main), { gapLine: gap })
    await runGate({ host: 'claude' }, bad.deps)
    expect(bad.out.stderr).not.toContain('Not run here')
  })

  it('a block carries no plan line at all: no usage, update notice, offer, pointer or coverage line', async () => {
    const main = mkRepo()
    commitFile(main, 'x.ts', `k = "${SECRET_MARKER}"\n`)
    const extra = { plan: { server: { usage: { state: 'warn', text: 'USAGE TEXT' }, offer: { text: 'OFFER TEXT' }, updateNotice: 'UPDATE TEXT' } } }
    const { deps, out } = mkDeps(main, claudeInput('git push', main), { runScan: fakeScan({ extra }) })
    await runGate({ host: 'claude' }, deps)
    for (const word of ['USAGE TEXT', 'OFFER TEXT', 'UPDATE TEXT', 'did not run here', 'shipguard upgrade', 'Pro ']) expect(out.stderr, word).not.toContain(word)
    // recorded in gate-last.json only
    expect(readGateRecord(main)?.plan?.server?.usage?.state).toBe('warn')
  })

  it('the rulebook fallback is one fixed line with a fixed reason, never server text; PLAN_INACTIVE is recorded only', async () => {
    const main = mkRepo()
    const cases: Array<[string, string | null]> = [
      ['RULEBOOK_UNREACHABLE', 'rulebook unreachable'],
      ['RULEBOOK_WITHHELD', 'rulebook withheld'],
      ['RULEBOOK_PARTIAL', 'rulebook partial'],
      ['PLAN_INACTIVE', null],
    ]
    for (const [code, phrase] of cases) {
      const { deps, out } = mkDeps(main, claudeInput('git push', main), {
        runScan: fakeScan({ extra: { rules: { corpus: 'general', fallback: { code, message: 'SERVER WORDS' } } } }),
      })
      await runGate({ host: 'claude' }, deps)
      const ctx = JSON.parse(out.stdout).hookSpecificOutput.additionalContext as string
      if (phrase) expect(ctx).toContain(`Rules: general only (${phrase}; not a full rulebook scan).`)
      else expect(ctx).not.toContain('Rules: general only')
      expect(ctx).not.toContain('SERVER WORDS')
      expect(lastLine(ctx)).toContain('agentAction=proceed')
    }
  })
})

describe('banned words and plan facts', () => {
  it('no text of the gate holds a banned word, a price or a count', async () => {
    const main = mkRepo()
    const texts: string[] = []
    const pass = mkDeps(main, claudeInput('git push', main))
    await runGate({ host: 'claude' }, pass.deps)
    texts.push(pass.out.stdout)
    commitFile(main, 'x.ts', `k = "${SECRET_MARKER}"\n`)
    const bad = mkDeps(main, claudeInput('git push', main))
    await runGate({ host: 'claude' }, bad.deps)
    texts.push(bad.out.stderr)
    for (const t of texts) {
      expect(t).not.toMatch(/release gate|\bcloud\b|our servers/i)
      expect(t).not.toMatch(/\$\d|per (month|year)|\d+ (scans|credits)/)
    }
  })
})

describe('review fixes: no false SAFE from a command form the parser does not know', () => {
  it('a bad cd followed by a launcher, a loop, an if or an eval blocks with NOT_A_PROJECT; the hook cwd is never scanned instead', async () => {
    const main = mkRepo()
    let scanned = 0
    const runScan = async () => { scanned++; return fakeScan()({ dir: main, budgetMs: 1, host: 'claude' }) }
    for (const command of [
      'cd "$BAD"; timeout 60 git push',
      'cd "$BAD" && xargs git push',
      'cd "$BAD" && stdbuf -o0 git push',
      'if cd "$BAD"; then git push; fi',
      'cd "$BAD"; for r in origin; do git push $r main; done',
      'cd "$BAD"; eval "git push origin main"',
    ]) {
      const { deps, out } = mkDeps(main, claudeInput(command, main), { runScan })
      expect(await runGate({ host: 'claude' }, deps), command).toBe(2)
      expect(out.stderr, command).toContain('code=NOT_A_PROJECT')
    }
    expect(scanned).toBe(0)
  })

  it('a good cd with the same forms scans the directory the cd names', async () => {
    const main = mkRepo()
    const wt = addWorktree(main, 'wt', 'feature')
    commitFile(wt, 'x.ts', `k = "${SECRET_MARKER}"\n`)
    for (const command of ['cd ../wt && timeout 60 git push', 'cd ../wt; xargs git push', 'if cd ../wt; then git push; fi', 'cd ../wt && eval "git push origin feature"']) {
      const { deps, out } = mkDeps(main, claudeInput(command, main))
      expect(await runGate({ host: 'claude' }, deps), command).toBe(2)
      expect(out.stderr, command).toContain(`Checked: ${wt} @`)
    }
  })

  it('push --all, --mirror and --tags check every pushed ref, not just HEAD', async () => {
    const main = mkRepo()
    git(main, 'checkout', '-q', '-b', 'other')
    commitFile(main, 'x.ts', `k = "${SECRET_MARKER}"\n`)
    git(main, 'checkout', '-q', 'main')
    git(main, 'tag', 'v1', 'other')
    for (const flag of ['--all', '--mirror', '--tags']) {
      const { deps, out } = mkDeps(main, claudeInput(`git push ${flag} origin`, main))
      expect(await runGate({ host: 'claude' }, deps), flag).toBe(2)
      expect(out.stderr, flag).toContain('x.ts')
    }
    // a clean repo passes with --all
    const clean = mkRepo()
    const ok = mkDeps(clean, claudeInput('git push --all', clean))
    expect(await runGate({ host: 'claude' }, ok.deps)).toBe(0)
  })

  it('more refs than the gate will list: it refuses instead of checking only some', async () => {
    const main = mkRepo()
    const { deps, out } = mkDeps(main, claudeInput('git push --all', main), { listRefCommits: () => null })
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(out.stderr).toContain('could not list and check them all')
    expect(out.stderr).toContain('push the branch you mean by name')
  })

  it('a working tree that git cannot report is unknown, never "clean"', async () => {
    const main = mkRepo()
    const pass = mkDeps(main, claudeInput('git push', main), { uncommittedFiles: () => null })
    expect(await runGate({ host: 'claude' }, pass.deps)).toBe(0)
    const ctx = JSON.parse(pass.out.stdout).hookSpecificOutput.additionalContext as string
    expect(ctx).toContain('Working tree: could not be read')
    expect(ctx).not.toContain('Working tree: clean')
    const unreadable = mkDeps(main, claudeInput('git push origin no-such-ref', main), { uncommittedFiles: () => null })
    expect(await runGate({ host: 'claude' }, unreadable.deps)).toBe(2)
    expect(unreadable.out.stderr).toContain('code=UNCOMMITTED_CHANGES')
  })
})

describe('hardening', () => {
  it('a committed .shipguard folder (a symlinked report file) cannot steer where the scan writes', async () => {
    const main = mkRepo()
    const victim = join(main, '..', 'victim.txt')
    writeFileSync(victim, 'untouched\n')
    mkdirSync(join(main, '.shipguard', 'reports'), { recursive: true })
    symlinkSync(victim, join(main, '.shipguard', 'reports', 'latest.md'))
    git(main, 'add', '-f', '-A')
    git(main, 'commit', '-q', '-m', 'hostile .shipguard')
    let existed: boolean | undefined
    const runScan = async (o: { dir: string; budgetMs: number; host: string }) => {
      existed = existsSync(join(o.dir, '.shipguard'))
      return fakeScan()(o)
    }
    const { deps } = mkDeps(main, claudeInput('git push', main), { runScan })
    expect(await runGate({ host: 'claude' }, deps)).toBe(0)
    expect(existed).toBe(false)
    expect(readFileSync(victim, 'utf-8')).toBe('untouched\n')
  })

  it('the extraction folder is removed after every run, pass or block', async () => {
    const main = mkRepo()
    const seen: string[] = []
    const { deps } = mkDeps(main, claudeInput('git push', main), { runScan: fakeScan({ seen }) })
    await runGate({ host: 'claude' }, deps)
    commitFile(main, 'x.ts', `k = "${SECRET_MARKER}"\n`)
    const second = mkDeps(main, claudeInput('git push', main), { runScan: fakeScan({ seen }) })
    await runGate({ host: 'claude' }, second.deps)
    expect(seen).toHaveLength(2)
    for (const dir of seen) expect(existsSync(dir)).toBe(false)
  })

  it('the git variables a hook exports do not redirect the gate to the hook repository', async () => {
    const main = mkRepo()
    const other = mkRepo({ 'package.json': '{"name":"other"}', 'o.ts': `x = "${SECRET_MARKER}"\n` })
    const before = { ...process.env }
    const expected = git(main, 'rev-parse', 'HEAD')
    process.env.GIT_DIR = join(other, '.git')
    process.env.GIT_INDEX_FILE = join(other, '.git', 'index')
    try {
      // Fresh import: GIT_ENV is built when the module loads.
      vi.resetModules()
      const scan = await import('../../src/core/gate-scan.js')
      expect(scan.repoTopLevel(main)).toBe(main)
      expect(scan.resolveCommit(main, 'HEAD')).toBe(expected)
    } finally {
      process.env = before
    }
  })

  it('an old hook script announces itself through its version (stale nudge at the top of the text)', async () => {
    const main = mkRepo()
    const { deps, out } = mkDeps(main, claudeInput('git push', main), {}, { SHIPGUARD_SHIM_VERSION: '1' })
    expect(await runGate({ host: 'claude' }, deps)).toBe(0)
    expect(JSON.parse(out.stdout).hookSpecificOutput.additionalContext.split('\n')[0]).toContain('your hook script is from an older ShipGuard')
  })
})

describe('the report', () => {
  it('is copied from the extraction into the repo and its path is printed', async () => {
    const main = mkRepo()
    commitFile(main, 'lib/stripe.ts', `k = "${SECRET_MARKER}"\n`)
    const scan = fakeScan()
    const runScan: typeof scan = async (o) => {
      mkdirSync(join(o.dir, '.shipguard', 'reports'), { recursive: true })
      writeFileSync(join(o.dir, '.shipguard', 'reports', 'latest.md'), '# report\n')
      return scan(o)
    }
    const { deps, out } = mkDeps(main, claudeInput('git push', main), { runScan })
    await runGate({ host: 'claude' }, deps)
    expect(out.stderr).toContain('all details: .shipguard/reports/latest.md, run 247f9045')
    expect(readFileSync(join(main, '.shipguard', 'reports', 'latest.md'), 'utf-8')).toBe('# report\n')
  })
})
