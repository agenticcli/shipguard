/**
 * The gate with the REAL scan: the built CLI is run as a child process on the extracted commit.
 * Proves the child wiring, the JSON reading against the real scan output, the report copy, and
 * that a policy `ignore` entry (written by `shipguard ignore`) turns a block into a pass.
 */
import { execSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { runGate, type GateDeps } from '../../src/commands/gate.js'
import { runScanChild } from '../../src/core/gate-scan.js'
import { runIgnore } from '../../src/commands/ignore.js'
import { claudeInput, cleanup, commitFile, git, mkDeps, mkRepo } from './gate-fixtures.js'

vi.setConfig({ testTimeout: 60_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

beforeAll(() => {
  if (!existsSync(distCli)) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
}, 240_000)
afterEach(cleanup)

const realScan: GateDeps['runScan'] = ({ dir, budgetMs, host, top, sha }) => runScanChild({ cliEntry: distCli, dir, budgetMs, host, top, sha })
// Split so this file does not itself hold a live-looking key.
const STRIPE = `sk_live_${'abcdefghijklmnopqrstuvwx1234567'}`

describe('gate with the real scan', () => {
  it('blocks a commit with a live key, names the file and the fix, copies the report; passes once it is fixed', async () => {
    const main = mkRepo()
    const bad = commitFile(main, 'lib/stripe.ts', `export const k = "${STRIPE}"\n`)
    const blocked = mkDeps(main, claudeInput('git push origin main', main), { runScan: realScan })
    expect(await runGate({ host: 'claude' }, blocked.deps)).toBe(2)
    const t = blocked.out.stderr
    expect(t).toContain(`@ ${bad.slice(0, 7)}`)
    expect(t).toContain('CRITICAL')
    expect(t).toContain('lib/stripe.ts:1')
    expect(t).not.toContain(STRIPE)
    expect(t).toMatch(/all details: \.shipguard\/reports\/latest\.md, run [0-9a-f]{8}/)
    expect(existsSync(join(main, '.shipguard', 'reports', 'latest.md'))).toBe(true)
    expect(t.trimEnd().split('\n').pop()).toMatch(/^shipguard-gate: code=BLOCKING_FINDINGS agentAction=fix_and_rerun run=[0-9a-f]{8} rerun=/)

    commitFile(main, 'lib/stripe.ts', 'export const k = process.env.STRIPE_SECRET_KEY\n', 'fix')
    const ok = mkDeps(main, claudeInput('git push origin main', main), { runScan: realScan })
    expect(await runGate({ host: 'claude' }, ok.deps)).toBe(0)
    expect(JSON.parse(ok.out.stdout).hookSpecificOutput.additionalContext).toContain('Verdict: SAFE TO SHIP')
  })

  it('an uncommitted fix is not a fix: the scan still sees the commit', async () => {
    const main = mkRepo()
    commitFile(main, 'lib/stripe.ts', `export const k = "${STRIPE}"\n`)
    writeFileSync(join(main, 'lib', 'stripe.ts'), 'export const k = process.env.STRIPE_SECRET_KEY\n')
    const { deps, out } = mkDeps(main, claudeInput('git push', main), { runScan: realScan })
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(out.stderr).toContain('not committed (lib/stripe.ts)')
  })

  it('shipguard ignore with a reason lets the next gate pass; the reason is in the policy file', async () => {
    const main = mkRepo()
    commitFile(main, 'lib/stripe.ts', `export const k = "${STRIPE}"\n`)
    const first = mkDeps(main, claudeInput('git push', main), { runScan: realScan })
    expect(await runGate({ host: 'claude' }, first.deps)).toBe(2)

    // The agent has no terminal: a critical finding is refused.
    const say: string[] = []
    const refused = await runIgnore('generic.secrets.stripe-live-key', { file: 'lib/stripe.ts', reason: 'test key' }, {
      cwd: main, isTerminal: () => false, confirm: async () => true, now: () => new Date('2026-11-21T10:00:00Z'), say: (l) => say.push(l),
    })
    expect(refused.exitCode).toBe(2)
    expect(say.join('\n')).toContain('CONFIRMATION_REQUIRED')

    // A person at a terminal confirms.
    const done = await runIgnore('generic.secrets.stripe-live-key', { file: 'lib/stripe.ts', reason: 'documented placeholder, checked with the user' }, {
      cwd: main, isTerminal: () => true, confirm: async () => true, now: () => new Date('2026-11-21T10:00:00Z'), say: () => undefined,
    })
    expect(done.exitCode).toBe(0)
    git(main, 'add', '-A')
    git(main, 'commit', '-q', '-m', 'ignore with a reason')
    const policy = readFileSync(join(main, 'shipguard.policy.yml'), 'utf-8')
    expect(policy).toContain('documented placeholder, checked with the user')

    const second = mkDeps(main, claudeInput('git push', main), { runScan: realScan })
    expect(await runGate({ host: 'claude' }, second.deps)).toBe(0)
    expect(readGateIgnores(main)).toEqual([{ id: 'generic.secrets.stripe-live-key', file: 'lib/stripe.ts' }])
  })
})

function readGateIgnores(dir: string): unknown {
  return (JSON.parse(readFileSync(join(dir, '.shipguard', 'gate-last.json'), 'utf-8')) as { ignoresUsed?: unknown }).ignoresUsed
}
