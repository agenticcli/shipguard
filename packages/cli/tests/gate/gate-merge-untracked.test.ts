/**
 * E2E block-1 fixes E-04 and E-16 (2026-11-22).
 *
 * E-04: the git pre-merge-commit hook blocked EVERY `git merge` (UNCOMMITTED_CHANGES). Git writes
 * MERGE_HEAD only AFTER that hook runs, so the incoming commit cannot be read there, and the merge
 * result is staged by design. The gate now checks the staged merge result (`git write-tree`).
 * Run through a REAL git hook and the REAL built CLI.
 *
 * E-16: an untracked file (it may hold a key) is named in the working-tree line; the gate never calls
 * the tree "clean" while one exists.
 */
import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { runGate } from '../../src/commands/gate.js'
import { uncommittedFiles } from '../../src/core/gate-scan.js'
import { claudeInput, cleanup, commitFile, git, mkDeps, mkRepo } from './gate-fixtures.js'

vi.setConfig({ testTimeout: 90_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')
beforeAll(() => {
  if (!existsSync(distCli)) execFileSync('npx', ['tsup'], { cwd: pkgRoot, stdio: 'inherit' })
}, 240_000)
afterEach(cleanup)

// Split so this file does not itself hold a live-looking key.
const STRIPE = `sk_live_${'abcdefghijklmnopqrstuvwx1234567'}`
const home = mkdtempSync(join(tmpdir(), 'sg-gate-merge-home-'))

/** Install the pre-merge-commit hook the way `shipguard setup --agent git` does: it runs the real gate. */
function installMergeHook(repo: string): void {
  const hook = join(repo, '.git', 'hooks', 'pre-merge-commit')
  mkdirSync(dirname(hook), { recursive: true })
  writeFileSync(hook, `#!/bin/sh\nexec "${process.execPath}" "${distCli}" gate --host git --hook pre-merge-commit\n`)
  chmodSync(hook, 0o755)
}

/** `git merge` through the real hook; returns the exit code and what git printed. */
function merge(repo: string, ...args: string[]): { code: number; out: string } {
  try {
    const out = execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', 'merge', '--no-edit', '--no-ff', ...args], {
      cwd: repo,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, HOME: home, SHIPGUARD_TELEMETRY: 'off', SHIPGUARD_NO_PROMO: '1', NODE_OPTIONS: '' },
    })
    return { code: 0, out }
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string }
    return { code: e.status ?? -1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` }
  }
}

describe('E-04: the git pre-merge-commit hook', () => {
  it('a clean merge goes through (it used to be blocked with UNCOMMITTED_CHANGES)', () => {
    const main = mkRepo()
    git(main, 'checkout', '-q', '-b', 'feat')
    commitFile(main, 'src/b.ts', 'export const b = 2\n', 'feat')
    git(main, 'checkout', '-q', 'main')
    commitFile(main, 'src/c.ts', 'export const c = 3\n', 'main change')
    installMergeHook(main)
    const r = merge(main, 'feat')
    expect(r.out).not.toContain('UNCOMMITTED_CHANGES')
    expect(r.code).toBe(0)
    expect(git(main, 'log', '--merges', '--oneline')).toContain('Merge branch')
  })

  it('a merge that brings in a key is blocked, no merge commit is made, the key is not printed', () => {
    const main = mkRepo()
    git(main, 'checkout', '-q', '-b', 'feat')
    commitFile(main, 'lib/stripe.ts', `export const k = "${STRIPE}"\n`, 'feat')
    git(main, 'checkout', '-q', 'main')
    commitFile(main, 'src/c.ts', 'export const c = 3\n', 'main change')
    installMergeHook(main)
    const r = merge(main, 'feat')
    expect(r.code).not.toBe(0)
    expect(r.out).toContain('SHIPGUARD BLOCKED: `git merge` did not run.')
    expect(r.out).toContain('in the merged result')
    expect(r.out).toContain('lib/stripe.ts:1')
    expect(r.out).toContain('code=BLOCKING_FINDINGS')
    expect(r.out).not.toContain(STRIPE)
    expect(git(main, 'log', '--merges', '--oneline')).toBe('')
  })

  it('the pass text says the merged result was checked (not "NOT checked: the merged result")', async () => {
    const main = mkRepo()
    git(main, 'checkout', '-q', '-b', 'feat')
    commitFile(main, 'src/b.ts', 'export const b = 2\n', 'feat')
    git(main, 'checkout', '-q', 'main')
    git(main, 'merge', '--no-commit', '--no-ff', 'feat')
    const { deps, out } = mkDeps(main, '')
    expect(await runGate({ host: 'git', hook: 'pre-merge-commit' }, deps)).toBe(0)
    expect(out.stderr).toContain('the merged result about to be committed')
    expect(out.stderr).toContain('Merge allowed')
    expect(out.stderr).not.toContain('NOT checked')
    // The staged merge result is not "uncommitted work left out".
    expect(out.stderr).not.toContain('Working tree:')
  })

  it('an unstaged or untracked file during a merge is named as not checked', async () => {
    const main = mkRepo()
    git(main, 'checkout', '-q', '-b', 'feat')
    commitFile(main, 'src/b.ts', 'export const b = 2\n', 'feat')
    git(main, 'checkout', '-q', 'main')
    git(main, 'merge', '--no-commit', '--no-ff', 'feat')
    writeFileSync(join(main, 'notes.txt'), 'scratch\n')
    const { deps, out } = mkDeps(main, '')
    expect(await runGate({ host: 'git', hook: 'pre-merge-commit' }, deps)).toBe(0)
    expect(out.stderr).toContain('Working tree: 1 file changed or new, not staged')
  })

  it('an index git cannot turn into a tree blocks instead of passing', async () => {
    const main = mkRepo()
    const { deps, out } = mkDeps(main, '', { stagedTree: () => null })
    expect(await runGate({ host: 'git', hook: 'pre-merge-commit' }, deps)).toBe(1)
    expect(out.stderr).toContain('merge result could not be read')
    expect(out.stderr).toContain('code=INTERNAL_ERROR')
  })
})

describe('E-16: untracked files are never called "clean"', () => {
  it('a clean commit plus an untracked file with a key: the pass names the file as left out', async () => {
    const main = mkRepo()
    writeFileSync(join(main, 'pay.ts'), `export const k = "${STRIPE}"\n`)
    const { deps, out } = mkDeps(main, claudeInput('git push', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(0)
    const ctx = JSON.parse(out.stdout).hookSpecificOutput.additionalContext as string
    expect(ctx).toContain('Working tree: 1 file changed, not committed. They are not pushed and were not checked.')
    expect(ctx).not.toContain('Working tree: clean')
  })

  it('a block names the untracked file too', async () => {
    const main = mkRepo()
    commitFile(main, 'lib/a.ts', 'export const a = 1\n')
    writeFileSync(join(main, 'pay.ts'), 'x\n')
    commitFile(main, 'bad.ts', `s = "PLANTED_SECRET"\n`)
    writeFileSync(join(main, 'later.ts'), 'y\n')
    const { deps, out } = mkDeps(main, claudeInput('git push', main))
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    expect(out.stderr).toContain('Working tree: 1 file changed, not committed (later.ts)')
  })

  it('ShipGuard\'s own .shipguard folder is not an untracked file, and a truly clean tree still says clean', async () => {
    const main = mkRepo()
    mkdirSync(join(main, '.shipguard'))
    writeFileSync(join(main, '.shipguard', 'gate-last.json'), '{}')
    expect(uncommittedFiles(main, { untracked: true })).toEqual([])
    const { deps, out } = mkDeps(main, claudeInput('git push', main))
    await runGate({ host: 'claude' }, deps)
    expect(JSON.parse(out.stdout).hookSpecificOutput.additionalContext).toContain('Working tree: clean')
  })

  it('a renamed file is one file, not two', () => {
    const main = mkRepo()
    git(main, 'mv', 'src/a.ts', 'src/z.ts')
    expect(uncommittedFiles(main, { untracked: true })).toEqual(['src/z.ts'])
  })

  it('only the tracked-and-untracked flags change the list: the default still ignores untracked files', () => {
    const main = mkRepo()
    writeFileSync(join(main, 'new.ts'), 'x\n')
    expect(uncommittedFiles(main)).toEqual([])
    expect(uncommittedFiles(main, { untracked: true })).toEqual(['new.ts'])
    expect(readFileSync(join(main, 'new.ts'), 'utf-8')).toBe('x\n')
  })
})
