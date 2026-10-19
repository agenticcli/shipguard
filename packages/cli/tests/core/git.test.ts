import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { isGitRepo, getChangedFiles, GitCommandError } from '../../src/core/git.js'

describe('isGitRepo', () => {
  it('returns true in a git repo', () => {
    // The current worktree is a git repo
    const result = isGitRepo(process.cwd())
    expect(result).toBe(true)
  })

  it('returns false in a non-git directory', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shipguard-nogit-'))
    const result = isGitRepo(dir)
    expect(result).toBe(false)
  })
})

describe('getChangedFiles', () => {
  it('returns an array', () => {
    const result = getChangedFiles(process.cwd())
    expect(Array.isArray(result)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Regression: distinguish "git ran, genuinely 0 changed
// files" from "git failed" — the old bare `catch { return [] }` made both
// indistinguishable, so a `--changed` scan on Windows (where the old
// `2>/dev/null || ...` shell fallback is guaranteed broken) or any git error
// silently reported "SAFE, 0 files scanned" instead of failing loud.
// ---------------------------------------------------------------------------

describe('getChangedFiles — real git repo scenarios (no mocking)', () => {
  const tmp: string[] = []
  function mkRepo(): string {
    const dir = mkdtempSync(join(tmpdir(), 'shipguard-git-real-'))
    tmp.push(dir)
    execSync('git init -q', { cwd: dir })
    execSync('git config user.email test@example.com', { cwd: dir })
    execSync('git config user.name test', { cwd: dir })
    return dir
  }
  afterEach(() => {
    for (const d of tmp.splice(0)) {
      try { rmSync(d, { recursive: true, force: true }) } catch { /* ignore */ }
    }
  })

  it('brand-new repo with no commits + a staged file → returns the staged file ' +
     '(no HEAD yet is NOT a genuine failure — must not throw)', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'a.txt'), 'hello', 'utf-8')
    execSync('git add a.txt', { cwd: dir })
    const result = getChangedFiles(dir)
    expect(result).toContain('a.txt')
  })

  it('FAIL-BEFORE regression: a repo with a commit and NO changes → returns [] ' +
     '(genuinely clean — this is the case the old code could not distinguish ' +
     'from a git failure; it must still return [] here, not throw)', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'a.txt'), 'hello', 'utf-8')
    execSync('git add a.txt', { cwd: dir })
    execSync('git commit -q -m init', { cwd: dir })
    const result = getChangedFiles(dir)
    expect(result).toEqual([])
  })

  it('untracked file (not staged, not committed) → included in the result', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'a.txt'), 'hello', 'utf-8')
    execSync('git add a.txt', { cwd: dir })
    execSync('git commit -q -m init', { cwd: dir })
    writeFileSync(join(dir, 'untracked.txt'), 'new', 'utf-8')
    const result = getChangedFiles(dir)
    expect(result).toContain('untracked.txt')
  })
})

describe('getChangedFiles — genuine git failure throws GitCommandError (not swallowed to [])', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.resetModules()
  })

  it('FAIL-BEFORE regression: a corrupted/failing git invocation THROWS ' +
     'GitCommandError with the stderr — it does NOT silently return []. ' +
     'This is the exact P1 bug: the old code had `catch { return [] }`, making ' +
     'a genuine git failure indistinguishable from "nothing changed."', async () => {
    // git.ts is already statically imported (real, unmocked) at the top of this
    // file — Node's ESM module cache would otherwise return that same real
    // instance from the dynamic import() below despite vi.doMock(). Reset the
    // module registry FIRST so the dynamic import re-evaluates git.ts against
    // the mocked node:child_process.
    vi.resetModules()
    vi.doMock('node:child_process', () => ({
      execFileSync: vi.fn(() => {
        const err = new Error('Command failed') as Error & { stderr?: string }
        err.stderr = 'fatal: index file corrupt'
        throw err
      }),
    }))
    const { getChangedFiles: getChangedFilesMocked, GitCommandError: GitCommandErrorMocked } =
      await import('../../src/core/git.js')

    let caught: unknown
    try {
      getChangedFilesMocked('/some/repo')
      expect.unreachable('expected getChangedFiles to throw')
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(GitCommandErrorMocked)
    expect((caught as InstanceType<typeof GitCommandErrorMocked>).stderr).toContain('index file corrupt')
    expect((caught as Error).message).toContain('index file corrupt')
  })

  it('GitCommandError carries the failing command string for diagnosability', () => {
    const err = new GitCommandError('git diff --cached --name-only', 'fatal: not a git repository')
    expect(err.message).toContain('git diff --cached --name-only')
    expect(err.message).toContain('fatal: not a git repository')
    expect(err.name).toBe('GitCommandError')
  })
})
