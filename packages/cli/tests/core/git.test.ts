import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { isGitRepo, getChangedFiles, getChangedFilesDetailed, GitCommandError } from '../../src/core/git.js'

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
     'This is the exact bug: the old code had `catch { return [] }`, making ' +
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

// ---------------------------------------------------------------------------
// B19 / B22 (plan A2, judge R3 MAJOR 4): exact names, NUL-separated output, nested scan root.
// ---------------------------------------------------------------------------
describe('getChangedFilesDetailed: exact names (B19)', () => {
  const tmp: string[] = []
  function mkRepo(): string {
    const dir = mkdtempSync(join(tmpdir(), 'shipguard-git-names-'))
    tmp.push(dir)
    execSync('git init -q', { cwd: dir })
    execSync('git config user.email test@example.com', { cwd: dir })
    execSync('git config user.name test', { cwd: dir })
    return dir
  }
  afterEach(() => {
    for (const d of tmp.splice(0)) rmSync(d, { recursive: true, force: true })
  })

  it('a file named "secret.ts " (trailing space) and its clean sibling are listed separately and exactly', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'secret.ts '), 'k')
    writeFileSync(join(dir, 'secret.ts'), 'c')
    const { paths } = getChangedFilesDetailed(dir)
    expect(paths).toContain('secret.ts ')
    expect(paths).toContain('secret.ts')
  })

  it('a whitespace-only name is kept', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, ' '), 'k')
    expect(getChangedFilesDetailed(dir).paths).toContain(' ')
  })

  it('a non-ASCII name arrives unquoted', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'café.ts'), 'k')
    expect(getChangedFilesDetailed(dir).paths).toContain('café.ts')
  })

  it('staged, modified and untracked files are all present', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'tracked.txt'), 'one')
    execSync('git add . && git commit -q -m init', { cwd: dir })
    writeFileSync(join(dir, 'tracked.txt'), 'two')
    writeFileSync(join(dir, 'staged.txt'), 's')
    execSync('git add staged.txt', { cwd: dir })
    writeFileSync(join(dir, 'new.txt'), 'n')
    const { paths } = getChangedFilesDetailed(dir)
    expect(paths.sort()).toEqual(['new.txt', 'staged.txt', 'tracked.txt'])
  })

  it('a name with the invalid byte FF is NOT merged with a sibling holding a literal U+FFFD', () => {
    const dir = mkRepo()
    writeFileSync(Buffer.concat([Buffer.from(dir + '/a'), Buffer.from([0xff]), Buffer.from('.env')]), 'AKIAIOSFODNN7EXAMPLE')
    writeFileSync(join(dir, 'a�.env'), 'clean')
    const { paths, unaddressable } = getChangedFilesDetailed(dir)
    expect(paths.filter((p) => p === 'a�.env')).toHaveLength(1)
    expect(unaddressable).toHaveLength(1)
    expect(unaddressable[0]).toContain('.env')
  })
})

describe('getChangedFilesDetailed: nested scan root (B22)', () => {
  const tmp: string[] = []
  afterEach(() => {
    for (const d of tmp.splice(0)) rmSync(d, { recursive: true, force: true })
  })
  function mkNested(diffRelative = false): string {
    const dir = mkdtempSync(join(tmpdir(), 'shipguard-git-nested-'))
    tmp.push(dir)
    execSync('git init -q', { cwd: dir })
    execSync('git config user.email test@example.com', { cwd: dir })
    execSync('git config user.name test', { cwd: dir })
    if (diffRelative) execSync('git config diff.relative true', { cwd: dir })
    mkdirSync(join(dir, 'app/app'), { recursive: true })
    writeFileSync(join(dir, 'app/config.js'), 'one')
    writeFileSync(join(dir, 'app/app/config.js'), 'clean')
    writeFileSync(join(dir, 'top.js'), 'one')
    execSync('git add . && git commit -q -m init', { cwd: dir })
    return dir
  }

  for (const diffRelative of [false, true]) {
    const label = diffRelative ? ' (repo has diff.relative=true)' : ''
    it(`modified file in app/ is returned relative to app/, outside files are counted${label}`, () => {
      const dir = mkNested(diffRelative)
      writeFileSync(join(dir, 'app/config.js'), 'KEY=AKIAIOSFODNN7EXAMPLE')
      writeFileSync(join(dir, 'top.js'), 'two')
      const r = getChangedFilesDetailed(join(dir, 'app'))
      expect(r.paths).toEqual(['config.js'])
      expect(r.outsideScope).toBe(1)
    })

    it(`staged file in app/ is found${label}`, () => {
      const dir = mkNested(diffRelative)
      writeFileSync(join(dir, 'app/new.js'), 'KEY')
      execSync('git add app/new.js', { cwd: dir })
      expect(getChangedFilesDetailed(join(dir, 'app')).paths).toEqual(['new.js'])
    })

    it(`untracked file in app/ is found${label}`, () => {
      const dir = mkNested(diffRelative)
      writeFileSync(join(dir, 'app/untracked.js'), 'KEY')
      expect(getChangedFilesDetailed(join(dir, 'app')).paths).toEqual(['untracked.js'])
    })
  }

  it('from the repo root nothing changes: paths are root-relative, outsideScope is 0', () => {
    const dir = mkNested()
    writeFileSync(join(dir, 'app/config.js'), 'two')
    const r = getChangedFilesDetailed(dir)
    expect(r.paths).toEqual(['app/config.js'])
    expect(r.outsideScope).toBe(0)
  })
})
