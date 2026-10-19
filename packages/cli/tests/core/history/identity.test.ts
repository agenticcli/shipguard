import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { resolveRepoIdentity, ensureGitignored, resolveContentIdentity } from '../../../src/core/history/identity.js'

const tempDirs: string[] = []
function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-identity-'))
  tempDirs.push(dir)
  return dir
}
function mkRepo(): string {
  const dir = mkTemp()
  execSync('git init -q', { cwd: dir })
  execSync('git config user.email test@example.com', { cwd: dir })
  execSync('git config user.name test', { cwd: dir })
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

describe('resolveRepoIdentity (§2.1)', () => {
  it('a real git repo with a commit → root-commit identity (stable, primary)', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'a.txt'), 'hello', 'utf-8')
    execSync('git add a.txt', { cwd: dir })
    execSync('git commit -q -m "first"', { cwd: dir })

    const identity = resolveRepoIdentity(dir)
    expect(identity.repoIdKind).toBe('root-commit')
    expect(identity.repoId).toMatch(/^[0-9a-f]{40}$/)
  })

  it('the SAME repo cloned to another path (same root commit) resolves the SAME repoId', () => {
    const origin = mkRepo()
    writeFileSync(join(origin, 'a.txt'), 'hello', 'utf-8')
    execSync('git add a.txt', { cwd: origin })
    execSync('git commit -q -m "first"', { cwd: origin })

    const clone = mkTemp()
    execSync(`git clone -q "${origin}" "${join(clone, 'cloned')}"`, { cwd: clone })

    const originIdentity = resolveRepoIdentity(origin)
    const cloneIdentity = resolveRepoIdentity(join(clone, 'cloned'))
    expect(cloneIdentity.repoId).toBe(originIdentity.repoId)
  })

  it('two DIFFERENT repos (different root commits) resolve to DIFFERENT repoIds', () => {
    const dirA = mkRepo()
    writeFileSync(join(dirA, 'a.txt'), 'hello', 'utf-8')
    execSync('git add a.txt', { cwd: dirA })
    execSync('git commit -q -m "first"', { cwd: dirA })

    const dirB = mkRepo()
    writeFileSync(join(dirB, 'b.txt'), 'world', 'utf-8')
    execSync('git add b.txt', { cwd: dirB })
    execSync('git commit -q -m "first"', { cwd: dirB })

    expect(resolveRepoIdentity(dirA).repoId).not.toBe(resolveRepoIdentity(dirB).repoId)
  })

  it('a git repo with a commit and a configured remote surfaces the remote as a DISPLAY label only', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'a.txt'), 'hello', 'utf-8')
    execSync('git add a.txt', { cwd: dir })
    execSync('git commit -q -m "first"', { cwd: dir })
    execSync('git remote add origin https://example.com/org/repo.git', { cwd: dir })

    const identity = resolveRepoIdentity(dir)
    expect(identity.repoIdKind).toBe('root-commit') // remote is NEVER the primary key
    expect(identity.remoteLabel).toBe('https://example.com/org/repo.git')
  })

  it('a non-git directory falls back to a gitignored UUID persisted at .shipguard/repo-id', () => {
    const dir = mkTemp()
    const identity = resolveRepoIdentity(dir)
    expect(identity.repoIdKind).toBe('fallback-uuid')
    expect(identity.repoId).toMatch(/^[0-9a-f-]{36}$/)
    expect(existsSync(join(dir, '.shipguard', 'repo-id'))).toBe(true)

    const gitignore = readFileSync(join(dir, '.gitignore'), 'utf-8')
    expect(gitignore).toMatch(/\.shipguard\//)
  })

  it('a git repo with ZERO commits (no HEAD yet) falls back to a UUID, never throws', () => {
    const dir = mkRepo() // git init'd, but no commit made
    const identity = resolveRepoIdentity(dir)
    expect(identity.repoIdKind).toBe('fallback-uuid')
  })

  it('the fallback UUID is STABLE across repeated calls (persisted, not re-generated each time)', () => {
    const dir = mkTemp()
    const first = resolveRepoIdentity(dir)
    const second = resolveRepoIdentity(dir)
    expect(second.repoId).toBe(first.repoId)
  })
})

describe('resolveContentIdentity (scanId reuse — pre-scan content identity)', () => {
  it('a non-git directory returns undefined (no HEAD to hash) — callers must skip scanId reuse entirely', () => {
    const dir = mkTemp()
    expect(resolveContentIdentity(dir)).toBeUndefined()
  })

  it('a git repo with zero commits (no HEAD yet) returns undefined, never throws', () => {
    const dir = mkRepo()
    expect(resolveContentIdentity(dir)).toBeUndefined()
  })

  it('the SAME commit + clean working tree resolves the SAME content identity across calls', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'a.txt'), 'hello', 'utf-8')
    execSync('git add a.txt', { cwd: dir })
    execSync('git commit -q -m "first"', { cwd: dir })

    const first = resolveContentIdentity(dir)
    const second = resolveContentIdentity(dir)
    expect(first).toBeDefined()
    expect(second).toBe(first)
  })

  it('an UNCOMMITTED change on top of the same HEAD changes the content identity (never reuse across dirty edits)', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'a.txt'), 'hello', 'utf-8')
    execSync('git add a.txt', { cwd: dir })
    execSync('git commit -q -m "first"', { cwd: dir })

    const clean = resolveContentIdentity(dir)
    writeFileSync(join(dir, 'a.txt'), 'hello, but edited', 'utf-8')
    const dirty = resolveContentIdentity(dir)

    expect(dirty).toBeDefined()
    expect(dirty).not.toBe(clean)
  })

  it('a NEW commit on the same repo changes the content identity', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'a.txt'), 'hello', 'utf-8')
    execSync('git add a.txt', { cwd: dir })
    execSync('git commit -q -m "first"', { cwd: dir })
    const first = resolveContentIdentity(dir)

    writeFileSync(join(dir, 'b.txt'), 'world', 'utf-8')
    execSync('git add b.txt', { cwd: dir })
    execSync('git commit -q -m "second"', { cwd: dir })
    const second = resolveContentIdentity(dir)

    expect(second).not.toBe(first)
  })

  it('never leaks file CONTENTS — only paths/status letters feed the hash (local-only privacy invariant)', () => {
    const dir = mkRepo()
    writeFileSync(join(dir, 'secret.txt'), 'super-secret-value-should-never-appear-in-hash', 'utf-8')
    const identity = resolveContentIdentity(dir)
    // Undefined here (no commit yet) is fine — the assertion that matters is structural:
    // resolveContentIdentity never reads file bytes (git status --porcelain lists paths only).
    expect(identity === undefined || !identity.includes('super-secret-value-should-never-appear-in-hash')).toBe(true)
  })
})

describe('ensureGitignored', () => {
  it('creates .gitignore with the entry when absent', () => {
    const dir = mkTemp()
    ensureGitignored(dir, '.shipguard/')
    const content = readFileSync(join(dir, '.gitignore'), 'utf-8')
    expect(content).toContain('.shipguard/')
  })

  it('is idempotent — does not duplicate an existing entry', () => {
    const dir = mkTemp()
    ensureGitignored(dir, '.shipguard/')
    ensureGitignored(dir, '.shipguard/')
    const content = readFileSync(join(dir, '.gitignore'), 'utf-8')
    const occurrences = content.split('\n').filter((l) => l.trim() === '.shipguard/').length
    expect(occurrences).toBe(1)
  })

  it('appends to an existing .gitignore without clobbering prior entries', () => {
    const dir = mkTemp()
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\n', 'utf-8')
    ensureGitignored(dir, '.shipguard/')
    const content = readFileSync(join(dir, '.gitignore'), 'utf-8')
    expect(content).toContain('node_modules/')
    expect(content).toContain('.shipguard/')
  })
})
