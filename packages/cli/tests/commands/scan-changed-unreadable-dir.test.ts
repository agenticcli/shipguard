/**
 * QA (2026-11-02, qa-final re-check on b9c8bc39): an untracked folder that cannot be read must never
 * give SAFE_TO_SHIP under `--changed`.
 *
 * Found by the QA adversarial sweep on b9c8bc39 (fails there): git repo, untracked `locked/x.env`
 * holding a key, `chmod 000 locked`. `git ls-files --others --exclude-standard` prints
 * "warning: could not open directory 'locked/': Permission denied" on stderr and exits 0 without
 * listing it, so `scan --changed --strict` reports SAFE_TO_SHIP, degraded:false, exit 0, and the
 * folder is not in coverage.discovered. The full scan of the same tree stops with exit 3 (EACCES from
 * fast-glob: fail closed, never SAFE), which the guard row pins.
 *
 * Plan A2 / utils/fs.ts readCandidate: a read failure is DEGRADED, never silently skipped; plan B.2:
 * the two read paths must agree. A permission-denied folder is common in real projects (for example a
 * database volume created by a container as another user).
 */
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, ENV_KEY_LINE, mkTree, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })

const locked: string[] = []
afterAll(() => {
  for (const d of locked) {
    try {
      chmodSync(d, 0o755)
    } catch {
      /* best-effort: let cleanup remove it */
    }
  }
  cleanupTrees()
})

function lockedTree(git: boolean): string {
  const dir = mkTree({ 'ok.js': 'const a = 1\n' }, { git })
  const l = join(dir, 'locked')
  mkdirSync(l)
  writeFileSync(join(l, 'x.env'), ENV_KEY_LINE)
  chmodSync(l, 0o000)
  locked.push(l)
  return dir
}

// root can read a mode-000 folder, so the case cannot be built there.
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0

describe.skipIf(process.platform === 'win32' || isRoot)('QA: an unreadable untracked folder is never SAFE under --changed', () => {
  it('changed: untracked locked/ (mode 000) holding a key: never SAFE_TO_SHIP, --strict exit is not 0', async () => {
    const dir = lockedTree(true)
    const r = await scanJson(dir, ['--strict', '--changed'])
    const ctx = JSON.stringify({ code: r.code, rec: r.json?.recommendation, degraded: r.json?.degraded, discovered: r.json?.coverage?.discovered })
    expect(r.json?.recommendation, ctx).not.toBe('SAFE_TO_SHIP')
    expect(r.code, ctx).not.toBe(0)
  })

  it('full (guard): the same tree is never SAFE_TO_SHIP, --strict exit is not 0', async () => {
    const dir = lockedTree(false)
    const r = await scanJson(dir, ['--strict'])
    const ctx = JSON.stringify({ code: r.code, rec: r.json?.recommendation })
    expect(r.json?.recommendation, ctx).not.toBe('SAFE_TO_SHIP')
    expect(r.code, ctx).not.toBe(0)
  })
})
