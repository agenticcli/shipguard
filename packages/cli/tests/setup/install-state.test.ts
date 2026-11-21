/** install-state.ts: the record `shipguard setup` writes and uninstall (W4b) reads. Strict reads, merge by path. */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { mergeInstallState, readInstallState, sha256, writeInstallState } from '../../src/core/install-state.js'

const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'sg-state-'))
  roots.push(d)
  return d
}

describe('install-state', () => {
  it('round-trips, writes the one-line .gitignore, and merges entries by path', () => {
    const d = tmp()
    const a = mergeInstallState(null, { shipguardVersion: '0.13.0', agents: ['claude'], hookVersion: 2, entries: [{ path: 'CLAUDE.md', kind: 'block', sha256: sha256('x') }] })
    writeInstallState(d, a)
    expect(readInstallState(d)).toEqual(a)
    expect(readFileSync(join(d, '.shipguard', '.gitignore'), 'utf-8')).toBe('*\n')
    const b = mergeInstallState(a, { shipguardVersion: '0.13.1', agents: ['ci', 'claude'], entries: [{ path: 'CLAUDE.md', kind: 'block', sha256: sha256('y') }, { path: '.github/workflows/shipguard.yml', kind: 'file', sha256: sha256('z') }] })
    expect(b.entries).toHaveLength(2)
    expect(b.entries[0].sha256).toBe(sha256('y'))
    expect(b.agents).toEqual(['claude', 'ci'])
    expect(b.hookVersion).toBe(2)
  })

  it('a missing, corrupt, wrong-shape or unknown-version record is no record', () => {
    const d = tmp()
    expect(readInstallState(d)).toBeNull()
    mkdirSync(join(d, '.shipguard'))
    const f = join(d, '.shipguard', 'installed.json')
    for (const bad of ['not json', '{}', '[]', '{"version":2}', JSON.stringify({ version: 1, shipguardVersion: '1', hookVersion: 2, agents: [], entries: [{ path: 'a', kind: 'weird', sha256: 'x' }] })]) {
      writeFileSync(f, bad)
      expect(readInstallState(d), bad).toBeNull()
    }
  })
})
