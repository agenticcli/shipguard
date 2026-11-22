/**
 * Test-strategy judge (2026-11-22), finding 3: the scan-id reuse store needed Node 22.5 (node:sqlite), so on Node 20 a
 * Pro re-scan after a dropped response minted a new scan id and could be charged twice. The reuse rule now also works
 * from a small file in `.shipguard/` when the SQLite store cannot open. `NODE_OPTIONS=--no-experimental-sqlite` makes
 * `node:sqlite` unknown, exactly as on Node 20, in the BUILT binary.
 */
import { execSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, runCli } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)
const homes: string[] = []
afterAll(() => homes.forEach((h) => rmSync(h, { recursive: true, force: true })))

const scan = async (p: string): Promise<{ reused: boolean; stderr: string }> => {
  const home = mkdtempSync(join(tmpdir(), 'sg-nosqlite-home-'))
  homes.push(home)
  const r = await runCli(['scan', p, '--json'], { env: { HOME: home, SHIPGUARD_TELEMETRY: 'off', NODE_OPTIONS: '--no-experimental-sqlite' } })
  expect(r.json, r.stderr).toBeDefined()
  return { reused: Boolean(r.json!.scanIdReused), stderr: r.stderr }
}
const fallbackFile = (p: string): string => join(p, '.shipguard', 'scan-id-reuse.json')

describe('scan id is reused on a retry without node:sqlite (Node < 22.5)', () => {
  it('non-git folder: same folder twice reuses the id; a changed folder does not', async () => {
    const p = mkTree({ 'a.js': 'console.log(1)\n' })
    expect((await scan(p)).reused).toBe(false)
    const again = await scan(p)
    expect(again.reused, again.stderr).toBe(true)
    expect(again.stderr).not.toContain('minting a fresh scanId')
    writeFileSync(join(p, 'b.js'), 'console.log(2)\n')
    expect((await scan(p)).reused).toBe(false)
  })

  it('git repo with a commit: same state reuses; a new edit does not', async () => {
    const p = mkTree({ 'a.js': 'console.log(1)\n' }, { git: true })
    execSync('git add -A && git commit -qm one', { cwd: p })
    expect((await scan(p)).reused).toBe(false)
    expect((await scan(p)).reused).toBe(true)
    writeFileSync(join(p, 'a.js'), 'console.log(1); console.log(2)\n')
    expect((await scan(p)).reused).toBe(false)
  })

  it('a committed file with a non-UUID scan id, a wrong shape or a symlink is never trusted', async () => {
    const p = mkTree({ 'a.js': 'console.log(1)\n' })
    expect((await scan(p)).reused).toBe(false)
    const good = JSON.parse(readFileSync(fallbackFile(p), 'utf-8'))
    const key = Object.keys(good.entries)[0] as string
    writeFileSync(fallbackFile(p), JSON.stringify({ version: 1, entries: { [key]: { scanId: '../../etc/passwd', createdAt: Date.now() } } }))
    expect((await scan(p)).reused, 'non-UUID id').toBe(false)
    writeFileSync(fallbackFile(p), '[1,2,3]')
    expect((await scan(p)).reused, 'wrong shape').toBe(false)

    const q = mkTree({ 'a.js': 'console.log(1)\n' })
    const out = mkdtempSync(join(tmpdir(), 'sg-nosqlite-out-'))
    homes.push(out)
    writeFileSync(join(out, 'target.json'), 'precious')
    mkdirSync(join(q, '.shipguard'))
    symlinkSync(join(out, 'target.json'), fallbackFile(q))
    expect((await scan(q)).reused).toBe(false)
    expect(readFileSync(join(out, 'target.json'), 'utf-8')).toBe('precious')
  })
})
