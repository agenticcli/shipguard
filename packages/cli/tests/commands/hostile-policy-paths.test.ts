/**
 * Test-strategy judge (2026-11-22), finding 1: a policy file in a cloned repo set `history.path` and
 * `report.output` to ANY path and the CLI wrote there (core/history/path.ts resolved the policy path with
 * no containment; the report writer used `report.output` as is). Both stay inside the project now; an
 * escape is refused with a warning and the default location is used. The user's own
 * SHIPGUARD_HISTORY_PATH override is not a policy value and stays allowed.
 */
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, runCli } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

const outsides: string[] = []
afterAll(() => {
  for (const d of outsides.splice(0)) rmSync(d, { recursive: true, force: true })
})
const outsideDir = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'sg-outside-'))
  outsides.push(d)
  return d
}

const policy = (extra: string): string =>
  `version: 1\nproject:\n  name: hostile\n  framework: auto\n  risk_profile: standard\nscan:\n  changed_files_only: false\n  generate_report: true\n${extra}`

const run = (p: string, env: NodeJS.ProcessEnv = {}) =>
  runCli(['scan', p, '--json'], { env: { HOME: outsideDir(), SHIPGUARD_HISTORY_PATH: '', SHIPGUARD_TELEMETRY: 'off', ...env } })

describe('policy file cannot make ShipGuard write outside the project', () => {
  it('absolute and ../ report.output and history.path: nothing written outside, warning, default location used', async () => {
    const out = outsideDir()
    const p = mkTree({
      'app.js': 'console.log(1)\n',
      'shipguard.policy.yml': policy(`report:\n  output: ${out}/report.md\n  format: markdown\nhistory:\n  path: ${out}/history.db\n`),
    })
    const r = await run(p)
    expect(readdirSync(out), 'files written outside the project').toEqual([])
    expect(r.stderr).toContain('Ignoring report.output')
    expect(r.stderr).toContain('Ignoring history.path')
    expect(existsSync(join(p, '.shipguard/reports/latest.md')), 'default report written').toBe(true)
    expect(existsSync(join(p, '.shipguard/history.db')), 'default history written').toBe(true)

    const q = mkTree({
      'app.js': 'console.log(1)\n',
      'shipguard.policy.yml': policy(`report:\n  output: ../escape-report.md\n  format: markdown\nhistory:\n  path: ../../escape-history.db\n`),
    })
    const r2 = await run(q)
    expect(r2.stderr).toContain('Ignoring report.output')
    expect(existsSync(join(q, '..', 'escape-report.md'))).toBe(false)
    expect(existsSync(join(q, '..', '..', 'escape-history.db'))).toBe(false)
  })

  it('a symlink that leaves the project (folder or the file itself) is refused', async () => {
    const out = outsideDir()
    writeFileSync(join(out, 'victim.md'), 'keep me')
    const p = mkTree({
      'app.js': 'console.log(1)\n',
      'shipguard.policy.yml': policy(`report:\n  output: link-dir/latest.md\n  format: markdown\nhistory:\n  path: victim-link.db\n`),
    })
    symlinkSync(out, join(p, 'link-dir'))
    symlinkSync(join(out, 'victim.md'), join(p, 'victim-link.db'))
    const r = await run(p)
    expect(readdirSync(out)).toEqual(['victim.md'])
    expect(r.stderr).toContain('symbolic link')
  })

  it('a path inside the project is still honoured', async () => {
    const p = mkTree({
      'app.js': 'console.log(1)\n',
      'shipguard.policy.yml': policy(`report:\n  output: out/r.md\n  format: markdown\nhistory:\n  path: out/h.db\n`),
    })
    const r = await run(p)
    expect(r.stderr).not.toContain('Ignoring')
    expect(existsSync(join(p, 'out/r.md'))).toBe(true)
    expect(existsSync(join(p, 'out/h.db'))).toBe(true)
  })

  it('the user-controlled SHIPGUARD_HISTORY_PATH env override stays allowed outside the project', async () => {
    const out = outsideDir()
    mkdirSync(out, { recursive: true })
    const p = mkTree({ 'app.js': 'console.log(1)\n' })
    const r = await run(p, { SHIPGUARD_HISTORY_PATH: join(out, 'mine.db') })
    expect(r.stderr).not.toContain('Ignoring')
    expect(existsSync(join(out, 'mine.db'))).toBe(true)
  })
})
