/**
 * Coordinator round 2 (2026-11-22), same class as the hostile policy paths: a cloned repo can commit `.shipguard` as a
 * symbolic link (out of the project, or just somewhere else inside it). History, reports, the repeat count, the gate record
 * and the scan-id file must never be created through it: one warning, the scan still runs and prints, nothing is
 * written. And on a repo with a root commit `.shipguard/` must stay out of git through its own `.gitignore` (`*`).
 */
import { execSync, spawn } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, cliPath, mkTree, runCli } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)
const extra: string[] = []
afterAll(() => extra.forEach((d) => rmSync(d, { recursive: true, force: true })))
const tmp = (p: string): string => {
  const d = mkdtempSync(join(tmpdir(), p))
  extra.push(d)
  return d
}

const env = () => ({ HOME: tmp('sg-dirsym-home-'), SHIPGUARD_HISTORY_PATH: '', SHIPGUARD_TELEMETRY: 'off' })
const commitAll = (p: string): void => void execSync('git add -A && git commit -qm c', { cwd: p, stdio: 'ignore' })

describe('.shipguard committed as a symlink is never written through', () => {
  for (const mode of ['non-git', 'git with a commit', 'git, no commit'] as const) {
    for (const target of ['outside', 'inside'] as const) {
      it(`${mode}, symlink to ${target} the project: nothing created behind it, the scan still prints (exit 0), one warning`, async () => {
        const out = tmp('sg-dirsym-out-')
        const p = mkTree({ 'a.js': 'console.log(1)\n', 'sub/keep.txt': 'x\n' }, { git: mode !== 'non-git' })
        const dest = target === 'outside' ? out : join(p, 'sub', 'dot')
        if (target === 'inside') mkdirSync(dest)
        symlinkSync(dest, join(p, '.shipguard'))
        if (mode === 'git with a commit') commitAll(p)
        const before = readdirSync(dest)
        for (let i = 0; i < 2; i++) {
          const r = await runCli(['scan', p, '--json'], { env: env() })
          expect(r.code, r.stderr).toBe(0)
          expect(r.json, r.stdout).toBeDefined()
          expect(r.json!.recommendation).toBeDefined()
          expect(r.stderr).toContain('Not saving')
          expect(r.stderr).toContain('symbolic link')
        }
        expect(readdirSync(dest), 'files created through the symlink').toEqual(before)
        const hist = await runCli(['history', p], { env: env() })
        expect(readdirSync(dest)).toEqual(before)
        expect(`${hist.stdout}${hist.stderr}`).toMatch(/unavailable|symbolic link/i)
      })
    }
  }

  it('the report path is refused too when only a PARENT of it is a symlink, with a user policy', async () => {
    const out = tmp('sg-dirsym-out-')
    const p = mkTree({
      'a.js': 'console.log(1)\n',
      'shipguard.policy.yml': 'version: 1\nscan:\n  generate_report: true\n',
    })
    mkdirSync(join(p, '.shipguard'))
    symlinkSync(out, join(p, '.shipguard', 'reports'))
    const r = await runCli(['scan', p, '--json'], { env: env() })
    expect(r.code, r.stderr).toBe(0)
    expect(readdirSync(out)).toEqual([])
  })

  it('.shipguard/reports/runs as a symlink: no latest.* and no runs/<id> files are written outside (scan and gate copy)', async () => {
    const out = tmp('sg-dirsym-out-')
    const p = mkTree({ 'a.js': 'console.log(1)\n' }, { git: true })
    commitAll(p)
    mkdirSync(join(p, '.shipguard', 'reports'), { recursive: true })
    symlinkSync(out, join(p, '.shipguard', 'reports', 'runs'))
    const r = await runCli(['scan', p, '--json'], { env: env() })
    expect(r.code, r.stderr).toBe(0)
    expect(r.stderr).toContain('Not saving the report')
    expect(readdirSync(out), 'files created through runs/').toEqual([])
    expect(existsSync(join(p, '.shipguard', 'reports', 'latest.md'))).toBe(false)
    // The gate (blocked commit, so it has a report to copy) copies nothing through the link either.
    const q = mkTree({ 'lib/k.ts': `export const k = "sk_live_${'abcdefghijklmnopqrstuvwx1234567'}"\n` }, { git: true })
    commitAll(q)
    mkdirSync(join(q, '.shipguard', 'reports'), { recursive: true })
    symlinkSync(out, join(q, '.shipguard', 'reports', 'runs'))
    const g = await runGate(q)
    expect(g.code, g.stderr).toBe(1)
    expect(readdirSync(out)).toEqual([])
  })

  it('the gate, in a repo whose commit holds a .shipguard symlink: it still answers (pass) and writes nothing behind the link', async () => {
    const out = tmp('sg-dirsym-out-')
    const p = mkTree({ 'a.js': 'console.log(1)\n' }, { git: true })
    symlinkSync(out, join(p, '.shipguard'))
    commitAll(p)
    const r = await runGate(p)
    expect(r.code, r.stderr).toBe(0)
    expect(readdirSync(out)).toEqual([])
  })
})

describe('on a repo with a root commit .shipguard/ stays out of git', () => {
  it('a scan leaves git status clean, ignores history through .shipguard/.gitignore (*) and never edits the user .gitignore', async () => {
    const gi = 'node_modules/\n.env.local'
    const p = mkTree({ 'a.js': 'console.log(1)\n', '.gitignore': gi }, { git: true })
    commitAll(p)
    const r = await runCli(['scan', p, '--json'], { env: env() })
    expect(r.code, r.stderr).toBe(0)
    expect(existsSync(join(p, '.shipguard', 'history.db')), 'history written').toBe(true)
    expect(readFileSync(join(p, '.shipguard', '.gitignore'), 'utf-8')).toBe('*\n')
    expect(readFileSync(join(p, '.gitignore'), 'utf-8')).toBe(gi)
    expect(execSync('git status --porcelain --untracked-files=all', { cwd: p, encoding: 'utf-8' })).toBe('')
    expect(execSync('git check-ignore .shipguard/history.db', { cwd: p, encoding: 'utf-8' }).trim()).toBe('.shipguard/history.db')
  })
})

// The gate is driven through the real CLI (git host, no refs on stdin).
function runGate(cwd: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((res) => {
    const child = spawn(process.execPath, [cliPath(), 'gate', '--host', 'git', '--hook', 'pre-push'], {
      cwd,
      env: { ...process.env, ...env() },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf-8').on('data', (d: string) => (stdout += d))
    child.stderr.setEncoding('utf-8').on('data', (d: string) => (stderr += d))
    child.on('close', (code) => res({ code: code ?? -1, stdout, stderr }))
    child.stdin.end('')
  })
}
