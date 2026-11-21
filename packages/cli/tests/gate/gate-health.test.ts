/**
 * QA fix 4 (QA-CLI-0130 FAIL 4): gate health is reported outside the gate. FAIL-BEFORE: `scan --json` warnings[] was
 * always [], neither `scan` nor `status` said anything about a stale 0.12 hook or a gate the host killed, and
 * `status` had no "Installed here / Last gate run / Gate strength" lines (spec 03, spec 07).
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { gateHealthLines, gateHealthWarnings, healthWarningLine } from '../../src/core/gate-state.js'
import { buildVariant } from '../helpers/recorded-cli.js'
import { spawnNode } from '../helpers/spawn-cli.js'

vi.setConfig({ testTimeout: 60_000 })

// A private build output, so this file never rewrites dist/ under the other test files.
let distCli = ''
beforeAll(() => {
  distCli = buildVariant('dev', 'gate-health')
}, 240_000)

const dirs: string[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'sg-health-'))
  dirs.push(d)
  return d
}

const LEGACY = `sh -c '_sg_in=$(cat); case "$_sg_in" in *"git push"*) ./node_modules/.bin/shipguard scan --json --strict;; esac; exit 0'`
const NOW = Date.parse('2026-11-21T12:00:00Z')

function project(opts: { legacyHook?: boolean; runningHoursAgo?: number; finished?: { status: string; at: string } } = {}): string {
  const d = tmp()
  writeFileSync(join(d, 'package.json'), '{"name":"health-fx"}\n')
  writeFileSync(join(d, 'index.js'), 'export const a = 1\n')
  if (opts.legacyHook) {
    mkdirSync(join(d, '.claude'), { recursive: true })
    writeFileSync(join(d, '.claude', 'settings.json'), JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: LEGACY }] }] } }))
  }
  if (opts.runningHoursAgo !== undefined || opts.finished) {
    mkdirSync(join(d, '.shipguard'), { recursive: true })
    writeFileSync(join(d, '.shipguard', '.gitignore'), '*\n')
    const rec = opts.finished
      ? { schema: 1, status: opts.finished.status, host: 'claude', command: 'git push origin main', startedAt: opts.finished.at, finishedAt: opts.finished.at }
      : { schema: 1, status: 'running', host: 'claude', command: 'git push origin main', startedAt: new Date(Date.now() - (opts.runningHoursAgo as number) * 3600_000).toISOString() }
    writeFileSync(join(d, '.shipguard', 'gate-last.json'), JSON.stringify(rec))
  }
  return d
}

describe('gateHealthWarnings / gateHealthLines (function level)', () => {
  it('a clean folder has no warnings', () => {
    expect(gateHealthWarnings(project(), NOW)).toEqual([])
  })

  it('a 0.12 inline hook is HOOK_STALE with the setup command', () => {
    const w = gateHealthWarnings(project({ legacyHook: true }), NOW)
    expect(w.map((x) => x.code)).toEqual(['HOOK_STALE'])
    expect(w[0].command).toBe('shipguard setup --agent claude')
    expect(healthWarningLine(w[0])).toMatch(/^warn HOOK_STALE: your Claude hook is from an older ShipGuard/)
  })

  it('a running record aged 3 h is GATE_UNFINISHED; a young one (another gate still working) is not', () => {
    const old = gateHealthWarnings(project({ runningHoursAgo: 3 }))
    expect(old.map((x) => x.code)).toEqual(['GATE_UNFINISHED'])
    expect(old[0].command).toBe('shipguard scan --strict')
    expect(gateHealthWarnings(project({ runningHoursAgo: 0 }))).toEqual([])
  })

  it('status lines: nothing installed, then a finished run, then a killed one', () => {
    expect(gateHealthLines(project(), NOW)).toEqual(['Installed here: nothing. Set it up: shipguard setup', 'Last gate run: none yet.'])
    const ok = gateHealthLines(project({ legacyHook: true, finished: { status: 'passed', at: '2026-11-17T23:07:30.000Z' } }), NOW)
    expect(ok[0]).toBe('Installed here: Claude project hook (older version, stale)')
    expect(ok[1]).toBe('Last gate run: 2026-11-17 23:07 UTC: passed. 0 unfinished runs.')
    expect(ok[2]).toBe('Gate strength: local hooks only stop well-behaved agents; CI branch protection is not confirmed.')
    const killed = gateHealthLines(project({ runningHoursAgo: 3 }))
    expect(killed[1]).toMatch(/^Last gate run: \d{4}-\d\d-\d\d \d\d:\d\d UTC: never finished\. 1 unfinished run\.$/)
  })
})

describe('the built CLI reports it', () => {
  const env = (home: string): NodeJS.ProcessEnv => ({ PATH: process.env.PATH, HOME: home, SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1', SHIPGUARD_NO_PROMO: '1', CI: '1' })

  it('scan --json: warnings[] carries both codes, nextSteps carries update_hook + rerun_gate, stdout is one JSON object, stderr stays quiet', async () => {
    const d = project({ legacyHook: true, runningHoursAgo: 3 })
    const r = await spawnNode(distCli, ['scan', '--json'], { cwd: d, env: env(tmp()) })
    const j = JSON.parse(r.stdout) as { warnings: Array<{ code: string; command: string }>; nextSteps: Array<{ kind: string; command: string | null }> }
    expect(j.warnings.map((w) => w.code).sort()).toEqual(['GATE_UNFINISHED', 'HOOK_STALE'])
    expect(j.nextSteps.map((s) => s.kind)).toEqual(expect.arrayContaining(['update_hook', 'rerun_gate']))
    expect(j.nextSteps.filter((s) => s.kind === 'update_hook')).toHaveLength(1)
    expect(r.stderr).not.toContain('warn ')
  })

  it('scan (screen) and scan --quiet: one `warn CODE: text` stderr line each, stdout line 1 is still the verdict', async () => {
    const d = project({ legacyHook: true, runningHoursAgo: 3 })
    for (const args of [['scan'], ['scan', '--quiet']]) {
      const r = await spawnNode(distCli, args, { cwd: d, env: env(tmp()) })
      expect(r.stderr).toContain('warn HOOK_STALE: your Claude hook is from an older ShipGuard')
      expect(r.stderr).toContain('warn GATE_UNFINISHED: the last gate check (git push origin main')
      expect(r.stdout.split('\n')[0]).not.toContain('warn ')
    }
  })

  it('a clean project: warnings[] is empty and stderr says nothing', async () => {
    const r = await spawnNode(distCli, ['scan', '--json'], { cwd: project(), env: env(tmp()) })
    expect((JSON.parse(r.stdout) as { warnings: unknown[] }).warnings).toEqual([])
  })

  it('status prints the gate-health lines and the warnings (stderr)', async () => {
    const d = project({ legacyHook: true, finished: { status: 'blocked', at: '2026-11-17T23:07:30.000Z' } })
    const r = await spawnNode(distCli, ['status', '--api-url', 'http://127.0.0.1:9'], { cwd: d, env: env(tmp()) })
    expect(r.stdout).toContain('Installed here: Claude project hook (older version, stale)')
    expect(r.stdout).toContain('Last gate run: 2026-11-17 23:07 UTC: blocked. 0 unfinished runs.')
    expect(r.stdout).toContain('Gate strength: local hooks only stop well-behaved agents')
    expect(r.stderr).toContain('warn HOOK_STALE:')
  })
})
