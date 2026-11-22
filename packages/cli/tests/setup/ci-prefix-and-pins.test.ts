/**
 * E-13 (2026-11-22 e2e): (1) with CI set every stderr line starts with `shipguard: ` (spec 01 rule 9), stdout unchanged,
 * the gate's own machine line and the quiet line keep their fixed prefixes; (2) the generated CI workflows pin every
 * action by full commit SHA, not by a movable tag (R10).
 */
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { ciWorkflowYaml } from '../../src/core/hook-templates.js'
import { ciWorkflowText } from '../../src/core/setup-templates.js'
import { prefixLines } from '../../src/utils/ci-prefix.js'

vi.setConfig({ testTimeout: 60_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')
beforeAll(() => {
  if (!existsSync(distCli)) execFileSync('npx', ['tsup'], { cwd: pkgRoot, stdio: 'inherit' })
}, 240_000)
const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))

describe('prefixLines', () => {
  it('prefixes every line, blank ones too, keeps the fixed prefixes, and handles a line split over two writes', () => {
    const a = prefixLines('one\n\ntwo', true)
    expect(a.text).toBe('shipguard: one\nshipguard: \nshipguard: two')
    expect(a.atLineStart).toBe(false)
    const b = prefixLines(' more\nshipguard: verdict=SAFE_TO_SHIP\nshipguard-gate: code=X\n', a.atLineStart)
    expect(b.text).toBe(' more\nshipguard: verdict=SAFE_TO_SHIP\nshipguard-gate: code=X\n')
    expect(b.atLineStart).toBe(true)
  })
})

describe('the real CLI with CI set', () => {
  function run(env: Record<string, string>, args: string[]): { stdout: string; stderr: string; code: number | null } {
    const home = mkdtempSync(join(tmpdir(), 'sg-ciprefix-'))
    roots.push(home)
    const project = join(home, 'proj')
    mkdirSync(project)
    writeFileSync(join(project, 'package.json'), '{"name":"p"}\n')
    writeFileSync(join(project, 'a.js'), 'console.log(1)\n')
    const base: Record<string, string> = { PATH: process.env['PATH'] ?? '', HOME: home, SHIPGUARD_TELEMETRY: 'off', DO_NOT_TRACK: '1' }
    const r = spawnSync(process.execPath, [distCli, ...args], { cwd: project, encoding: 'utf-8', env: { ...base, ...env } })
    return { stdout: r.stdout, stderr: r.stderr, code: r.status }
  }

  it('every stderr line starts with "shipguard: " and stdout has no prefix', () => {
    const r = run({ CI: 'true' }, ['scan'])
    const lines = r.stderr.split('\n').filter((l, i, all) => !(i === all.length - 1 && l === ''))
    expect(lines.length).toBeGreaterThan(0)
    expect(lines.filter((l) => !l.startsWith('shipguard: '))).toEqual([])
    expect(r.stdout.split('\n').some((l) => l.startsWith('shipguard: '))).toBe(false)
  })

  it('without CI nothing changes: no stderr line is prefixed', () => {
    const r = run({}, ['scan'])
    expect(r.stderr.length).toBeGreaterThan(0)
    expect(r.stderr.split('\n').some((l) => l.startsWith('shipguard: ') && !l.startsWith('shipguard: usage'))).toBe(false)
  })

  it('CI=false is not CI', () => {
    const r = run({ CI: 'false' }, ['scan'])
    expect(r.stderr.split('\n').filter((l) => l.startsWith('shipguard: ')).length).toBe(0)
  })
})

describe('generated CI workflows pin every action by full commit SHA', () => {
  const uses = (t: string): string[] => [...t.matchAll(/^\s*-?\s*uses:\s*(\S.*)$/gm)].map((m) => m[1].trim())
  for (const [name, text] of [['shipguard setup --agent ci', ciWorkflowText('0.13.0')], ['shipguard hook --target ci', ciWorkflowYaml()]] as const) {
    it(name, () => {
      const list = uses(text)
      expect(list.length).toBeGreaterThanOrEqual(2)
      for (const u of list) expect(u).toMatch(/^actions\/[a-z-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$/)
      expect(text).not.toMatch(/@v\d+\s*$/m)
    })
  }
})
