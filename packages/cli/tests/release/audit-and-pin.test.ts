/**
 * Release gates G10 (npm audit with an allowlist) and G11 (picomatch pin), plan W0.
 * Logic: scripts/check-audit.mjs, scripts/check-picomatch-pin.mjs.
 */
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
// @ts-expect-error plain .mjs script, no types
import { evaluateAudit, parseAllowlist } from '../../scripts/check-audit.mjs'
// @ts-expect-error plain .mjs script, no types
import { checkPin } from '../../scripts/check-picomatch-pin.mjs'

const CLI = resolve(__dirname, '..', '..')
const ROOT = resolve(CLI, '..', '..')

const advisory = (name: string, severity: string, ghsa: string) => ({
  name,
  severity,
  vulnerabilities: undefined,
  via: [{ source: 1, name, title: 't', url: `https://github.com/advisories/${ghsa}`, severity }],
})

describe('parseAllowlist', () => {
  const today = '2026-11-21'
  it('keeps a valid entry and ignores the rest with a warning', () => {
    const { allowed, warnings } = parseAllowlist(
      [
        '# comment',
        'GHSA-aaaa-bbbb-cccc | has a reason | 2026-12-31',
        'GHSA-dddd-eeee-ffff | | 2026-12-31',
        'GHSA-gggg-hhhh-iiii | expired | 2026-01-01',
        'GHSA-jjjj-kkkk-llll | no date',
        'not-an-id | reason | 2026-12-31',
      ].join('\n'),
      today,
    )
    expect([...allowed.keys()]).toEqual(['ghsa-aaaa-bbbb-cccc'])
    expect(warnings).toHaveLength(4)
  })
})

describe('evaluateAudit (npm audit --json shape)', () => {
  const allowed = new Map([['ghsa-aaaa-bbbb-cccc', { reason: 'r', expiry: '2026-12-31' }]])
  it('blocks an unlisted high advisory', () => {
    const r = evaluateAudit({ vulnerabilities: { foo: advisory('foo', 'high', 'GHSA-zzzz-yyyy-xxxx') } }, allowed)
    expect(r.blocking).toEqual([{ id: 'ghsa-zzzz-yyyy-xxxx', severity: 'high', module: 'foo' }])
  })
  it('blocks critical, ignores moderate and low', () => {
    const r = evaluateAudit(
      { vulnerabilities: { a: advisory('a', 'critical', 'GHSA-1111-2222-3333'), b: advisory('b', 'moderate', 'GHSA-4444-5555-6666'), c: advisory('c', 'low', 'GHSA-7777-8888-9999') } },
      allowed,
    )
    expect(r.blocking.map((x: { module: string }) => x.module)).toEqual(['a'])
  })
  it('lets a listed advisory through and reports it as allowed', () => {
    const r = evaluateAudit({ vulnerabilities: { foo: advisory('foo', 'high', 'GHSA-AAAA-BBBB-CCCC') } }, allowed)
    expect(r.blocking).toEqual([])
    expect(r.allowed).toHaveLength(1)
  })
  it('a package that only names another package (string via) adds nothing', () => {
    expect(evaluateAudit({ vulnerabilities: { x: { severity: 'high', via: ['foo'] } } }, allowed)).toEqual({ blocking: [], allowed: [] })
  })
  it('output that is not an audit report throws (never "clean")', () => {
    expect(() => evaluateAudit({}, allowed)).toThrow(/vulnerabilities/)
    expect(() => evaluateAudit(null, allowed)).toThrow()
  })
})

describe('check-audit.mjs as a command (fixtures via --input)', () => {
  const run = (json: unknown, extra: string[] = []) => {
    const dir = mkdtempSync(join(tmpdir(), 'sg-audit-test-'))
    try {
      const f = join(dir, 'audit.json')
      writeFileSync(f, typeof json === 'string' ? json : JSON.stringify(json))
      const allow = join(dir, 'allow.txt')
      writeFileSync(allow, 'GHSA-aaaa-bbbb-cccc | covered | 2099-01-01\n')
      return spawnSync(process.execPath, [join(CLI, 'scripts', 'check-audit.mjs'), '--input', f, '--allow', allow, ...extra], { encoding: 'utf-8' })
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }
  it('exit 0 on a clean report', () => expect(run({ vulnerabilities: {} }).status).toBe(0))
  it('exit 1 on an unlisted high advisory', () => expect(run({ vulnerabilities: { foo: advisory('foo', 'high', 'GHSA-zzzz-yyyy-xxxx') } }).status).toBe(1))
  it('exit 0 on a listed advisory', () => expect(run({ vulnerabilities: { foo: advisory('foo', 'high', 'GHSA-aaaa-bbbb-cccc') } }).status).toBe(0))
  it('exit 3 (unavailable, not a pass) on garbage or a registry error', () => {
    expect(run('not json').status).toBe(3)
    expect(run({ error: { code: 'ENOTFOUND', summary: 'offline' } }).status).toBe(3)
    expect(run({ unexpected: true }).status).toBe(3)
  })
})

describe('checkPin', () => {
  const lock = `overrides:\n  picomatch@^2: 2.3.2\n\npackages:\n\n  picomatch@2.3.2:\n    resolution: {}\n\n  picomatch@4.0.4:\n    resolution: {}\n\nsnapshots:\n\n  fdir@6.5.0(picomatch@4.0.4):\n    x: 1\n  picomatch@2.3.2: {}\n  picomatch@4.0.4: {}\n`
  const root = { pnpm: { overrides: { 'picomatch@^2': '2.3.2', 'picomatch@^4': '4.0.4' } } }
  const cli = { overrides: { 'picomatch@^2': '2.3.2', 'picomatch@^4': '4.0.4' } }
  it('passes when overrides, lockfile and the packed package.json agree', () => {
    expect(checkPin({ rootPkg: root, lockText: lock, cliPkg: cli })).toEqual([])
  })
  it('fails without an override', () => {
    expect(checkPin({ rootPkg: { pnpm: { overrides: {} } }, lockText: lock, cliPkg: cli }).join('\n')).toMatch(/no picomatch pin/)
  })
  it('fails on a range instead of an exact version', () => {
    const r = { pnpm: { overrides: { 'picomatch@^2': '^2.3.2', 'picomatch@^4': '4.0.4' } } }
    expect(checkPin({ rootPkg: r, lockText: lock, cliPkg: cli }).join('\n')).toMatch(/not an exact version/)
  })
  it('fails when the lockfile resolves another picomatch', () => {
    const l = lock + '  picomatch@3.0.1:\n    resolution: {}\n'
    expect(checkPin({ rootPkg: root, lockText: l, cliPkg: cli }).join('\n')).toMatch(/resolves picomatch 3\.0\.1/)
  })
  it('fails when the packed package.json lost the pin', () => {
    expect(checkPin({ rootPkg: root, lockText: lock, cliPkg: {} }).join('\n')).toMatch(/packed package.json/)
    expect(checkPin({ rootPkg: root, lockText: lock, cliPkg: { overrides: { 'picomatch@^2': '2.3.1', 'picomatch@^4': '4.0.4' } } }).join('\n')).toMatch(/expected "2\.3\.2"/)
  })
})

describe('this repository', () => {
  it('picomatch is pinned (root overrides, lockfile, package.json that ships)', () => {
    const input = {
      rootPkg: JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf-8')),
      lockText: readFileSync(join(ROOT, 'pnpm-lock.yaml'), 'utf-8'),
      cliPkg: JSON.parse(readFileSync(join(CLI, 'package.json'), 'utf-8')),
    }
    expect(checkPin(input)).toEqual([])
  })
  it('jose is no longer a dependency, in package.json or the lockfile', () => {
    const pkg = JSON.parse(readFileSync(join(CLI, 'package.json'), 'utf-8'))
    expect(Object.keys(pkg.dependencies)).not.toContain('jose')
    expect(readFileSync(join(ROOT, 'pnpm-lock.yaml'), 'utf-8')).not.toMatch(/^ {2,6}jose[@:]/m)
  })
  // The npm description is the short "Open source CLI ..." line (owner decision 2026-11-23, licence switch),
  // so the core line now lives in the npm README, which is the package page.
  it('the package README carries the core line', () => {
    expect(readFileSync(join(CLI, 'README.md'), 'utf-8')).toContain('Check code against a rulebook before you ship')
  })
  it('the tagline is one line everywhere: source constant, both READMEs, and the old line is gone', () => {
    const NEW = 'Check code against a rulebook before you ship'
    const OLD = 'Review code with a rulebook to build secure code'
    expect(readFileSync(join(CLI, 'src/core/outcome.ts'), 'utf-8')).toContain(`CORE_LINE = '${NEW}'`)
    for (const f of [join(ROOT, 'README.md'), join(CLI, 'README.md'), join(CLI, 'src/core/outcome.ts')]) {
      const t = readFileSync(f, 'utf-8')
      expect(t, f).not.toContain(OLD)
    }
    expect(readFileSync(join(ROOT, 'README.md'), 'utf-8')).toContain(NEW)
  })
})
