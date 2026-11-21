/**
 * Release gate G9 (plan W0): the budget rules, tested with fake measurements. The real measuring is
 * run by scripts/release-gate.sh on the built CLI.
 */
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
// @ts-expect-error plain .mjs script, no types
import { BASELINE_DEPS, BUDGETS, evaluateBudgets, measureInstallBytes } from '../../scripts/check-budgets.mjs'

const GOOD = {
  tarballBytes: 530_000,
  unpackedBytes: 2_000_000,
  installBytes: 4_000_000,
  dependencies: [...BASELINE_DEPS],
  versionMs: 130,
  freeScanSeconds: 4,
  rssMb: 190,
  proScanSeconds: 6,
  fetches: { ci: 0, quiet: 0, 'safe-mode': 0, 'do-not-track': 0 },
}

const failing = (m: unknown): string[] => (evaluateBudgets(m) as Array<{ id: string; ok: boolean }>).filter((r) => !r.ok).map((r) => r.id)

describe('the budget numbers are the plan numbers', () => {
  it('match plan section 7 W0', () => {
    expect(BUDGETS).toMatchObject({
      tarballBytes: 800 * 1024,
      unpackedBytes: 3 * 1024 * 1024,
      installBytes: 7 * 1024 * 1024,
      directDeps: 7,
      versionMs: 250,
      freeScanSeconds: 8,
      proScanSeconds: 10,
      rssMb: 300,
      zeroFetchModes: 0,
    })
  })
})

describe('evaluateBudgets', () => {
  it('passes a build inside every budget', () => {
    expect(failing(GOOD)).toEqual([])
  })
  it('passes exactly at each limit', () => {
    expect(
      failing({ ...GOOD, tarballBytes: BUDGETS.tarballBytes, unpackedBytes: BUDGETS.unpackedBytes, installBytes: BUDGETS.installBytes, versionMs: 250, freeScanSeconds: 8, rssMb: 300, proScanSeconds: 10 }),
    ).toEqual([])
  })
  it.each([
    ['tarball', { tarballBytes: 800 * 1024 + 1 }, 'tarball'],
    ['unpacked', { unpackedBytes: 3 * 1024 * 1024 + 1 }, 'unpacked'],
    ['install', { installBytes: 7 * 1024 * 1024 + 1 }, 'install'],
    ['--version time', { versionMs: 251 }, 'version-time'],
    ['Free scan time', { freeScanSeconds: 8.01 }, 'free-scan-time'],
    ['Pro scan time', { proScanSeconds: 10.5 }, 'pro-scan-time'],
    ['memory', { rssMb: 301 }, 'rss'],
  ])('fails on %s', (_n, patch, id) => {
    expect(failing({ ...GOOD, ...patch })).toEqual([id])
  })
  it('fails with more than 7 direct dependencies', () => {
    const deps = [...BASELINE_DEPS, 'a', 'b']
    expect(failing({ ...GOOD, dependencies: deps })).toEqual(expect.arrayContaining(['direct-deps', 'no-new-runtime-dep']))
  })
  it('fails on a NEW runtime dependency even when the count is still within 7', () => {
    const deps = BASELINE_DEPS.slice(1).concat('left-pad')
    expect(failing({ ...GOOD, dependencies: deps })).toEqual(['no-new-runtime-dep'])
  })
  it('fails when any zero-fetch mode makes a public fetch', () => {
    for (const mode of ['ci', 'quiet', 'safe-mode', 'do-not-track']) {
      expect(failing({ ...GOOD, fetches: { ...GOOD.fetches, [mode]: 1 } })).toEqual([`fetches-${mode}`])
    }
  })
  it('a missing measurement is a failure, never a pass', () => {
    for (const k of ['tarballBytes', 'unpackedBytes', 'installBytes', 'versionMs', 'freeScanSeconds', 'rssMb']) {
      expect(failing({ ...GOOD, [k]: undefined })).toHaveLength(1)
      expect(failing({ ...GOOD, [k]: NaN })).toHaveLength(1)
    }
    expect(failing({ ...GOOD, dependencies: undefined })).toEqual(['direct-deps'])
    expect(failing({ ...GOOD, fetches: undefined })).toEqual(['zero-fetch-modes'])
    expect(failing({ ...GOOD, fetches: {} })).toEqual(['zero-fetch-modes'])
  })
  it('Pro scan speed is reported as skipped (not a pass) when it was not measured', () => {
    const r = (evaluateBudgets({ ...GOOD, proScanSeconds: undefined }) as Array<{ id: string; skipped?: boolean }>).find((x) => x.id === 'pro-scan-time')
    expect(r?.skipped).toBe(true)
  })
})

describe('measureInstallBytes (production dependency closure)', () => {
  it('sums the package files of the closure, follows dependencies, skips dev dependencies', () => {
    const root = mkdtempSync(join(tmpdir(), 'sg-install-'))
    try {
      const pkg = (dir: string, json: object, bytes: number): void => {
        mkdirSync(dir, { recursive: true })
        writeFileSync(join(dir, 'package.json'), JSON.stringify(json))
        writeFileSync(join(dir, 'index.js'), 'x'.repeat(bytes))
      }
      const store = join(root, 'store', 'node_modules')
      pkg(join(store, 'a'), { name: 'a', dependencies: { b: '1' } }, 1000)
      pkg(join(store, 'b'), { name: 'b', optionalDependencies: { gone: '1' } }, 500)
      pkg(join(store, 'dev-only'), { name: 'dev-only' }, 99999)
      const cli = join(root, 'cli')
      mkdirSync(join(cli, 'node_modules'), { recursive: true })
      writeFileSync(join(cli, 'package.json'), JSON.stringify({ name: 'cli', dependencies: { a: '1' }, devDependencies: { 'dev-only': '1' } }))
      symlinkSync(join(store, 'a'), join(cli, 'node_modules', 'a'))
      symlinkSync(join(store, 'dev-only'), join(cli, 'node_modules', 'dev-only'))
      const jsonLen = (o: object): number => JSON.stringify(o).length
      const expected = 1000 + jsonLen({ name: 'a', dependencies: { b: '1' } }) + 500 + jsonLen({ name: 'b', optionalDependencies: { gone: '1' } })
      expect(measureInstallBytes(cli)).toBe(expected)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
  it('throws when a declared dependency is not installed (never a silent 0)', () => {
    const root = mkdtempSync(join(tmpdir(), 'sg-install-'))
    try {
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'cli', dependencies: { nope: '1' } }))
      expect(() => measureInstallBytes(root)).toThrow(/not installed/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
