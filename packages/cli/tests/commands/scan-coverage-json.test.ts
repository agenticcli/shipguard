/**
 * B7: the JSON always carries `coverage`, schemaVersion is 6, internal fields never leak, SARIF has
 * no `coverage`, and the human output prints the Coverage line on a clean scan too.
 */
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, noise, runCli, scanJson, type FileMap } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

describe('coverage in --json', () => {
  it('a clean scan has coverage, the invariant, schemaVersion 6 and no _skipped* keys', async () => {
    const run = await scanJson(mkTree({ 'a.js': 'const a = 1\n', 'b.js': 'const b = 2\n' }))
    const json = run.json!
    expect(json.schemaVersion).toBe('6')
    expect(json.coverage).toMatchObject({ discovered: 2, scanned: 2, mode: 'full', truncated: false })
    expect(json.coverage.skipped).toEqual({
      binary: 0, tooLarge: 0, symlink: 0, unknownBinary: 0, invalidUtf8: 0, unreadable: 0, special: 0, binaryHeadOnly: 0,
    })
    expect(json.coverage.decoded).toEqual({ utf16: 0, nulSubstituted: 0, multiReading: 0, asciiStrings: 0 })
    expect(Object.keys(json).filter((k) => k.startsWith('_'))).toEqual([])
  })

  it('names are sorted, project-relative and capped at 50 while the count stays exact', async () => {
    const files: FileMap = { 'ok.js': 'const ok = 1\n' }
    for (let i = 0; i < 60; i++) {
      const b = noise(200, 77 + i)
      b[0] = 0x41
      b[1] = 0
      files[`junk/n${String(i).padStart(2, '0')}.dat`] = b
    }
    const json = (await scanJson(mkTree(files))).json!
    expect(json.coverage.skipped.unknownBinary).toBe(60)
    const names: string[] = json.coverage.files.unknownBinary
    expect(names).toHaveLength(50)
    expect(names).toEqual([...names].sort())
    expect(names[0]).toBe('junk/n00.dat')
  })

  it('--changed reports mode and the raw git count', async () => {
    const json = (await scanJson(mkTree({ 'a.js': 'x\n', 'b.js': 'y\n' }, { git: true }), ['--changed'])).json!
    expect(json.coverage.mode).toBe('changed')
    expect(json.coverage.changed).toEqual({ listed: 2, outsideScope: 0 })
  })

  it('SARIF output has no coverage block', async () => {
    const run = await runCli(['scan', mkTree({ 'a.js': 'x\n' }), '--sarif'])
    expect(run.stdout).not.toContain('"coverage"')
    expect(JSON.parse(run.stdout).version).toBeDefined()
  })

  it('human output prints the Coverage line on a CLEAN scan and names each skip category', async () => {
    const clean = await runCli(['scan', mkTree({ 'a.js': 'x\n' })])
    expect(clean.stdout + clean.stderr).toMatch(/Coverage: scanned 1 of 1 files/)
    const b = noise(200, 5)
    b[0] = 0x41
    b[1] = 0
    const mixed = await runCli(['scan', mkTree({ 'a.js': 'x\n', 'k.dat': b })])
    const text = mixed.stdout + mixed.stderr
    expect(text).toMatch(/Coverage: scanned 1 of 2 files/)
    expect(text).toMatch(/unknown/i)
    expect(text).toContain('k.dat')
  })
})
