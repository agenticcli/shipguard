/**
 * B2, B3, B4, B5, B6, B23 + the behavioural mutation matrix (plan B.2).
 *
 * One fixtures table. Every row runs TWICE: (full) `scan <dir>` and (changed) the same files created
 * untracked inside a fresh git repo and scanned with `--changed`. The test asserts the expectations
 * AND that `coverage` (apart from mode/changed) and the degrade codes are IDENTICAL between the two
 * runs. A classifier reverted in only one read path therefore turns that path's rows red.
 */
import { execSync } from 'node:child_process'
import { gzipSync } from 'node:zlib'
import { afterAll, describe, expect, it, vi } from 'vitest'
import {
  cleanupTrees, degradeCodes, ENV_KEY_LINE, KEY, keyFoundIn, mkTree, noise, runCli, scanJson, utf16be, utf16le,
  type FileMap, type ScanJson,
} from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

const bytes = (...n: number[]): Buffer => Buffer.from(n)
const png1x1 = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
)
const withMagic = (magic: Buffer, seed: number): Buffer => Buffer.concat([magic, bytes(0), noise(600, seed)])

const realBinaries: FileMap = {
  'logo.png': png1x1,
  'a.zip': withMagic(bytes(0x50, 0x4b, 0x03, 0x04), 1),
  'b.gz': gzipSync(noise(500, 2)),
  'c.elf': withMagic(bytes(0x7f, 0x45, 0x4c, 0x46), 3),
  'd.woff2': withMagic(Buffer.from('wOF2'), 4),
}

function padNul(s: string): Buffer {
  const b = Buffer.from(s)
  for (let i = 25; i < b.length; i += 49) b[i] = 0 // 49 is odd: NULs land on both byte parities
  return b
}

interface Row {
  id: string
  files: FileMap
  /** Exact set of degrade codes (sorted). */
  codes: string[]
  /** File in which the planted key must be found, or null when it must NOT be found. */
  key: string | null
  scanned: number
  decoded?: Partial<Record<'utf16' | 'nulSubstituted' | 'multiReading' | 'asciiStrings', number>>
  skipped?: Partial<Record<string, number>>
}

const CFG = 'cfg.txt'
const padded = (s: string): string => '# header\n' + s + 'pad=1\n'.repeat(300)

const rows: Row[] = [
  // ---- B2: found, not degraded --------------------------------------------------------------
  { id: 'nul-next-to-key', files: { [CFG]: Buffer.from(padded(ENV_KEY_LINE).replace('# h', '#\0h')) }, codes: [], key: CFG, scanned: 1, decoded: { nulSubstituted: 1 } },
  { id: 'utf16le-bom', files: { [CFG]: utf16le(padded(ENV_KEY_LINE), true) }, codes: [], key: CFG, scanned: 1, decoded: { utf16: 1 } },
  { id: 'utf16be-bom', files: { [CFG]: utf16be(padded(ENV_KEY_LINE), true) }, codes: [], key: CFG, scanned: 1, decoded: { utf16: 1 } },
  { id: 'utf16le-no-bom', files: { [CFG]: utf16le(padded(ENV_KEY_LINE)) }, codes: [], key: CFG, scanned: 1, decoded: { utf16: 1 } },
  { id: 'utf16be-no-bom', files: { [CFG]: utf16be(padded(ENV_KEY_LINE)) }, codes: [], key: CFG, scanned: 1, decoded: { utf16: 1 } },
  { id: 'cjk-then-key-le', files: { [CFG]: utf16le('汉'.repeat(10_000) + '\n' + ENV_KEY_LINE) }, codes: [], key: CFG, scanned: 1, decoded: { utf16: 1 } },
  // ---- B23: ambiguity, every plausible reading is scanned -----------------------------------
  { id: 'ambiguous-a1001-key-nul', files: { [CFG]: Buffer.from('a'.repeat(1001) + '\n' + ENV_KEY_LINE + '\0') }, codes: [], key: CFG, scanned: 1, decoded: { multiReading: 1 } },
  { id: 'cjk-then-key-be', files: { [CFG]: utf16be('汉'.repeat(10_000) + '\n' + ENV_KEY_LINE) }, codes: [], key: CFG, scanned: 1, decoded: { utf16: 1 } },
  { id: 'cjk-utf8-magic-nul-key', files: { [CFG]: Buffer.concat([Buffer.from('%PDF-1.7\n'), Buffer.from('汉字漢字'.repeat(300) + '\n'), bytes(0), Buffer.from(ENV_KEY_LINE)]) }, codes: [], key: CFG, scanned: 1 },
  // ---- judge R3 MAJOR 2: mixed encodings -----------------------------------------------------
  {
    id: 'ascii-env-then-utf16le-append',
    files: { [CFG]: Buffer.concat([Buffer.from((ENV_KEY_LINE + 'APP_NAME=demo\nDEBUG=false\nPORT=3000\n'.repeat(80)).slice(0, 2000)), utf16le('EXTRA=1\nMORE=2\nSTILL=3\nAND=4\nX=5\nY=6\nZ=7\n')]) },
    codes: [], key: CFG, scanned: 1,
  },
  { id: 'bom-utf16le-then-ascii-append', files: { [CFG]: Buffer.concat([utf16le('# note\n', true), Buffer.from('#' + ENV_KEY_LINE)]) }, codes: [], key: CFG, scanned: 1 },
  { id: 'magic-prefix-utf16le-key', files: { [CFG]: Buffer.concat([Buffer.from('%PDF'), utf16le('\n' + ENV_KEY_LINE.repeat(3))]) }, codes: [], key: CFG, scanned: 1, decoded: { utf16: 1 } },
  // ---- spoofs (D4): content decides, never the name ------------------------------------------
  { id: 'spoof-mz-env', files: { [CFG]: 'MZ=1\n' + ENV_KEY_LINE }, codes: [], key: CFG, scanned: 1 },
  { id: 'spoof-ustar-257', files: { [CFG]: 'x'.repeat(257) + 'ustar\n' + ENV_KEY_LINE }, codes: [], key: CFG, scanned: 1 },
  { id: 'spoof-png-named-text', files: { 'secret.png': ENV_KEY_LINE }, codes: [], key: 'secret.png', scanned: 1 },
  {
    id: 'spoof-png-header-key-lines',
    files: { [CFG]: Buffer.concat([bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0), Buffer.from(ENV_KEY_LINE.repeat(40))]) },
    codes: ['NO_FILES_SCANNED', 'UNSCANNED_UNKNOWN_BINARY'], key: null, scanned: 0, skipped: { unknownBinary: 1, binary: 0 },
  },
  // ---- uncompressed binary formats: ASCII strings reading ------------------------------------
  {
    id: 'sqlite-with-key',
    files: { 'dev.db': Buffer.concat([Buffer.from('SQLite format 3'), bytes(0, 0x10, 0, 1, 1), noise(3000, 5), bytes(0, 0, 0), Buffer.from('CREATE TABLE t(k TEXT)'), bytes(0, 1, 2), Buffer.from(KEY), bytes(0, 0)]) },
    codes: [], key: 'dev.db', scanned: 1, decoded: { asciiStrings: 1 },
  },
  // ---- B3: degrading rows ---------------------------------------------------------------------
  { id: 'bom-lone-surrogate', files: { [CFG]: Buffer.concat([bytes(0xff, 0xfe), Buffer.from([0x41, 0, 0, 0xd8, 0x42, 0])]) }, codes: ['INVALID_UTF8', 'NO_FILES_SCANNED'], key: null, scanned: 0, skipped: { invalidUtf8: 1 } },
  { id: 'bom-odd-length', files: { [CFG]: Buffer.concat([bytes(0xff, 0xfe), Buffer.from([0x41, 0, 0x42])]) }, codes: ['INVALID_UTF8', 'NO_FILES_SCANNED'], key: null, scanned: 0, skipped: { invalidUtf8: 1 } },
  { id: 'bomless-be-all-cjk', files: { [CFG]: utf16be('二三四五六七八九十'.repeat(400)) }, codes: ['INVALID_UTF8', 'NO_FILES_SCANNED'], key: null, scanned: 0, skipped: { invalidUtf8: 1 } },
  { id: 'utf32le', files: { [CFG]: Buffer.concat([bytes(0xff, 0xfe, 0, 0), Buffer.from('A\0\0\0B\0\0\0C\0\0\0D\0\0\0')]) }, codes: ['NO_FILES_SCANNED', 'UNSCANNED_UNKNOWN_BINARY'], key: null, scanned: 0, skipped: { unknownBinary: 1 } },
  { id: 'creds-bin-2pct-nul', files: { 'creds.bin': padNul('secret-material-'.repeat(400).slice(0, 6400)) }, codes: ['NO_FILES_SCANNED', 'UNSCANNED_UNKNOWN_BINARY'], key: null, scanned: 0, skipped: { unknownBinary: 1 } },
  { id: 'dump-dat-2pct-nul', files: { 'dump.dat': padNul('row-data-value--'.repeat(400).slice(0, 6400)) }, codes: ['NO_FILES_SCANNED', 'UNSCANNED_UNKNOWN_BINARY'], key: null, scanned: 0, skipped: { unknownBinary: 1 } },
  // ---- B5: real binaries only ----------------------------------------------------------------
  { id: 'real-binaries-only', files: realBinaries, codes: ['NO_FILES_SCANNED'], key: null, scanned: 0, skipped: { binary: 5, unknownBinary: 0 } },
  { id: 'real-binaries-plus-clean-js', files: { ...realBinaries, 'ok.js': 'const ok = 1\n' }, codes: [], key: null, scanned: 1, skipped: { binary: 5 } },
]

function coverageCore(json: ScanJson): unknown {
  const { mode: _mode, changed: _changed, ...rest } = json.coverage
  return rest
}

describe('coverage matrix: every row on BOTH read paths', () => {
  for (const row of rows) {
    it(row.id, async () => {
      const full = await scanJson(mkTree(row.files), ['--strict'])
      const changed = await scanJson(mkTree(row.files, { git: true }), ['--strict', '--changed'])
      for (const [mode, run] of [['full', full], ['changed', changed]] as const) {
        const ctx = `${row.id} (${mode})\n${run.stderr.slice(0, 800)}`
        expect(run.json, ctx).toBeDefined()
        const json = run.json!
        expect(json.schemaVersion, ctx).toBe('6')
        expect(degradeCodes(json), ctx).toEqual(row.codes)
        expect(json.degraded === true, ctx).toBe(row.codes.length > 0)
        if (row.key) expect(keyFoundIn(json, row.key), `${ctx}: key must be found`).toBe(true)
        else expect(keyFoundIn(json, CFG), `${ctx}: key must not appear`).toBe(false)
        expect(json.coverage.scanned, ctx).toBe(row.scanned)
        expect(json.filesScanned, ctx).toBe(row.scanned)
        expect(json.coverage.mode).toBe(mode)
        for (const [k, v] of Object.entries(row.decoded ?? {})) expect(json.coverage.decoded[k], `${ctx} decoded.${k}`).toBe(v)
        for (const [k, v] of Object.entries(row.skipped ?? {})) expect(json.coverage.skipped[k], `${ctx} skipped.${k}`).toBe(v)
        // invariant: discovered = scanned + sum(skipped, except binaryHeadOnly) + notReached
        const s = json.coverage.skipped as Record<string, number>
        const sum = Object.entries(s).filter(([k]) => k !== 'binaryHeadOnly').reduce((a, [, v]) => a + v, 0)
        const notReached = json.coverage.truncated ? json.coverage.truncated.notReached : 0
        expect(json.coverage.discovered, ctx).toBe(json.coverage.scanned + sum + notReached)
        const blocking = json.riskScore.blockingCount > 0 || json.recommendation === 'DO_NOT_SHIP' || row.codes.length > 0
        expect(run.code, ctx).toBe(blocking ? 1 : 0)
        if (row.codes.length > 0) expect(json.recommendation, ctx).toBe('DO_NOT_SHIP')
      }
      expect(coverageCore(changed.json!)).toEqual(coverageCore(full.json!))
      expect(degradeCodes(changed.json)).toEqual(degradeCodes(full.json))
    })
  }

  it('a degrading row exits 0 without --strict (verdict-neutral exit code is kept)', async () => {
    const run = await scanJson(mkTree({ [CFG]: Buffer.concat([bytes(0xff, 0xfe), Buffer.from([0x41, 0, 0x42])]) }))
    expect(run.code).toBe(0)
    expect(run.json!.degraded).toBe(true)
  })
})

describe('B6: nothing was scanned is never SAFE', () => {
  it('a directory whose files are all default-ignored: NO_FILES_SCANNED, DO_NOT_SHIP, --strict exit 1, plain exit 0', async () => {
    const dir = mkTree({ 'node_modules/p/i.js': 'x', 'package-lock.json': '{}' })
    const strict = await scanJson(dir, ['--strict'])
    expect(degradeCodes(strict.json)).toEqual(['NO_FILES_SCANNED'])
    expect(strict.json!.recommendation).toBe('DO_NOT_SHIP')
    expect(strict.code).toBe(1)
    expect((await scanJson(dir)).code).toBe(0)
  })

  it('--changed on a clean checkout: degraded, DO_NOT_SHIP, exit 1 with --strict, hint on stderr only', async () => {
    const dir = mkTree({ 'a.js': 'const a = 1\n' }, { git: true })
    execSync('git add . && git commit -q -m init', { cwd: dir })
    const json = await scanJson(dir, ['--changed', '--strict'])
    expect(degradeCodes(json.json)).toEqual(['NO_FILES_SCANNED'])
    expect(json.json!.recommendation).toBe('DO_NOT_SHIP')
    expect(json.code).toBe(1)
    expect(json.stdout.trim().startsWith('{')).toBe(true)
    expect(json.stdout).not.toMatch(/clean checkout/i)
    expect((await scanJson(dir, ['--changed'])).code).toBe(0)
    const human = await runCli(['scan', dir, '--changed'])
    expect(human.stderr).toMatch(/clean checkout/i)
  })
})
