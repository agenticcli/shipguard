/**
 * B8: limits are visible (cap name and count), the head-read shortcut for files over the size cap
 * is safe (judge R3 MAJOR 1), and binary files are counted but do not use the file cap.
 */
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, degradeCodes, KEY, mkTree, noise, scanJson, type FileMap } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 90_000 })
afterAll(cleanupTrees)

const OVER = 600 * 1024
const policy = (limits: string): string => `limits:\n${limits}\n`

function manyFiles(n: number, size = 20): FileMap {
  const f: FileMap = {}
  for (let i = 0; i < n; i++) f[`f${String(i).padStart(2, '0')}.txt`] = 'x'.repeat(size) + '\n'
  return f
}

describe('truncation names the cap and the count', () => {
  for (const mode of ['full', 'changed'] as const) {
    const extra = mode === 'changed' ? ['--changed'] : []
    it(`${mode}: maxFiles 10 of 25 files`, async () => {
      const dir = mkTree({ ...manyFiles(25), 'shipguard.policy.yml': policy('  maxFiles: 10') }, { git: mode === 'changed' })
      const json = (await scanJson(dir, extra)).json!
      expect(json.degraded).toBe(true)
      expect(degradeCodes(json)).toEqual(['OUTPUT_TRUNCATED'])
      expect(json.coverage.scanned).toBe(10)
      expect(json.coverage.truncated).toEqual({ by: 'maxFiles', notReached: json.coverage.discovered - 10 })
      const detail = json.degradedReasons.find((r: { code: string }) => r.code === 'OUTPUT_TRUNCATED').detail
      expect(detail).toContain('maxFiles')
      expect(detail).toContain(String(json.coverage.truncated.notReached))
    })

    it(`${mode}: maxTotalBytes`, async () => {
      const dir = mkTree({ ...manyFiles(10, 999), 'shipguard.policy.yml': policy('  maxTotalBytes: 3000') }, { git: mode === 'changed' })
      const json = (await scanJson(dir, extra)).json!
      expect(json.coverage.truncated.by).toBe('maxTotalBytes')
      expect(json.coverage.truncated.notReached).toBe(json.coverage.discovered - json.coverage.scanned)
      expect(degradeCodes(json)).toEqual(['OUTPUT_TRUNCATED'])
    })

    it(`${mode}: exactly at the cap is NOT truncated`, async () => {
      const dir = mkTree({ ...manyFiles(9), 'shipguard.policy.yml': policy('  maxFiles: 10') }, { git: mode === 'changed' })
      const json = (await scanJson(dir, extra)).json!
      expect(json.coverage.truncated).toBe(false)
      expect(json.coverage.scanned).toBe(10)
      expect(degradeCodes(json)).toEqual([])
    })
  }

  it('an over-size text file is FILE_TOO_LARGE and counted', async () => {
    const json = (await scanJson(mkTree({ 'ok.js': 'const a = 1\n', 'big.txt': 'x'.repeat(OVER) }))).json!
    expect(degradeCodes(json)).toEqual(['FILE_TOO_LARGE'])
    expect(json.coverage.skipped.tooLarge).toBe(1)
    expect(json.coverage.files.tooLarge).toEqual(['big.txt'])
  })
})

describe('head-read shortcut: real large assets are not a false degrade', () => {
  const tail = (n: number, seed: number): Buffer => noise(n, seed)
  const jpeg = Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    // APP1 EXIF: "Exif\0\0", TIFF header, one IFD entry with the ExifIFD pointer tag 0x8769
    Buffer.from([0xff, 0xe1, 0x00, 0x20]), Buffer.from('Exif\0\0'), Buffer.from('MM\0*\0\0\0\x08\0\x01\x87\x69\0\x04\0\0\0\x01\0\0\0\x1a', 'latin1'),
    // APP1 XMP with plain text
    Buffer.from([0xff, 0xe1, 0x07, 0xd0]), Buffer.from('http://ns.adobe.com/xap/1.0/\0<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>'.padEnd(1900, ' ')),
    Buffer.from([0xff, 0xdb, 0x00, 0x43]), tail(OVER, 11),
  ])
  const pdf = Buffer.concat([
    Buffer.from('%PDF-1.7\n%'), Buffer.from([0xe2, 0xe3, 0xcf, 0xd3]), Buffer.from('\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'), tail(OVER, 12),
  ])
  const mp4 = Buffer.concat([
    Buffer.from([0, 0, 0, 0x18]), Buffer.from('ftypisom'), Buffer.from([0, 0, 2, 0]), Buffer.from('isomiso2avc1mp41'),
    Buffer.from([0x00, 0x09, 0x00, 0x00]), Buffer.from('mdat'), tail(OVER, 13),
  ])

  it('camera JPEG, PDF with early text objects and MP4 over 512 KiB: counted as binary, NOT degraded', async () => {
    const json = (await scanJson(mkTree({ 'ok.js': 'const a = 1\n', 'photo.jpg': jpeg, 'doc.pdf': pdf, 'clip.mp4': mp4 }))).json!
    expect(degradeCodes(json)).toEqual([])
    expect(json.coverage.skipped.binary).toBe(3)
    expect(json.coverage.skipped.binaryHeadOnly).toBe(3)
    expect(json.coverage.skipped.tooLarge).toBe(0)
  })

  const mk = (magic: Buffer): Buffer =>
    Buffer.concat([magic, Buffer.alloc(4096), Buffer.from(`\nAWS_ACCESS_KEY_ID=${KEY}\n`), Buffer.alloc(OVER, 0x20)])
  const attacks: Array<[string, Buffer]> = [
    ['PNG', mk(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))],
    ['JPEG', mk(Buffer.from([0xff, 0xd8, 0xff, 0xe0]))],
    ['GZIP', mk(Buffer.from([0x1f, 0x8b, 0x08, 0x00]))],
  ]
  for (const [name, buf] of attacks) {
    it(`attack: ${name} magic + 4 KiB of NULs + a credential later, over the cap, is FILE_TOO_LARGE (degraded)`, async () => {
      const json = (await scanJson(mkTree({ 'ok.js': 'const a = 1\n', 'evil.dat': buf }), ['--strict'])).json!
      expect(degradeCodes(json)).toEqual(['FILE_TOO_LARGE'])
      expect(json.coverage.skipped.tooLarge).toBe(1)
      expect(json.coverage.skipped.binary).toBe(0)
    })
  }

  it('attack: an over-cap text file with a PNG header and a text head is FILE_TOO_LARGE', async () => {
    const buf = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47]), Buffer.from('KEY=value\n'.repeat(100)), Buffer.alloc(OVER, 0x78)])
    const json = (await scanJson(mkTree({ 'ok.js': 'const a = 1\n', 'evil.txt': buf }))).json!
    expect(degradeCodes(json)).toEqual(['FILE_TOO_LARGE'])
  })
})

describe('L4: binary files are counted and do not use the file cap', () => {
  it('60 files, 20 unknown-binary first in order: they are counted, the cap applies to accepted files only', async () => {
    const files: FileMap = { 'shipguard.policy.yml': policy('  maxFiles: 30') }
    for (let i = 0; i < 20; i++) {
      const b = noise(200, 300 + i)
      b[0] = 0x41
      b[1] = 0
      files[`a${String(i).padStart(2, '0')}.dat`] = b
    }
    for (let i = 0; i < 40; i++) files[`b${String(i).padStart(2, '0')}.txt`] = 'x\n'
    const json = (await scanJson(mkTree(files))).json!
    expect(json.coverage.skipped.unknownBinary).toBe(20)
    expect(json.coverage.scanned).toBe(30)
    expect(json.coverage.truncated).toEqual({ by: 'maxFiles', notReached: json.coverage.discovered - 20 - 30 })
    expect(json.coverage.discovered).toBe(61)
  })
})
