/**
 * B1, B17, B23 (unit rows): the single content classifier.
 *
 * Plan: docs/plans/scan-honest-coverage-20261102.md (D2, D3, D4, A1) plus
 * docs/plans/JUDGE-R3-BUILD-REQUIREMENTS.md. Fixture keys are the public example values.
 */
import { describe, it, expect, expectTypeOf } from 'vitest'
import {
  classifyFile,
  headLooksLikeRealBinary,
  type ClassifyResult,
  type Reading,
} from '../../src/utils/classify.js'

const KEY = 'AKIAIOSFODNN7EXAMPLE'
const ENV_KEY = `AWS_ACCESS_KEY_ID=${KEY}\n`

const bytes = (...n: number[]): Buffer => Buffer.from(n)
const ascii = (s: string): Buffer => Buffer.from(s, 'latin1')
const utf16le = (s: string, bom = false): Buffer =>
  Buffer.concat([bom ? bytes(0xff, 0xfe) : Buffer.alloc(0), Buffer.from(s, 'utf16le')])
const utf16be = (s: string, bom = false): Buffer => {
  const b = Buffer.from(s, 'utf16le')
  b.swap16()
  return Buffer.concat([bom ? bytes(0xfe, 0xff) : Buffer.alloc(0), b])
}

/** Deterministic pseudo-random bytes (LCG), so fixtures are reproducible. */
function noise(n: number, seed = 12345): Buffer {
  const out = Buffer.alloc(n)
  let s = seed
  for (let i = 0; i < n; i++) {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0
    out[i] = (s >>> 16) & 0xff
  }
  return out
}

function textOf(r: ClassifyResult): Reading[] {
  if (r.kind !== 'text') throw new Error(`expected text, got ${r.kind}`)
  return r.texts
}
const anyHasKey = (r: ClassifyResult): boolean => r.kind === 'text' && r.texts.some((t) => t.text.includes(KEY))

describe('classifyFile: text branches', () => {
  it('takes no file name (the name and extension can never influence the result)', () => {
    expectTypeOf(classifyFile).parameters.toEqualTypeOf<[Uint8Array]>()
  })

  it('empty buffer is text', () => {
    const r = classifyFile(new Uint8Array(0))
    expect(textOf(r)).toHaveLength(1)
    expect(textOf(r)[0].text).toBe('')
  })

  it('plain ASCII/UTF-8 is exactly one utf8 reading, no extra readings', () => {
    const r = classifyFile(Buffer.from(`hello\n${ENV_KEY}`))
    expect(textOf(r)).toHaveLength(1)
    expect(textOf(r)[0]).toMatchObject({ encoding: 'utf8', nulSubstituted: false })
  })

  it('UTF-8 BOM is stripped and CRLF is folded', () => {
    const r = classifyFile(Buffer.concat([bytes(0xef, 0xbb, 0xbf), Buffer.from('a\r\nb\n')]))
    expect(textOf(r)[0].text).toBe('a\nb\n')
  })

  it('UTF-16LE with BOM is decoded and the key is found', () => {
    const r = classifyFile(utf16le(`x\r\n${ENV_KEY}`, true))
    expect(textOf(r).some((t) => t.encoding === 'utf16le' && t.text.includes(KEY))).toBe(true)
    expect(textOf(r).find((t) => t.encoding === 'utf16le')!.text.startsWith('x\n')).toBe(true)
  })

  it('UTF-16BE with BOM is decoded and the key is found', () => {
    const r = classifyFile(utf16be(`x\n${ENV_KEY}`, true))
    expect(textOf(r).some((t) => t.encoding === 'utf16be' && t.text.includes(KEY))).toBe(true)
  })

  it('BOM-less UTF-16LE ASCII text is decoded', () => {
    const r = classifyFile(utf16le(`# c\n${ENV_KEY}`))
    expect(textOf(r).some((t) => t.encoding === 'utf16le' && t.text.includes(KEY))).toBe(true)
  })

  it('BOM-less UTF-16BE ASCII text is decoded', () => {
    const r = classifyFile(utf16be(`# c\n${ENV_KEY}`))
    expect(textOf(r).some((t) => t.encoding === 'utf16be' && t.text.includes(KEY))).toBe(true)
  })

  it('BOM-less UTF-16LE: 10,000 CJK characters then a key (Codex case) finds the key', () => {
    const r = classifyFile(utf16le('汉'.repeat(10_000) + '\n' + ENV_KEY))
    expect(anyHasKey(r)).toBe(true)
  })

  it('BOM-less UTF-16BE: 10,000 CJK characters then a key finds the key (B23)', () => {
    const r = classifyFile(utf16be('汉'.repeat(10_000) + '\n' + ENV_KEY))
    expect(anyHasKey(r)).toBe(true)
    expect(textOf(r).some((t) => t.encoding === 'utf16be' && t.text.includes(KEY))).toBe(true)
  })

  it('one NUL in 10 KB of text: NUL becomes one space, same length, same line and column', () => {
    const body = 'x'.repeat(5000) + '\n' + ENV_KEY + 'y'.repeat(5000) + '\n'
    const withNul = body.slice(0, 100) + '\0' + body.slice(101)
    const r = classifyFile(Buffer.from(withNul))
    const t = textOf(r).find((x) => x.encoding === 'utf8')!
    expect(t.nulSubstituted).toBe(true)
    expect(t.text).toHaveLength(body.length)
    expect(t.text.indexOf(KEY)).toBe(body.indexOf(KEY))
  })

  it("ambiguity (B23): 'a' x 1000 + key + one NUL is read several ways and the key is found", () => {
    const r = classifyFile(Buffer.from('a'.repeat(1000) + '\n' + ENV_KEY + '\0'))
    expect(anyHasKey(r)).toBe(true)
    const nonAscii = textOf(r).filter((t) => t.encoding !== 'ascii')
    expect(nonAscii.length).toBeGreaterThanOrEqual(2)
  })

  it('CJK UTF-8 + ASCII magic prefix + one NUL + key is text, not binary (B23, spoof)', () => {
    const buf = Buffer.concat([ascii('%PDF-1.7\n'), Buffer.from('汉字漢字'.repeat(300) + '\n'), bytes(0), Buffer.from(ENV_KEY)])
    const r = classifyFile(buf)
    expect(r.kind).toBe('text')
    expect(anyHasKey(r)).toBe(true)
  })
})

describe('classifyFile: mixed encodings (judge R3 MAJOR 2)', () => {
  it('(a) ASCII .env with a key, then an appended UTF-16LE block (PowerShell 5.1 >>): key found', () => {
    const head = ascii(ENV_KEY + '#'.repeat(2000 - ENV_KEY.length - 1) + '\n')
    expect(head.length % 2).toBe(0)
    const r = classifyFile(Buffer.concat([head, utf16le('EXTRA=1\nMORE=2\nSTILL=3\nAND=4\nX=5\nY=6\nZ=7\n')]))
    expect(r.kind).toBe('text')
    expect(anyHasKey(r)).toBe(true)
  })

  it('(b) BOM-marked UTF-16LE file with ASCII (and a key) appended: key found', () => {
    const r = classifyFile(Buffer.concat([utf16le('# note\n', true), ascii('#' + ENV_KEY + '#'.repeat(1))]))
    expect(r.kind).toBe('text')
    expect(anyHasKey(r)).toBe(true)
  })

  it('every flagged text file gets a byte-wise ASCII reading (non-text bytes become spaces, newlines kept)', () => {
    const r = classifyFile(utf16le(`a\n${ENV_KEY}`, true))
    const a = textOf(r).find((t) => t.encoding === 'ascii')
    expect(a).toBeDefined()
    expect(a!.text.split('\n')).toHaveLength(3)
  })

  it('no ASCII reading is added to ordinary UTF-8 text (it would only double the work)', () => {
    expect(textOf(classifyFile(Buffer.from('plain\n'))).map((t) => t.encoding)).toEqual(['utf8'])
  })
})

describe('classifyFile: not text', () => {
  it('BOM-less random even-length bytes are not text', () => {
    const r = classifyFile(noise(4096))
    expect(r.kind).toBe('unknown-binary')
  })

  it('BOM-marked UTF-16 with a lone surrogate is invalid-text (degraded), never retried', () => {
    const r = classifyFile(Buffer.concat([bytes(0xff, 0xfe), Buffer.from([0x41, 0x00, 0x00, 0xd8, 0x42, 0x00])]))
    expect(r.kind).toBe('invalid-text')
    expect((r as { reason: string }).reason).toMatch(/UTF-16 with BOM, invalid/)
  })

  it('BOM-marked UTF-16 of odd byte length is invalid-text', () => {
    const r = classifyFile(Buffer.concat([bytes(0xff, 0xfe), Buffer.from([0x41, 0x00, 0x42])]))
    expect(r.kind).toBe('invalid-text')
  })

  it('UTF-32LE BOM is not UTF-16: unknown-binary', () => {
    const r = classifyFile(Buffer.concat([bytes(0xff, 0xfe, 0, 0), Buffer.from('A\0\0\0B\0\0\0C\0\0\0D\0\0\0')]))
    expect(r.kind).toBe('unknown-binary')
  })

  it('2% scattered NULs and no magic (creds.bin / dump.dat style) is unknown-binary', () => {
    const b = Buffer.from('secret-material-'.repeat(400).slice(0, 6400))
    for (let i = 25; i < b.length; i += 50) b[i] = 0
    expect(b.length % 2).toBe(0)
    expect(classifyFile(b).kind).toBe('unknown-binary')
  })

  it('B17 (documents a limit): a key split by an embedded NUL is NOT matched, and the file is not degraded', () => {
    const split = KEY.slice(0, 4) + '\0' + KEY.slice(4)
    const r = classifyFile(Buffer.from(`# config\nAWS_ACCESS_KEY_ID=${split}\n` + 'x'.repeat(2000) + '\n'))
    expect(r.kind).toBe('text')
    expect(textOf(r).some((t) => t.nulSubstituted)).toBe(true)
    expect(anyHasKey(r)).toBe(false)
  })
})

describe('classifyFile: real binaries (magic AND binary-dominant, only for flagged files)', () => {
  const body = noise(6000, 99)
  const flagged = (head: Buffer): Buffer => Buffer.concat([head, bytes(0), body])
  const samples: Array<[string, Buffer]> = [
    ['PNG', flagged(bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a))],
    ['ZIP', flagged(bytes(0x50, 0x4b, 0x03, 0x04))],
    ['gzip', flagged(bytes(0x1f, 0x8b, 0x08))],
    ['ELF', flagged(bytes(0x7f, 0x45, 0x4c, 0x46))],
    ['WASM', flagged(bytes(0x00, 0x61, 0x73, 0x6d))],
    ['PDF', flagged(Buffer.concat([ascii('%PDF-1.4\n%'), bytes(0xe2, 0xe3, 0xcf, 0xd3, 0x0a)]))],
    ['WOFF2', flagged(bytes(0x77, 0x4f, 0x46, 0x32))],
  ]
  for (const [name, buf] of samples) {
    it(`${name} is a real binary`, () => {
      expect(classifyFile(buf).kind).toBe('binary')
    })
  }

  it('SPOOF: a no-NUL .env that starts "MZ=1" is text (magic is never consulted)', () => {
    const r = classifyFile(Buffer.from(`MZ=1\n${ENV_KEY}`))
    expect(r.kind).toBe('text')
    expect(anyHasKey(r)).toBe(true)
  })

  it('SPOOF: a text file with "ustar" at offset 257 is text', () => {
    const t = 'x'.repeat(257) + 'ustar' + '\n' + ENV_KEY
    const r = classifyFile(Buffer.from(t))
    expect(r.kind).toBe('text')
    expect(anyHasKey(r)).toBe(true)
  })

  it('SPOOF: a PNG header followed by KEY= lines is never binary', () => {
    const buf = Buffer.concat([bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0), Buffer.from(ENV_KEY.repeat(40))])
    expect(classifyFile(buf).kind).not.toBe('binary')
  })

  it('mutation guard: a magic prefix + UTF-16LE ASCII text + a key is read as UTF-16 and the key is found', () => {
    const buf = Buffer.concat([ascii('%PDF'), utf16le('\n' + ENV_KEY.repeat(3))])
    expect(buf.length % 2).toBe(0)
    const r = classifyFile(buf)
    expect(r.kind).toBe('text')
    expect(anyHasKey(r)).toBe(true)
  })

  it('SQLite (e.g. a Prisma dev.db): counted as strings, key inside a row is found', () => {
    const page = Buffer.concat([ascii('SQLite format 3'), bytes(0, 0x10, 0x00, 0x01, 0x01), noise(3000, 5), bytes(0, 0, 0), ascii('CREATE TABLE t(k TEXT)'), bytes(0, 1, 2), ascii(KEY), bytes(0, 0)])
    const r = classifyFile(page)
    expect(r.kind).toBe('text')
    expect(anyHasKey(r)).toBe(true)
  })

  it('uncompressed TAR: key inside a member is found through the ASCII reading', () => {
    const hdr = Buffer.alloc(512)
    hdr.write('config.env', 0)
    hdr.write('ustar', 257)
    const data = Buffer.alloc(512)
    data.write(ENV_KEY, 0)
    const r = classifyFile(Buffer.concat([hdr, data, Buffer.alloc(1024)]))
    expect(r.kind).toBe('text')
    expect(anyHasKey(r)).toBe(true)
  })
})

describe('headLooksLikeRealBinary (head-read shortcut for files over the size cap)', () => {
  const head = (magic: Buffer, rest: Buffer): Buffer => Buffer.concat([magic, rest]).subarray(0, 4096)
  const png = bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)
  const jpeg = bytes(0xff, 0xd8, 0xff)
  const gzip = bytes(0x1f, 0x8b)

  it('magic + a head that fails strict UTF-8 after the magic: real binary (PNG, JPEG, gzip)', () => {
    expect(headLooksLikeRealBinary(head(png, noise(4096, 3)))).toBe(true)
    expect(headLooksLikeRealBinary(head(jpeg, noise(4096, 4)))).toBe(true)
    expect(headLooksLikeRealBinary(head(gzip, noise(4096, 5)))).toBe(true)
  })

  it('judge R3 MAJOR 1: the magic bytes themselves are never part of the UTF-8 test', () => {
    // PNG 0x89, JPEG 0xFF and gzip 0x8B are not valid UTF-8 on their own. Testing them would make
    // every attack head "fail", so the strict-UTF-8 test must start AFTER the magic.
    expect(headLooksLikeRealBinary(head(png, Buffer.alloc(4096)))).toBe(false)
    expect(headLooksLikeRealBinary(head(jpeg, Buffer.alloc(4096)))).toBe(false)
    expect(headLooksLikeRealBinary(head(gzip, Buffer.alloc(4096)))).toBe(false)
  })

  it('a head cut in the middle of a multi-byte character (at most 3 trailing bytes) still counts as valid UTF-8', () => {
    const t = Buffer.concat([png, Buffer.from('汉'.repeat(1500))]).subarray(0, 4095) // cuts a 3-byte char
    expect(headLooksLikeRealBinary(t)).toBe(false)
  })

  it('no magic: never', () => {
    expect(headLooksLikeRealBinary(noise(4096, 8))).toBe(false)
  })
})
