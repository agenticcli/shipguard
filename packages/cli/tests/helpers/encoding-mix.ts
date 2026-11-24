/**
 * QA (2026-11-02): seeded generator of files that hold a credential line as contiguous ASCII bytes
 * inside a random mix of encodings (ASCII, UTF-8 CJK, UTF-16 LE/BE, BOMs, NUL runs, control bytes,
 * Latin-1, noise, magic prefixes, odd padding). Deterministic: the same seed gives the same bytes.
 * Used by the classifier property test and the end-to-end "never SAFE over an unread key" test.
 */
export const MIX_KEY = 'AKIAIOSFODNN7EXAMPLE'
const KEY_LINE = Buffer.from(`\nAWS_ACCESS_KEY_ID=${MIX_KEY}\n`, 'latin1')

/** Small deterministic PRNG (mulberry32). */
function rng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const MAGICS: number[][] = [
  [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], [0xff, 0xd8, 0xff, 0xe0], [0x47, 0x49, 0x46, 0x38, 0x39, 0x61],
  [0x25, 0x50, 0x44, 0x46, 0x2d], [0x50, 0x4b, 0x03, 0x04], [0x1f, 0x8b, 0x08], [0x42, 0x5a, 0x68],
  [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], [0x7f, 0x45, 0x4c, 0x46],
  [0xcf, 0xfa, 0xed, 0xfe], [0x4d, 0x5a], [0x00, 0x61, 0x73, 0x6d], [0x77, 0x4f, 0x46, 0x32], [0x00, 0x01, 0x00, 0x00],
  [0xca, 0xfe, 0xba, 0xbe], [0x00, 0x00, 0x01, 0x00], [...Buffer.from('SQLite format 3\0')],
]

type Gen = (r: () => number, n: number) => Buffer

const pick = <T,>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]
const int = (r: () => number, lo: number, hi: number): number => lo + Math.floor(r() * (hi - lo + 1))

const asciiText: Gen = (r, n) => {
  const out = Buffer.alloc(n)
  for (let i = 0; i < n; i++) out[i] = r() < 0.05 ? 0x0a : int(r, 0x20, 0x7e)
  return out
}
const cjk: Gen = (r, n) =>
  Buffer.from(Array.from({ length: Math.max(1, Math.floor(n / 3)) }, () => String.fromCharCode(int(r, 0x4e00, 0x9fa5))).join(''), 'utf8')
const le = (b: Buffer): Buffer => Buffer.from(b.toString('latin1'), 'utf16le')
const be = (b: Buffer): Buffer => {
  const x = Buffer.from(b.toString('latin1'), 'utf16le')
  x.swap16()
  return x
}
const SEGMENTS: Record<string, Gen> = {
  ascii: asciiText,
  cjkUtf8: cjk,
  utf16leAscii: (r, n) => le(asciiText(r, n)),
  utf16beAscii: (r, n) => be(asciiText(r, n)),
  utf16leCjk: (r, n) => Buffer.from(cjk(r, n).toString('utf8'), 'utf16le'),
  nulRun: (_r, n) => Buffer.alloc(Math.max(1, Math.floor(n / 8))),
  oneNul: () => Buffer.from([0]),
  control: (r, n) => Buffer.from(Array.from({ length: Math.max(1, Math.floor(n / 4)) }, () => int(r, 1, 0x1f))),
  latin1: (r, n) => Buffer.from(Array.from({ length: n }, () => int(r, 0xa0, 0xff))),
  noise: (r, n) => Buffer.from(Array.from({ length: n }, () => int(r, 0, 255))),
  oddByte: (r) => Buffer.from([int(r, 0x20, 0x7e)]),
}
const SEGMENT_NAMES = Object.keys(SEGMENTS)

/** One random file (well under the 512 KiB cap) that contains the credential line as contiguous ASCII. */
export function makeMixCase(seed: number): { buf: Buffer; recipe: string } {
  const r = rng(seed)
  const parts: Buffer[] = []
  const recipe: string[] = []
  const lead = r()
  if (lead < 0.25) {
    const m = pick(r, MAGICS)
    parts.push(Buffer.from(m))
    recipe.push(`magic:${Buffer.from(m).toString('hex')}`)
  } else if (lead < 0.35) {
    parts.push(Buffer.from([0xff, 0xfe]))
    recipe.push('bomLE')
  } else if (lead < 0.42) {
    parts.push(Buffer.from([0xfe, 0xff]))
    recipe.push('bomBE')
  }
  const segs = int(r, 1, 5)
  const keyAt = int(r, 0, segs)
  for (let i = 0; i <= segs; i++) {
    if (i === keyAt) {
      parts.push(KEY_LINE)
      recipe.push('KEY')
    }
    if (i === segs) break
    const name = pick(r, SEGMENT_NAMES)
    const n = int(r, 1, 3000)
    parts.push(SEGMENTS[name](r, n))
    recipe.push(`${name}:${n}`)
  }
  return { buf: Buffer.concat(parts), recipe: recipe.join(' ') }
}
