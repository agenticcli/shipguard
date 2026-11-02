/**
 * The single content classifier for every file the scanner reads (full scan AND `--changed`).
 *
 * Pure: bytes in, verdict out. It takes NO file name on purpose: neither the name nor the
 * extension may influence the result (a text file called `secret.png` is read, a blob called
 * `creds.bin` with no real-binary evidence is not trusted).
 *
 * Order (plan A1, round 3):
 *   1. Empty => text.
 *   2. detectBinary false (no NUL, low control density) => strict UTF-8; failure => invalid-text.
 *      Magic bytes are NEVER consulted here.
 *   3. Flagged + UTF-16 BOM => UTF-16 decode; failure => invalid-text (no other branch is tried).
 *   4. Flagged, no BOM: every plausible UTF-16 reading (LE, BE) is kept.
 *   5. If no UTF-16 reading is plausible and the file is a real binary (magic AND mostly
 *      non-printable) => binary. SQLite and TAR are the exception: they are scanned as ASCII strings.
 *   6. NUL-to-space UTF-8 reading, when it passes the text-likeness test.
 *   7. Nothing plausible => unknown-binary. Otherwise every reading is kept (UNION) and a byte-wise
 *      ASCII reading is added, so a secret hidden by a mixed-encoding file is still seen.
 */
import { decodeUtf8Strict, detectBinary, stripBom, normalizeNewlines } from '@agenticcli/matcher-contract'

// ---------------------------------------------------------------------------
// Thresholds (named and exported for tests)
// ---------------------------------------------------------------------------
export const CONTROL_WINDOW_BYTES = 32 * 1024
/** Share of a UTF-8 NUL-substituted file that may be NUL. */
export const NUL_SHARE_MAX = 0.01
/** Share of control bytes (other than TAB/LF/FF/CR) allowed in the first 32 KiB of a NUL-substituted file. */
export const CONTROL_SHARE_MAX = 0.05
/** A real binary is mostly NOT printable: printable share below this. */
export const PRINTABLE_SHARE_BINARY_BELOW = 0.7
/** UTF-16 plausibility: at most this share of U+0000 code units. */
export const UTF16_NUL_SHARE_MAX = 0.01
/** UTF-16 plausibility: at most this share of other control code units. */
export const UTF16_CONTROL_SHARE_MAX = 0.05
/** UTF-16 plausibility: at least this share of code units inside the named text blocks. */
export const UTF16_BLOCK_SHARE_MIN = 0.8
/**
 * A BOM-less UTF-16 reading needs the NULs to sit on ONE byte parity (ASCII or Latin-1 in UTF-16
 * puts every NUL on the same side). Scattered NULs, as in a NUL-padded blob, fail this.
 */
export const UTF16_PARITY_DOMINANCE = 4
/** Head-read shortcut for files over the size cap. */
export const HEAD_BYTES = 4096

export type Encoding = 'utf8' | 'utf16le' | 'utf16be' | 'ascii'

export interface Reading {
  encoding: Encoding
  /** BOM stripped and newlines normalised, ready for the checks. */
  text: string
  /** true when at least one NUL byte was replaced by a space (utf8 reading only). */
  nulSubstituted: boolean
}

export type ClassifyResult =
  | { kind: 'text'; texts: Reading[]; /** true when the only reading is the byte-wise ASCII one (SQLite, TAR). */ stringsOnly: boolean }
  | { kind: 'binary'; /** Printable strings of a magic-verified binary read in full (under the size cap); absent when none. */ strings?: Reading }
  | { kind: 'unknown-binary' }
  | { kind: 'invalid-text'; encoding: 'utf8' | 'utf16'; reason: string }

// ---------------------------------------------------------------------------
// Magic bytes (content only; used solely for a file detectBinary already flagged)
// ---------------------------------------------------------------------------
interface Magic {
  name: string
  /** Number of leading bytes that make up the signature (the UTF-8 head test starts after it). */
  length: number
}

const startsWith = (b: Uint8Array, sig: number[], at = 0): boolean =>
  b.length >= at + sig.length && sig.every((v, i) => b[at + i] === v)
const ascii = (s: string): number[] => Array.from(s, (c) => c.charCodeAt(0))

export function matchMagic(b: Uint8Array): Magic | null {
  const m = (name: string, length: number): Magic => ({ name, length })
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47])) return m('png', 4)
  if (startsWith(b, [0xff, 0xd8, 0xff])) return m('jpeg', 3)
  if (startsWith(b, ascii('GIF8'))) return m('gif', 4)
  if (startsWith(b, ascii('RIFF')) && startsWith(b, ascii('WEBP'), 8)) return m('webp', 12)
  if (startsWith(b, [0, 0, 1, 0])) return m('ico', 4)
  if (startsWith(b, ascii('%PDF'))) return m('pdf', 4)
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04])) return m('zip', 4)
  if (startsWith(b, [0x1f, 0x8b])) return m('gzip', 2)
  if (startsWith(b, ascii('BZh'))) return m('bzip2', 3)
  if (startsWith(b, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return m('xz', 6)
  if (startsWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return m('7z', 6)
  if (startsWith(b, ascii('ustar'), 257)) return m('tar', 262)
  if (startsWith(b, [0x7f, 0x45, 0x4c, 0x46])) return m('elf', 4)
  if (
    startsWith(b, [0xfe, 0xed, 0xfa, 0xce]) || startsWith(b, [0xfe, 0xed, 0xfa, 0xcf]) ||
    startsWith(b, [0xce, 0xfa, 0xed, 0xfe]) || startsWith(b, [0xcf, 0xfa, 0xed, 0xfe])
  ) return m('macho', 4)
  if (startsWith(b, [0x4d, 0x5a])) return m('pe', 2)
  if (startsWith(b, [0x00, 0x61, 0x73, 0x6d])) return m('wasm', 4)
  if (startsWith(b, ascii('SQLite format 3'))) return m('sqlite', 16)
  if (startsWith(b, ascii('wOFF'))) return m('woff', 4)
  if (startsWith(b, ascii('wOF2'))) return m('woff2', 4)
  if (startsWith(b, [0x00, 0x01, 0x00, 0x00])) return m('ttf', 4)
  if (startsWith(b, ascii('OTTO'))) return m('otf', 4)
  if (startsWith(b, ascii('ftyp'), 4)) return m('mp4', 8)
  if (startsWith(b, [0xca, 0xfe, 0xba, 0xbe])) return m('class', 4)
  return null
}

/** Formats whose payload is stored uncompressed, so an ASCII reading of the bytes finds secrets in it. */
const STRINGS_READABLE = new Set(['sqlite', 'tar'])

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const isTextWhitespace = (b: number): boolean => b === 0x09 || b === 0x0a || b === 0x0c || b === 0x0d

/**
 * Length of a complete, well-formed UTF-8 multibyte sequence starting at i (0 if not one).
 * Standard well-formed table (no overlongs, no surrogates, max U+10FFFF).
 */
function utf8SeqLen(b: Uint8Array, i: number): number {
  const c = b[i]
  const cont = (k: number, lo = 0x80, hi = 0xbf): boolean => i + k < b.length && b[i + k] >= lo && b[i + k] <= hi
  if (c >= 0xc2 && c <= 0xdf) return cont(1) ? 2 : 0
  if (c === 0xe0) return cont(1, 0xa0, 0xbf) && cont(2) ? 3 : 0
  if ((c >= 0xe1 && c <= 0xec) || c === 0xee || c === 0xef) return cont(1) && cont(2) ? 3 : 0
  if (c === 0xed) return cont(1, 0x80, 0x9f) && cont(2) ? 3 : 0
  if (c === 0xf0) return cont(1, 0x90, 0xbf) && cont(2) && cont(3) ? 4 : 0
  if (c >= 0xf1 && c <= 0xf3) return cont(1) && cont(2) && cont(3) ? 4 : 0
  if (c === 0xf4) return cont(1, 0x80, 0x8f) && cont(2) && cont(3) ? 4 : 0
  return 0
}

/** Share of bytes that count as printable: ASCII 0x20-0x7E, TAB/LF/FF/CR, and complete valid UTF-8 sequences. */
function printableShare(b: Uint8Array): number {
  if (b.length === 0) return 1
  let printable = 0
  for (let i = 0; i < b.length; ) {
    const c = b[i]
    if ((c >= 0x20 && c <= 0x7e) || isTextWhitespace(c)) {
      printable++
      i++
    } else if (c >= 0xc2) {
      const n = utf8SeqLen(b, i)
      if (n > 0) {
        printable += n
        i += n
      } else i++
    } else i++
  }
  return printable / b.length
}

function isRealBinary(b: Uint8Array): Magic | null {
  const magic = matchMagic(b)
  if (!magic) return null
  return printableShare(b) < PRINTABLE_SHARE_BINARY_BELOW ? magic : null
}

/** Strict UTF-8 on a slice, forgiving at most 3 trailing bytes of a sequence cut by the head limit. */
function validUtf8WithCutTail(b: Uint8Array): boolean {
  for (let cut = 0; cut <= 3 && cut <= b.length; cut++) {
    if (decodeUtf8Strict(b.subarray(0, b.length - cut)).ok) return true
  }
  return false
}

/**
 * Head-read shortcut for a file OVER the size cap (judge R3 MAJOR 1). True only when the head
 * (a) matches a magic value AND (b) FAILS a strict UTF-8 decode taken AFTER the magic bytes.
 * Many magic values start with a non-UTF-8 byte, so including them would make every head "fail".
 * A head of NULs and ASCII is valid UTF-8, so "PNG magic + NUL-heavy head + secret later" is not a
 * shortcut candidate and ends as FILE_TOO_LARGE (degraded).
 */
export function headLooksLikeRealBinary(head: Uint8Array): boolean {
  const h = head.subarray(0, HEAD_BYTES)
  const magic = matchMagic(h)
  if (!magic) return false
  return !validUtf8WithCutTail(h.subarray(Math.min(magic.length, h.length)))
}

const finish = (s: string): string => normalizeNewlines(stripBom(s))

function fromCharCodes(u16: Uint16Array): string {
  const parts: string[] = []
  const CHUNK = 8192
  for (let i = 0; i < u16.length; i += CHUNK) {
    parts.push(String.fromCharCode.apply(null, Array.from(u16.subarray(i, i + CHUNK))))
  }
  return parts.join('')
}

/** Strict UTF-16 decode of the whole buffer: even length, no lone surrogates. Null on failure. */
function decodeUtf16(b: Uint8Array, bigEndian: boolean): Uint16Array | null {
  if (b.length % 2 !== 0) return null
  const n = b.length / 2
  const u = new Uint16Array(n)
  for (let i = 0; i < n; i++) {
    u[i] = bigEndian ? (b[2 * i] << 8) | b[2 * i + 1] : (b[2 * i + 1] << 8) | b[2 * i]
  }
  for (let i = 0; i < n; i++) {
    const c = u[i]
    if (c >= 0xd800 && c <= 0xdbff) {
      if (i + 1 >= n || u[i + 1] < 0xdc00 || u[i + 1] > 0xdfff) return null
      i++
    } else if (c >= 0xdc00 && c <= 0xdfff) return null
  }
  return u
}

const BLOCKS: Array<[number, number]> = [
  [0x09, 0x0d], [0x20, 0x7e], [0xa0, 0x24f], [0x370, 0x1fff], [0x2000, 0x206f],
  [0x3000, 0x9fff], [0xac00, 0xd7af], [0xff00, 0xffef],
]

function plausibleUtf16(u: Uint16Array): boolean {
  if (u.length === 0) return false
  let nul = 0
  let control = 0
  let inBlocks = 0
  for (let i = 0; i < u.length; i++) {
    const c = u[i]
    if (c === 0) nul++
    else if (c < 0x20 && !(c >= 0x09 && c <= 0x0d)) control++
    else if (c >= 0x7f && c < 0xa0) control++
    for (const [lo, hi] of BLOCKS) {
      if (c >= lo && c <= hi) {
        inBlocks++
        break
      }
    }
  }
  return nul / u.length <= UTF16_NUL_SHARE_MAX && control / u.length <= UTF16_CONTROL_SHARE_MAX && inBlocks / u.length >= UTF16_BLOCK_SHARE_MIN
}

/** Which UTF-16 byte order the NUL bytes point to: 'le' (NULs on odd indexes), 'be' (even), or null. */
function nulParity(b: Uint8Array): 'le' | 'be' | null {
  let even = 0
  let odd = 0
  for (let i = 0; i < b.length; i++) {
    if (b[i] === 0) (i & 1 ? odd++ : even++)
  }
  if (odd > 0 && odd >= UTF16_PARITY_DOMINANCE * even) return 'le'
  if (even > 0 && even >= UTF16_PARITY_DOMINANCE * odd) return 'be'
  return null
}

function nulSubstitutedReading(b: Uint8Array): Reading | null {
  let nul = 0
  for (let i = 0; i < b.length; i++) if (b[i] === 0) nul++
  if (nul / b.length > NUL_SHARE_MAX) return null
  const s = new Uint8Array(b)
  for (let i = 0; i < s.length; i++) if (s[i] === 0) s[i] = 0x20
  const win = Math.min(s.length, CONTROL_WINDOW_BYTES)
  let control = 0
  for (let i = 0; i < win; i++) if (s[i] < 0x20 && !isTextWhitespace(s[i])) control++
  if (control / win > CONTROL_SHARE_MAX) return null
  const d = decodeUtf8Strict(s)
  if (!d.ok) return null
  return { encoding: 'utf8', text: finish(d.text), nulSubstituted: true }
}

/** Byte-wise ASCII reading: every byte outside TAB/LF/CR/0x20-0x7E becomes one space (lines unchanged). */
function asciiReading(b: Uint8Array): Reading {
  const out = new Uint8Array(b.length)
  for (let i = 0; i < b.length; i++) {
    const c = b[i]
    out[i] = (c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d ? c : 0x20
  }
  return { encoding: 'ascii', text: finish(Buffer.from(out).toString('latin1')), nulSubstituted: false }
}

/** Shortest run of printable ASCII that counts as a string (like `strings -n 8`). */
export const STRINGS_MIN_RUN = 8

/**
 * strings-style reading of a binary: runs of at least STRINGS_MIN_RUN printable ASCII bytes
 * (0x20-0x7E), one run per line, so a reported line number is the run's index, not a file line.
 * Null when there is no run.
 */
export function stringsReading(b: Uint8Array): Reading | null {
  const runs: string[] = []
  let start = -1
  for (let i = 0; i <= b.length; i++) {
    const printable = i < b.length && b[i] >= 0x20 && b[i] <= 0x7e
    if (printable) {
      if (start < 0) start = i
    } else if (start >= 0) {
      if (i - start >= STRINGS_MIN_RUN) runs.push(Buffer.from(b.subarray(start, i)).toString('latin1'))
      start = -1
    }
  }
  if (runs.length === 0) return null
  return { encoding: 'ascii', text: runs.join('\n'), nulSubstituted: false }
}

function withAscii(readings: Reading[], b: Uint8Array): Reading[] {
  const a = asciiReading(b)
  return readings.some((r) => r.text === a.text) ? readings : [...readings, a]
}

// ---------------------------------------------------------------------------
// classifyFile
// ---------------------------------------------------------------------------
export function classifyFile(buffer: Uint8Array): ClassifyResult {
  if (buffer.length === 0) return { kind: 'text', texts: [{ encoding: 'utf8', text: '', nulSubstituted: false }], stringsOnly: false }

  if (!detectBinary(buffer)) {
    const d = decodeUtf8Strict(buffer)
    if (!d.ok) return { kind: 'invalid-text', encoding: 'utf8', reason: d.reason }
    return { kind: 'text', texts: [{ encoding: 'utf8', text: finish(d.text), nulSubstituted: false }], stringsOnly: false }
  }

  // Flagged. UTF-16 BOM: the BOM makes the reading certain; a failed decode is NOT retried.
  const le = buffer[0] === 0xff && buffer[1] === 0xfe && !(buffer[2] === 0 && buffer[3] === 0)
  const be = buffer[0] === 0xfe && buffer[1] === 0xff
  if (le || be) {
    const u = decodeUtf16(buffer, be)
    if (!u) return { kind: 'invalid-text', encoding: 'utf16', reason: 'UTF-16 with BOM, invalid (odd length or lone surrogate)' }
    const bomReading: Reading = { encoding: be ? 'utf16be' : 'utf16le', text: finish(fromCharCodes(u)), nulSubstituted: false }
    return { kind: 'text', texts: withAscii([bomReading], buffer), stringsOnly: false }
  }

  const readings: Reading[] = []
  const parity = nulParity(buffer)
  for (const order of ['le', 'be'] as const) {
    if (parity !== order) continue
    const u = decodeUtf16(buffer, order === 'be')
    if (u && plausibleUtf16(u)) {
      readings.push({ encoding: order === 'be' ? 'utf16be' : 'utf16le', text: finish(fromCharCodes(u)), nulSubstituted: false })
    }
  }

  if (readings.length === 0) {
    const magic = isRealBinary(buffer)
    if (magic) {
      if (STRINGS_READABLE.has(magic.name)) return { kind: 'text', texts: [asciiReading(buffer)], stringsOnly: true }
      // The whole file is in memory (it is under the size cap), so also read its printable strings:
      // a magic header must never hide a credential that sits in the same file.
      const strings = stringsReading(buffer)
      return strings ? { kind: 'binary', strings } : { kind: 'binary' }
    }
  }

  const nulReading = nulSubstitutedReading(buffer)
  if (nulReading) readings.push(nulReading)
  if (readings.length === 0) return { kind: 'unknown-binary' }
  return { kind: 'text', texts: withAscii(readings, buffer), stringsOnly: false }
}
