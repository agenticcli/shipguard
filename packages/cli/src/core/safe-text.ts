/**
 * safe-text.ts: the ONE function every server-provided string passes before it is printed or put in JSON
 * (spec 02 "Safe display", design 3.5). The server is trusted to word things, never to control the
 * terminal: no escape sequences, no control or invisible characters, no links, bounded length.
 * Colour is added by the CLI around the text, never inside it.
 */

/** Length caps in characters (spec 02 "Safe display"). Display limits only, not plan facts. */
export const TEXT_CAPS = {
  offer: 300,
  usage: 120,
  label: 32,
  limit: 200,
  account: 200,
  updateNotice: 200,
  item: 40,
  items: 8,
} as const

// ANSI CSI, OSC (BEL or ST terminated), DCS/SOS/PM/APC strings, and any other ESC + one char.
const ESCAPE_SEQUENCES = new RegExp(
  [
    '\\u001b\\[[0-?]*[ -/]*[@-~]', // CSI
    '\\u009b[0-?]*[ -/]*[@-~]', // 8-bit CSI
    '\\u001b\\][^\\u0007\\u001b]*(?:\\u0007|\\u001b\\\\)?', // OSC
    '\\u009d[^\\u0007\\u009c]*(?:\\u0007|\\u009c)?', // 8-bit OSC
    '\\u001b[PX^_][^\\u001b]*(?:\\u001b\\\\)?', // DCS, SOS, PM, APC
    '\\u001b[\\s\\S]?', // any other ESC pair
  ].join('|'),
  'g',
)

// The server never sends a link (links come from the closed slot list). Removed: scheme://..., the opaque schemes
// (mailto:, javascript:, data:, ...), e-mail addresses, www.host names, and bare domains (evil.com, evil.com/x). A bare
// domain needs a well-known top-level name, so "Next.js" and version numbers are not touched.
const TLDS = 'com|net|org|io|dev|app|co|xyz|info|biz|ru|cn|tk|top|ly|me|sh|ai|gg|us|uk|de|fr|cc|link|click|site|online|store|shop|page|pw|ws|to|ink|club|live|tech|work|zip|mov'
const URLS = new RegExp(
  [
    '\\b[a-z][a-z0-9+.-]{1,15}:\\/\\/\\S*',
    '\\b(?:mailto|javascript|vbscript|data|file|tel|sms|blob|about):\\S*',
    '[^\\s@]+@[^\\s@]+\\.[a-z]{2,}\\S*',
    '\\bwww\\.\\S+',
    `\\b(?:[a-z0-9-]+\\.)+(?:${TLDS})\\b(?:[/:?#]\\S*)?`,
  ].join('|'),
  'gi',
)

// C0, DEL, C1, bidi controls, zero-width and tag characters.
const UNSAFE_CHARS = new RegExp(
  '[\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200b-\\u200f\\u202a-\\u202e\\u2060\\u2066-\\u2069\\ufeff\\u{e0000}-\\u{e007f}]',
  'gu',
)

/**
 * Returns the cleaned string, or null when the value is not a string or nothing printable is left.
 * Over the cap it is cut and ends with "..." (the result is never longer than maxLen).
 */
export function safeServerText(value: unknown, maxLen: number): string | null {
  if (typeof value !== 'string' || !Number.isInteger(maxLen) || maxLen < 4) return null
  // Bound the work on hostile input before any regex runs; the caps are far below this.
  const bounded = value.length > 8192 ? value.slice(0, 8192) : value
  const cleaned = bounded
    .normalize('NFC')
    .replace(ESCAPE_SEQUENCES, ' ')
    .replace(URLS, ' ')
    .replace(UNSAFE_CHARS, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (cleaned === '') return null
  const chars = Array.from(cleaned)
  if (chars.length <= maxLen) return cleaned
  return chars.slice(0, maxLen - 3).join('').trimEnd() + '...'
}

/** A list of short names (stacks, areas): strings only, each capped, at most TEXT_CAPS.items. */
export function safeServerList(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  const out: string[] = []
  for (const item of value) {
    const text = safeServerText(item, TEXT_CAPS.item)
    if (text !== null) out.push(text)
    if (out.length >= TEXT_CAPS.items) break
  }
  return out
}
