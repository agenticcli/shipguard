/**
 * json-layout.ts: write a JSON file back the way the user had it (indent, compact form, final newline, line ends), so
 * `setup` then `uninstall` hands the user's settings file back byte for byte when ShipGuard's entry was the only change.
 */

export interface JsonLayout {
  /** The indent JSON.stringify takes: a string (spaces or tabs), or undefined for a compact one-line file. */
  indent: string | undefined
  /** The file ended with a newline. */
  finalNewline: boolean
  /** The file used CRLF line ends. */
  crlf: boolean
  /** The layout was recognised (a hand-made layout we cannot copy falls back to 2 spaces). */
  recognised: boolean
}

/** Read the layout of an existing JSON text. Text we cannot read the layout of gets 2 spaces and `recognised: false`. */
export function detectJsonLayout(raw: string): JsonLayout {
  const finalNewline = /\n$/.test(raw)
  const crlf = raw.includes('\r\n')
  const body = raw.trim()
  if (body === '' || body === '{}') return { indent: '  ', finalNewline, crlf, recognised: true } // nothing to copy: the usual 2 spaces
  if (!/[\r\n]/.test(body)) return { indent: undefined, finalNewline, crlf, recognised: true } // compact: one line
  const found = /^\{[ \t]*\r?\n([ \t]+)\S/.exec(body)
  if (found) return { indent: found[1], finalNewline, crlf, recognised: true }
  return { indent: '  ', finalNewline, crlf, recognised: false }
}

/** Serialise `value` in the given layout. */
export function writeJsonLayout(value: unknown, layout: JsonLayout): string {
  let text = JSON.stringify(value, null, layout.indent)
  if (layout.crlf) text = text.replace(/\n/g, '\r\n')
  return text + (layout.finalNewline ? (layout.crlf ? '\r\n' : '\n') : '')
}
