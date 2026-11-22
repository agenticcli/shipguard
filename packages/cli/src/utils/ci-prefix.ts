/**
 * ci-prefix.ts: with CI set, every stderr line starts with `shipguard: ` so a CI log can be filtered with one grep
 * (spec 01 rule 9). stdout is unchanged. A line that already carries one of our fixed prefixes keeps it: the quiet
 * line `shipguard: ...` and the gate's machine line `shipguard-gate: ...` (spec 03) never change.
 */
import { detectCi } from '../core/telemetry.js'

export const CI_PREFIX = 'shipguard: '

/** Prefix every line of `chunk`; `atLineStart` says whether the previous write ended a line. Returns the text and the new state. */
export function prefixLines(chunk: string, atLineStart: boolean): { text: string; atLineStart: boolean } {
  let out = ''
  let start = atLineStart
  let rest = chunk
  while (rest.length > 0) {
    const nl = rest.indexOf('\n')
    const line = nl === -1 ? rest : rest.slice(0, nl + 1)
    if (start && !line.startsWith(CI_PREFIX) && !line.startsWith('shipguard-gate: ')) out += CI_PREFIX
    out += line
    start = nl !== -1
    rest = nl === -1 ? '' : rest.slice(nl + 1)
  }
  return { text: out, atLineStart: start }
}

let installed = false

/** Wrap process.stderr.write once, only when CI is set. */
export function installCiStderrPrefix(env: NodeJS.ProcessEnv = process.env): void {
  if (installed || !detectCi(env)) return
  installed = true
  const original = process.stderr.write.bind(process.stderr) as (chunk: unknown, ...rest: unknown[]) => boolean
  let atLineStart = true
  process.stderr.write = ((chunk: unknown, ...rest: unknown[]): boolean => {
    if (typeof chunk !== 'string' && !(chunk instanceof Uint8Array)) return original(chunk, ...rest)
    const r = prefixLines(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'), atLineStart)
    atLineStart = r.atLineStart
    return original(r.text, ...rest)
  }) as typeof process.stderr.write
}
