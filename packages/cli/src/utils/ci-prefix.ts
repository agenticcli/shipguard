/** With CI set every stderr line starts with `shipguard: ` (spec 01 rule 9); stdout is unchanged. Lines already carrying a fixed prefix (the quiet line, the gate's `shipguard-gate: ` line) keep it. */
import { detectCi } from '../core/telemetry.js'

const PREFIX = 'shipguard: '

/** Prefix every line of `chunk`; `atLineStart` = the previous write ended a line. */
export function prefixLines(chunk: string, atLineStart: boolean): { text: string; atLineStart: boolean } {
  let text = ''
  for (const line of chunk.split(/(?<=\n)/)) {
    if (atLineStart && !line.startsWith(PREFIX) && !line.startsWith('shipguard-gate: ')) text += PREFIX
    text += line
    atLineStart = line.endsWith('\n')
  }
  return { text, atLineStart }
}

let installed = false

export function installCiStderrPrefix(env: NodeJS.ProcessEnv = process.env): void {
  if (installed || !detectCi(env)) return
  installed = true
  const write = process.stderr.write.bind(process.stderr) as (chunk: unknown, ...rest: unknown[]) => boolean
  let atLineStart = true
  process.stderr.write = ((chunk: unknown, ...rest: unknown[]): boolean => {
    if (typeof chunk !== 'string' && !(chunk instanceof Uint8Array)) return write(chunk, ...rest)
    const r = prefixLines(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'), atLineStart)
    atLineStart = r.atLineStart
    return write(r.text, ...rest)
  }) as typeof process.stderr.write
}
