/**
 * Baseline for the blocking findings the scanner raises on its OWN bundled dist/ output.
 *
 * dist/ embeds the scanner's detector patterns and rule text (Razorpay/GCP key regexes,
 * "Access-Control-Allow-Origin: *", TLS-disabled strings, ...), so scanning it always yields
 * blockers. A blanket exemption would let a REAL secret bundled into dist/cli.js ship, so instead
 * the current blockers are pinned: (normalized file, rule id, sha256 of the matched source line)
 * -> count. Anything new OR changed (different line text, more occurrences) fails the gate.
 *
 * Refresh deliberately after reviewing the diff: `UPDATE_DIST_BASELINE=1 pnpm test:slow`.
 */
import { createHash } from 'node:crypto'

export interface BaselineEntry {
  file: string
  ruleId: string
  /** sha256 of the trimmed source line the finding points at (the matched detector text). */
  lineHash: string
  count: number
}

export interface DistFinding {
  id: string
  file: string
  line?: number
  blocking?: boolean
  suppressed?: boolean
}

/** Bundler chunk names carry a content hash (chunk-7XDWXBO4.js); normalize so the baseline is stable. */
export function normalizeDistFile(file: string): string {
  return file.replace(/chunk-[A-Z0-9]+\.js$/, 'chunk-*.js').replace(/-[A-Z0-9]{8}\.js$/, '-*.js')
}

export function summarizeDistBlockers(
  findings: DistFinding[],
  readLine: (file: string, line: number) => string | undefined,
): BaselineEntry[] {
  const counts = new Map<string, BaselineEntry>()
  for (const f of findings) {
    if (!f.blocking || f.suppressed || !f.file.startsWith('shipped-dist/')) continue
    const text = f.line === undefined ? undefined : readLine(f.file, f.line)
    const lineHash = createHash('sha256').update((text ?? `<no-line:${f.line}>`).trim()).digest('hex')
    const file = normalizeDistFile(f.file)
    const key = `${file}\0${f.id}\0${lineHash}`
    const e = counts.get(key)
    if (e) e.count++
    else counts.set(key, { file, ruleId: f.id, lineHash, count: 1 })
  }
  return [...counts.values()].sort((a, b) =>
    `${a.file}${a.ruleId}${a.lineHash}`.localeCompare(`${b.file}${b.ruleId}${b.lineHash}`),
  )
}

/** Entries present now but absent (or with a higher count) in the baseline. */
export function diffAgainstBaseline(current: BaselineEntry[], baseline: BaselineEntry[]): BaselineEntry[] {
  const base = new Map(baseline.map((e) => [`${e.file}\0${e.ruleId}\0${e.lineHash}`, e.count]))
  return current.filter((e) => e.count > (base.get(`${e.file}\0${e.ruleId}\0${e.lineHash}`) ?? 0))
}
