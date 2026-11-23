/**
 * Golden-equality helpers: scan a generated tree in-process and reduce the findings to an
 * order-normalized digest, so two scans (before/after a speed change, prefilter on/off) can be
 * compared exactly. Generated trees live in a temp dir and are never committed.
 */
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Finding } from '@agenticcli/shared'
import { generateRepo } from './synthetic-repo.mjs'
import { scan } from '../../src/core/scanner.js'

export interface Digest {
  files: number
  findings: number
  /** sha256 over the sorted finding lines. */
  sha256: string
  /** Findings per rule id, for readable failures. */
  byRule: Record<string, number>
}

const sha = (s: string): string => createHash('sha256').update(s).digest('hex')

export function findingLine(f: Finding): string {
  return [f.id, f.file, f.line, f.column, f.suppressed ? 's' : 'a', f.blocking ? 'b' : 'w', sha(f.evidence ?? '')].join('|')
}

export function digestOf(findings: Finding[], files: number): Digest {
  const lines = findings.map(findingLine).sort()
  const byRule: Record<string, number> = {}
  for (const f of findings) byRule[f.id] = (byRule[f.id] ?? 0) + 1
  return { files, findings: findings.length, sha256: sha(lines.join('\n')), byRule: Object.fromEntries(Object.entries(byRule).sort()) }
}

/** Generate a tree of `n` files in a temp dir, scan it in-process, remove it, return the digest. */
export async function scanDigest(n: number, seed = 1): Promise<Digest> {
  const dir = mkdtempSync(join(tmpdir(), 'sg-golden-'))
  const prev = process.cwd()
  try {
    generateRepo(dir, n, seed)
    process.chdir(dir)
    const result = await scan({})
    return digestOf(result.findings, result.filesScanned)
  } finally {
    process.chdir(prev)
    rmSync(dir, { recursive: true, force: true })
  }
}

const GOLDEN_PATH = join(dirname(fileURLToPath(import.meta.url)), '../perf/golden-baseline.json')

export function loadGolden(): Record<string, Digest> {
  return JSON.parse(readFileSync(GOLDEN_PATH, 'utf8'))
}

/** Used only with GOLDEN_RECORD=1, on the UNCHANGED scanner, when the rules or checks legitimately change. */
export function recordGolden(size: number, digest: Digest): void {
  let all: Record<string, Digest> = {}
  try {
    all = loadGolden()
  } catch {
    all = {}
  }
  all[String(size)] = digest
  writeFileSync(GOLDEN_PATH, JSON.stringify(all, null, 2) + '\n')
}
