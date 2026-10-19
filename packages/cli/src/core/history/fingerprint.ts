import { createHash } from 'node:crypto'

export interface ScopeFingerprintInput {
  /** true = changed-files-only mode, false = full-project scan. */
  changedOnly: boolean
  /** Normalized category filter for pro rules (e.g. `--category secrets,auth`). Empty = no filter. */
  categories: string[]
  /** Effective ignore-paths list (policy `ignore.paths`, normalized). */
  ignorePaths: string[]
  /**
   * Whether pro rules were ACTUALLY applied this scan (not merely requested) — a `--pro`
   * request that degraded to free-only must fingerprint as a free scan, since that is what
   * genuinely ran (§2.2: "flags that change what runs ... DO belong [in the fingerprint]").
   */
  proApplied: boolean
}

/**
 * Compute the scan-scope fingerprint (§2.2). Two scans are only ever compared by the
 * regression query when their fingerprints are byte-identical — this is what makes scope
 * drift (changed-files vs full-repo, a narrower category filter, free vs pro) structurally
 * impossible to misread as code drift, rather than something the comparison has to reason
 * about after the fact.
 *
 * `--strict` deliberately does NOT feed the fingerprint — it only changes the exit code,
 * never what gets checked (A1 contract, scan.ts).
 */
export function computeScopeFingerprint(input: ScopeFingerprintInput): string {
  const normalized = {
    mode: input.changedOnly ? 'changed' : 'full',
    categories: [...input.categories].map((c) => c.trim().toLowerCase()).filter(Boolean).sort(),
    ignorePaths: [...input.ignorePaths].map((p) => p.trim()).filter(Boolean).sort(),
    tier: input.proApplied ? 'pro' : 'free',
  }
  const json = JSON.stringify(normalized)
  // Truncated for readability (§2.2) — still astronomically collision-resistant for the
  // handful of distinct scopes any one repo will ever actually use.
  return createHash('sha256').update(json).digest('hex').slice(0, 16)
}
