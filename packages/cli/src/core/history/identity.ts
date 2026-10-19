import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { RepoIdKind } from '@agenticcli/shared'
import { DEFAULT_REPO_ID_FALLBACK_PATH } from '@agenticcli/shared'
import { logger } from '../../utils/logger.js'

export interface RepoIdentity {
  repoId: string
  repoIdKind: RepoIdKind
  /** Display label only (git remote URL) — never used as the comparison key itself (§2.1). */
  remoteLabel?: string
}

function tryGit(cwd: string, args: string[]): string | undefined {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim()
  } catch {
    return undefined
  }
}

/**
 * Idempotently ensure `entry` (e.g. `.shipguard/`) is present in the repo's own .gitignore.
 * Never throws — a failure here must not break a scan; it just means the user's own
 * .gitignore doesn't get the courtesy line and history.db/repo-id could get committed.
 */
export function ensureGitignored(cwd: string, entry: string): void {
  try {
    const gitignorePath = join(cwd, '.gitignore')
    const existing = existsSync(gitignorePath) ? readFileSync(gitignorePath, 'utf-8') : ''
    const alreadyPresent = existing
      .split('\n')
      .map((l) => l.trim())
      .some((l) => l === entry || l === entry.replace(/\/$/, ''))
    if (alreadyPresent) return
    const prefix = existing.length > 0 && !existing.endsWith('\n') ? '\n' : ''
    writeFileSync(gitignorePath, `${existing}${prefix}${entry}\n`, 'utf-8')
  } catch (err) {
    logger.warn(`Could not update .gitignore for history store: ${err instanceof Error ? err.message : err}`)
  }
}

/**
 * Resolve the repo identity used to key the history store (§2.1).
 * Primary: the root-commit hash (stable across clones/worktrees/renames, present the moment
 * there is ≥1 commit). Secondary/display only: the git remote URL. Fallback: a gitignored
 * ad hoc UUID persisted at `.shipguard/repo-id`, generated on first scan — imperfect (doesn't
 * survive a fresh clone) but never blocks a scan.
 */
export function resolveRepoIdentity(cwd: string): RepoIdentity {
  const rootCommits = tryGit(cwd, ['rev-list', '--max-parents=0', 'HEAD'])
  const remoteLabel = tryGit(cwd, ['remote', 'get-url', 'origin'])

  if (rootCommits) {
    // Sort + join defensively for the rare octopus-history case with multiple root commits —
    // still deterministic and stable across clones of the SAME repo.
    const roots = rootCommits
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .sort()
    if (roots.length > 0) {
      return { repoId: roots.join(','), repoIdKind: 'root-commit', remoteLabel }
    }
  }

  // Fallback: no root commit readable (shallow clone, zero commits, not a git repo at all).
  // Never blocks a scan — persist a UUID gitignored at .shipguard/repo-id.
  const fallbackPath = join(cwd, DEFAULT_REPO_ID_FALLBACK_PATH)
  try {
    if (existsSync(fallbackPath)) {
      const existing = readFileSync(fallbackPath, 'utf-8').trim()
      if (existing) {
        return { repoId: existing, repoIdKind: 'fallback-uuid', remoteLabel }
      }
    }
    const id = randomUUID()
    mkdirSync(dirname(fallbackPath), { recursive: true })
    writeFileSync(fallbackPath, `${id}\n`, 'utf-8')
    ensureGitignored(cwd, '.shipguard/')
    return { repoId: id, repoIdKind: 'fallback-uuid', remoteLabel }
  } catch (err) {
    // Even the fallback-uuid persistence failed (read-only fs, etc.) — mint an ephemeral
    // in-memory id for THIS scan only. History for this run will never find a baseline
    // (nothing was ever persisted under it), which is safe (regressionCheckSkipped), never
    // a false regression claim.
    logger.warn(`Could not persist fallback repo identity: ${err instanceof Error ? err.message : err}`)
    return { repoId: randomUUID(), repoIdKind: 'fallback-uuid', remoteLabel }
  }
}

/**
 * ScanId reuse — a cheap, LOCAL-ONLY working-tree content identity, one INPUT to
 * the scanId reuse key (scan-id.ts), used to help decide whether a retried scan is plausibly
 * "the same scan" (safe to reuse its scanId) or genuinely new (must mint a fresh one). Hashes
 * the HEAD commit + the porcelain status listing (paths and per-path STATUS LETTERS only —
 * NEVER file contents; see Security & Privacy: this store never transmits or persists source).
 *
 * IMPORTANT — what this does NOT catch: because it is path+status only, it is coarse. A
 * SECOND edit to an already-modified tracked file (e.g. package.json edited twice with no
 * intervening commit) leaves the porcelain record byte-identical (` M package.json` stays
 * ` M package.json`, HEAD unchanged) and so does NOT change this identity. That is deliberate
 * and safe ONLY because it is not the sole signal: the reuse key ALSO includes the detected
 * framework set (scan-id.ts), so a re-edit that changes which frameworks are detected — and
 * thus which paid bundle the server builds — still mints a fresh scanId. Do not overload this
 * function to try to detect content-level changes it structurally cannot see.
 *
 * `excludePrefixes` are repo-relative posix path prefixes to DROP from the porcelain listing
 * — ShipGuard's OWN artifacts (`.shipguard/`, the history db). This is essential, not
 * cosmetic: ShipGuard writes its history db into the working tree, so on the SECOND run of an
 * otherwise-identical retry `git status` would show that db as a new untracked file and the
 * content identity would flip — defeating the reuse the whole feature exists to provide.
 * The tool's own bookkeeping must never count as "the user changed their code."
 *
 * Returns undefined when there is no resolvable git HEAD (not a git repo, shallow clone with
 * no commits, etc.) — callers MUST treat that as "content identity unavailable" and skip
 * scanId reuse entirely rather than guess; this keeps the reuse feature purely additive: no
 * git HEAD means behavior is identical to before this feature existed.
 */
export function resolveContentIdentity(cwd: string, excludePrefixes: string[] = []): string | undefined {
  const headSha = tryGit(cwd, ['rev-parse', 'HEAD'])
  if (!headSha) return undefined
  // `-z` → NUL-separated records, so a path containing spaces/newlines is never mis-split.
  const raw = tryGit(cwd, ['status', '--porcelain', '-z']) ?? ''
  const normalizedExcludes = excludePrefixes
    .map((p) => p.replace(/\\/g, '/').replace(/^\.\//, ''))
    .filter(Boolean)
  const records = raw.split('\0').filter(Boolean)
  const kept = records.filter((rec) => {
    // Porcelain -z record: 2 status chars + 1 space + path (col 3+). Rename/copy carries a
    // second NUL-separated old-path record, which we treat identically (path filtering only).
    const path = rec.length > 3 ? rec.slice(3) : rec
    return !normalizedExcludes.some((ex) => path === ex || path === ex.replace(/\/$/, '') || path.startsWith(ex))
  })
  // Sorted so the hash input is order-stable regardless of git's listing order.
  const dirtyStatus = kept.sort().join('\n')
  return createHash('sha256').update(`${headSha}\n${dirtyStatus}`).digest('hex').slice(0, 16)
}
