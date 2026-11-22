import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { RepoIdKind } from '@agenticcli/shared'
import { DEFAULT_REPO_ID_FALLBACK_PATH } from '@agenticcli/shared'
import { logger } from '../../utils/logger.js'
import { assertCwdAlive } from '../../utils/cwd-guard.js'

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
 * Keep ShipGuard's own folder out of git WITHOUT touching the user's `.gitignore` (never edited, by spec):
 * `.shipguard/.gitignore` holding `*` ignores the folder, itself included (the same self-ignoring file `setup` writes).
 * Idempotent. Never throws: a failure only means the folder could get committed, and is warned about.
 */
function ensureShipguardDirIgnored(cwd: string): void {
  try {
    const dir = join(cwd, '.shipguard')
    mkdirSync(dir, { recursive: true })
    const ignore = join(dir, '.gitignore')
    if (!existsSync(ignore)) writeFileSync(ignore, '*\n', 'utf-8')
  } catch (err) {
    logger.warn(`Could not write .shipguard/.gitignore for the history store: ${err instanceof Error ? err.message : err}`)
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
  // Never blocks a scan — persist a UUID at .shipguard/repo-id (the folder ignores itself via .shipguard/.gitignore).
  const fallbackPath = join(cwd, DEFAULT_REPO_ID_FALLBACK_PATH)
  try {
    if (existsSync(fallbackPath)) {
      const existing = readFileSync(fallbackPath, 'utf-8').trim()
      if (existing) {
        return { repoId: existing, repoIdKind: 'fallback-uuid', remoteLabel }
      }
    }
    const id = randomUUID()
    assertCwdAlive()
    mkdirSync(dirname(fallbackPath), { recursive: true })
    writeFileSync(fallbackPath, `${id}\n`, 'utf-8')
    ensureShipguardDirIgnored(cwd)
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

/** Folders never listed by the non-git identity: dependencies, build output and ShipGuard's own files. */
const LISTING_SKIP_DIRS = new Set(['.git', 'node_modules', '.shipguard', 'dist', 'build', '.next', 'coverage', 'out', 'tmp', 'vendor'])
/** Hard cap on listed entries: a bigger folder gets no reuse (identity unavailable), never a slow scan. */
const LISTING_MAX_ENTRIES = 5000

/**
 * Non-git content identity for scanId reuse (no git HEAD): a hash over the sorted list of
 * `path NUL size NUL mtime` for the files under `cwd`. Local only; file CONTENTS are never read or hashed.
 * Coarse on purpose (an edit that keeps size and mtime is invisible), exactly like the git identity, and
 * safe for the same reason: it only decides whether a retry may reuse its scan id.
 * Returns undefined when the listing cannot be completed (too many entries, unreadable folder).
 */
export function resolveListingIdentity(cwd: string, excludePrefixes: string[] = []): string | undefined {
  // Only for folders git knows nothing about. Inside a git work tree (even one with no commit yet) the
  // history store would have to write its own files (`.gitignore`) BEFORE the scan, and git would then
  // report them as changed files: that keeps the old behaviour there (no reuse without a HEAD).
  if (tryGit(cwd, ['rev-parse', '--is-inside-work-tree']) === 'true') return undefined
  const excludes = excludePrefixes.map((p) => p.replace(/\\/g, '/').replace(/^\.\//, '')).filter(Boolean)
  const lines: string[] = []
  const stack: string[] = ['']
  try {
    while (stack.length > 0) {
      const rel = stack.pop() as string
      for (const entry of readdirSync(join(cwd, rel), { withFileTypes: true })) {
        const childRel = rel ? `${rel}/${entry.name}` : entry.name
        if (excludes.some((ex) => childRel === ex.replace(/\/$/, '') || childRel.startsWith(ex))) continue
        if (entry.isDirectory()) {
          if (!LISTING_SKIP_DIRS.has(entry.name)) stack.push(childRel)
          continue
        }
        if (lines.length >= LISTING_MAX_ENTRIES) return undefined
        // ShipGuard's own courtesy `.gitignore` (only `.shipguard/`) appears after the first run: not a user change.
        if (childRel === '.gitignore' && readFileSync(join(cwd, childRel), 'utf-8').trim() === '.shipguard/') continue
        const st = lstatSync(join(cwd, childRel))
        lines.push(`${childRel}\0${st.size}\0${Math.trunc(st.mtimeMs)}`)
      }
    }
  } catch (err) {
    logger.debug(`scanId reuse: folder listing failed (no reuse for this run): ${err instanceof Error ? err.message : String(err)}`)
    return undefined
  }
  if (lines.length === 0) return undefined
  return createHash('sha256').update(lines.sort().join('\n')).digest('hex').slice(0, 16)
}
