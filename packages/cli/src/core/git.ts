import { execFileSync } from 'node:child_process'
import { decodeUtf8Strict } from '@agenticcli/matcher-contract'

export function isGitRepo(dir: string): boolean {
  try {
    execFileSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: dir, stdio: 'pipe' })
    return true
  } catch {
    return false
  }
}

/**
 * Error thrown when `git` itself fails while collecting changed files — as
 * opposed to git succeeding and genuinely reporting zero changed files.
 *
 * Root cause: the old getChangedFiles had a bare `catch { return [] }`,
 * so ANY git failure (a corrupted index, a git binary that doesn't understand
 * a flag, a transient I/O error) was indistinguishable from "no files changed"
 * — a `--changed` scan would silently scan zero files and report SAFE. The old
 * `git diff --name-only HEAD 2>/dev/null || git diff --name-only` shell
 * redirect is ALSO guaranteed-broken on Windows cmd.exe (no `2>/dev/null`,
 * no `||` fallback semantics) — every git invocation there would throw and
 * be swallowed into the same silent empty array.
 *
 * Fix: getChangedFiles() no longer shells out through a string command (which
 * needed the broken `2>/dev/null || ...` fallback in the first place) — it
 * uses execFileSync with argv arrays for each git invocation, and captures
 * stderr instead of discarding it. On a genuine git failure it throws
 * GitCommandError (caller decides how to fail loud); it returns `[]` ONLY
 * when git actually ran successfully and reported no changes.
 */
export class GitCommandError extends Error {
  constructor(
    /** The git subcommand that failed, e.g. "git diff --name-only HEAD". */
    public readonly command: string,
    /** Captured stderr from the failed git invocation. */
    public readonly stderr: string,
  ) {
    super(`git command failed: ${command}${stderr ? ` — ${stderr.trim()}` : ''}`)
    this.name = 'GitCommandError'
  }
}

function runGit(dir: string, args: string[]): Buffer {
  const command = `git ${args.join(' ')}`
  try {
    // Raw bytes: git file names are bytes, not necessarily valid UTF-8. They are decoded one by one
    // (strictly) by the caller; decoding the whole output lossily would alias different files.
    return execFileSync('git', args, {
      cwd: dir,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
  } catch (err: unknown) {
    const stderr =
      err && typeof err === 'object' && 'stderr' in err
        ? String((err as { stderr?: unknown }).stderr ?? '')
        : err instanceof Error
          ? err.message
          : String(err)
    throw new GitCommandError(command, stderr)
  }
}

export interface ChangedFiles {
  /** Exact file names relative to the scan directory (never trimmed, never lossily decoded). */
  paths: string[]
  /** Changed files whose name is not valid UTF-8: they cannot be addressed safely, so they are never read. Lossy display names. */
  unaddressable: string[]
  /** Changed files that git reports outside the scan directory (not scanned, not degraded). */
  outsideScope: number
}

/** Split NUL-separated git output into raw entries; empty entries are dropped, nothing is trimmed. */
function splitNul(out: Buffer): Buffer[] {
  const entries: Buffer[] = []
  let start = 0
  for (let i = 0; i < out.length; i++) {
    if (out[i] === 0) {
      if (i > start) entries.push(out.subarray(start, i))
      start = i + 1
    }
  }
  if (start < out.length) entries.push(out.subarray(start))
  return entries
}

/**
 * Collect the set of changed files (staged + unstaged + untracked) for `dir`.
 *
 * Callers MUST call isGitRepo(dir) first. Throws GitCommandError on a genuine git failure; an empty
 * result means git ran successfully and there are genuinely zero changed files.
 *
 * Exactness (plan A2, judge R3 MAJOR 4):
 *  - Every command uses `-z`: names are NUL-separated, never quoted, and never trimmed, so a file
 *    called "secret.ts " cannot alias "secret.ts".
 *  - Names are parsed as BYTES and decoded strictly one by one; an invalid-UTF-8 name is reported in
 *    `unaddressable` and never scanned as a different (U+FFFD) file.
 *  - `-c diff.relative=false` makes `git diff` print repository-root-relative paths even when the
 *    user's config says otherwise; `ls-files --full-name` does the same. The scan-directory prefix
 *    (`rev-parse --show-prefix`) is then stripped, so a nested scan root joins correctly.
 */
export function getChangedFilesDetailed(dir: string): ChangedFiles {
  // `git diff --name-only HEAD` fails in a repo with no commits yet (no HEAD). That is expected in a
  // fresh repo: fall back to nothing, without masking a REAL git failure.
  let diffOutput: Buffer
  try {
    diffOutput = runGit(dir, ['-c', 'diff.relative=false', 'diff', '--name-only', '-z', 'HEAD'])
  } catch (err) {
    if (err instanceof GitCommandError && /unknown revision|ambiguous argument|bad revision/i.test(err.stderr)) {
      diffOutput = Buffer.alloc(0)
    } else {
      throw err
    }
  }

  const stagedOutput = runGit(dir, ['-c', 'diff.relative=false', 'diff', '--cached', '--name-only', '-z'])
  const untrackedOutput = runGit(dir, ['ls-files', '--others', '--exclude-standard', '--full-name', '-z'])
  // Prefix of the scan directory inside the repository ("" at the root, "app/" below it).
  const prefix = Buffer.from(runGit(dir, ['rev-parse', '--show-prefix']).toString('latin1').replace(/\r?\n$/, ''), 'latin1')

  const seen = new Set<string>()
  const paths: string[] = []
  const unaddressable: string[] = []
  let outsideScope = 0
  for (const output of [diffOutput, stagedOutput, untrackedOutput]) {
    for (const raw of splitNul(output)) {
      const key = raw.toString('latin1')
      if (seen.has(key)) continue
      seen.add(key)
      if (prefix.length > 0 && !(raw.length > prefix.length && raw.subarray(0, prefix.length).equals(prefix))) {
        outsideScope++
        continue
      }
      const rel = raw.subarray(prefix.length)
      const decoded = decodeUtf8Strict(rel)
      if (decoded.ok) paths.push(decoded.text)
      else unaddressable.push(rel.toString('utf8'))
    }
  }
  return { paths, unaddressable, outsideScope }
}

/** Convenience wrapper: the addressable changed paths only. */
export function getChangedFiles(dir: string): string[] {
  return getChangedFilesDetailed(dir).paths
}
