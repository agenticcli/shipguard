import { execFileSync } from 'node:child_process'

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

function runGit(dir: string, args: string[]): string {
  const command = `git ${args.join(' ')}`
  try {
    return execFileSync('git', args, {
      cwd: dir,
      encoding: 'utf-8',
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

/**
 * Collect the set of changed files (staged + unstaged + untracked) for `dir`.
 *
 * Callers MUST call isGitRepo(dir) first — this function assumes `dir` is
 * already known to be a git repo, so any failure here is a genuine git
 * failure (corrupted repo, transient error, unsupported git version), never
 * "this isn't a repo." Throws GitCommandError on failure; NEVER silently
 * returns an empty array to mean "git failed" — an empty array means git
 * ran successfully and there are genuinely zero changed files.
 */
export function getChangedFiles(dir: string): string[] {
  // `git diff --name-only HEAD` fails in a repo with no commits yet (no HEAD).
  // That is expected in a fresh repo — fall back to a diff against the empty
  // tree so a brand-new repo with staged-but-uncommitted files still works,
  // without masking a REAL git failure (corrupted index, missing binary, etc.)
  // by swallowing every error indiscriminately like the old `2>/dev/null || ...`
  // shell fallback did.
  let diffOutput: string
  try {
    diffOutput = runGit(dir, ['diff', '--name-only', 'HEAD'])
  } catch (err) {
    if (err instanceof GitCommandError && /unknown revision|ambiguous argument|bad revision/i.test(err.stderr)) {
      // No HEAD yet (empty repo, first commit not made) — not a genuine
      // failure, just nothing to diff against yet.
      diffOutput = ''
    } else {
      throw err
    }
  }

  const stagedOutput = runGit(dir, ['diff', '--cached', '--name-only'])
  const untrackedOutput = runGit(dir, ['ls-files', '--others', '--exclude-standard'])

  const allFiles = new Set<string>()
  const outputs = [diffOutput, stagedOutput, untrackedOutput]
  for (const output of outputs) {
    output
      .split('\n')
      .map((f) => f.trim())
      .filter(Boolean)
      .forEach((f) => allFiles.add(f))
  }

  return [...allFiles]
}
