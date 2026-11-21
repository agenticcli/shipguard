import { relative, resolve } from 'node:path'

/**
 * THE one re-run command builder (spec 01 rule 7). The screen `Next:` line, `nextSteps`,
 * `fix.verify.command`, the report and the gate all call this and print its string word for word.
 *
 *   shipguard scan [<target>] --strict [<options>]
 *
 * Built from THIS run's invocation, never fixed text:
 * - `<target>` = the resolved scan path relative to the folder the command was run from, shell-quoted
 *   when needed, left out when it is that folder.
 * - Carried over: `--all`, `--policy <file>`, an explicit `--pro` or `--general`, `--allow-degraded`.
 * - Never carried: output flags (`--json`, `--quiet`, `--sarif`, `--schema-version`) and `--strict` itself
 *   (it is always added once, in its fixed place).
 */
export interface RerunInput {
  /** Folder the command was run from (process.cwd() before any chdir). */
  invocationCwd: string
  /** Resolved absolute scan root. */
  scanRoot: string
  all?: boolean
  /** `--policy <file>` as the user typed it. */
  policy?: string
  /** Explicit `--pro` on this run. */
  pro?: boolean
  /** Explicit `--general` on this run. */
  general?: boolean
  allowDegraded?: boolean
}

const SAFE_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/

/** POSIX single-quote a word when it holds anything outside the safe set. */
export function shellQuote(word: string): string {
  if (word.length > 0 && SAFE_WORD.test(word)) return word
  return `'${word.replace(/'/g, `'\\''`)}'`
}

/** The target as the user would type it: relative to where they ran from, `./`-prefixed, or null for the cwd. */
export function rerunTarget(invocationCwd: string, scanRoot: string): string | null {
  const rel = relative(resolve(invocationCwd), resolve(scanRoot))
  if (rel === '') return null
  // `..` and dot-folders keep their own prefix; everything else is shown as `./<path>`.
  return rel.startsWith('.') ? rel : `./${rel}`
}

export function buildRerunCommand(input: RerunInput): string {
  const parts = ['shipguard', 'scan']
  const target = rerunTarget(input.invocationCwd, input.scanRoot)
  if (target !== null) parts.push(shellQuote(target))
  parts.push('--strict')
  if (input.all) parts.push('--all')
  if (input.policy) parts.push('--policy', shellQuote(input.policy))
  if (input.pro) parts.push('--pro')
  if (input.general) parts.push('--general')
  if (input.allowDegraded) parts.push('--allow-degraded')
  return parts.join(' ')
}
