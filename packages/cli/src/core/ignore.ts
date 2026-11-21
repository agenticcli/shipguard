/**
 * The ONE ignore list, shared by the full scan (fast-glob) and the `--changed` filter, so the two
 * can never drift apart again (before this, `--changed` used a shorter list and ignored
 * `policy.ignore.paths` entirely).
 *
 * Dependency/build/VCS directories, lockfiles, `*.log`, `*.min.js`, `*.map`. The media and binary
 * EXTENSIONS (png, pdf, zip, wasm ...) are deliberately NOT here any more: those files are found and
 * classified by their content (utils/classify.ts), so a text file named `x.png` is scanned and a
 * real image is counted under `coverage.skipped.binary`.
 *
 * Whatever is ignored by this list is counted in `coverage.ignoredByDefault`, never silent.
 */
import { dirname, join } from 'node:path'
import fg from 'fast-glob'
import { Minimatch } from 'minimatch'
import type { Policy } from '@agenticcli/shared'
import { HISTORY_PATH_ENV_VAR } from '@agenticcli/shared'
import { RUNS_SUBDIR } from './report.js'
import { logger } from '../utils/logger.js'

export const DEFAULT_IGNORE = [
  'node_modules/**',
  'dist/**',
  'build/**',
  '.next/**',
  'coverage/**',
  '.git/**',
  '*.lock',
  'pnpm-lock.yaml',
  'package-lock.json',
  '.cache/**',
  '.turbo/**',
  '.venv/**',
  'venv/**',
  'vendor/**',
  'tmp/**',
  'out/**',
  '*.log',
  '*.min.js',
  '*.map',
  '.DS_Store',
  // ShipGuard's own report output: never scan the tool's own artifacts
  '.shipguard/**',
]

/**
 * Ignore patterns for ShipGuard's OWN artifacts when the policy points them somewhere other than
 * the default `.shipguard/` directory (report.output, history.path, the history env override).
 * Pure: (policy) -> patterns. No filesystem access.
 */
export function selfArtifactIgnorePatterns(policy: Policy): string[] {
  const patterns: string[] = []

  // These come from the scanned project's own policy file, so they are LITERAL paths: every glob
  // character is escaped before the pattern reaches fast-glob (picomatch). Unescaped, a policy value
  // such as `+(*a)` makes picomatch backtrack exponentially (a 29-character file name took 20 s).
  const add = (p: string | undefined, suffix = ''): void => {
    if (!p) return
    // Only project-relative paths can be matched against fast-glob's relative results;
    // an absolute path is outside the scan root's pattern space anyway.
    if (p.startsWith('/')) return
    const rel = p.replace(/^\.\//, '')
    if (!rel) return
    patterns.push(fg.escapePath(rel) + suffix)
  }

  const reportOutput = policy.report?.output
  add(reportOutput)
  if (reportOutput) {
    // generateReport() writes a .json sibling next to the .md: exclude it too.
    add(reportOutput.replace(/\.md$/, '.json'))
    // ...and the whole per-run report directory: run filenames are unpredictable run ids.
    const reportDir = dirname(reportOutput)
    add(join(reportDir === '.' ? '' : reportDir, RUNS_SUBDIR), '/**')
  }
  add(policy.history?.path)
  // The env override wins over the policy value (see history/path.ts), so honour it here too.
  add(process.env[HISTORY_PATH_ENV_VAR])

  return patterns
}

export interface IgnoreRule {
  pattern: string
  by: 'default' | 'user'
  /** Present for a reasoned `shipguard ignore <path>` entry; plain `ignore.paths` patterns have none. */
  reason?: string
}

/**
 * One reasoned exception in `shipguard.policy.yml`, written by `shipguard ignore`:
 *   ignore:
 *     entries:
 *       - { path: data/dump.txt, reason: "...", by: user, date: 2026-11-21 }          # a file or folder, taken literally
 *       - { finding: missing_idempotency, file: app/api/x/route.ts, reason: "...", by: agent, date: ... }
 * `by` says who asked: `user` from a terminal, `agent` when it ran without one. A reason is required:
 * an entry without one is NOT honoured (an undocumented exception is not accepted), and says so.
 */
export interface IgnoreEntry {
  path?: string
  finding?: string
  /** With `finding`: limit it to this repo-relative file; absent = that rule everywhere. */
  file?: string
  reason: string
  by: string
  date: string
}

const warnedEntries = new Set<string>()

/** The valid entries of the policy. Invalid ones are skipped with one warning each (never silently). */
export function readIgnoreEntries(policy: Policy): IgnoreEntry[] {
  const raw = (policy.ignore as { entries?: unknown } | undefined)?.entries
  if (raw === undefined) return []
  if (!Array.isArray(raw)) {
    warnOnce('ignore.entries', 'ignore.entries in shipguard.policy.yml is not a list, so none of its entries are applied.')
    return []
  }
  const out: IgnoreEntry[] = []
  raw.forEach((e: unknown, i: number) => {
    const o = (e ?? {}) as Record<string, unknown>
    const str = (v: unknown): string | undefined => (typeof v === 'string' && v.trim() ? v.trim() : undefined)
    const path = str(o.path)
    const finding = str(o.finding)
    const reason = str(o.reason)
    if ((path === undefined) === (finding === undefined)) {
      warnOnce(`ignore.entries[${i}]`, `ignore.entries[${i}] in shipguard.policy.yml needs exactly one of path or finding, so it is not applied.`)
      return
    }
    if (reason === undefined) {
      warnOnce(`ignore.entries[${i}]`, `ignore.entries[${i}] (${path ?? finding}) in shipguard.policy.yml has no reason, so it is not applied. Add one: shipguard ignore ... --reason "<why>"`)
      return
    }
    out.push({ ...(path ? { path } : { finding, ...(str(o.file) ? { file: str(o.file) } : {}) }), reason, by: str(o.by) ?? 'unknown', date: str(o.date) ?? String(o.date ?? '') })
  })
  return out
}

function warnOnce(key: string, message: string): void {
  if (warnedEntries.has(key)) return
  warnedEntries.add(key)
  logger.warn(message)
}

/** A path entry is a literal file or folder: glob characters in the name are escaped, never expanded. */
export function escapeGlobLiteral(path: string): string {
  return path.replace(/[\\*?[\]{}()!+@]/g, (c) => `\\${c}`)
}

/** Defaults and ShipGuard's own artifacts count as `default`; `policy.ignore.paths` and path entries count as `user`. */
export function buildIgnoreRules(policy: Policy): IgnoreRule[] {
  const defaults = [...new Set([...DEFAULT_IGNORE, ...selfArtifactIgnorePatterns(policy)])]
  const isDefault = new Set(defaults)
  // The built-in policy lists some of the same patterns; those are defaults, not the user's choice.
  const user = [...new Set(policy.ignore?.paths ?? [])].filter((p) => !isDefault.has(p))
  const entries = readIgnoreEntries(policy)
    .filter((e): e is IgnoreEntry & { path: string } => e.path !== undefined)
    .map((e): IgnoreRule => ({ pattern: escapeGlobLiteral(e.path), by: 'user', reason: e.reason }))
  return [
    ...defaults.map((pattern): IgnoreRule => ({ pattern, by: 'default' })),
    ...user.map((pattern): IgnoreRule => ({ pattern, by: 'user' })),
    ...entries.filter((e) => !user.includes(e.pattern)),
  ]
}

/** The same list as plain patterns, exactly what is handed to fast-glob. */
export function buildIgnorePatterns(policy: Policy): string[] {
  return buildIgnoreRules(policy).map((r) => r.pattern)
}

/** A rule that names one whole directory at the root (`node_modules/**`): never walked, only reported. */
export function isDirectoryRule(pattern: string): boolean {
  return pattern.endsWith('/**') && !/[*?[\]{}!()]/.test(pattern.slice(0, -3))
}

/**
 * Which rule (if any) ignores this project-relative path. Tests the path AND every parent folder
 * prefix against each pattern, so a bare `docs` or `secrets/` pattern ignores `docs/a/b.js` exactly
 * as fast-glob's directory pruning does.
 */
export function classifyIgnored(relPath: string, rules: readonly IgnoreRule[]): IgnoreRule | null {
  const parts = relPath.split('/')
  const prefixes: string[] = []
  for (let i = 1; i <= parts.length; i++) prefixes.push(parts.slice(0, i).join('/'))
  for (const rule of rules) {
    const matcher = compiled(rule.pattern)
    for (const candidate of prefixes) {
      if (matcher.match(candidate)) return rule
    }
  }
  return null
}

const matcherCache = new Map<string, Minimatch>()
function compiled(pattern: string): Minimatch {
  let m = matcherCache.get(pattern)
  if (!m) {
    m = new Minimatch(pattern.replace(/^\.\//, ''), { dot: true })
    matcherCache.set(pattern, m)
  }
  return m
}

/**
 * ShipGuard's own artifacts at ANY depth: `<folder>/.shipguard/...` (history store, reports, repo
 * id). A scan of a sub-folder writes them there. They are never the project's content, so they are
 * counted in `coverage.selfArtifacts` and never scanned, on both read paths. (A root `.shipguard/`
 * is already a default ignore rule.)
 */
export function isShipguardArtifactPath(rel: string): boolean {
  return rel.split('/').slice(0, -1).includes('.shipguard')
}
