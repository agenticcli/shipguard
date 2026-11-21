/**
 * gate-scan.ts — the parts of the gate that touch git, the file system and the scan process.
 *
 *  - read the target repository and the commits (git, untranslated output);
 *  - extract ONE commit into a private temp folder (never the working tree);
 *  - run `shipguard scan --all --json --strict --report` on that folder as a child process, killed
 *    at the budget it was given (the gate's deadline lives in the caller);
 *  - read the scan JSON into the small shape the gate prints from. Both the 0.12 shape (schema 6)
 *    and the 0.13 shape (schema 7) are read: old keys keep their meaning, new keys sit beside them.
 *
 * Why an extraction and not `git archive`: `git archive` honours `export-ignore` in .gitattributes,
 * so a committed file could hide itself from the scan. `read-tree` into a private index plus
 * `checkout-index` writes every tracked file, whatever the attributes say, and never touches the
 * real index, the working tree or any ref.
 */
import { execFileSync, spawn } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, sep } from 'node:path'
import { logger } from '../utils/logger.js'
import { occurrenceKey } from './gate-state.js'
import { firstSentence, type GateFinding, type NotScanned, type ScanSummary } from './gate-text.js'

/** Variables git itself exports to a hook: they would point every command below at the hook's own repository. */
const GIT_LOCATION_VARS = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR', 'GIT_PREFIX', 'GIT_OBJECT_DIRECTORY']

function inheritedEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env }
  for (const name of GIT_LOCATION_VARS) delete env[name]
  return env
}

const GIT_ENV: NodeJS.ProcessEnv = {
  ...inheritedEnv(),
  LC_ALL: 'C',
  LANGUAGE: 'C',
  GIT_TERMINAL_PROMPT: '0',
  // A hook never fetches: a missing blob in a partial clone is an error, not a download.
  GIT_NO_LAZY_FETCH: '1',
  GIT_LFS_SKIP_SMUDGE: '1',
}

/** Run git and return stdout exactly as printed, or null when git fails (the caller decides what that means). */
function gitRaw(dir: string, args: string[]): string | null {
  try {
    return execFileSync('git', args, {
      cwd: dir,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: GIT_ENV,
      maxBuffer: 64 * 1024 * 1024,
    })
  } catch {
    return null
  }
}

/** Run git and return trimmed stdout, or null when git fails (the caller decides what that means). */
export function git(dir: string, args: string[]): string | null {
  return gitRaw(dir, args)?.trim() ?? null
}

/** The repository top level containing `dir`, or null when `dir` is not inside a git work tree. */
export function repoTopLevel(dir: string): string | null {
  if (!existsSync(dir)) return null
  const top = git(dir, ['rev-parse', '--show-toplevel'])
  return top ? resolve(top) : null
}

/** The commit a name resolves to, or null. Names that start with `-` are never passed to git. */
export function resolveCommit(dir: string, name: string): string | null {
  if (!name || name.startsWith('-')) return null
  const sha = git(dir, ['rev-parse', '--verify', '--quiet', `${name}^{commit}`])
  return sha && /^[0-9a-f]{40,64}$/.test(sha) ? sha : null
}

/** Upper bound for the refs one `--all` / `--mirror` / `--tags` push may name before the gate refuses to guess. */
export const MAX_PUSHED_REFS = 200

/** The commits of every ref under `prefixes` (deduplicated, labelled by the short ref name); null when there are too many or git fails. */
export function listRefCommits(dir: string, prefixes: string[]): Array<{ sha: string; label: string }> | null {
  const names = gitRaw(dir, ['for-each-ref', '--format=%(refname)', ...prefixes])
  if (names === null) return null
  const refs = names.split('\n').filter(Boolean)
  if (refs.length > MAX_PUSHED_REFS) return null
  const seen = new Set<string>()
  const out: Array<{ sha: string; label: string }> = []
  for (const ref of refs) {
    const sha = resolveCommit(dir, ref)
    if (!sha) return null
    if (seen.has(sha)) continue
    seen.add(sha)
    out.push({ sha, label: ref.replace(/^refs\/(heads|tags)\//, '') })
  }
  return out
}

/** `HEAD of main`, or `HEAD (detached)`. */
export function headLabel(dir: string): string {
  const branch = git(dir, ['symbolic-ref', '--short', '-q', 'HEAD'])
  return branch ? `HEAD of ${branch}` : 'HEAD (detached)'
}

/**
 * Tracked files that differ from HEAD (staged or not). Untracked files are not pushed, so they are
 * not listed. null = git could not say: the state is UNKNOWN, never "clean".
 */
export function uncommittedFiles(dir: string): string[] | null {
  const out = gitRaw(dir, ['status', '--porcelain=v1', '-z', '--untracked-files=no'])
  if (out === null) return null
  if (!out) return []
  return out
    .split('\0')
    .filter((r) => r.length > 3)
    .map((r) => r.slice(3))
}

/** Extract the tracked tree of one commit into a new private folder; returns its path. Caller removes it. */
export function extractCommit(topLevel: string, sha: string): string {
  const root = mkdtempSync(join(tmpdir(), 'shipguard-gate-'))
  const dest = join(root, 'tree')
  mkdirSync(dest)
  const env = { GIT_INDEX_FILE: join(root, 'index') }
  try {
    execFileSync('git', ['-C', topLevel, 'read-tree', sha], { env: { ...GIT_ENV, ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
    execFileSync('git', ['-C', topLevel, 'checkout-index', '-a', '-f', `--prefix=${dest}${sep}`], {
      env: { ...GIT_ENV, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 64 * 1024 * 1024,
    })
  } catch (err) {
    rmSync(root, { recursive: true, force: true })
    throw new Error(`could not read commit ${sha.slice(0, 7)}: ${err instanceof Error ? err.message : String(err)}`)
  }
  // ShipGuard's own folder is never project content, and a committed `.shipguard/` (a symlinked
  // report file, say) must not steer where this run writes its report. Removing a symlink removes
  // the link, never its target.
  rmSync(join(dest, '.shipguard'), { recursive: true, force: true })
  return dest
}

/** Remove an extraction made by extractCommit (its parent folder holds the private index too). */
export function removeExtraction(dest: string): void {
  try {
    rmSync(resolve(dest, '..'), { recursive: true, force: true })
  } catch (err) {
    logger.warn(`Could not remove the temporary scan folder ${dest}: ${err instanceof Error ? err.message : String(err)}`)
  }
}

export interface ScanRun {
  exitCode: number | null
  stdout: string
  timedOut: boolean
  stderrTail: string
}

const MAX_STDOUT_BYTES = 32 * 1024 * 1024

/** Run the scan on `dir` as a child process of this same program, killed at `budgetMs`. */
export function runScanChild(opts: { cliEntry: string; dir: string; budgetMs: number; host: string }): Promise<ScanRun> {
  return new Promise((resolveRun) => {
    const child = spawn(process.execPath, [opts.cliEntry, 'scan', '--all', '--json', '--strict', '--report'], {
      cwd: opts.dir,
      env: { ...inheritedEnv(), SHIPGUARD_GATE_KIND: opts.host },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const chunks: Buffer[] = []
    let size = 0
    let stderrTail = ''
    let timedOut = false
    child.stdout.on('data', (b: Buffer) => {
      size += b.length
      if (size <= MAX_STDOUT_BYTES) chunks.push(b)
      else child.kill('SIGKILL')
    })
    child.stderr.on('data', (b: Buffer) => {
      stderrTail = (stderrTail + b.toString('utf-8')).slice(-2000)
    })
    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, Math.max(1, opts.budgetMs))
    child.on('error', (err) => {
      clearTimeout(timer)
      resolveRun({ exitCode: null, stdout: '', timedOut, stderrTail: `${stderrTail}\n${err.message}`.trim() })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolveRun({ exitCode: code, stdout: Buffer.concat(chunks).toString('utf-8'), timedOut, stderrTail })
    })
  })
}

/** Copy the reports the scan wrote in the extraction into the real repo, so the paths in the text are real. */
export function copyReports(extracted: string, topLevel: string, runId: string | null): string | null {
  const from = join(extracted, '.shipguard', 'reports')
  if (!existsSync(from)) return null
  const to = join(topLevel, '.shipguard', 'reports')
  try {
    mkdirSync(to, { recursive: true })
    for (const name of ['latest.md', 'latest.json']) {
      if (existsSync(join(from, name))) cpSync(join(from, name), join(to, name))
    }
    if (runId) {
      const runs = join(from, 'runs')
      if (existsSync(runs)) cpSync(runs, join(to, 'runs'), { recursive: true })
    }
    return existsSync(join(to, 'latest.md')) ? '.shipguard/reports/latest.md' : null
  } catch (err) {
    logger.warn(`Could not copy the scan report into ${to}: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}

// ---------------------------------------------------------------------------
// Reading the scan JSON
// ---------------------------------------------------------------------------

type Json = Record<string, unknown>
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v)
const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null)
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)

const REASON_WORDS: Record<string, string> = {
  FILE_TOO_LARGE: 'too large',
  UNSCANNED_UNKNOWN_BINARY: 'binary data, unknown format',
  INVALID_UTF8: 'not valid text (UTF-8)',
  FILE_UNREADABLE: 'could not be read',
  UNREADABLE_FILE: 'could not be read',
  SYMLINK_SKIPPED: 'symlink, not followed',
  OUTPUT_TRUNCATED: 'not reached: the file or size limit stopped the scan',
  NO_FILES_SCANNED: 'nothing was scanned',
}

function reasonFor(code: string, bytes: number | null, detail: string | null): string {
  const base = REASON_WORDS[code] ?? detail ?? code
  return bytes !== null && code === 'FILE_TOO_LARGE' ? `${base} (${Math.round(bytes / 1024)} KB)` : base
}

function fixText(f: Json): string | null {
  const fix = f.fix
  if (isObj(fix) && str(fix.summary)) return firstSentence(String(fix.summary))
  if (typeof fix === 'string' && fix.trim()) return firstSentence(fix)
  const rec = str(f.recommendation)
  return rec ? firstSentence(rec) : null
}

function readFindings(j: Json): GateFinding[] {
  const list = Array.isArray(j.findings) ? j.findings : []
  const out: GateFinding[] = []
  for (const raw of list) {
    if (!isObj(raw)) continue
    const id = str(raw.id) ?? str(raw.ruleId) ?? 'unknown'
    const file = str(raw.file) ?? ''
    out.push({
      id,
      title: str(raw.title) ?? id,
      severity: str(raw.severity) ?? 'info',
      file,
      line: num(raw.line),
      blocking: raw.blocking === true && raw.suppressed !== true,
      fix: fixText(raw),
      category: str(raw.category),
      occurrence: str(raw.occurrence) ?? occurrenceKey(id, file),
    })
  }
  return out
}

function readNotScanned(j: Json): NotScanned[] {
  const out: NotScanned[] = []
  const seen = new Set<string>()
  const add = (file: string | null, code: string, bytes: number | null, detail: string | null): void => {
    const key = `${code}\0${file ?? ''}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ file, code, reason: reasonFor(code, bytes, detail) })
  }
  const coverage = isObj(j.coverage) ? j.coverage : {}
  // 0.13: coverage.notScanned[] (entries marked counts:false do not degrade the verdict).
  if (Array.isArray(coverage.notScanned)) {
    for (const e of coverage.notScanned) {
      if (isObj(e) && e.counts !== false && str(e.code)) add(str(e.file), String(e.code), num(e.bytes), null)
    }
  }
  const reasons = Array.isArray(j.degradedReasons) ? j.degradedReasons.filter(isObj) : []
  const coveredCodes = new Set(out.map((n) => n.code))
  const files = isObj(coverage.files) ? coverage.files : {}
  const byList: Array<[string, unknown]> = [
    ['FILE_TOO_LARGE', files.tooLarge],
    ['UNSCANNED_UNKNOWN_BINARY', files.unknownBinary],
    ['SYMLINK_SKIPPED', files.symlink],
  ]
  for (const r of reasons) {
    const code = str(r.code)
    if (!code) continue
    if (coveredCodes.has(code)) continue
    const named: string[] = Array.isArray(r.files)
      ? r.files.filter((x): x is string => typeof x === 'string')
      : ((byList.find(([c]) => c === code)?.[1] as unknown[] | undefined) ?? []).filter((x): x is string => typeof x === 'string')
    if (named.length > 0) for (const f of named) add(f, code, null, str(r.detail))
    else add(null, code, null, str(r.detail))
  }
  return out
}

export interface ParsedScan {
  summary: ScanSummary
  /** `plan.server.usage.state` and the rules receipt, recorded in gate-last.json only. */
  usageState: string | null
  receipt: unknown
  suppressed: Array<{ id: string; file: string }>
  reportMarkdown: string | null
}

const VERDICTS = new Set(['SAFE_TO_SHIP', 'REVIEW_BEFORE_SHIP', 'DO_NOT_SHIP'])

/** Read the scan JSON. Returns null when it is not a scan result (the caller fails closed). */
export function parseScanJson(stdout: string, measuredSeconds: number): ParsedScan | null {
  let j: unknown
  try {
    j = JSON.parse(stdout)
  } catch {
    return null
  }
  if (!isObj(j)) return null
  const verdictObj = isObj(j.verdict) ? j.verdict : {}
  const verdictRaw = str(verdictObj.value) ?? str(j.recommendation)
  if (!verdictRaw || !VERDICTS.has(verdictRaw)) return null
  const coverage = isObj(j.coverage) ? j.coverage : {}
  const findings = readFindings(j)
  const notScanned = readNotScanned(j)
  const filesScanned = num(j.filesScanned) ?? num(coverage.scanned) ?? 0
  const rules = isObj(j.rules) ? j.rules : {}
  const fallback = isObj(rules.fallback) ? str(rules.fallback.code) : null
  const plan = isObj(j.plan) ? j.plan : {}
  const server = isObj(plan.server) ? plan.server : {}
  const usage = isObj(server.usage) ? server.usage : {}
  const report = isObj(j.report) ? j.report : {}
  const run = str(j.runId)
  const degraded = j.degraded === true || verdictObj.complete === false
  const elapsed = num(j.elapsedMs)
  const raw = Array.isArray(j.findings) ? j.findings.filter(isObj) : []
  const suppressed = raw.filter((f) => f.suppressed === true).map((f) => ({ id: str(f.id) ?? 'unknown', file: str(f.file) ?? '' }))
  return {
    summary: {
      verdict: verdictRaw as ScanSummary['verdict'],
      findings,
      filesScanned,
      degraded,
      notScanned,
      filesTotal: num(coverage.discovered) ?? filesScanned + notScanned.filter((n) => n.file).length,
      rulesApplied: num(rules.applied) ?? num(j.rulesApplied),
      corpus: str(rules.corpus),
      runId: run ? run.slice(0, 8) : null,
      seconds: elapsed !== null ? elapsed / 1000 : measuredSeconds,
      fallbackCode: fallback,
    },
    usageState: str(usage.state),
    receipt: rules.receipt ?? null,
    suppressed,
    reportMarkdown: str(report.markdown),
  }
}

/** The error code a failed scan child reported (`{code}` in 0.12, `{error:{code}}` in 0.13), or null. */
export function scanErrorCode(stdout: string): string | null {
  try {
    const j = JSON.parse(stdout) as unknown
    if (!isObj(j)) return null
    if (str(j.code)) return String(j.code)
    if (isObj(j.error) && str(j.error.code)) return String(j.error.code)
  } catch {
    return null
  }
  return null
}
