import { Command } from 'commander'
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { createInterface } from 'node:readline/promises'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import YAML from 'yaml'
import { DEFAULT_POLICY_PATH } from '@agenticcli/shared'
import { logger } from '../utils/logger.js'
import { setExitCode } from '../utils/exit.js'
import { createPolicyFile, DEFAULT_POLICY } from '../core/policy.js'
import { readGateRecord } from '../core/gate-state.js'
import type { IgnoreEntry } from '../core/ignore.js'

/**
 * `shipguard ignore <finding-id|path> [--file <path>] --reason "<why>"` (spec 03, 04).
 *
 * The only sanctioned way past a gate block. It records ONE reasoned exception in
 * `shipguard.policy.yml`; the reason is required and is shown in the report. Rules:
 *  - a reason is always required (exit 2 REASON_REQUIRED), because the reason is the audit trail;
 *  - a CRITICAL finding can only be ignored from a terminal, by a person. An agent without a
 *    terminal is refused (CONFIRMATION_REQUIRED, ask the user). If the last run does not say how
 *    severe the finding is, it is treated the same way: deny by default;
 *  - a path is taken literally (a file or a folder inside the project), never as a pattern;
 *  - no inline markers: the exception lives in the policy file only.
 * `by` records who asked: `user` from a terminal, `agent` otherwise.
 */

export interface IgnoreOptions {
  file?: string
  reason?: string
}

export interface IgnoreDeps {
  cwd: string
  isTerminal: () => boolean
  confirm: (question: string) => Promise<boolean>
  now: () => Date
  /** Writes one line to the error stream. */
  say: (line: string) => void
}

export interface IgnoreOutcome {
  exitCode: number
  /** The entry that was written, when one was. */
  entry?: IgnoreEntry
  status?: 'added' | 'updated'
}

const SEVERITY_RANK = ['info', 'low', 'medium', 'high', 'critical']

function defaultDeps(): IgnoreDeps {
  return {
    cwd: process.cwd(),
    isTerminal: () => Boolean(process.stdin.isTTY && process.stderr.isTTY),
    confirm: async (question) => {
      const rl = createInterface({ input: process.stdin, output: process.stderr })
      try {
        return /^y(es)?$/i.test((await rl.question(question)).trim())
      } finally {
        rl.close()
      }
    },
    now: () => new Date(),
    say: (line) => void process.stderr.write(line + '\n'),
  }
}

function fail(deps: IgnoreDeps, code: string, what: string, fix: string, cause?: string): IgnoreOutcome {
  deps.say(`✗ ${code}: ${what}`)
  if (cause) deps.say(`  Cause: ${cause}`)
  deps.say(`  Fix: ${fix}`)
  return { exitCode: 2 }
}

interface RecordedFinding {
  id: string
  file: string
  severity: string
}

/** Every finding on record from the last gate run and the last report; onRecord is false when neither exists. */
function recordedFindings(cwd: string): { onRecord: boolean; list: RecordedFinding[] } {
  const list: RecordedFinding[] = []
  let onRecord = false
  const gate = readGateRecord(cwd)
  if (gate) {
    onRecord = true
    for (const f of gate.findings ?? []) list.push({ id: f.id, file: f.file, severity: f.severity.toLowerCase() })
  }
  // latest.json is either the report itself or a pointer (`runJson`) to the run's report file.
  const reportsDir = join(cwd, '.shipguard', 'reports')
  const readReport = (file: string, follow: boolean): Array<{ id?: unknown; file?: unknown; severity?: unknown }> | null => {
    if (!existsSync(file)) return null
    try {
      const report = JSON.parse(readFileSync(file, 'utf-8')) as { findings?: Array<{ id?: unknown; file?: unknown; severity?: unknown }>; runJson?: unknown }
      if (Array.isArray(report.findings)) return report.findings
      if (follow && typeof report.runJson === 'string') {
        const target = resolve(reportsDir, report.runJson)
        // One hop, and only to a report inside this project's reports folder.
        if (target.startsWith(reportsDir + sep)) return readReport(target, false)
        return null
      }
      return follow && typeof report.runJson === 'string' ? null : []
    } catch (err) {
      logger.warn(`Could not read ${file}: ${err instanceof Error ? err.message : String(err)}`)
      return null
    }
  }
  const findings = readReport(join(reportsDir, 'latest.json'), true)
  if (findings) {
    onRecord = true
    for (const f of findings) {
      if (typeof f.id === 'string' && typeof f.file === 'string' && typeof f.severity === 'string') list.push({ id: f.id, file: f.file, severity: f.severity.toLowerCase() })
    }
  }
  return { onRecord, list }
}

const highest = (sev: string[]): string | null =>
  sev.length === 0 ? null : sev.sort((a, b) => SEVERITY_RANK.indexOf(b) - SEVERITY_RANK.indexOf(a))[0]

/** The highest severity known for this rule (and file) from the last gate run or the last report; null when unknown. */
export function knownSeverity(cwd: string, id: string, file: string | undefined): string | null {
  return highest(recordedFindings(cwd).list.filter((f) => f.id === id && (file === undefined || f.file === file)).map((f) => f.severity))
}

/**
 * What the last run knows about everything under a path (the file itself, or a folder and what is in it).
 * `known` is false when there is no gate record and no report at all.
 */
export function pathSeverity(cwd: string, path: string): { known: boolean; highest: string | null } {
  const { onRecord, list } = recordedFindings(cwd)
  const under = list.filter((f) => f.file === path || f.file.startsWith(`${path}/`))
  return { known: onRecord, highest: highest(under.map((f) => f.severity)) }
}

/** A path inside the project as a project-relative posix path, or null when it escapes or is the project itself. */
function projectRelative(cwd: string, input: string): string | null {
  const abs = isAbsolute(input) ? resolve(input) : resolve(cwd, input)
  const rel = relative(cwd, abs)
  if (rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return null
  return rel.split(sep).join('/')
}

const FINDING_ID = /^[A-Za-z0-9_.-]+$/

export async function runIgnore(target: string, opts: IgnoreOptions, deps: IgnoreDeps = defaultDeps()): Promise<IgnoreOutcome> {
  const reason = opts.reason?.trim()
  if (!reason) {
    return fail(
      deps,
      'REASON_REQUIRED',
      'shipguard ignore needs a reason.',
      'add --reason "<why: what this is>". Ask the user first for an unscanned file or a critical finding; never copy a reason from an example.',
    )
  }

  const cwd = deps.cwd
  let entry: Omit<IgnoreEntry, 'by' | 'date'>
  let label: string

  if (opts.file !== undefined) {
    const file = projectRelative(cwd, opts.file)
    if (!file) return fail(deps, 'PATH_NOT_FOUND', `${opts.file} is not a file inside this project.`, 'pass a path inside the project folder, for example --file app/api/x/route.ts')
    if (!FINDING_ID.test(target)) return fail(deps, 'UNKNOWN_OPTION', `${target} is not a finding id.`, 'with --file, pass the finding id from the report, for example missing_idempotency')
    entry = { finding: target, file, reason }
    label = `${target} in ${file}`
  } else if (target.includes('/') || existsSync(resolve(cwd, target))) {
    const path = projectRelative(cwd, target)
    if (!path) return fail(deps, 'PATH_NOT_FOUND', `${target} is not a file or folder inside this project.`, 'pass a path inside the project folder, for example data/dump.txt')
    if (!existsSync(resolve(cwd, path))) return fail(deps, 'PATH_NOT_FOUND', `${path} does not exist.`, 'pass the path of the file or folder exactly as the report names it')
    entry = { path, reason }
    label = path
  } else if (FINDING_ID.test(target)) {
    entry = { finding: target, reason }
    label = `${target} (every file)`
  } else {
    return fail(deps, 'UNKNOWN_OPTION', `${target} is neither a path in this project nor a finding id.`, 'pass a finding id (for example missing_idempotency) or a path (for example data/dump.txt)')
  }

  const terminal = deps.isTerminal()
  // The critical guard covers BOTH forms: ignoring a file or folder that holds a critical finding
  // is the same decision as ignoring the finding. Severity not on record = unknown = deny (no terminal).
  const subject = entry.finding ?? entry.path ?? ''
  let severity: string | null
  let known = true
  if (entry.finding !== undefined) {
    severity = knownSeverity(cwd, entry.finding, entry.file)
    known = severity !== null
  } else {
    const p = pathSeverity(cwd, entry.path as string)
    severity = p.highest
    known = p.known
  }
  if (!known || severity === 'critical') {
    if (!terminal) {
      return fail(
        deps,
        'CONFIRMATION_REQUIRED',
        severity === 'critical'
          ? `${subject} holds a critical finding, and a critical finding can only be ignored from a terminal, by a person.`
          : `ShipGuard cannot tell from the last run how severe ${entry.finding !== undefined ? subject : `what is in ${subject}`} is, so it will not ignore it without a person at a terminal.`,
        severity === 'critical'
          ? 'ask the user to run this command themselves in a terminal.'
          : 'run shipguard scan --strict first so the findings are on record, then run this again; or ask the user to run it in a terminal.',
      )
    }
    if (severity === 'critical' && !(await deps.confirm(`${subject} holds a CRITICAL finding. Ignore it anyway? [y/N] `))) {
      deps.say('Nothing was changed.')
      return { exitCode: 2 }
    }
  }

  const policyPath = join(cwd, DEFAULT_POLICY_PATH)
  if (!existsSync(policyPath)) await createPolicyFile(cwd)
  const doc = YAML.parseDocument(readFileSync(policyPath, 'utf-8'))
  if (doc.errors.length > 0) {
    return fail(deps, 'INVALID_POLICY', `${DEFAULT_POLICY_PATH} could not be read${doc.errors[0].linePos ? ` (line ${doc.errors[0].linePos[0].line})` : ''}.`, `correct ${DEFAULT_POLICY_PATH} first, then run this again.`)
  }

  const full: IgnoreEntry = { ...entry, by: terminal ? 'user' : 'agent', date: deps.now().toISOString().slice(0, 10) }
  if (!doc.hasIn(['ignore'])) doc.setIn(['ignore'], doc.createNode({ paths: [...DEFAULT_POLICY.ignore.paths] }))
  // A policy whose `ignore` block has no `paths` list must keep one: other code reads it directly.
  if (!doc.hasIn(['ignore', 'paths'])) doc.setIn(['ignore', 'paths'], doc.createNode([]))
  if (!doc.hasIn(['ignore', 'entries'])) doc.setIn(['ignore', 'entries'], doc.createNode([]))
  const entries = doc.getIn(['ignore', 'entries'])
  if (!YAML.isSeq(entries)) {
    return fail(deps, 'INVALID_POLICY', `ignore.entries in ${DEFAULT_POLICY_PATH} is not a list.`, 'make it a list (or remove it), then run this again.')
  }

  const same = (item: unknown): boolean => {
    const o = (YAML.isMap(item) ? item.toJSON() : {}) as Partial<IgnoreEntry>
    return full.path !== undefined ? o.path === full.path : o.finding === full.finding && (o.file ?? null) === (full.file ?? null)
  }
  const index = entries.items.findIndex(same)
  const node = doc.createNode(full)
  let status: 'added' | 'updated'
  if (index === -1) {
    entries.add(node)
    status = 'added'
  } else {
    entries.items[index] = node
    status = 'updated'
  }

  const tmp = `${policyPath}.${process.pid}.tmp`
  try {
    writeFileSync(tmp, String(doc), 'utf-8')
    renameSync(tmp, policyPath)
  } catch (err) {
    deps.say(`✗ INTERNAL_ERROR: ${DEFAULT_POLICY_PATH} could not be written: ${err instanceof Error ? err.message : String(err)}`)
    deps.say('  Fix: check that the file is writable, then run this again.')
    return { exitCode: 3 }
  }

  deps.say(`✓ ${status === 'added' ? 'Ignored' : 'Updated the exception for'} ${label}. The reason is saved in ${DEFAULT_POLICY_PATH} (by: ${full.by}) and shown in the report under "Ignored".`)
  deps.say('  Check: shipguard scan --strict')
  return { exitCode: 0, entry: full, status }
}

export function ignoreCommand(): Command {
  return new Command('ignore')
    .description('Record a reasoned exception for a finding or a path in shipguard.policy.yml.')
    .argument('<target>', 'A finding id (use --file to limit it to one file) or a file or folder in this project')
    .option('--file <path>', 'Limit a finding to this file')
    .option('--reason <why>', 'Why this is safe to ignore (required; ask the user first for an unscanned file or a critical finding)')
    .addHelpText('after', `
Examples:
  shipguard ignore missing_idempotency --file app/api/webhooks/stripe/route.ts --reason "repeats are handled by a unique index on event.id"
  shipguard ignore data/dump.txt --reason "generated by scripts/export.sh, no secrets"

A critical finding can only be ignored from a terminal, by a person. The exception is saved in
shipguard.policy.yml and shown in the report. There are no inline ignore comments for this.

Exit codes:
  0  Saved.
  2  Not saved: a reason is required, or a person must confirm, or the target is not valid.
  3  The policy file could not be written.`)
    .action(async (target: string, opts: IgnoreOptions) => {
      const outcome = await runIgnore(target, opts)
      setExitCode(outcome.exitCode)
    })
}
