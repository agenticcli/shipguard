/**
 * gate-state.ts — what the gate remembers between runs, and the clock it works against.
 *
 * `.shipguard/gate-last.json` is written TWICE per run: a `running` record before the scan and a
 * finished record (`passed`, `blocked`, `timeout`) after. A `running` record that never finished is
 * the proof that the host (Claude Code) killed the hook, which lets the command run unchecked
 * (spec 03, "Host timeout"). The next gate, scan or status run reports it as GATE_UNFINISHED.
 *
 * The same file carries the loop-stop counters. A blocking OCCURRENCE is the rule id plus the file
 * (never the line or the matched text, so moving or editing code does not reset it and no secret
 * value is ever hashed). The same occurrence on a third run in a row stops the loop and asks the
 * human (`ask_human`). The running record keeps the previous counters, so a host kill does not
 * reset them.
 *
 * Pure where possible: the functions that touch disk take the directory and never throw (a state
 * file problem must never turn into a pass; the caller logs and carries on).
 */
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { logger } from '../utils/logger.js'
import {
  CLAUDE_HOOK_TIMEOUT_SECONDS,
  GATE_DEADLINE_SECONDS,
  HOOK_BLOCK_VERSION,
  SHIM_RELATIVE_PATH,
  SHIM_VERSION,
  classifyClaudeHookCommand,
  managedBlockVersion,
  shimFileVersion,
} from './hook-templates.js'

export const GATE_LAST_RELATIVE = '.shipguard/gate-last.json'

/** Default for `gate.timeoutSeconds` in shipguard.policy.yml. */
export const DEFAULT_GATE_TIMEOUT_SECONDS = 120
/** The host kills the hook this long after the shim starts; the gate answers 30 s earlier. */
export const HOST_MARGIN_SECONDS = 30
/** A `running` record older than this was not a concurrent gate: the host stopped it. */
export const RUNNING_STALE_SECONDS = CLAUDE_HOOK_TIMEOUT_SECONDS + 20
/** Loop-stop: the same blocking occurrence on this many runs in a row asks the human. */
export const LOOP_STOP_RUNS = 3

export type GateStatus = 'running' | 'passed' | 'blocked' | 'timeout'

export interface GateFindingRecord {
  id: string
  file: string
  line: number | null
  severity: string
  blocking: boolean
  occurrence: string
}

export interface GateRecord {
  schema: 1
  status: GateStatus
  host: string
  /** The command the gate ran for, e.g. `git push origin main`. */
  command: string
  startedAt: string
  finishedAt?: string
  dir?: string
  commit?: string | null
  /** The commit of a gate that is still running (or was stopped); `commit` stays the last finished one. */
  runningCommit?: string
  code?: string
  agentAction?: string
  run?: string | null
  /** Consecutive runs that showed each blocking occurrence (1 = first time). */
  blocking?: Record<string, { id: string; file: string; count: number }>
  /** Compact list of every finding of the last run (id, file, severity), so `shipguard ignore` can tell a critical one. */
  findings?: GateFindingRecord[]
  /** Findings that a reasoned ignore in the policy suppressed in this run. */
  ignoresUsed?: Array<{ id: string; file: string }>
  rules?: { fallback?: { code: string } | null; receipt?: unknown } | null
  plan?: { server?: { usage?: { state?: string } | null } | null } | null
}

/** First 12 hex of a SHA-256 over the rule id and the repo-relative file; nothing else (spec 02). */
export function occurrenceKey(id: string, file: string): string {
  return createHash('sha256').update(`${id}\n${file}`).digest('hex').slice(0, 12)
}

export function gateLastPath(dir: string): string {
  return join(dir, GATE_LAST_RELATIVE)
}

/** Read the last record; null when there is none or it cannot be read (logged, never thrown). */
export function readGateRecord(dir: string): GateRecord | null {
  const path = gateLastPath(dir)
  if (!existsSync(path)) return null
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf-8')) as Partial<GateRecord>
    if (!parsed || parsed.schema !== 1 || typeof parsed.status !== 'string') return null
    return parsed as GateRecord
  } catch (err) {
    logger.warn(`Could not read ${GATE_LAST_RELATIVE}: ${err instanceof Error ? err.message : String(err)}. Loop counting starts over.`)
    return null
  }
}

/** Write the record atomically (temp file + rename). Returns false when it could not be written. */
export function writeGateRecord(dir: string, record: GateRecord): boolean {
  const path = gateLastPath(dir)
  try {
    const shipguardDir = join(dir, '.shipguard')
    if (!existsSync(shipguardDir)) {
      mkdirSync(shipguardDir, { recursive: true })
      // `.shipguard/` must never be committed by accident; setup writes the same file.
      writeFileSync(join(shipguardDir, '.gitignore'), '*\n', 'utf-8')
    }
    const tmp = `${path}.${process.pid}.tmp`
    writeFileSync(tmp, JSON.stringify(record, null, 2) + '\n', 'utf-8')
    renameSync(tmp, path)
    return true
  } catch (err) {
    logger.warn(`Could not write ${GATE_LAST_RELATIVE}: ${err instanceof Error ? err.message : String(err)}`)
    return false
  }
}

export interface RepeatInfo {
  /** The count to store for each occurrence of this run. */
  counts: Record<string, { id: string; file: string; count: number }>
  /** Highest `sinceLastRun.unchanged[].runs` equivalent (0 = nothing repeats, 1 = second run, 2 = third run). */
  maxRuns: number
  /** True when the previous run was for the same commit (nothing was committed in between). */
  sameCommit: boolean
  /** True when the third run in a row shows the same rule + file: stop and ask the human. */
  loopStop: boolean
}

/**
 * Compare this run's blocking occurrences with the last record. `previous` is the last record read
 * BEFORE this run wrote its `running` record (the running record keeps the counters anyway).
 * Only a blocked or interrupted run keeps counters; a passed run clears them.
 */
export function computeRepeat(
  previous: GateRecord | null,
  current: Array<{ id: string; file: string; occurrence: string }>,
  commit: string | null,
): RepeatInfo {
  const prior = previous && previous.status !== 'passed' ? previous.blocking ?? {} : {}
  const counts: RepeatInfo['counts'] = {}
  let maxRuns = 0
  for (const f of current) {
    const had = prior[f.occurrence]?.count ?? 0
    const count = had + 1
    counts[f.occurrence] = { id: f.id, file: f.file, count }
    maxRuns = Math.max(maxRuns, count - 1)
  }
  const sameCommit = Boolean(previous && commit && previous.commit === commit)
  return { counts, maxRuns, sameCommit, loopStop: maxRuns >= LOOP_STOP_RUNS - 1 }
}

// ---------------------------------------------------------------------------
// The clock
// ---------------------------------------------------------------------------

export interface DeadlinePlan {
  /** Epoch ms the shim (or this process) started the clock. */
  startMs: number
  /** Epoch ms after which nothing may still be running. */
  deadlineMs: number
  /** `gate.timeoutSeconds` in effect. */
  gateTimeoutSeconds: number
  /** True when the timer plus the margin is longer than the host allows: do not run, block. */
  configInvalid: boolean
  /** The host timeout in seconds the check used, or null when no host limit applies (CI). */
  hostTimeoutSeconds: number | null
}

/**
 * One deadline for everything the hook does. The shim exports SHIPGUARD_GATE_START (epoch seconds)
 * and SHIPGUARD_HOST_TIMEOUT; without them (CI, a direct run) the clock starts now and no host limit
 * applies. A start time in the future or very old is not trusted: it can only shorten the deadline,
 * never extend it.
 */
export function planDeadline(input: {
  nowMs: number
  host: string
  env: { SHIPGUARD_GATE_START?: string; SHIPGUARD_HOST_TIMEOUT?: string }
  gateTimeoutSeconds: number | undefined
}): DeadlinePlan {
  const gateTimeoutSeconds = input.gateTimeoutSeconds ?? DEFAULT_GATE_TIMEOUT_SECONDS
  const hostLimited = input.host !== 'ci'
  const envHost = Number(input.env.SHIPGUARD_HOST_TIMEOUT)
  const hostTimeoutSeconds = !hostLimited
    ? null
    : Number.isFinite(envHost) && envHost > HOST_MARGIN_SECONDS && envHost <= 3600
      ? envHost
      : CLAUDE_HOOK_TIMEOUT_SECONDS
  const envStart = Number(input.env.SHIPGUARD_GATE_START) * 1000
  const startMs =
    Number.isFinite(envStart) && envStart > 0 && envStart <= input.nowMs && input.nowMs - envStart < 3_600_000
      ? envStart
      : input.nowMs
  const windowSeconds = hostTimeoutSeconds === null ? gateTimeoutSeconds : hostTimeoutSeconds - HOST_MARGIN_SECONDS
  return {
    startMs,
    deadlineMs: startMs + windowSeconds * 1000,
    gateTimeoutSeconds,
    configInvalid: hostTimeoutSeconds !== null && gateTimeoutSeconds + HOST_MARGIN_SECONDS > hostTimeoutSeconds,
    hostTimeoutSeconds,
  }
}

/** Seconds the scan may use now: its own timer or what is left of the deadline, whichever is smaller. */
export function scanBudgetSeconds(plan: DeadlinePlan, nowMs: number): number {
  const left = Math.floor((plan.deadlineMs - nowMs) / 1000)
  return Math.max(0, Math.min(plan.gateTimeoutSeconds, left))
}

/** The shim's deadline in seconds, re-exported so tests and text read one number. */
export const SHIM_DEADLINE_SECONDS = GATE_DEADLINE_SECONDS

// ---------------------------------------------------------------------------
// Warnings the gate, scan and status report
// ---------------------------------------------------------------------------

/**
 * The text for a gate run that never finished (the host stopped the hook), or null. A `running`
 * record younger than RUNNING_STALE_SECONDS is another gate that is still working.
 */
export function unfinishedGateWarning(dir: string, nowMs: number = Date.now(), record: GateRecord | null = readGateRecord(dir)): string | null {
  if (!record || record.status !== 'running') return null
  const started = Date.parse(record.startedAt)
  if (!Number.isFinite(started) || nowMs - started < RUNNING_STALE_SECONDS * 1000) return null
  const when = new Date(started).toISOString().replace('T', ' ').replace(/:\d\d\.\d+Z$/, ' UTC')
  return (
    `WARNING: the last gate check (${record.command}, ${when}) never finished. Claude Code may have stopped it, ` +
    `which lets the command run unchecked. That command was NOT checked. Run: shipguard scan --strict`
  )
}

export interface StaleHook {
  /** Which layer is stale. */
  layer: 'claude' | 'git'
  text: string
}

/**
 * Hooks written by an older ShipGuard (the 0.12 inline `sh -c` blob, a shim or git block with a
 * lower version). Pure file reads; null when nothing is installed or everything is current.
 */
export function detectStaleHook(dir: string): StaleHook | null {
  try {
    const settingsPath = join(dir, '.claude', 'settings.json')
    if (existsSync(settingsPath)) {
      const settings = JSON.parse(readFileSync(settingsPath, 'utf-8')) as {
        hooks?: { PreToolUse?: Array<{ hooks?: Array<{ command?: string }> }> }
      }
      const kinds = (settings.hooks?.PreToolUse ?? [])
        .flatMap((e) => e.hooks ?? [])
        .map((h) => (typeof h.command === 'string' ? classifyClaudeHookCommand(h.command) : 'foreign'))
      const stale = kinds.includes('legacy') && !kinds.includes('shim')
      const shimPath = join(dir, SHIM_RELATIVE_PATH)
      const shimOld = existsSync(shimPath) && shimFileVersion(readFileSync(shimPath, 'utf-8')) < SHIM_VERSION
      if (stale || shimOld) {
        return {
          layer: 'claude',
          text: 'WARNING: your Claude hook is from an older ShipGuard and can skip the gate silently. Update it: shipguard setup --agent claude',
        }
      }
    }
    for (const name of ['pre-push', 'pre-merge-commit']) {
      const path = join(dir, '.git', 'hooks', name)
      if (existsSync(path)) {
        const v = managedBlockVersion(readFileSync(path, 'utf-8'))
        if (v > 0 && v < HOOK_BLOCK_VERSION) {
          return {
            layer: 'git',
            text: 'WARNING: your git hook is from an older ShipGuard and can skip the gate silently. Update it: shipguard setup --agent git',
          }
        }
      }
    }
  } catch (err) {
    logger.warn(`Could not check the installed hook version: ${err instanceof Error ? err.message : String(err)}`)
  }
  return null
}
