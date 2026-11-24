/**
 * Gate memory and clock: loop-stop counters, the 150 s deadline plan, the unfinished-gate record
 * (host kill), stale hook detection. (spec 03, 04 "Fix loop")
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  LOOP_STOP_RUNS,
  RUNNING_STALE_SECONDS,
  computeRepeat,
  detectStaleHook,
  occurrenceKey,
  planDeadline,
  readGateRecord,
  scanBudgetSeconds,
  unfinishedGateWarning,
  writeGateRecord,
  type GateRecord,
} from '../../src/core/gate-state.js'
import { CLAUDE_HOOK_COMMAND, gitHookScript } from '../../src/core/hook-templates.js'

const dirs: string[] = []
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'sg-gate-state-'))
  dirs.push(d)
  return d
}
afterEach(() => {
  vi.restoreAllMocks()
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

const rec = (over: Partial<GateRecord> = {}): GateRecord => ({
  schema: 1,
  status: 'blocked',
  host: 'claude',
  command: 'git push origin main',
  startedAt: new Date(0).toISOString(),
  ...over,
})

describe('occurrence key', () => {
  it('is 12 hex chars of rule id + file, and ignores nothing else', () => {
    const k = occurrenceKey('generic.secrets.stripe-live-key', 'lib/stripe.ts')
    expect(k).toMatch(/^[0-9a-f]{12}$/)
    expect(occurrenceKey('generic.secrets.stripe-live-key', 'lib/stripe.ts')).toBe(k)
    expect(occurrenceKey('generic.secrets.stripe-live-key', 'lib/other.ts')).not.toBe(k)
    expect(occurrenceKey('other.rule', 'lib/stripe.ts')).not.toBe(k)
  })
})

describe('loop-stop counters (rule id + file; a third run in a row asks the human)', () => {
  const f = (line = 1) => ({ id: 'rule.a', file: 'a.ts', occurrence: occurrenceKey('rule.a', 'a.ts'), line })

  it('first run: counts 1, no repeat', () => {
    const r = computeRepeat(null, [f()], 'sha1')
    expect(r.maxRuns).toBe(0)
    expect(r.loopStop).toBe(false)
    expect(Object.values(r.counts)[0].count).toBe(1)
  })

  it('second run: runs 1 (repeat string, not yet a stop); same commit is detected', () => {
    const first = computeRepeat(null, [f()], 'sha1')
    const r = computeRepeat(rec({ commit: 'sha1', blocking: first.counts }), [f()], 'sha1')
    expect(r.maxRuns).toBe(1)
    expect(r.sameCommit).toBe(true)
    expect(r.loopStop).toBe(false)
  })

  it(`run ${LOOP_STOP_RUNS}: loop-stop; a changed line or a new commit does not reset it`, () => {
    let prev: GateRecord | null = null
    let last = computeRepeat(prev, [f(1)], 'sha1')
    for (const [line, sha] of [[7, 'sha2'], [99, 'sha3']] as const) {
      prev = rec({ commit: 'earlier', blocking: last.counts })
      last = computeRepeat(prev, [f(line)], sha)
    }
    expect(last.maxRuns).toBe(2)
    expect(last.loopStop).toBe(true)
    expect(last.sameCommit).toBe(false)
  })

  it('a passed run clears the counters', () => {
    const first = computeRepeat(null, [f()], 'sha1')
    const r = computeRepeat(rec({ status: 'passed', blocking: first.counts }), [f()], 'sha2')
    expect(r.maxRuns).toBe(0)
  })

  it('a running record (host kill) keeps the counters, so a kill cannot reset the loop', () => {
    const first = computeRepeat(null, [f()], 'sha1')
    const r = computeRepeat(rec({ status: 'running', blocking: first.counts }), [f()], 'sha2')
    expect(r.maxRuns).toBe(1)
  })

  it('a different file or rule is a new occurrence', () => {
    const first = computeRepeat(null, [f()], 'sha1')
    const other = { id: 'rule.a', file: 'b.ts', occurrence: occurrenceKey('rule.a', 'b.ts') }
    expect(computeRepeat(rec({ blocking: first.counts }), [other], 'sha2').maxRuns).toBe(0)
  })
})

describe('deadline plan: one clock for startup checks, download and scan', () => {
  const NOW = 1_800_000_000_000
  const plan = (env: Record<string, string | undefined>, gateTimeoutSeconds?: number, host = 'claude') =>
    planDeadline({ nowMs: NOW, host, env, gateTimeoutSeconds })

  it('claude: the deadline is the host timeout minus 30 s, counted from the shim start', () => {
    const p = plan({ SHIPGUARD_GATE_START: String(NOW / 1000 - 20), SHIPGUARD_HOST_TIMEOUT: '180' })
    expect(p.hostTimeoutSeconds).toBe(180)
    expect(p.deadlineMs).toBe(NOW - 20_000 + 150_000)
    expect(p.configInvalid).toBe(false)
  })

  it('the scan gets its own timer (default 120 s) or what is left, whichever is smaller', () => {
    const early = plan({ SHIPGUARD_GATE_START: String(NOW / 1000), SHIPGUARD_HOST_TIMEOUT: '180' })
    expect(scanBudgetSeconds(early, NOW)).toBe(120)
    const late = plan({ SHIPGUARD_GATE_START: String(NOW / 1000 - 100), SHIPGUARD_HOST_TIMEOUT: '180' })
    expect(scanBudgetSeconds(late, NOW)).toBe(50)
    const over = plan({ SHIPGUARD_GATE_START: String(NOW / 1000 - 160), SHIPGUARD_HOST_TIMEOUT: '180' })
    expect(scanBudgetSeconds(over, NOW)).toBe(0)
  })

  it('gate.timeoutSeconds plus the 30 s margin longer than the host timeout is invalid (no scan is started)', () => {
    expect(plan({ SHIPGUARD_HOST_TIMEOUT: '180' }, 300).configInvalid).toBe(true)
    expect(plan({ SHIPGUARD_HOST_TIMEOUT: '180' }, 150).configInvalid).toBe(false)
    expect(plan({ SHIPGUARD_HOST_TIMEOUT: '180' }, 151).configInvalid).toBe(true)
  })

  it('a start time in the future or very old is not trusted: it can only shorten the deadline, never extend it', () => {
    const future = plan({ SHIPGUARD_GATE_START: String(NOW / 1000 + 500), SHIPGUARD_HOST_TIMEOUT: '180' })
    expect(future.startMs).toBe(NOW)
    const old = plan({ SHIPGUARD_GATE_START: String(NOW / 1000 - 86_400), SHIPGUARD_HOST_TIMEOUT: '180' })
    expect(old.startMs).toBe(NOW)
    const junk = plan({ SHIPGUARD_GATE_START: 'abc', SHIPGUARD_HOST_TIMEOUT: '9999999' })
    expect(junk.startMs).toBe(NOW)
    expect(junk.hostTimeoutSeconds).toBe(180)
  })

  it('CI has no host limit: the gate timer alone applies', () => {
    const p = plan({}, 200, 'ci')
    expect(p.hostTimeoutSeconds).toBeNull()
    expect(p.configInvalid).toBe(false)
    expect(p.deadlineMs).toBe(NOW + 200_000)
  })
})

describe('gate-last.json and the unfinished-gate proof', () => {
  it('round-trips and is written atomically; .shipguard/ is kept out of git', () => {
    const d = tmp()
    expect(writeGateRecord(d, rec({ status: 'passed' }))).toBe(true)
    expect(readGateRecord(d)?.status).toBe('passed')
    expect(readFileOrEmpty(join(d, '.shipguard', '.gitignore'))).toBe('*\n')
  })

  it('a corrupt record reads as none and is reported, never thrown', () => {
    const d = tmp()
    mkdirSync(join(d, '.shipguard'), { recursive: true })
    writeFileSync(join(d, '.shipguard', 'gate-last.json'), '{ nope')
    const warn = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    expect(readGateRecord(d)).toBeNull()
    expect(warn).toHaveBeenCalled()
  })

  it('a running record that never finished is the proof of a host kill', () => {
    const now = Date.now()
    const killed = rec({ status: 'running', startedAt: new Date(now - (RUNNING_STALE_SECONDS + 5) * 1000).toISOString() })
    const text = unfinishedGateWarning('/x', now, killed)
    expect(text).toContain('never finished')
    expect(text).toContain('git push origin main')
    expect(text).toContain('NOT checked')
    expect(text).toContain('shipguard scan --strict')
  })

  it('a young running record is another gate still working, not a kill', () => {
    const now = Date.now()
    expect(unfinishedGateWarning('/x', now, rec({ status: 'running', startedAt: new Date(now - 20_000).toISOString() }))).toBeNull()
    expect(unfinishedGateWarning('/x', now, rec({ status: 'passed' }))).toBeNull()
    expect(unfinishedGateWarning('/x', now, null)).toBeNull()
  })
})

function readFileOrEmpty(path: string): string {
  try {
    return readFileSync(path, 'utf-8')
  } catch {
    return ''
  }
}

describe('stale hook detection', () => {
  it('the 0.12 inline Claude hook is stale', () => {
    const d = tmp()
    mkdirSync(join(d, '.claude'), { recursive: true })
    const legacy = `sh -c '_sg_in=$(cat); case "$_sg_in" in *"git push"*) ./node_modules/.bin/shipguard scan --json --strict;; esac; exit 0'`
    writeFileSync(join(d, '.claude', 'settings.json'), JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: legacy }] }] } }))
    const stale = detectStaleHook(d)
    expect(stale?.layer).toBe('claude')
    expect(stale?.text).toBe('WARNING: your Claude hook is from an older ShipGuard and can skip the gate silently. Update it: shipguard setup --agent claude')
  })

  it('the current shim entry is not stale', () => {
    const d = tmp()
    mkdirSync(join(d, '.claude'), { recursive: true })
    writeFileSync(join(d, '.claude', 'settings.json'), JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: CLAUDE_HOOK_COMMAND }] }] } }))
    expect(detectStaleHook(d)).toBeNull()
  })

  it('an old shim file or an old git block is stale; the current ones are not', () => {
    const d = tmp()
    mkdirSync(join(d, '.claude', 'hooks'), { recursive: true })
    writeFileSync(join(d, '.claude', 'settings.json'), '{}')
    writeFileSync(join(d, '.claude', 'hooks', 'shipguard-gate.sh'), '#!/bin/sh\n# shipguard-hook v1 (managed by ShipGuard)\n')
    expect(detectStaleHook(d)?.layer).toBe('claude')

    const g = tmp()
    mkdirSync(join(g, '.git', 'hooks'), { recursive: true })
    writeFileSync(join(g, '.git', 'hooks', 'pre-push'), '#!/bin/sh\n# >>> shipguard managed block >>> v1 (pre-push)\n# <<< shipguard managed block <<<\n')
    expect(detectStaleHook(g)?.layer).toBe('git')
    writeFileSync(join(g, '.git', 'hooks', 'pre-push'), gitHookScript('pre-push'))
    expect(detectStaleHook(g)).toBeNull()
  })

  it('nothing installed is not stale', () => {
    expect(detectStaleHook(tmp())).toBeNull()
  })
})
