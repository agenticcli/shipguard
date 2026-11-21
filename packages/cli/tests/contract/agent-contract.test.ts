/**
 * W2b: the agent contract, pure functions (spec 02 + 06).
 * outcome.ts (codes, template, agentAction precedence, nextSteps, loop state, occurrence key) and rerun.ts.
 */
import { describe, it, expect } from 'vitest'
import type { Finding } from '@agenticcli/shared'
import {
  ERROR_CODES, OUTCOMES, NEXT_STEP_KINDS, REPEAT_LABELS, buildErrorEnvelope, buildNextSteps, buildPlanJson,
  computeSinceLastRun, decideAgentAction, errorTemplateLines, mapProFetchCode, occurrenceKey,
  renderErrorTemplate, secretEvidenceText, blockingOccurrences, evidenceOf, sortFindings,
} from '../../src/core/outcome.js'
import type { ErrorCode, NextStep, OutcomeInput, SinceLastRun } from '../../src/core/outcome.js'
import { buildRerunCommand, shellQuote } from '../../src/core/rerun.js'

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: 'rule.a', title: 'T', severity: 'high', category: 'auth', file: 'a.ts', line: 1,
    explanation: 'Because. More.', recommendation: 'Do it.', blocking: true, ...over,
  } as Finding
}

describe('error code table (one table, every code has cause + fix + agent action)', () => {
  const codes = Object.keys(ERROR_CODES) as ErrorCode[]

  it('has every code of spec 02 and nothing else', () => {
    expect(codes.sort()).toEqual([
      'CONFIRMATION_REQUIRED', 'GATE_CONFIG_INVALID', 'GATE_NOT_STARTED', 'GATE_STARTUP_STALLED', 'GATE_TIMEOUT',
      'INTERNAL_ERROR', 'INVALID_POLICY', 'LOGIN_CANCELLED', 'LOGIN_CONFIRM_FAILED', 'LOGIN_EXPIRED', 'LOGIN_REQUIRED',
      'LOGIN_START_FAILED', 'NOT_A_PROJECT', 'NO_RULES_APPLIED', 'PATH_NOT_A_DIRECTORY', 'PATH_NOT_FOUND',
      'PLAN_INACTIVE', 'RATE_LIMITED', 'REASON_REQUIRED', 'RULEBOOK_PARTIAL', 'RULEBOOK_UNREACHABLE',
      'RULEBOOK_WITHHELD', 'SETUP_VERIFY_FAILED', 'TOKEN_EXPIRED', 'UNCOMMITTED_CHANGES', 'UNINSTALL_VERIFY_FAILED',
      'UNKNOWN_COMMAND', 'UNKNOWN_OPTION',
    ].sort())
  })

  it.each(codes)('%s: template has the code line, a Cause or self-explaining line and exactly one Fix line', (code) => {
    const env = buildErrorEnvelope({ code, message: `something about ${code}`, cliVersion: '0.13.0' })
    const lines = errorTemplateLines(env)
    expect(lines.head.startsWith(`${code}: `)).toBe(true)
    expect(lines.rest.filter((l) => l.startsWith('  Fix: '))).toHaveLength(1)
    expect(env.error.fix.length).toBeGreaterThan(0)
    expect(env.error.cause.length).toBeGreaterThan(0)
    expect(['proceed', 'fix_and_rerun', 'retry', 'ask_human', 'stop']).toContain(env.agentAction)
    expect([2, 3, 130]).toContain(env.exit.code)
  })

  it('exit semantics: 2 = fix your command or config, 3 = environment/sign-in/internal, 130 = cancelled', () => {
    expect(ERROR_CODES.PATH_NOT_FOUND.exit).toBe(2)
    expect(ERROR_CODES.INVALID_POLICY.exit).toBe(2)
    expect(ERROR_CODES.LOGIN_REQUIRED.exit).toBe(3)
    expect(ERROR_CODES.RULEBOOK_UNREACHABLE.exit).toBe(3)
    expect(ERROR_CODES.INTERNAL_ERROR.exit).toBe(3)
    expect(ERROR_CODES.LOGIN_CANCELLED.exit).toBe(130)
    expect(ERROR_CODES.GATE_TIMEOUT).toMatchObject({ exit: 2, exitGit: 1 })
  })

  it('`Run:` only for a command that works as printed AND is not already in the Fix line', () => {
    const login = renderErrorTemplate(buildErrorEnvelope({ code: 'LOGIN_REQUIRED', message: 'x', cliVersion: '0.13.0' }))
    expect(login).not.toContain('Run:') // Fix is already `shipguard login`
    const custom = buildErrorEnvelope({ code: 'RULEBOOK_UNREACHABLE', message: 'x', cliVersion: '0.13.0', command: 'shipguard scan --strict' })
    expect(renderErrorTemplate(custom)).toContain('Run: shipguard scan --strict')
    // placeholder paths never become a command
    expect(buildErrorEnvelope({ code: 'PATH_NOT_FOUND', message: 'x', cliVersion: '0.13.0' }).error.command).toBeNull()
    expect(buildErrorEnvelope({ code: 'NOT_A_PROJECT', message: 'x', cliVersion: '0.13.0' }).error.command).toBeNull()
  })

  it('the envelope carries the contract keys', () => {
    const env = buildErrorEnvelope({ code: 'PATH_NOT_FOUND', message: 'Scan path does not exist: /x', cliVersion: '0.13.0', extra: { path: '/x' } })
    expect(env).toMatchObject({ schemaVersion: '7', ok: false, runId: null, agentAction: 'fix_and_rerun', exit: { code: 2 } })
    expect(Object.keys(env.error)).toEqual(expect.arrayContaining(['code', 'message', 'cause', 'fix', 'command', 'path']))
  })

  it('pro-fetch classes map to the public table; unknown classes fail loud (never a quiet fallback)', () => {
    expect(mapProFetchCode('AUTH_FAILED', 'Not authenticated. Run `shipguard login` first.')).toBe('LOGIN_REQUIRED')
    expect(mapProFetchCode('AUTH_FAILED', 'Auth expired.')).toBe('TOKEN_EXPIRED')
    expect(mapProFetchCode('RATE_LIMITED')).toBe('RATE_LIMITED')
    expect(mapProFetchCode('INSUFFICIENT_CREDITS')).toBe('RULEBOOK_WITHHELD')
    expect(mapProFetchCode('NO_ACTIVE_RELEASE')).toBe('RULEBOOK_UNREACHABLE')
    expect(mapProFetchCode('SOMETHING_NEW')).toBe('RULEBOOK_UNREACHABLE')
  })

  it('no credit wording anywhere in the table (the CLI holds no plan facts)', () => {
    expect(JSON.stringify(ERROR_CODES).toLowerCase()).not.toMatch(/credit|price|\$\d/)
  })
})

describe('occurrence key and redaction text', () => {
  it('is 12 hex of sha256(rule id + file); line and text never change it', () => {
    const k = occurrenceKey('generic.secrets.stripe-live-key', 'lib/stripe.ts')
    expect(k).toMatch(/^[0-9a-f]{12}$/)
    expect(occurrenceKey('generic.secrets.stripe-live-key', 'lib/stripe.ts')).toBe(k)
    expect(occurrenceKey('generic.secrets.stripe-live-key', 'lib/other.ts')).not.toBe(k)
    expect(occurrenceKey('other.rule', 'lib/stripe.ts')).not.toBe(k)
  })

  it('secret evidence is type and length only, never a character of the value', () => {
    expect(secretEvidenceText('stripe_live_secret_key', 32)).toBe('stripe_live_secret_key, 32 characters, value hidden')
    const ev = evidenceOf(finding({ id: 'generic.secrets.stripe-live-key', category: 'secrets', evidence: '...sk_live_***...' }))
    expect(ev).toEqual({ kind: 'secret', secretType: 'stripe_live_key', length: null, valueHidden: true })
    expect(JSON.stringify(ev)).not.toContain('sk_live')
    expect(evidenceOf(finding({ evidence: 'No guard found' }))).toEqual({ kind: 'text', text: 'No guard found' })
    expect(evidenceOf(finding({}))).toBeNull()
  })

  it('findings sort: blocking first, then severity, confidence, file, line', () => {
    const sorted = sortFindings([
      finding({ id: 'low-nb', blocking: false, severity: 'low' }),
      finding({ id: 'high-b', blocking: true, severity: 'high' }),
      finding({ id: 'crit-b', blocking: true, severity: 'critical' }),
      finding({ id: 'high-nb', blocking: false, severity: 'high' }),
    ]).map((f) => f.id)
    expect(sorted).toEqual(['crit-b', 'high-b', 'high-nb', 'low-nb'])
  })
})

describe('loop state (spec 04): runs = consecutive repeats of the same rule + file', () => {
  const blocking = (...ids: Array<[string, string]>): Map<string, string> =>
    blockingOccurrences(ids.map(([id, file]) => finding({ id, file })))

  it('first run: no sinceLastRun; second identical run: runs 1; third: runs 2', () => {
    const b = blocking(['rule.a', 'a.ts'])
    const r1 = computeSinceLastRun(null, { runId: 'r1', treeDigest: 'd', blocking: b })
    expect(r1.since).toBeNull()
    const r2 = computeSinceLastRun(r1.next, { runId: 'r2', treeDigest: 'd', blocking: b })
    expect(r2.since?.treeChanged).toBe(false)
    expect(r2.since?.unchanged).toEqual([{ id: 'rule.a', occurrence: occurrenceKey('rule.a', 'a.ts'), runs: 1 }])
    const r3 = computeSinceLastRun(r2.next, { runId: 'r3', treeDigest: 'd2', blocking: b })
    expect(r3.since?.treeChanged).toBe(true)
    expect(r3.since?.unchanged[0].runs).toBe(2)
  })

  it('a changed line or matched text does not reset the count (the key has neither)', () => {
    const a = blockingOccurrences([finding({ line: 3, evidence: 'x' })])
    const b = blockingOccurrences([finding({ line: 40, evidence: 'completely different' })])
    expect([...a.keys()]).toEqual([...b.keys()])
  })

  it('fixed / new are reported; a fix drops the count', () => {
    const r1 = computeSinceLastRun(null, { runId: 'r1', treeDigest: 'd', blocking: blocking(['rule.a', 'a.ts'], ['rule.b', 'b.ts']) })
    const r2 = computeSinceLastRun(r1.next, { runId: 'r2', treeDigest: 'd', blocking: blocking(['rule.b', 'b.ts'], ['rule.c', 'c.ts']) })
    expect(r2.since?.fixed).toEqual([occurrenceKey('rule.a', 'a.ts')])
    expect(r2.since?.new).toEqual([occurrenceKey('rule.c', 'c.ts')])
    expect(r2.since?.unchanged.map((u) => u.id)).toEqual(['rule.b'])
  })

  it('non-blocking and suppressed findings are not counted', () => {
    const m = blockingOccurrences([finding({ blocking: false }), finding({ id: 'x', suppressed: true })])
    expect(m.size).toBe(0)
  })
})

describe('agentAction precedence (first row that applies, top to bottom)', () => {
  const since = (runs: number): SinceLastRun => ({ runId: 'p', treeChanged: true, fixed: [], new: [], unchanged: [{ id: 'rule.a', occurrence: 'x', runs }] })
  const base = { value: 'DO_NOT_SHIP' as const, blockingCount: 1, degraded: false, steps: [] as NextStep[], sinceLastRun: null }

  it('row 2 beats everything: a repeat at runs >= 2 asks the human, even with coverage gaps', () => {
    expect(decideAgentAction({ ...base, sinceLastRun: since(2), degraded: true })).toBe('ask_human')
    expect(decideAgentAction({ ...base, sinceLastRun: since(1) })).toBe('fix_and_rerun')
  })

  it('row 3: incomplete scan asks the human when a coverage step has askUser, else fix_and_rerun', () => {
    const askStep = { order: 1, kind: 'coverage', label: 'x', command: null, safe: false, blocking: true, askUser: true } as NextStep
    const plain = { ...askStep, askUser: false } as NextStep
    expect(decideAgentAction({ ...base, degraded: true, blockingCount: 0, steps: [askStep] })).toBe('ask_human')
    expect(decideAgentAction({ ...base, degraded: true, blockingCount: 0, steps: [plain] })).toBe('fix_and_rerun')
  })

  it('rows 4-6: blocking = fix_and_rerun; REVIEW and SAFE = proceed', () => {
    expect(decideAgentAction(base)).toBe('fix_and_rerun')
    expect(decideAgentAction({ ...base, value: 'REVIEW_BEFORE_SHIP', blockingCount: 0 })).toBe('proceed')
    expect(decideAgentAction({ ...base, value: 'SAFE_TO_SHIP', blockingCount: 0 })).toBe('proceed')
  })

  it('a fallback or an offline plan can never turn a blocking scan into proceed (modifier rows set nothing)', () => {
    // The decision function has no input for them: the scan's own row decides.
    expect(decideAgentAction({ ...base })).toBe('fix_and_rerun')
  })

  it('the outcome table printed by `schema --json` has 6 numbered rows and 2 modifier rows', () => {
    expect(OUTCOMES.filter((o) => o.precedence !== null).map((o) => o.precedence)).toEqual([1, 2, 3, 4, 5, 6])
    expect(OUTCOMES.filter((o) => o.precedence === null)).toHaveLength(2)
  })
})

describe('nextSteps', () => {
  const baseInput: OutcomeInput = {
    value: 'DO_NOT_SHIP', blockingFindings: [], degraded: false, degradedReasons: [], notScanned: [], sinceLastRun: null,
    warnings: [], rerunCommand: 'shipguard scan --strict', reportMarkdown: '.shipguard/reports/latest.md',
  }

  it('orders fixes: secrets first, then severity, payments/auth before the rest; ends with the re-run', () => {
    const steps = buildNextSteps({
      ...baseInput,
      blockingFindings: [
        finding({ id: 'cfg', category: 'config', severity: 'high', file: 'c.ts' }),
        finding({ id: 'auth', category: 'auth', severity: 'high', file: 'b.ts' }),
        finding({ id: 'key', category: 'secrets', severity: 'critical', file: 'a.ts' }),
      ],
    })
    expect(steps.map((s) => s.findingId ?? s.kind)).toEqual(['key', 'auth', 'cfg', 'rerun'])
    expect(steps.map((s) => s.order)).toEqual([1, 2, 3, 4])
    expect(steps[3]).toMatchObject({ kind: 'rerun', command: 'shipguard scan --strict', safe: true, label: 'Re-run after fixing all 3' })
    for (const s of steps) expect(NEXT_STEP_KINDS).toContain(s.kind)
  })

  it('two matches of one rule in one file are one fix step (one occurrence key)', () => {
    const steps = buildNextSteps({ ...baseInput, blockingFindings: [finding({ line: 1 }), finding({ line: 9 })] })
    expect(steps.filter((s) => s.kind === 'fix')).toHaveLength(1)
  })

  it('coverage steps carry askUser, never a runnable command with a placeholder reason; re-run comes last', () => {
    const steps = buildNextSteps({
      ...baseInput,
      value: 'DO_NOT_SHIP', degraded: true,
      degradedReasons: [{ code: 'FILE_TOO_LARGE', files: ['big.txt'], detail: 'd', fix: 'raise it', command: null, askUser: true }],
      notScanned: [{ file: 'big.txt', code: 'FILE_TOO_LARGE', bytes: null, counts: true }],
    })
    expect(steps[0]).toMatchObject({ kind: 'coverage', file: 'big.txt', code: 'FILE_TOO_LARGE', askUser: true, command: null })
    expect(steps[steps.length - 1].kind).toBe('rerun')
    expect(steps.every((s) => s.kind !== 'ignore' || s.command === null)).toBe(true)
  })

  it('a repeat adds the one fixed string; runs >= 2 stops (review step, no re-run command)', () => {
    const since = (runs: number, treeChanged: boolean): SinceLastRun => ({ runId: 'p', treeChanged, fixed: [], new: [], unchanged: [{ id: 'rule.a', occurrence: 'x', runs }] })
    const f = [finding()]
    const changed = buildNextSteps({ ...baseInput, blockingFindings: f, sinceLastRun: since(1, true) })
    expect(changed.map((s) => s.label)).toContain(REPEAT_LABELS.changed)
    const same = buildNextSteps({ ...baseInput, blockingFindings: f, sinceLastRun: since(1, false) })
    expect(same.map((s) => s.label)).toContain(REPEAT_LABELS.unchangedScan)
    const stop = buildNextSteps({ ...baseInput, blockingFindings: f, sinceLastRun: since(2, true) })
    expect(stop[stop.length - 1]).toMatchObject({ kind: 'review', label: REPEAT_LABELS.stop, askUser: true })
    expect(stop.some((s) => s.kind === 'rerun')).toBe(false)
  })

  it('a clean scan: setup when no gate is installed, update_hook when stale, else a re-check', () => {
    const clean = { ...baseInput, value: 'SAFE_TO_SHIP' as const }
    expect(buildNextSteps({ ...clean, install: { agent: 'claude', gateInstalled: false, hookStale: false } })[0])
      .toMatchObject({ kind: 'setup', command: 'shipguard setup --agent claude' })
    expect(buildNextSteps({ ...clean, install: { agent: 'claude', gateInstalled: true, hookStale: true } })[0].kind).toBe('update_hook')
    expect(buildNextSteps(clean)[0]).toMatchObject({ kind: 'rerun', label: 'Nothing to fix. Re-check after changes' })
  })
})

describe('plan block with no plan data (spec 02 coverage branch): states no plan fact', () => {
  const input = { stacks: ['nextjs', 'supabase'], complete: true, blockingCount: 0, rulebookRan: false, rulebookFallbackCode: null, ci: false, muted: false, jsonPitchAllowed: true }

  it('every recommendation object has all seven keys; next.command is always `shipguard upgrade --json`', () => {
    for (const over of [{}, { blockingCount: 2 }, { ci: true }, { muted: true }, { stacks: [] }, { rulebookRan: true }, { complete: false }, { jsonPitchAllowed: false }]) {
      const plan = buildPlanJson({ ...input, ...over }) as { recommendation: Record<string, unknown> }
      expect(Object.keys(plan.recommendation).sort()).toEqual(['eligible', 'kind', 'mute', 'next', 'reason', 'relay', 'sentence'])
      expect((plan.recommendation.next as { command: string }).command).toBe('shipguard upgrade --json')
    }
  })

  it('coverage sentence is number-free and names the detected stack; relay only when nothing suppresses it', () => {
    const plan = buildPlanJson(input) as { recommendation: { relay: boolean; kind: string; sentence: string } }
    expect(plan.recommendation).toMatchObject({ relay: true, kind: 'coverage' })
    expect(plan.recommendation.sentence).toBe('Checks for Next.js + Supabase beyond the general rules did not run here; details: shipguard upgrade')
    expect(plan.recommendation.sentence).not.toMatch(/\d/)
    const blocked = buildPlanJson({ ...input, blockingCount: 1 }) as { recommendation: { relay: boolean; reason: string; sentence: string } }
    expect(blocked.recommendation).toMatchObject({ relay: false, reason: 'BLOCKING_FINDINGS' })
    expect(blocked.recommendation.sentence).toBeTruthy()
    expect((buildPlanJson({ ...input, ci: true }) as { recommendation: { reason: string } }).recommendation.reason).toBe('CI')
    expect((buildPlanJson({ ...input, muted: true }) as { recommendation: { reason: string } }).recommendation.reason).toBe('MUTED')
  })

  it('the block itself is unavailable/NOT_FETCHED with no server data and no link', () => {
    expect(buildPlanJson(input)).toMatchObject({ status: 'unavailable', reason: 'NOT_FETCHED', server: null, link: null, command: 'shipguard upgrade' })
  })
})

describe('re-run command builder (spec 01 rule 7): one function, one test per option', () => {
  const root = '/work/proj'
  const mk = (over: Partial<Parameters<typeof buildRerunCommand>[0]> = {}): string =>
    buildRerunCommand({ invocationCwd: root, scanRoot: root, ...over })

  it('bare form when the target is the cwd', () => {
    expect(mk()).toBe('shipguard scan --strict')
  })
  it('target relative to where the command ran, ./-prefixed, shell-quoted when needed', () => {
    expect(mk({ scanRoot: `${root}/apps/web` })).toBe('shipguard scan ./apps/web --strict')
    expect(mk({ scanRoot: `${root}/apps/my web`, pro: true })).toBe("shipguard scan './apps/my web' --strict --pro")
    expect(mk({ scanRoot: '/work/other' })).toBe('shipguard scan ../other --strict')
  })
  it('carries --all, --policy, --pro, --general and --allow-degraded; --strict is added once, in its place', () => {
    expect(mk({ all: true })).toBe('shipguard scan --strict --all')
    expect(mk({ policy: 'my policy.yml' })).toBe("shipguard scan --strict --policy 'my policy.yml'")
    expect(mk({ pro: true })).toBe('shipguard scan --strict --pro')
    expect(mk({ general: true })).toBe('shipguard scan --strict --general')
    expect(mk({ allowDegraded: true })).toBe('shipguard scan --strict --allow-degraded')
  })
  it('never carries output flags (the builder has no input for them)', () => {
    expect(mk({ pro: true, all: true })).not.toMatch(/--json|--quiet|--sarif|--schema-version/)
  })
  it('shellQuote round-trips an apostrophe and leaves safe words alone', () => {
    expect(shellQuote("a'b")).toBe("'a'\\''b'")
    expect(shellQuote('./a/b-c_d.ts')).toBe('./a/b-c_d.ts')
    expect(shellQuote('')).toBe("''")
  })
})
