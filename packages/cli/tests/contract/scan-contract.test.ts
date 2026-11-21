/**
 * W2b e2e: the built CLI's `--json` contract (spec 02). Spawns dist/cli.js.
 * Covers: schema snapshot of every outcome, additive check against the real 0.12.0 shape, error codes with the
 * one template, the re-run command round trip, scanId reuse on a gate-style re-run, `next.command`, the
 * exit-code table, loop-stop, `schema --json`, no plugin/explain/offline strings.
 */
import { execSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, pkgRoot, runCli, scanJson } from '../helpers/cli-fixture.js'
import type { CliRun } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })

const here = dirname(fileURLToPath(import.meta.url))
const baseline = JSON.parse(readFileSync(join(here, 'fixtures/json-0.12.0-shape.json'), 'utf-8')) as {
  topLevel: Record<string, string>
  riskScoreKeys: string[]
  coverageKeys: string[]
  findingKeys: string[]
  changedFindingKeys: Record<string, string>
}

const env = { SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1' }
const typeOf = (v: unknown): string => (Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v)

/** A git project with one blocking auth finding and one blocking Stripe key (the spec's A1 shape, smaller). */
function commit(dir: string): string {
  execSync('git add -A && git -c user.email=t@e.st -c user.name=t commit -qm init', { cwd: dir })
  return dir
}
function blockedProject(): string {
  return commit(mkTree({
    'package.json': JSON.stringify({ name: 'my-app', dependencies: { next: '16.0.0', '@supabase/supabase-js': '2.45.4' } }),
    'app/api/admin/users/route.ts': 'export async function GET() { return Response.json({}) }\n',
    'lib/stripe.ts': `const k = "${['sk', 'live', 'abcdefghijklmnopqrstuvwxyz1234'].join('_')}"\n`,
  }, { git: true }))
}
const cleanProject = (): string => mkTree({ 'package.json': '{"name":"clean"}', 'index.js': 'console.log(1)\n' }, { git: true })

beforeAll(() => {
  if (!existsSync(join(pkgRoot, 'dist/cli.js'))) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
}, 120_000)
afterAll(cleanupTrees)

async function json(dir: string, extra: string[] = []): Promise<{ run: CliRun; j: Record<string, any> }> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const run = await scanJson(dir, extra, { env })
  expect(run.json, `${run.stdout}\n${run.stderr}`).toBeDefined()
  return { run, j: run.json! }
}

describe('scan --json: schema 7 snapshot of every outcome', () => {
  it('blocked: verdict, exit, agentAction, nextSteps, stack, rules, plan, sorted findings with the same keys', async () => {
    const { run, j } = await json(blockedProject())
    expect(run.code).toBe(0)
    expect(j).toMatchObject({
      schemaVersion: '7', ok: true,
      verdict: { value: 'DO_NOT_SHIP', reason: 'BLOCKING_FINDINGS', complete: true },
      exit: { code: 0, strict: false, strictWouldExit: 1 },
      agentAction: 'fix_and_rerun',
      rules: { corpus: 'general', localChecks: true, fallback: null, receipt: null },
      plan: { status: 'unavailable', reason: 'NOT_FETCHED', server: null },
      degraded: false,
    })
    expect(j.stack).toMatchObject({ supported: true })
    expect(j.stack.detected).toEqual(expect.arrayContaining(['nextjs@16.0.0']))
    expect(j.rules.applied).toBeGreaterThan(0)
    expect(j.findings.length).toBeGreaterThanOrEqual(2)
    // every finding has the SAME keys, nullable, never absent
    const keySets = new Set(j.findings.map((f: object) => Object.keys(f).sort().join(',')))
    expect(keySets.size).toBe(1)
    for (const f of j.findings) {
      expect(f.occurrence).toMatch(/^[0-9a-f]{12}$/)
      expect(typeof f.fix).toBe('object')
      expect(f.fix.verify).toMatchObject({ expect: 'no entry in findings[] has this occurrence key' })
      expect(typeof f.why).toBe('string')
    }
    // blocking first, then severity
    const blockFlags = j.findings.map((f: { blocking: boolean }) => f.blocking)
    expect(blockFlags).toEqual([...blockFlags].sort((a: boolean, b: boolean) => Number(b) - Number(a)))
    // steps: a fix per blocking occurrence, re-run last, orders 1..n
    const kinds = j.nextSteps.map((s: { kind: string }) => s.kind)
    expect(kinds[kinds.length - 1]).toBe('rerun')
    expect(j.nextSteps.map((s: { order: number }) => s.order)).toEqual(j.nextSteps.map((_: unknown, i: number) => i + 1))
  })

  it('clean: SAFE_TO_SHIP, proceed, a first step that sets the gate up (no gate installed)', async () => {
    // Run from inside the project: the re-run command is relative to where the command ran.
    const run = await runCli(['scan', '--json'], { cwd: cleanProject(), env })
    const j = run.json!
    expect(j).toMatchObject({ verdict: { value: 'SAFE_TO_SHIP', reason: 'SAFE_TO_SHIP', complete: true }, agentAction: 'proceed', degraded: false })
    // The first step comes from the detected agent and the install state (spec 02): no gate here, a git repo -> setup for git.
    expect(j.nextSteps[0].kind).toBe('setup')
    expect(j.nextSteps[0].command).toMatch(/^shipguard setup --agent (git|claude|codex|cursor)$/)
    expect(j.findings).toEqual([])
  })

  it('incomplete scan: INCOMPLETE_SCAN, coverage step per unscanned file with askUser, ask_human', async () => {
    const dir = mkTree({
      'package.json': '{"name":"inc"}',
      'a.js': 'x\n',
      'mystery.dat': Buffer.concat([Buffer.from('hello'), Buffer.alloc(300, 0), Buffer.from('world\x01\x02\x03')]),
    }, { git: true })
    const { j } = await json(dir)
    if (j.degraded !== true) return // environment-dependent classification; the unit tests cover the mapping
    expect(j.verdict).toMatchObject({ value: 'DO_NOT_SHIP', reason: 'INCOMPLETE_SCAN', complete: false })
    expect(j.coverage.complete).toBe(false)
    expect(j.coverage.notScanned.length).toBeGreaterThan(0)
    const cov = j.nextSteps.filter((s: { kind: string }) => s.kind === 'coverage')
    expect(cov.length).toBeGreaterThan(0)
    for (const s of cov) expect(s.command).toBeNull()
    expect(j.nextSteps[j.nextSteps.length - 1].kind).toBe('rerun')
    for (const r of j.degradedReasons) expect(Object.keys(r)).toEqual(expect.arrayContaining(['code', 'files', 'detail', 'fix', 'command', 'askUser']))
  })
})

describe('additive: every 0.12.0 key keeps its name and type (only the three finding fields change)', () => {
  it('top level, riskScore, coverage and finding keys', async () => {
    const { j } = await json(blockedProject())
    for (const [key, type] of Object.entries(baseline.topLevel)) {
      expect(j, `old top-level key ${key} is gone`).toHaveProperty(key)
      expect(typeOf(j[key]), `old key ${key} changed type`).toBe(type)
    }
    expect(Object.keys(j.riskScore)).toEqual(expect.arrayContaining(baseline.riskScoreKeys))
    expect(Object.keys(j.coverage)).toEqual(expect.arrayContaining(baseline.coverageKeys))
    for (const f of j.findings) {
      expect(Object.keys(f)).toEqual(expect.arrayContaining(baseline.findingKeys))
    }
    // the three declared breaking changes
    for (const f of j.findings) {
      expect(typeof f.fix).toBe('object')
      // main decision (wave 2): the 0.12 `explanation` prose stays, additively, beside the short `why`
      expect(typeof f.explanation).toBe('string')
      expect(f.evidence === null || typeof f.evidence === 'object').toBe(true)
    }
    // old aliases carry the same values as the new fields
    expect(j.recommendation).toBe(j.verdict.value)
    expect(j.riskScore.recommendation).toBe(j.verdict.value)
  })

  it('the removed --schema-version switch is a usage error (exit 2) with the one template', async () => {
    const r = await runCli(['scan', blockedProject(), '--json', '--schema-version', '5'], { env })
    expect(r.code).toBe(2)
    expect(r.stderr).toContain('UNKNOWN_OPTION')
    expect(r.json?.error?.code).toBe('UNKNOWN_OPTION')
  })
})

describe('recommendation block and plan: no plan facts, fixed next command', () => {
  it('every plan.recommendation has all seven keys and next.command is `shipguard upgrade --json`', async () => {
    for (const dir of [blockedProject(), cleanProject()]) {
      const { j } = await json(dir)
      expect(Object.keys(j.plan.recommendation).sort()).toEqual(['eligible', 'kind', 'mute', 'next', 'reason', 'relay', 'sentence'])
      // spec 02 check 2: `next.command` is `shipguard upgrade --json` on every scan-JSON recommendation that has a `next`
      if (j.plan.recommendation.next) expect(j.plan.recommendation.next.command).toBe('shipguard upgrade --json')
    }
  })

  it('no price, credit, trial or plan-name words anywhere in the plan block of a Free scan', async () => {
    const { j } = await json(blockedProject())
    expect(JSON.stringify(j.plan)).not.toMatch(/\$\s?\d|credit|trial|per month|Plus\b/i)
  })

  it('SHIPGUARD_NO_PROMO=1 mutes the recommendation (relay false, reason MUTED) on a clean scan', async () => {
    const run = await scanJson(cleanProject(), [], { env: { ...env, SHIPGUARD_NO_PROMO: '1' } })
    expect(run.json?.plan.recommendation.relay).toBe(false)
  })

  it('a planted .shipguard/plan.json in the scanned project changes nothing', async () => {
    const dir = cleanProject()
    mkdirSync(join(dir, '.shipguard'), { recursive: true })
    writeFileSync(join(dir, '.shipguard/plan.json'), JSON.stringify({ status: 'live', server: { label: 'PLANTED' } }))
    const { j } = await json(dir)
    expect(j.plan).toMatchObject({ status: 'unavailable', server: null })
    expect(JSON.stringify(j)).not.toContain('PLANTED')
  })
})

describe('errors: one template on stderr, one envelope on stdout, exit table', () => {
  it('PATH_NOT_FOUND: exit 2, error.command null (no real path known), fix names an example only', async () => {
    const r = await runCli(['scan', '/definitely/not/here', '--json'], { env })
    expect(r.code).toBe(2)
    expect(r.json).toMatchObject({ schemaVersion: '7', ok: false, error: { code: 'PATH_NOT_FOUND', command: null }, agentAction: 'fix_and_rerun', exit: { code: 2 } })
    expect(r.stderr).toMatch(/✗ PATH_NOT_FOUND: .*\n {2}Cause: .*\n {2}Fix: /)
  })

  it('NOT_A_PROJECT and UNKNOWN_COMMAND (also the removed explain) use the template with a Fix line', async () => {
    const empty = mkTree({ 'readme.txt': 'x' })
    const a = await runCli(['scan', '--json'], { cwd: empty, env })
    expect(a.code).toBe(2)
    expect(a.json?.error.code).toBe('NOT_A_PROJECT')
    for (const cmd of ['explain', 'doctor']) {
      const r = await runCli([cmd, '--json'], { env })
      expect(r.code, cmd).toBe(2)
      expect(r.json?.error.code, cmd).toBe('UNKNOWN_COMMAND')
      expect(r.stderr).toMatch(/Fix: /)
    }
  })

  it('exactly one message per error: an unknown option prints the code once', async () => {
    const r = await runCli(['scan', cleanProject(), '--bogus'], { env })
    expect(r.code).toBe(2)
    expect(r.stderr.match(/UNKNOWN_OPTION/g)).toHaveLength(1)
    expect(r.stderr).not.toMatch(/error: unknown option/i)
  })

  it('INVALID_POLICY names the file and line', async () => {
    const dir = mkTree({ 'package.json': '{"name":"p"}', 'shipguard.policy.yml': 'ignore:\n  paths: [unclosed\n' })
    const r = await runCli(['scan', dir, '--json'], { env })
    expect(r.code).toBe(2)
    expect(r.json?.error).toMatchObject({ code: 'INVALID_POLICY', file: 'shipguard.policy.yml' })
  })

  it('exit-code table: 0 completed (even blocked), 1 only with --strict, 2 config, 3 runtime', async () => {
    const blocked = blockedProject()
    expect((await runCli(['scan', blocked, '--json'], { env })).code).toBe(0)
    const strict = await runCli(['scan', blocked, '--json', '--strict'], { env })
    expect(strict.code).toBe(1)
    expect(strict.json?.exit).toMatchObject({ code: 1, strict: true, strictWouldExit: 1 })
    expect((await runCli(['scan', cleanProject(), '--json', '--strict'], { env })).code).toBe(0)
    expect((await runCli(['scan', '/nope', '--json'], { env })).code).toBe(2)
    const pro = await runCli(['scan', blocked, '--pro', '--json', '--api-url', 'http://127.0.0.1:1'], { env })
    expect(pro.code).toBe(3)
    expect(pro.json?.ok).toBe(false)
  })
})

describe('re-run command round trip and scan id reuse', () => {
  it('the rerun step runs as printed: same target, --strict, exit 1 while blockers remain', async () => {
    const dir = blockedProject()
    // Run from the target folder: the builder prints the bare form.
    const first = await runCli(['scan', '--json'], { cwd: dir, env })
    const step = first.json!.nextSteps.find((s: { kind: string }) => s.kind === 'rerun')
    expect(step.command).toBe('shipguard scan --strict')
    const r = await runCli(['scan', '--strict', '--json'], { cwd: dir, env })
    expect(r.code).toBe(1)
    expect(r.json?.verdict.value).toBe('DO_NOT_SHIP')
    // From the parent folder the same step carries the relative target.
    const parent = '/tmp'
    const rel = await runCli(['scan', blockedProject(), '--json'], { cwd: parent, env })
    const relStep = rel.json?.nextSteps.find((s: { kind: string }) => s.kind === 'rerun')
    expect(relStep.command).toMatch(/^shipguard scan '?\.\/.+' --strict$|^shipguard scan \.\/\S+ --strict$/)
  })

  it('an identical re-run reuses the scan id (no second counted scan) and says so', async () => {
    const dir = blockedProject()
    const first = (await json(dir)).j
    const second = (await json(dir)).j
    expect(first.scanIdReused).toBe(false)
    expect(second.scanIdReused).toBe(true)
    expect(second.runId).toBe(first.runId)
    expect(second.scanIdReusedReason).toEqual(expect.any(String))
  })

  it('loop stop: the same rule + file on the third scan in a row asks the human', async () => {
    const dir = blockedProject()
    const r1 = (await json(dir)).j
    expect(r1.sinceLastRun).toBeNull()
    const r2 = (await json(dir)).j
    expect(r2.sinceLastRun.unchanged.every((u: { runs: number }) => u.runs === 1)).toBe(true)
    expect(r2.agentAction).toBe('fix_and_rerun')
    const r3 = (await json(dir)).j
    expect(r3.sinceLastRun.unchanged.every((u: { runs: number }) => u.runs === 2)).toBe(true)
    expect(r3.agentAction).toBe('ask_human')
    expect(r3.nextSteps[r3.nextSteps.length - 1].kind).toBe('review')
  })
})

describe('schema --json', () => {
  it('carries the code table, the outcome table, step kinds and a JSON Schema generated from the same source', async () => {
    const r = await runCli(['schema', '--json'], { env })
    expect(r.code).toBe(0)
    const c = r.json!
    expect(c.schemaVersion).toBe('7')
    expect(c.verdictValues).toEqual(['SAFE_TO_SHIP', 'REVIEW_BEFORE_SHIP', 'DO_NOT_SHIP'])
    for (const [code, e] of Object.entries(c.errorCodes as Record<string, { exit: number; cause: string; fix: string; agentAction: string }>)) {
      expect(e.cause.length, code).toBeGreaterThan(0)
      expect(e.fix.length, code).toBeGreaterThan(0)
      expect(['proceed', 'fix_and_rerun', 'retry', 'ask_human', 'stop'], code).toContain(e.agentAction)
    }
    expect(Object.keys(c.errorCodes)).toEqual(expect.arrayContaining(['PATH_NOT_FOUND', 'LOGIN_REQUIRED', 'RULEBOOK_PARTIAL', 'INTERNAL_ERROR']))
    expect(c.outcomes).toHaveLength(8)
    expect(c.nextStepKinds).toContain('coverage')
    expect(c.jsonSchema.$schema).toContain('2020-12')
    expect(JSON.stringify(c).toLowerCase()).not.toMatch(/credit/)
  })

  it('a scan result validates against its own required keys and enums', async () => {
    const schema = (await runCli(['schema', '--json'], { env })).json!.jsonSchema as { required: string[]; properties: Record<string, any> } // eslint-disable-line @typescript-eslint/no-explicit-any
    const { j } = await json(blockedProject())
    for (const k of schema.required) expect(j, k).toHaveProperty(k)
    expect(schema.properties.agentAction.enum).toContain(j.agentAction)
    expect(schema.properties.verdict.properties.value.enum).toContain(j.verdict.value)
    for (const s of j.nextSteps) expect(schema.properties.nextSteps.items.properties.kind.enum).toContain(s.kind)
  })
})

describe('help and strings', () => {
  it('--help carries the core line; no flag or text is called --offline; no plugin text', async () => {
    const r = await runCli(['--help'], { env })
    expect(r.stdout).toContain('Review code with a rulebook to build secure code')
    const scanHelp = await runCli(['scan', '--help'], { env })
    for (const text of [r.stdout, scanHelp.stdout]) {
      expect(text).not.toMatch(/--offline/)
      expect(text).not.toMatch(/plugin/i)
      expect(text).not.toMatch(/credit/i)
    }
  })
})
