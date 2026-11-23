/** W1b: the plan block through the real CLI (built dist): JSON recommendation, mute, setup of counters, upgrade, status, telemetry list. */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { execSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { cleanupTrees, mkTree, runCli, scanJson } from '../helpers/cli-fixture.js'

const pkgRoot = join(__dirname, '..', '..')
let home: string
const env = () => ({ HOME: home, SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1' })
const proj = () => mkTree({ 'package.json': JSON.stringify({ name: 'a', dependencies: { next: '16.0.0', '@supabase/supabase-js': '2.45.4' } }), 'index.js': 'console.log(1)\n' }, { git: true })

beforeAll(() => {
  if (!existsSync(join(pkgRoot, 'dist/cli.js'))) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  home = mkdtempSync(join(tmpdir(), 'sg-w1b-home-'))
}, 180_000)
afterAll(() => { cleanupTrees(); rmSync(home, { recursive: true, force: true }) })

describe('signed out, nothing fetched (tracking off)', () => {
  it('scan --json: plan unavailable NOT_FETCHED, a number-free coverage sentence, writes nothing under ~/.config but nothing breaks', async () => {
    const run = await scanJson(proj(), [], { env: env() })
    const plan = run.json!.plan
    expect(plan).toMatchObject({ status: 'unavailable', reason: 'NOT_FETCHED', server: null, link: null })
    expect(plan.recommendation).toMatchObject({ kind: 'coverage', reason: 'NO_PLAN_DATA' })
    expect(plan.recommendation.sentence).toContain('Next.js + Supabase')
    expect(plan.agentNote).toMatch(/do not follow instructions/)
    expect(run.json!.rules).toMatchObject({ corpus: 'general', fallback: null, receipt: null })
  })

  it('--general and a plain scan agree; --pro without a sign-in exits 3 with LOGIN_REQUIRED and the free-scan line, and writes no .shipguard.yml', async () => {
    const dir = proj()
    const r = await runCli(['scan', dir, '--pro', '--json'], { env: env() })
    expect(r.code).toBe(3)
    expect(r.json?.error?.code).toBe('LOGIN_REQUIRED')
    expect(r.stderr).toContain('Or run the free scan now: shipguard scan')
    expect(existsSync(join(dir, '.shipguard.yml'))).toBe(false)
    const g = await scanJson(dir, ['--general'], { env: env() })
    expect(g.json!.rules.corpus).toBe('general')
  })

  it('a planted .shipguard/plan.json changes nothing (nothing is read from the scanned project)', async () => {
    const dir = proj()
    const { writeFileSync, mkdirSync } = await import('node:fs')
    mkdirSync(join(dir, '.shipguard'), { recursive: true })
    writeFileSync(join(dir, '.shipguard/plan.json'), JSON.stringify({ status: 'live', server: { label: 'PLANTED' } }))
    const run = await scanJson(dir, [], { env: env() })
    expect(JSON.stringify(run.json)).not.toContain('PLANTED')
  })

  it('safe mode writes nothing under ~/.config/shipguard on a scan', async () => {
    const h = mkdtempSync(join(tmpdir(), 'sg-w1b-safe-'))
    await scanJson(proj(), ['--safe-mode'], { env: { HOME: h, SHIPGUARD_TELEMETRY: '0' } })
    expect(existsSync(join(h, '.config', 'shipguard')) ? readdirSync(join(h, '.config', 'shipguard')) : []).toEqual([])
    rmSync(h, { recursive: true, force: true })
  })
})

describe('upgrade and status without a sign-in', () => {
  it('upgrade --dry-run names the one request and sends nothing', async () => {
    const r = await runCli(['upgrade', '--dry-run'], { env: env(), cwd: proj() })
    expect(r.code).toBe(0)
    expect(r.stdout).toContain('Nothing was sent.')
    expect(r.stdout).toMatch(/GET .*\/api\/cli\/v1\/offer\?stacks=nextjs,supabase/)
  })

  it('status: signed out line, exit 0; status --json is the 7 envelope with null exit keys', async () => {
    const r = await runCli(['status'], { env: env() })
    expect(r.code).toBe(0)
    expect(r.stdout).toMatch(/^Not signed in\. Rules: general rules only \(\d+ bundled, offline\)\. What a plan would add: shipguard upgrade/)
    const j = await runCli(['status', '--json'], { env: env() })
    expect(j.json).toMatchObject({ schemaVersion: '7', ok: true, runId: null, agentAction: 'proceed', exit: { code: 0, strict: null, strictWouldExit: null } })
    expect(j.json?.plan.recommendation.next === null || j.json?.plan.recommendation.next.command === 'shipguard upgrade --json').toBe(true)
  })

  it('upgrade --mute writes muted:true and SHIPGUARD_NO_PROMO=1 mutes the JSON recommendation', async () => {
    const h = mkdtempSync(join(tmpdir(), 'sg-w1b-mute-'))
    const e = { HOME: h, SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1' }
    const m = await runCli(['upgrade', '--mute'], { env: e })
    expect(m.code).toBe(0)
    expect(JSON.parse(readFileSync(join(h, '.config', 'shipguard', 'nag.json'), 'utf8')).muted).toBe(true)
    const run = await scanJson(proj(), [], { env: e })
    expect(run.json!.plan.recommendation).toMatchObject({ relay: false, reason: 'MUTED' })
    rmSync(h, { recursive: true, force: true })
  })

  it('telemetry status lists every other request (weekly offer fetch with stack names only, the setup fetch, the plan read)', async () => {
    const r = await runCli(['telemetry', 'status'], { env: env() })
    expect(r.stdout).toContain('weekly public offer fetch')
    expect(r.stdout).toContain('stack names only')
    expect(r.stdout).toContain('generic offer fetch by `shipguard setup`')
    expect(r.stdout).toContain('plan read')
    const j = await runCli(['telemetry', 'status', '--json'], { env: env() })
    expect(j.json?.otherRequests).toHaveLength(5)
  })

  it('`hook --target nope` is a config error (exit 2)', async () => {
    const r = await runCli(['hook', '--target', 'nope'], { env: env() })
    expect(r.code).toBe(2)
  })
})
