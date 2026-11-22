/**
 * Regression tests for the 0.13.0 E2E block-1 failures (B-17/B-29, B-15, S-02, A-03, A-04, A-06, E-09, C-02).
 * Spawns the built CLI (dist/cli.js). Each case fails on a5d6a6f and passes with the fix.
 */
import { execSync } from 'node:child_process'
import { chmodSync, existsSync, mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, pkgRoot, runCli } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })

const env = { SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1' }
const stripe = `const k = "${['sk', 'live', 'abcdefghijklmnopqrstuvwxyz1234'].join('_')}"\n`
const SQL = 'const q = db.queryRawUnsafe("SELECT * FROM t WHERE id=" + req.query.id)\n'

beforeAll(() => {
  if (!existsSync(join(pkgRoot, 'dist/cli.js'))) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
}, 120_000)
afterAll(cleanupTrees)

const project = (files: Record<string, string | Buffer>): string => mkTree({ 'package.json': '{"name":"app"}', ...files }, { git: true })

describe('B-17 / B-29: one verdict for screen, JSON, --strict and the gate', () => {
  it('a blocking finding is DO NOT SHIP everywhere and --strict exits 1', async () => {
    const dir = project({ 'lib/stripe.ts': stripe })
    const human = await runCli(['scan', dir, '--strict'], { env })
    expect(human.code).toBe(1)
    expect(human.stdout.split('\n')[0]).toMatch(/^DO NOT SHIP · 1 blocking/)
    expect(human.stdout).not.toContain('Nothing here blocks a push')
    const j = (await runCli(['scan', dir, '--json'], { env })).json!
    expect(j.verdict).toMatchObject({ value: 'DO_NOT_SHIP', reason: 'BLOCKING_FINDINGS', blockingCount: 1 })
    expect(j.exit.strictWouldExit).toBe(1)
    expect(j.agentAction).toBe('fix_and_rerun')
  })

  it('non-blocking findings only: REVIEW BEFORE SHIP, never "no rule matched", --strict exits 0', async () => {
    const dir = project({ 'src/a.js': SQL })
    const human = await runCli(['scan', dir, '--strict'], { env })
    expect(human.code).toBe(0)
    expect(human.stdout.split('\n')[0]).toMatch(/^REVIEW BEFORE SHIP · 1 finding, 0 blocking/)
    expect(human.stdout).not.toContain('no rule matched')
    const j = (await runCli(['scan', dir, '--json'], { env })).json!
    expect(j.verdict).toMatchObject({ value: 'REVIEW_BEFORE_SHIP', blockingCount: 0 })
    expect(j.exit.strictWouldExit).toBe(0)
    expect(j.agentAction).toBe('proceed')
  })
})

describe('B-15: fix and evidence keep their 0.12 string shape; objects are fixInfo / evidenceInfo', () => {
  it('scan --json and schema --json', async () => {
    const dir = project({ 'lib/stripe.ts': stripe, 'src/a.js': SQL })
    const j = (await runCli(['scan', dir, '--json'], { env })).json!
    for (const f of j.findings) {
      expect(typeof f.fix).toBe('string')
      expect(f.evidence === null || typeof f.evidence === 'string').toBe(true)
      expect(f.fixInfo.verify.command).toContain('shipguard scan')
      expect(f.evidenceInfo === null || typeof f.evidenceInfo.kind === 'string').toBe(true)
    }
    const secret = j.findings.find((f: { category: string }) => f.category === 'secrets')
    expect(secret.evidence).toContain('value hidden')
    expect(secret.evidenceInfo).toMatchObject({ kind: 'secret', valueHidden: true })
    const schema = (await runCli(['schema', '--json'], { env })).json!
    const props = schema.jsonSchema.properties.findings.items
    expect(props.required).toEqual(expect.arrayContaining(['fix', 'fixInfo', 'evidence', 'evidenceInfo']))
    expect(props.properties.fix.type).toBe('string')
    expect(props.properties.fixInfo.type).toBe('object')
  })
})

describe('S-02: one not-scanned count on screen and in JSON, every file named', () => {
  it('invalid UTF-8 and NUL-data files', async () => {
    const dir = project({
      'index.js': 'console.log(1)\n',
      'lib/b.js': 'console.log(2)\n',
      'latin1.txt': Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x20, 0xff, 0xfe, 0xfd, 0x0a, 0xc3, 0x28]),
      'blob.dat': Buffer.concat([Buffer.from([0, 1, 2, 3, 0, 5, 0, 7]), Buffer.alloc(300, 0)]),
    })
    const human = await runCli(['scan', dir], { env })
    const j = (await runCli(['scan', dir, '--json'], { env })).json!
    const m = /(\d+) of (\d+) files were not scanned/.exec(human.stdout.split('\n')[0])
    expect(m, human.stdout).not.toBeNull()
    const jm = /(\d+) of (\d+) files were not scanned/.exec(j.verdict.summary)
    expect(jm, j.verdict.summary).not.toBeNull()
    expect([jm![1], jm![2]]).toEqual([m![1], m![2]])
    // the numbers add up: not scanned + scanned = total
    expect(Number(m![1]) + j.coverage.scanned).toBe(Number(m![2]))
    // every file is named on screen and in the JSON
    for (const name of ['latin1.txt', 'blob.dat']) {
      expect(human.stdout, name).toContain(name)
      expect(JSON.stringify(j.coverage.notScanned), name).toContain(name)
    }
    expect(human.stdout).not.toContain('names are in the JSON')
  })
})

describe('A-03: stdout starts with the verdict; one write notice on stderr, once', () => {
  it('first run prints the notice on stderr only; second run prints none', async () => {
    const dir = project({ 'index.js': 'console.log(1)\n' })
    const home = mkdtempSync(join(tmpdir(), 'sg-home-'))
    const homeEnv = { ...env, HOME: home, XDG_CONFIG_HOME: join(home, '.config') }
    const run1 = await runCli(['scan', dir], { env: homeEnv })
    expect(run1.stdout.split('\n')[0]).toMatch(/^(SAFE TO SHIP|REVIEW BEFORE SHIP|DO NOT SHIP) · /)
    expect(run1.stdout).not.toContain('ShipGuard by AgenticCLI')
    expect(run1.stderr).toContain('wrote .shipguard/ (reports, history; ignored by git) and ~/.config/shipguard/ (usage-ping id)')
    const run2 = await runCli(['scan', dir], { env: homeEnv })
    expect(run2.stderr).not.toContain('wrote .shipguard/')
  })
})

describe('A-04: help and --help are one table', () => {
  it('same text, history listed', async () => {
    const a = await runCli(['help'], { env })
    const b = await runCli(['--help'], { env })
    expect(a.code).toBe(0)
    expect(a.stdout).toBe(b.stdout)
    expect(a.stdout).toMatch(/^\s*history /m)
    expect(a.stdout).toMatch(/What a plan would add for this repo and how to\s+start it/)
  })
})

describe('A-06: a broken policy file is explained in our words with the right line', () => {
  it('an unclosed [ is reported at the line that opens it, in text and JSON', async () => {
    const dir = project({ 'index.js': 'x\n', 'shipguard.policy.yml': 'version: 1\nblock: [a, b\nwarn: [x]\n' })
    const human = await runCli(['scan', dir], { env })
    expect(human.code).toBe(2)
    expect(human.stderr).toContain('INVALID_POLICY')
    expect(human.stderr).toContain('(line 2)')
    expect(human.stderr).toContain('line 2 starts a list with [ and never closes it with ].')
    expect(human.stderr).not.toMatch(/Flow sequence|at line \d+, column/)
    const j = (await runCli(['scan', dir, '--json'], { env })).json!
    expect(j.error.code).toBe('INVALID_POLICY')
    expect(j.error.line).toBe(2)
    expect(j.error.cause).toBe('line 2 starts a list with [ and never closes it with ].')
  })

  it('a bad indent names its own line', async () => {
    const dir = project({ 'index.js': 'x\n', 'shipguard.policy.yml': 'a:\n  b: 1\n c: 2\n' })
    const j = (await runCli(['scan', dir, '--json'], { env })).json!
    expect(j.error.line).toBe(3)
    expect(j.error.cause).toBe('line 3 is indented wrongly.')
  })
})

describe('E-09: Ignored (N) counts a finding ignored with shipguard ignore', () => {
  it('report lists it with its reason; screen counts only active findings', async () => {
    const dir = project({ 'src/a.js': SQL })
    await runCli(['scan', dir, '--strict'], { env }) // puts the finding on record (ignore needs its severity)
    const ig = await runCli(['ignore', 'generic.injection.sql-string-built', '--file', 'src/a.js', '--reason', 'test fixture, not real SQL'], { cwd: dir, env })
    expect(ig.code, ig.stderr).toBe(0)
    const human = await runCli(['scan', dir], { env })
    expect(human.stdout.split('\n')[0]).toMatch(/^SAFE TO SHIP · 0 findings/)
    expect(human.stdout).not.toContain('Also found')
    const report = readFileSync(join(dir, '.shipguard/reports/latest.md'), 'utf-8')
    expect(report).toMatch(/## Ignored \(1\)\n- high src\/a\.js:1 .*reason: test fixture, not real SQL/)
    expect(report).not.toContain('Also found')
    expect(report).toMatch(/findings: 0 /)
  })
})

describe('C-02: the global Ctrl-C handler steps aside when a command owns the signal', () => {
  it('handleSignal exits alone, but returns when another listener (login) exists', async () => {
    const { handleSignal } = await import('../../src/handlers.js')
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never)
    const err = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const sig = 'SIGUSR2' // a signal nothing else listens to, so the count is ours alone
    const global = (): void => handleSignal(sig)
    const login = (): void => undefined
    try {
      process.on(sig, global)
      process.on(sig, login)
      handleSignal(sig)
      expect(exit).not.toHaveBeenCalled() // login's listener decides (LOGIN_CANCELLED, exit 130)
      process.removeListener(sig, login)
      handleSignal(sig)
      expect(exit).toHaveBeenCalledWith(130)
    } finally {
      process.removeListener(sig, global)
      process.removeListener(sig, login)
      exit.mockRestore()
      err.mockRestore()
    }
  })
})

describe('B-35: a read-only project gets ONE plain warning, no raw system errors', () => {
  it('one warning per cause, standard wording, no EACCES, no "Report generation failed", no write notice', async () => {
    if (process.getuid?.() === 0) return // root can write anywhere: nothing to test
    const dir = project({ 'index.js': 'console.log(1)\n' })
    const home = mkdtempSync(join(tmpdir(), 'sg-home-'))
    chmodSync(dir, 0o555)
    try {
      const r = await runCli(['scan', dir], { env: { ...env, HOME: home } })
      expect(r.code).toBe(0)
      expect(r.stdout.split('\n')[0]).toMatch(/^SAFE TO SHIP/)
      expect(r.stderr).not.toMatch(/EACCES|Report generation failed|permission denied, mkdir/)
      expect(r.stderr.match(/Could not save ShipGuard's files in this project/g)).toHaveLength(1)
      expect(r.stderr).toContain('(permission denied)')
      expect(r.stderr).not.toContain('wrote .shipguard/')
    } finally {
      chmodSync(dir, 0o755)
    }
  })

  it('the usage-ping notice is remembered for the run even when the config folder cannot keep its marker', async () => {
    if (process.getuid?.() === 0) return
    const { noticeShown, markNoticeShown } = await import('../../src/core/telemetry-config.js')
    const home = mkdtempSync(join(tmpdir(), 'sg-home-'))
    chmodSync(home, 0o555)
    try {
      const dir = join(home, 'shipguard')
      expect(noticeShown(dir)).toBe(false)
      markNoticeShown(dir) // cannot write the marker
      expect(existsSync(join(dir, 'telemetry-notice-shown'))).toBe(false)
      expect(noticeShown(dir)).toBe(true) // a second print in the same run is blocked
    } finally {
      chmodSync(home, 0o755)
    }
  })
})
