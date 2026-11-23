/**
 * W1c: status/upgrade in safe mode, `upgrade` live output with a SIGNED offer, the gate gap line from a real offer cache,
 * and the last-scan re-run command taken from history (spec 05/06: one re-run builder, never fixed text).
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { cleanupTrees, mkTree, runCli } from '../helpers/cli-fixture.js'
import { makeSigner, offerPayload, type TestSigner } from './helpers.js'

const { upgradeCommand } = await import('../../src/commands/upgrade.js')
const { statusCommand } = await import('../../src/commands/status.js')
const { gateGapFromCache, lastScanHere } = await import('../../src/core/plan-client.js')
const { stackSetFile } = await import('../../src/core/offer-cache.js')
const { writeFileSync } = await import('node:fs')

const pkgRoot = join(__dirname, '..', '..')
let signer: TestSigner
let home: string
let out: string[]
const OFFER = 'shipguard-offer+jws'
const counts = { nextjs: { rules: 30, areas: ['Server actions', 'Row-level security'] } }
const cfg = () => join(home, '.config', 'shipguard')
const proj = () => mkTree({ 'package.json': JSON.stringify({ name: 'a', dependencies: { next: '16.0.0' } }), 'index.js': 'console.log(1)\n' }, { git: true })
const nowS = (): number => Math.floor(Date.now() / 1000)
const offerToken = () => signer.sign(offerPayload({ iat: nowS() - 60, exp: nowS() + 86400, offer: { text: 'Signed offer words', slot: 'checkout' }, counts, combined: { nextjs: 30 } }), { typ: OFFER, })

beforeAll(() => {
  signer = makeSigner('w1c-signer')
  if (!existsSync(join(pkgRoot, 'dist/cli.js'))) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
}, 180_000)
afterAll(() => { signer.cleanup(); cleanupTrees() })
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sg-w1c-'))
  vi.stubEnv('HOME', home)
  out = []
  vi.spyOn(console, 'log').mockImplementation((m?: unknown) => void out.push(String(m)))
  vi.spyOn(console, 'error').mockImplementation(() => {})
  process.exitCode = undefined
})
afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  rmSync(home, { recursive: true, force: true })
  process.exitCode = undefined
})

const files = (): string[] => (existsSync(cfg()) ? readdirSync(cfg()) : [])
const fetchOffer = () => vi.fn(async () => new Response(offerToken(), { status: 200 }))

describe('upgrade live output with a signed offer', () => {
  it('prints the verified offer text, the server counts and the checkout link; step 3 is the plain scan when there is no history', async () => {
    const dir = proj()
    vi.spyOn(process, 'cwd').mockReturnValue(dir)
    vi.stubGlobal('fetch', fetchOffer())
    await upgradeCommand().parseAsync(['node', 'upgrade'])
    const text = out.join('\n')
    expect(text).toContain('Signed offer words')
    expect(text).toContain('30 rules for this stack')
    expect(text).toContain('Areas without those checks: Server actions, Row-level security')
    expect(text).toContain('https://agenticcli.dev/go/checkout')
    expect(text).toMatch(/3\. Run a scan again:\s+shipguard scan\s/)
    expect(process.exitCode).toBeUndefined()
  })

  it('an offer signed by an unknown key is not shown (nothing from the server is trusted unsigned)', async () => {
    const other = makeSigner('w1c-other')
    const bad = other.sign(offerPayload({ iat: nowS() - 60, exp: nowS() + 86400, offer: { text: 'FORGED words', slot: 'checkout' } }), { typ: OFFER, kid: 'not-pinned' })
    other.cleanup()
    vi.spyOn(process, 'cwd').mockReturnValue(proj())
    vi.stubGlobal('fetch', vi.fn(async () => new Response(bad, { status: 200 })))
    await upgradeCommand().parseAsync(['node', 'upgrade'])
    expect(out.join('\n')).not.toContain('FORGED')
  })
})

describe('safe mode (status and upgrade write nothing under ~/.config/shipguard)', () => {
  it('status', async () => {
    vi.stubEnv('SHIPGUARD_SAFE_MODE', '1')
    vi.spyOn(process, 'cwd').mockReturnValue(proj())
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 503 })))
    await statusCommand().parseAsync(['node', 'status'])
    expect(out.join('\n')).toMatch(/Not signed in/)
    expect(files()).toEqual([])
  })

  it('upgrade (explicit command may read the offer, but the signed file is not cached and no counter is written)', async () => {
    vi.stubEnv('SHIPGUARD_SAFE_MODE', '1')
    vi.spyOn(process, 'cwd').mockReturnValue(proj())
    vi.stubGlobal('fetch', fetchOffer())
    await upgradeCommand().parseAsync(['node', 'upgrade'])
    expect(out.join('\n')).toContain('Signed offer words')
    expect(files()).toEqual([])
  })

  it('upgrade --mute writes nothing and says so', async () => {
    vi.stubEnv('SHIPGUARD_SAFE_MODE', '1')
    vi.spyOn(process, 'cwd').mockReturnValue(proj())
    await upgradeCommand().parseAsync(['node', 'upgrade', '--mute'])
    expect(files()).toEqual([])
    expect(out.join('\n')).not.toContain('Promotion is muted')
  })
})

describe('gate gap line from a real signed offer cache', () => {
  function seedCache(): void {
    mkdirSync(cfg(), { recursive: true, mode: 0o700 })
    writeFileSync(join(cfg(), stackSetFile(['nextjs'])), offerToken(), { mode: 0o600 })
  }

  beforeEach(() => { vi.stubEnv('SHIPGUARD_TELEMETRY', '1'); vi.stubEnv('DO_NOT_TRACK', ''); vi.stubEnv('CI', '') })

  it('first line only, once a week; the second call the same week is silent', async () => {
    const dir = proj()
    seedCache()
    const first = await gateGapFromCache(dir)
    expect(first).toContain('Next.js')
    expect(first).not.toContain('\n')
    expect(await gateGapFromCache(dir)).toBeNull()
  })

  it('no cache, safe mode and CI each give no line', async () => {
    const dir = proj()
    expect(await gateGapFromCache(dir)).toBeNull()
    seedCache()
    vi.stubEnv('SHIPGUARD_SAFE_MODE', '1')
    expect(await gateGapFromCache(dir)).toBeNull()
    vi.stubEnv('SHIPGUARD_SAFE_MODE', '')
    vi.stubEnv('CI', 'true')
    expect(await gateGapFromCache(dir)).toBeNull()
  })

  it('a tampered cache file shows no line', async () => {
    const dir = proj()
    seedCache()
    const p = join(cfg(), stackSetFile(['nextjs']))
    const { readFileSync } = await import('node:fs')
    const t = readFileSync(p, 'utf8')
    const i = t.lastIndexOf('.') + 10 // inside the signature segment
    writeFileSync(p, `${t.slice(0, i)}${t[i] === 'A' ? 'B' : 'A'}${t.slice(i + 1)}`)
    expect(await gateGapFromCache(dir)).toBeNull()
  })
})

describe('the re-run command comes from the last scan in history', () => {
  it('a real scan is remembered; lastScanHere gives the re-run builder\'s command (history keeps the target only)', async () => {
    const dir = mkTree({ 'package.json': JSON.stringify({ name: 'a' }), 'index.js': 'console.log(1)\n' }, { git: true })
    expect(await lastScanHere(dir)).toBeNull()
    const r = await runCli(['scan', '--json'], { cwd: dir, env: { HOME: home, SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1' } })
    expect(r.code).toBe(0)
    const last = await lastScanHere(dir)
    expect(last?.scanCommand).toBe('shipguard scan --strict')
    // and `upgrade` step 3 uses it (a bare `shipguard scan` would lose --strict)
    vi.spyOn(process, 'cwd').mockReturnValue(dir)
    vi.stubGlobal('fetch', fetchOffer())
    await upgradeCommand().parseAsync(['node', 'upgrade'])
    expect(out.join('\n')).toMatch(/3\. Run a scan again:\s+shipguard scan --strict\s/)
  })
})
