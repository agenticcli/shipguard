/**
 * Plain `scan` while signed in prints ONE hint: add --pro to use the full rulebook (1 credit).
 *
 * Why: plain scan never fetches the rulebook (credits are only spent with --pro), so a signed-in
 * user running the setup-guide command silently never gets what they signed in for. The CLI says so
 * once, spends nothing on its own, and the hook/CI path adds --pro.
 *
 * FAIL-BEFORE (0.11.0): no hint, no `hints` field.
 * PASS-AFTER: human mode -> one stderr line; --json -> `hints` array, stdout still one JSON document;
 * no hint when not signed in, with --pro, or with --offline.
 */
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, runCli } from '../helpers/cli-fixture.js'
import { SIGNED_IN_HINT, signedInHint } from '../../src/commands/scan.js'

vi.setConfig({ testTimeout: 30_000 })

const homes: string[] = []
afterEach(() => {
  cleanupTrees()
  for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true })
})

const FILES = { 'package.json': '{"name":"fixture"}', 'app.js': 'const x = 1\n' }

/** A HOME that holds saved credentials (the file the CLI reads; never contacted by a plain scan). */
function signedInHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'sg-hint-home-'))
  homes.push(home)
  const dir = join(home, '.config', 'shipguard')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const file = join(dir, 'credentials.json')
  writeFileSync(
    file,
    JSON.stringify({ accessToken: 'test-token', refreshToken: 'test-refresh', expiresAt: Date.now() + 3_600_000, apiUrl: 'https://agenticcli.dev' }),
  )
  chmodSync(file, 0o600)
  return home
}

function signedOutHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'sg-hint-home-'))
  homes.push(home)
  return home
}

const hintCount = (s: string): number => s.split(SIGNED_IN_HINT).length - 1

describe('the hint text', () => {
  it('is the agreed sentence', () => {
    expect(SIGNED_IN_HINT).toBe('signed in: add --pro to use the full rulebook (1 credit)')
  })
})

describe('signedInHint (decision)', () => {
  it('shows only when signed in, without --pro, and not offline', () => {
    expect(signedInHint({ signedIn: true, pro: false, offline: false })).toBe(SIGNED_IN_HINT)
    expect(signedInHint({ signedIn: false, pro: false, offline: false })).toBeUndefined()
    expect(signedInHint({ signedIn: true, pro: true, offline: false })).toBeUndefined()
    expect(signedInHint({ signedIn: true, pro: false, offline: true })).toBeUndefined()
  })
})

describe('signed-in plain scan', () => {
  it('human mode: exactly one hint line on stderr, none on stdout', async () => {
    const r = await runCli(['scan', mkTree(FILES)], { env: { SHIPGUARD_API_KEY: '', HOME: signedInHome() } })
    expect(r.code).toBe(0)
    expect(hintCount(r.stderr)).toBe(1)
    expect(r.stdout).not.toContain(SIGNED_IN_HINT)
  })

  it('--json: `hints` carries it, stdout is one valid JSON document, stderr has no hint', async () => {
    const r = await runCli(['scan', mkTree(FILES), '--json'], { env: { SHIPGUARD_API_KEY: '', HOME: signedInHome() } })
    expect(r.code).toBe(0)
    expect(r.json?.hints).toEqual([SIGNED_IN_HINT])
    expect(hintCount(r.stderr)).toBe(0)
  })

  it('SHIPGUARD_API_KEY counts as signed in', async () => {
    const r = await runCli(['scan', mkTree(FILES), '--json'], { env: { SHIPGUARD_API_KEY: '', HOME: signedOutHome(), SHIPGUARD_API_KEY: 'test-key' } })
    expect(r.json?.hints).toEqual([SIGNED_IN_HINT])
  })

  it('--quiet stays one line (no hint line on stdout)', async () => {
    const r = await runCli(['scan', mkTree(FILES), '--quiet'], { env: { SHIPGUARD_API_KEY: '', HOME: signedInHome() } })
    expect(r.stdout.trim().split('\n')).toHaveLength(1)
  })

  it('--offline: no hint', async () => {
    const r = await runCli(['scan', mkTree(FILES), '--json', '--offline'], { env: { SHIPGUARD_API_KEY: '', HOME: signedInHome() } })
    expect(r.json?.hints).toBeUndefined()
    expect(hintCount(r.stderr)).toBe(0)
  })
})

describe('not signed in', () => {
  it('no hint in human or --json mode', async () => {
    const home = signedOutHome()
    const human = await runCli(['scan', mkTree(FILES)], { env: { SHIPGUARD_API_KEY: '', HOME: home } })
    expect(hintCount(human.stderr)).toBe(0)
    const json = await runCli(['scan', mkTree(FILES), '--json'], { env: { SHIPGUARD_API_KEY: '', HOME: home } })
    expect(json.json?.hints).toBeUndefined()
  })
})
