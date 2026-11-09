/**
 * N3 (benchmark 2026-11-08, D8): `scan --json` with a broken policy file printed human text and
 * nothing on stdout. An agent reading stdout got no machine-readable error.
 * Contract: with --json (or --sarif) a config error puts exactly one JSON object
 * `{ error, code }` on stdout, keeps the human line on stderr, and exits 2 (same shape as the
 * PATH_NOT_FOUND error in scan-missing-path.test.ts). Without --json stdout stays empty.
 */
import { execSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'
import { spawnNode } from '../helpers/spawn-cli.js'

vi.setConfig({ testTimeout: 30_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

const tempDirs: string[] = []
function brokenProject(): string {
  const d = mkdtempSync(join(tmpdir(), 'shipguard-n3-'))
  tempDirs.push(d)
  writeFileSync(join(d, 'package.json'), '{"name":"n3","version":"1.0.0"}')
  writeFileSync(join(d, 'a.ts'), 'export const a = 1\n')
  writeFileSync(join(d, 'shipguard.policy.yml'), 'telemetry: [unclosed\n')
  return d
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true })
})
beforeAll(() => {
  if (!existsSync(distCli)) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
}, 120_000)

const env = { ...process.env, SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1' }

describe('scan config error in machine mode', () => {
  it('--json: stdout is one parseable error object with code INVALID_POLICY, exit 2', async () => {
    const dir = brokenProject()
    const r = await spawnNode(distCli, ['scan', '--json', dir], { cwd: tmpdir(), env })
    expect(r.code).toBe(2)
    const parsed = JSON.parse(r.stdout)
    expect(parsed.code).toBe('INVALID_POLICY')
    expect(parsed.error).toMatch(/Invalid policy file/)
    expect(r.stderr).toMatch(/Config error/)
  })

  it('without --json stdout stays empty (human text only on stderr)', async () => {
    const dir = brokenProject()
    const r = await spawnNode(distCli, ['scan', dir], { cwd: tmpdir(), env })
    expect(r.code).toBe(2)
    expect(r.stdout).toBe('')
  })

  it('--json on a non-project directory refusal also emits an error object', async () => {
    const d = mkdtempSync(join(tmpdir(), 'shipguard-n3-empty-'))
    tempDirs.push(d)
    const r = await spawnNode(distCli, ['scan', '--json'], { cwd: d, env })
    expect(r.code).toBe(2)
    expect(JSON.parse(r.stdout).code).toBe('NOT_A_PROJECT')
  })
})
