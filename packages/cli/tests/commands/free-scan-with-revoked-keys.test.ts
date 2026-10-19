/**
 * Free scans do not depend on the Pro signing keys.
 *
 * Spawns the BUILT binary (dist/cli.js) with an empty HOME (no credentials, no floor) on a small
 * fixture and requires a normal completed scan: exit 0 + a JSON recommendation. Also proves the
 * built artifact carries none of the revoked public keys.
 */
import { execSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { spawnNode } from '../helpers/spawn-cli.js'

vi.setConfig({ testTimeout: 30_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

const EXPOSED_PEM_B64 = [
  'MCowBQYDK2VwAyEAkpeX0A3zIOttGn8t+jagJHLRTv5Q809vqIZU37lE6xQ=', // k1-2026
  'MCowBQYDK2VwAyEANcib9WOOIys1wLQW30T/RvRv+3d/+2DAWKOKwEj5sS0=', // ra-k1-2026
  'MCowBQYDK2VwAyEAaQ49ermPqqsENKA7fFi8K0zIEyxYEje56a34Pus6UhM=', // cf-k1-2026
]

let work: string
beforeAll(() => {
  if (!existsSync(distCli)) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  work = mkdtempSync(join(tmpdir(), 'sg-394-free-'))
}, 120_000)
afterAll(() => { rmSync(work, { recursive: true, force: true }) })

describe('free scan unaffected by the key rotation', () => {
  it('no built file (cli.js or any chunk) contains a revoked public key', () => {
    const distDir = resolve(pkgRoot, 'dist')
    const files = readdirSync(distDir).filter(f => f.endsWith('.js'))
    expect(files.length).toBeGreaterThan(1)
    for (const f of files) {
      const js = readFileSync(join(distDir, f), 'utf-8')
      for (const b64 of EXPOSED_PEM_B64) expect(js.includes(b64), `${f} contains ${b64}`).toBe(false)
    }
  })

  it('anonymous free scan (empty HOME, no credentials) completes: exit 0 + JSON recommendation', async () => {
    const home = join(work, 'home')
    const proj = join(work, 'proj')
    execSync(`mkdir -p "${home}" "${proj}/src"`)
    writeFileSync(join(proj, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: { next: '15.0.0' } }))
    writeFileSync(join(proj, 'src', 'index.ts'), 'export const hello = () => "world"\n')

    const { code, stdout, stderr, timedOut } = await spawnNode(distCli, ['scan', proj, '--json'], {
      cwd: proj,
      env: {
        PATH: process.env.PATH,
        HOME: home,
        SHIPGUARD_TELEMETRY: '0',
        DO_NOT_TRACK: '1',
      },
    })
    expect(timedOut).toBe(false)
    expect(code, stderr).toBe(0)
    const out = JSON.parse(stdout)
    expect(typeof out.recommendation).toBe('string')
    // No key-resolution failure leaks into a free scan.
    expect(stderr).not.toMatch(/Unknown key|placeholder|revoked|fingerprint mismatch/i)
  })
})
