/**
 * Bug HANG-1 (2026-11-09): a scan whose folder was deleted while it ran never ended (~40% CPU for
 * hours). Cause: Node's recursive mkdir of the RELATIVE report/history dir loops forever when the
 * working directory is gone. Fix: assertCwdAlive() (src/utils/cwd-guard.ts) -> exit 3, never SAFE.
 */
import { describe, it, expect, afterEach, beforeAll } from 'vitest'
import { execSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnNode } from '../helpers/spawn-cli.js'

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')
const preload = resolve(pkgRoot, 'tests/helpers/vanish-cwd-preload.cjs')
const dirs: string[] = []

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

beforeAll(() => {
  if (!existsSync(distCli)) execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
}, 180_000)

describe('scan folder removed while the scan runs', () => {
  it('ends with exit 3 and never prints a SAFE verdict (fail-before: timed out)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sg-vanish-'))
    dirs.push(dir)
    mkdirSync(join(dir, 'src'), { recursive: true })
    writeFileSync(join(dir, 'package.json'), '{"name":"x"}')
    writeFileSync(join(dir, 'src', 'a.js'), 'const a = 1\n')
    const res = await spawnNode(distCli, ['scan', '--json'], {
      cwd: dir,
      timeoutMs: 20_000, // kills the child process group if the bug is back
      env: { PATH: process.env.PATH, NODE_OPTIONS: `--require=${preload}`, SG_VANISH_DIR: dir },
    })
    expect(res.timedOut, 'scan hung after its folder was removed').toBe(false)
    expect(res.code).toBe(3)
    expect(res.stdout).not.toContain('"recommendation": "SAFE"')
  }, 30_000)
})
