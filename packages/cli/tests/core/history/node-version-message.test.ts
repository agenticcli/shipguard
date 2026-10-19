/**
 * Node < 22.5 has no node:sqlite, so scan history cannot be recorded.
 * The scan still runs; the user must be told LOUDLY and actionably, never silently.
 */
import { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect, vi } from 'vitest'
import { sqliteUnavailableReason } from '../../../src/core/history/store.js'
import { spawnSync } from 'node:child_process'

vi.setConfig({ testTimeout: 30_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../')
const pkg = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf-8'))

describe('node:sqlite unavailable message', () => {
  it('names the running Node version, the minimum, and the fix', () => {
    const msg = sqliteUnavailableReason('20.20.2')
    expect(msg).toContain('Node.js 20.20.2')
    expect(msg).toContain('>=22.5')
    expect(msg).toMatch(/upgrade/i)
    expect(msg).toMatch(/scan.*unaffected/i)
  })
})

describe('package.json engines', () => {
  it('declares a Node engine range (scan runs on >=20; history needs >=22.5 at runtime)', () => {
    expect(pkg.engines?.node).toBeTruthy()
  })
})

// Only runs where a real Node 20 is installed (dev boxes via nvm); CI on Node 22+ skips it.
const node20 = join(process.env.NVM_DIR ?? join(homedir(), '.nvm'), 'versions/node/v20.20.2/bin/node')
describe.skipIf(!existsSync(node20))('`shipguard history` on Node 20 (built binary)', () => {
  it('says history cannot be recorded on this Node, not "recorded automatically"', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shipguard-node20-'))
    try {
      writeFileSync(join(dir, 'package.json'), '{"name":"x"}')
      const { stderr } = spawnSync(node20, [join(pkgRoot, 'dist/cli.js'), 'history', dir], {
        cwd: dir,
        encoding: 'utf-8',
        timeout: 25_000,
        env: { ...process.env, SHIPGUARD_TELEMETRY: '0', HOME: dir },
      })
      expect(stderr).toContain('Node.js 20.20.2')
      expect(stderr).not.toMatch(/recorded automatically/)
      expect(stderr).toMatch(/cannot be recorded on this Node/i)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
