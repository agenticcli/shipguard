/**
 * QA fix 2 (QA-CLI-0130 FAIL 2): a gate rerun on the same commit reuses the scan id (scanIdReused true), so a Pro
 * gate rerun is not counted twice. FAIL-BEFORE: the gate scanned a fresh mkdtemp extraction and the child had no
 * history path, so every gate run minted a new id. The reuse key is now repo folder + commit (+ the usual request
 * fields), not the temp path.
 */
import { execSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Policy } from '@agenticcli/shared'
import { extractCommit, removeExtraction, runScanChild } from '../../src/core/gate-scan.js'
import { GATE_COMMIT_ENV, GATE_DIR_ENV, gateReuseFromEnv, resolveScanId } from '../../src/core/history/scan-id.js'
import { cleanup, commitFile, git, mkRepo } from './gate-fixtures.js'

vi.setConfig({ testTimeout: 60_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

beforeAll(() => {
  // Always rebuild: this test is about the code in src, not a stale dist.
  execSync('npx tsup', { cwd: pkgRoot, stdio: 'ignore' })
}, 240_000)

const homes: string[] = []
const saved = { ...process.env }
beforeEach(() => {
  const home = mkdtempSync(join(tmpdir(), 'sg-gate-id-home-'))
  homes.push(home)
  process.env.HOME = home
  process.env.SHIPGUARD_TELEMETRY = '0'
  process.env.DO_NOT_TRACK = '1'
  delete process.env.SHIPGUARD_GATE_KIND
})
afterEach(() => {
  cleanup()
  for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true })
  for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k]
  Object.assign(process.env, saved)
})

function policy(): Policy {
  return {
    version: 1,
    project: { name: 'test', framework: 'auto', risk_profile: 'standard' },
    scan: { changed_files_only: false, generate_report: false },
    block: [],
    warn: [],
    ignore: { paths: [] },
    report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
  } as Policy
}

const SHA = 'a'.repeat(40)

describe('gateReuseFromEnv: only the gate child, only a well-formed pair', () => {
  const ok = { SHIPGUARD_GATE_KIND: 'git', [GATE_DIR_ENV]: '/work/repo', [GATE_COMMIT_ENV]: SHA }
  it('reads dir + commit for a gate host', () => {
    expect(gateReuseFromEnv(ok)).toEqual({ dir: '/work/repo', commit: SHA })
  })
  it.each([
    ['no gate kind', { ...ok, SHIPGUARD_GATE_KIND: undefined }],
    ['unknown kind', { ...ok, SHIPGUARD_GATE_KIND: 'x' }],
    ['relative dir', { ...ok, [GATE_DIR_ENV]: 'repo' }],
    ['non-hex commit', { ...ok, [GATE_COMMIT_ENV]: 'main; rm -rf /' }],
    ['missing commit', { ...ok, [GATE_COMMIT_ENV]: undefined }],
  ])('refuses: %s', (_n, env) => {
    expect(gateReuseFromEnv(env as NodeJS.ProcessEnv)).toBeUndefined()
  })
})

describe('resolveScanId with the gate hand-over (function level)', () => {
  const base = { policy: policy(), cliVersion: '0.13.0-test', changedOnly: false, categories: [], rulebookRequested: true, frameworks: ['generic'] }

  it('two different temp extractions of the same repo + commit share one scan id', async () => {
    const main = mkRepo()
    const sha = git(main, 'rev-parse', 'HEAD')
    const a = extractCommit(main, sha)
    const b = extractCommit(main, sha)
    try {
      expect(a).not.toBe(b)
      const first = await resolveScanId({ ...base, cwd: a, gate: { dir: main, commit: sha } })
      const second = await resolveScanId({ ...base, cwd: b, gate: { dir: main, commit: sha } })
      expect(first.scanIdReused).toBe(false)
      expect(second.scanIdReused).toBe(true)
      expect(second.scanId).toBe(first.scanId)
    } finally {
      removeExtraction(a)
      removeExtraction(b)
    }
  })

  it('a new commit, or the rulebook no longer requested, mints a new id', async () => {
    const main = mkRepo()
    const sha1 = git(main, 'rev-parse', 'HEAD')
    const sha2 = commitFile(main, 'src/b.ts', 'export const b = 2\n')
    const d1 = extractCommit(main, sha1)
    const d2 = extractCommit(main, sha2)
    try {
      const first = await resolveScanId({ ...base, cwd: d1, gate: { dir: main, commit: sha1 } })
      const otherCommit = await resolveScanId({ ...base, cwd: d2, gate: { dir: main, commit: sha2 } })
      const noRulebook = await resolveScanId({ ...base, cwd: d1, rulebookRequested: false, gate: { dir: main, commit: sha1 } })
      expect(otherCommit.scanIdReused).toBe(false)
      expect(otherCommit.scanId).not.toBe(first.scanId)
      expect(noRulebook.scanIdReused).toBe(false)
      expect(noRulebook.scanId).not.toBe(first.scanId)
    } finally {
      removeExtraction(d1)
      removeExtraction(d2)
    }
  })

  it('another repo folder with the same commit id never shares an id', async () => {
    const one = mkRepo()
    const two = mkRepo()
    const d1 = extractCommit(one, git(one, 'rev-parse', 'HEAD'))
    try {
      const a = await resolveScanId({ ...base, cwd: d1, gate: { dir: one, commit: SHA } })
      const b = await resolveScanId({ ...base, cwd: d1, gate: { dir: two, commit: SHA } })
      expect(b.scanIdReused).toBe(false)
      expect(b.scanId).not.toBe(a.scanId)
    } finally {
      removeExtraction(d1)
    }
  })
})

describe('the real gate child (built CLI): a rerun on the same commit reuses the id', () => {
  it('second runScanChild on a new extraction of the same commit reports scanIdReused true and the same scanId', async () => {
    expect(existsSync(distCli)).toBe(true)
    const main = mkRepo()
    // The gate writes its .shipguard/.gitignore before any scan; the child must not need it, but keep the tree quiet.
    const sha = git(main, 'rev-parse', 'HEAD')
    const run = async (): Promise<{ scanId: string; scanIdReused: boolean }> => {
      const dir = extractCommit(main, sha)
      try {
        const r = await runScanChild({ cliEntry: distCli, dir, budgetMs: 50_000, host: 'git', top: main, sha })
        const j = JSON.parse(r.stdout) as { scanId: string; scanIdReused: boolean }
        return { scanId: j.scanId, scanIdReused: j.scanIdReused }
      } finally {
        removeExtraction(dir)
      }
    }
    const first = await run()
    const second = await run()
    expect(first.scanIdReused).toBe(false)
    expect(second.scanIdReused).toBe(true)
    expect(second.scanId).toBe(first.scanId)
  })
})
