/**
 * QA fix 2 (QA-CLI-0130 FAIL 2): a gate rerun on the same commit reuses the scan id (scanIdReused true), so a Pro
 * gate rerun is not counted twice. FAIL-BEFORE: the gate scanned a fresh mkdtemp extraction and the child had no
 * history path, so every gate run minted a new id. The reuse key is now repo folder + commit (+ the usual request
 * fields), not the temp path.
 */
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnNode } from '../helpers/spawn-cli.js'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Policy } from '@agenticcli/shared'
import { extractCommit, removeExtraction, runScanChild } from '../../src/core/gate-scan.js'
import { gateReuseFor, resolveScanId, writeGateHandover } from '../../src/core/history/scan-id.js'
import { buildVariant } from '../helpers/recorded-cli.js'
import { cleanup, commitFile, git, mkRepo } from './gate-fixtures.js'

vi.setConfig({ testTimeout: 60_000 })

// A private build of the current src (never a stale dist/, and never rewrites dist/ under the other test files).
let distCli = ''
beforeAll(() => {
  distCli = buildVariant('dev', 'gate-scan-id')
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

describe('gateReuseFor: only the gate\'s own extraction with its private hand-over file', () => {
  const GATE = { SHIPGUARD_GATE_KIND: 'git' } as NodeJS.ProcessEnv
  const realSha = (main: string): string => git(main, 'rev-parse', 'HEAD')

  it('reads dir + commit for the gate\'s extraction', () => {
    const main = mkRepo()
    const dest = extractCommit(main, realSha(main))
    try {
      writeGateHandover(dest, { dir: main, commit: realSha(main) })
      expect(gateReuseFor(dest, GATE)).toEqual({ dir: main, commit: realSha(main) })
    } finally { removeExtraction(dest) }
  })

  it('refuses: not a gate child, no hand-over file, wrong folder, loose file mode, folder that is not a git top, unknown commit', () => {
    const main = mkRepo()
    const sha = realSha(main)
    const dest = extractCommit(main, sha)
    try {
      expect(gateReuseFor(dest, GATE)).toBeUndefined() // no hand-over file yet
      writeGateHandover(dest, { dir: main, commit: sha })
      expect(gateReuseFor(dest, {})).toBeUndefined() // not a gate child
      expect(gateReuseFor(dest, { SHIPGUARD_GATE_KIND: 'x' })).toBeUndefined()
      expect(gateReuseFor(main, GATE)).toBeUndefined() // a plain folder, not the extraction
      expect(gateReuseFor(dest, GATE, join(tmpdir(), 'elsewhere'))).toBeUndefined() // not under the OS tmpdir the gate used
      const file = join(dest, '..', 'gate-handover.json')
      chmodSync(file, 0o644)
      expect(gateReuseFor(dest, GATE)).toBeUndefined() // loose mode
      chmodSync(file, 0o600)
      writeFileSync(file, JSON.stringify({ dir: join(main, 'src'), commit: sha }))
      expect(gateReuseFor(dest, GATE)).toBeUndefined() // not a git top level
      writeFileSync(file, JSON.stringify({ dir: main, commit: SHA }))
      expect(gateReuseFor(dest, GATE)).toBeUndefined() // a commit the repo does not hold
      writeFileSync(file, JSON.stringify({ dir: 'repo', commit: sha }))
      expect(gateReuseFor(dest, GATE)).toBeUndefined() // relative dir
    } finally { removeExtraction(dest) }
  })

  it('a symlinked hand-over file is refused', () => {
    const main = mkRepo()
    const sha = realSha(main)
    const dest = extractCommit(main, sha)
    try {
      const real = join(dest, '..', 'real.json')
      writeFileSync(real, JSON.stringify({ dir: main, commit: sha }), { mode: 0o600 })
      symlinkSync(real, join(dest, '..', 'gate-handover.json'))
      expect(gateReuseFor(dest, GATE)).toBeUndefined()
    } finally { removeExtraction(dest) }
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

describe('abuse: user-set variables on a plain scan do nothing', () => {
  it('SHIPGUARD_GATE_KIND + GATE_DIR + GATE_COMMIT in the environment: no reuse for changed content, no history written elsewhere', async () => {
    const proj = mkRepo()
    const elsewhere = mkdtempSync(join(tmpdir(), 'sg-elsewhere-'))
    homes.push(elsewhere)
    const home = mkdtempSync(join(tmpdir(), 'sg-abuse-home-'))
    homes.push(home)
    const env = {
      PATH: process.env.PATH, HOME: home, SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1',
      SHIPGUARD_GATE_KIND: 'claude', SHIPGUARD_GATE_DIR: elsewhere, SHIPGUARD_GATE_COMMIT: 'c'.repeat(40),
    }
    const id = async (): Promise<{ scanId: string; scanIdReused: boolean }> => {
      const r = await spawnNode(distCli, ['scan', '--json'], { cwd: proj, env })
      const j = JSON.parse(r.stdout) as { scanId?: string; runId: string; scanIdReused: boolean }
      return { scanId: j.scanId ?? j.runId, scanIdReused: j.scanIdReused }
    }
    const first = await id()
    commitFile(proj, 'src/b.ts', 'export const b = 2\n') // different content
    const second = await id()
    expect(second.scanIdReused).toBe(false)
    expect(second.scanId).not.toBe(first.scanId)
    expect(existsSync(join(elsewhere, '.shipguard'))).toBe(false)
  })

  it('a forged hand-over file next to a folder that is not the gate\'s extraction is ignored too', () => {
    const main = mkRepo()
    const sha = git(main, 'rev-parse', 'HEAD')
    const fake = mkdtempSync(join(tmpdir(), 'not-the-gate-'))
    homes.push(fake)
    mkdirSync(join(fake, 'tree'))
    writeFileSync(join(fake, 'gate-handover.json'), JSON.stringify({ dir: main, commit: sha }), { mode: 0o600 })
    expect(gateReuseFor(join(fake, 'tree'), { SHIPGUARD_GATE_KIND: 'claude' })).toBeUndefined()
  })
})
