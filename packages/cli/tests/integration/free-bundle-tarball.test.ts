/**
 * free-bundle-tarball.test.ts — the PUBLISHED artifact really carries the free corpus.
 *
 * This is the exit test for the "free CLI ships none of the corpus" defect, and it is
 * deliberately run against a PACKED TARBALL rather than against `src/` or `dist/`.
 * Reading the source proves what we wrote; only the tarball proves what a user would
 * actually install. Every prior check in this area passed while the shipped artifact
 * contained zero corpus rules, because every prior check looked at the wrong thing.
 *
 * `npm pack` (never publish) produces exactly the bytes a release would upload.
 *
 * Two independent things are asserted, because either alone would be satisfiable while the
 * product was still broken:
 *   1. the tarball contains `rules/free-bundle.json` with the full expected rule set —
 *      the human-readable, greppable artifact;
 *   2. every one of those rule IDs also appears inside the compiled `dist/cli.js` — proof
 *      the rules are actually reachable by the running binary, not just riding along as a
 *      data file nothing loads. (This is the exact failure mode of the old design: the
 *      corpus existed, and nothing consumed it.)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { bundledRuleIds, bundledRulesMeta } from '../../src/core/bundled-rules.js'

const CLI_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

let workDir: string
let packageRoot: string

beforeAll(() => {
  workDir = mkdtempSync(join(tmpdir(), 'shipguard-pack-'))

  // `npm pack` honours package.json "files" and .npmignore exactly as a publish would.
  // It runs no `prepublishOnly` hook (that fires only on publish), so this cannot
  // accidentally trip a release gate or reach the network.
  execFileSync('npm', ['pack', '--pack-destination', workDir, '--silent'], {
    cwd: CLI_DIR,
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  const tarball = readdirSync(workDir).find((f) => f.endsWith('.tgz'))
  if (!tarball) throw new Error(`npm pack produced no .tgz in ${workDir}`)

  execFileSync('tar', ['-xzf', join(workDir, tarball), '-C', workDir])
  packageRoot = join(workDir, 'package')
}, 180_000)

afterAll(() => {
  if (workDir) rmSync(workDir, { recursive: true, force: true })
})

describe('packed tarball — the bundled corpus is really in the shipped artifact', () => {
  it('includes rules/free-bundle.json', () => {
    expect(existsSync(join(packageRoot, 'rules', 'free-bundle.json'))).toBe(true)
  })

  it('the packed bundle carries the exact rule set this build loads', () => {
    const packed = JSON.parse(
      readFileSync(join(packageRoot, 'rules', 'free-bundle.json'), 'utf-8'),
    ) as { rules: Array<{ id: string }>; contentHash: string; ruleCount: number }

    expect(packed.rules.map((r) => r.id).sort()).toEqual(bundledRuleIds())
    expect(packed.contentHash).toBe(bundledRulesMeta().contentHash)
    expect(packed.ruleCount).toBe(bundledRuleIds().length)
  })

  it('the packed bundle is not empty — a zero-rule ship would scan nothing', () => {
    const packed = JSON.parse(
      readFileSync(join(packageRoot, 'rules', 'free-bundle.json'), 'utf-8'),
    ) as { rules: unknown[] }
    expect(packed.rules.length).toBeGreaterThan(0)
  })

  it('every bundled rule ID is compiled into dist/cli.js — reachable, not just shipped', () => {
    const bundleJs = readFileSync(join(packageRoot, 'dist', 'cli.js'), 'utf-8')
    const missing = bundledRuleIds().filter((id) => !bundleJs.includes(id))
    expect(missing, 'rule IDs present in the data file but absent from the binary').toEqual([])
  })

  it('the packed cli-facts.json reports the bundled corpus, not just the legacy checks', () => {
    const facts = JSON.parse(readFileSync(join(packageRoot, 'dist', 'cli-facts.json'), 'utf-8')) as {
      bundledCorpusRuleIds: string[]
      bundledCorpusRuleCount: number
      freeRuleCount: number
      offlineRuleCount: number
      corpusVersion: number
    }
    expect(facts.bundledCorpusRuleIds).toEqual(bundledRuleIds())
    expect(facts.bundledCorpusRuleCount).toBe(bundledRuleIds().length)
    expect(facts.corpusVersion).toBe(bundledRulesMeta().corpusVersion)
    // The number the web site and llms.txt quote for an offline scan.
    expect(facts.offlineRuleCount).toBe(facts.freeRuleCount + facts.bundledCorpusRuleCount)
  })

  it('ships no .env file and no stray secret material', () => {
    // Cheap standing guard on the thing a security tool must never do.
    const walk = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)],
      )
    const files = walk(packageRoot).map((f) => f.slice(packageRoot.length + 1))
    expect(files.filter((f) => /(^|\/)\.env(\.|$)/.test(f))).toEqual([])
  })
})
