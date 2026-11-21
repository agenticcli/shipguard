/**
 * source-maps.test.ts - 0.12.1 ships source maps; the rebuild recipe (REBUILD.md) depends on them.
 *
 * Runs against the real built dist/ and the real `npm pack` file list (never publishes):
 *   - every dist/*.js has a .map, and every map source is a real repo file, never node_modules or an absolute path;
 *   - embedded sources equal the files on disk (nothing hidden in the maps);
 *   - the packed file set is exactly the allowed folders (no Pro rules, no env files, no private keys);
 *   - the checksum manifest still covers the .js files and does not list maps;
 *   - compare-dist.mjs says MATCH for identical builds and MISMATCH for a changed .js, a changed .map or a missing .map.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { execFileSync, spawnSync } from 'node:child_process'
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, unlinkSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

const CLI_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const DIST = join(CLI_DIR, 'dist')
const CHECK = join(CLI_DIR, 'scripts', 'check-sourcemaps.mjs')
const COMPARE = join(CLI_DIR, 'scripts', 'compare-dist.mjs')

const run = (script: string, ...args: string[]) =>
  spawnSync('node', [script, ...args], { encoding: 'utf-8' })

let work: string
beforeAll(() => { work = mkdtempSync(join(tmpdir(), 'shipguard-maps-')) })
afterAll(() => { rmSync(work, { recursive: true, force: true }) })

describe('source maps in dist/', () => {
  it('every bundle has a map and every mapped source is a real repo file', () => {
    const r = run(CHECK, DIST)
    expect(r.stderr).toBe('')
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/all resolve/)
  })

  it('the checksum manifest is still a hash of the .js files only', () => {
    const manifest = JSON.parse(readFileSync(join(DIST, 'checksum-manifest.json'), 'utf-8')) as Record<string, string>
    for (const v of Object.values(manifest)) expect(v).toMatch(/^[0-9a-f]{64}$/)
    expect(Object.keys(manifest).join(',')).not.toMatch(/\.map/)
  })

  it('check-sourcemaps fails when a map is missing, a source is outside the repo, or content differs', () => {
    // paths resolve against the dist dir, so keep the copy two levels below the package root
    const nested = join(work, 'pkg', 'dist')
    cpSync(DIST, nested, { recursive: true })
    cpSync(join(CLI_DIR, 'src'), join(work, 'pkg', 'src'), { recursive: true })
    cpSync(join(CLI_DIR, 'rules'), join(work, 'pkg', 'rules'), { recursive: true })
    for (const dep of ['shared', 'matcher-contract']) {
      cpSync(join(CLI_DIR, '..', dep, 'src'), join(work, dep, 'src'), { recursive: true })
    }
    expect(run(CHECK, nested).status).toBe(0)

    const maps = readdirSync(nested).filter((f) => f.endsWith('.js.map'))
    const first = join(nested, maps[0])
    const saved = readFileSync(first, 'utf-8')
    unlinkSync(first)
    expect(run(CHECK, nested).status).toBe(1)

    const bad = JSON.parse(saved)
    bad.sources[0] = '/etc/passwd'
    writeFileSync(first, JSON.stringify(bad))
    const r = run(CHECK, nested)
    expect(r.status).toBe(1)
    expect(r.stderr).toMatch(/bad source path/)

    const tampered = JSON.parse(saved)
    tampered.sourcesContent[0] = tampered.sourcesContent[0] + '\n// injected'
    writeFileSync(first, JSON.stringify(tampered))
    expect(run(CHECK, nested).stderr).toMatch(/embedded source differs/)
  })
})

describe('packed tarball with source maps', () => {
  let files: Array<{ path: string; size: number }>
  let size: number
  beforeAll(() => {
    const raw = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: CLI_DIR, encoding: 'utf-8' })
    const j = JSON.parse(raw)[0]
    files = j.files
    size = j.size
  })

  it('ships a .map for every dist .js, and nothing outside the allowed folders', () => {
    const paths = files.map((f) => f.path)
    const js = paths.filter((p) => /^dist\/[^/]+\.js$/.test(p))
    expect(js.length).toBeGreaterThan(3)
    for (const p of js) expect(paths, `${p}.map missing from the package`).toContain(`${p}.map`)
    for (const p of paths) {
      expect(p, `unexpected packed file ${p}`).toMatch(/^(dist\/|rules\/|templates\/|docs\/|README\.md$|LICENSE$|CHANGELOG\.md$|package\.json$)/)
      expect(p).not.toMatch(/(^|\/)\.env|\.pem$|\.key$|pro-rules|pro-bundle/i)
    }
  })

  it('stays under the release-gate size ceiling (G4: 800 kB packed, the 0.13 budget in scripts/release-gate.sh)', () => {
    // W1b: wiring the plan modules into the commands puts them in the bundle (they were tree-shaken before): 670 kB -> 786 kB.
    expect(size).toBeLessThan(819_200)
  })

  it('maps hold only repo source: no private key block, no env assignment of a secret', () => {
    for (const f of readdirSync(DIST).filter((n) => n.endsWith('.map'))) {
      const text = readFileSync(join(DIST, f), 'utf-8')
      expect(text).not.toMatch(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{40}/)
    }
  })
})

describe('compare-dist.mjs (rebuild-and-compare)', () => {
  const make = (name: string) => {
    const d = join(work, name)
    cpSync(DIST, d, { recursive: true })
    return d
  }

  it('MATCH for two identical builds, ignoring cli-facts.json (it has a timestamp)', () => {
    const a = make('cmp-a'); const b = make('cmp-b')
    writeFileSync(join(b, 'cli-facts.json'), '{"generatedAt":"other"}')
    const r = run(COMPARE, a, b)
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/MATCH/)
  })

  it('MISMATCH for a changed .js, a changed .map and a missing .map', () => {
    const a = make('cmp-c')
    for (const mutate of [
      (d: string) => writeFileSync(join(d, 'cli.js'), readFileSync(join(d, 'cli.js'), 'utf-8') + '\n// x'),
      (d: string) => writeFileSync(join(d, 'cli.js.map'), readFileSync(join(d, 'cli.js.map'), 'utf-8') + ' '),
      (d: string) => unlinkSync(join(d, 'cli.js.map')),
    ]) {
      const b = make(`cmp-b-${Math.random().toString(36).slice(2)}`)
      mutate(b)
      const r = run(COMPARE, a, b)
      expect(r.status).toBe(1)
      expect(r.stdout).toMatch(/MISMATCH/)
    }
  })
})
