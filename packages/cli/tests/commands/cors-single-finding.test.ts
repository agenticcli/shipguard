/**
 * One wildcard-CORS line must yield exactly ONE CORS finding.
 *
 * Two independent detectors can fire on the same line: the legacy check
 * (`deployment_cors_wildcard` / `deployment_config_cors_wildcard_origin`) and the governed
 * corpus rule `generic.cors.wildcard-origin`. legacy-corpus-map.ts maps both legacy ids to
 * the corpus rule, and scanner.ts drops the legacy duplicate when the corpus finding is on
 * the same file+line and is at least as severe. This pins that end to end through the built
 * CLI, per input shape. (Same-rule-id same-line duplicates - e.g. res.setHeader(...) matching
 * two corpus patterns - are a separate concern.)
 */
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { spawnNode } from '../helpers/spawn-cli.js'

vi.setConfig({ testTimeout: 30_000 })

const distCli = resolve(dirname(fileURLToPath(import.meta.url)), '../../dist/cli.js')
const dirs: string[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

async function corsFindings(fileName: string, content: string) {
  expect(existsSync(distCli), 'build first').toBe(true)
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-cors-'))
  dirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"cors-fixture"}', 'utf-8')
  writeFileSync(join(dir, fileName), content, 'utf-8')
  const res = await spawnNode(distCli, ['scan', dir, '--json'], { cwd: dir })
  const json = JSON.parse(res.stdout) as { findings: Array<{ id: string; line?: number; severity: string; blocking: boolean }> }
  return {
    cors: json.findings.filter((f) => /cors/i.test(f.id)),
    strictExit: (await spawnNode(distCli, ['scan', dir, '--json', '--strict'], { cwd: dir })).code,
  }
}

describe('a single wildcard-CORS line yields exactly one CORS finding (legacy <-> corpus dedup)', () => {
  const cases: Array<[string, string, string]> = [
    ['cors() middleware origin', 'server.ts', "app.use(cors({ origin: '*' }))\n"],
    ['header object literal', 'server.js', "const h = { 'Access-Control-Allow-Origin': '*' }\n"],
    ['yaml header', 'headers.yaml', 'headers:\n  Access-Control-Allow-Origin: *\n'],
  ]
  for (const [label, file, content] of cases) {
    it(`${label} (${file})`, async () => {
      const { cors: found, strictExit } = await corsFindings(file, content)
      expect(found, JSON.stringify(found)).toHaveLength(1)
      expect(found[0].id).toBe('generic.cors.wildcard-origin')
      expect(found[0].severity).toBe('high')
      // Behaviour preserved: the legacy check blocked, and the severity reconciliation only relabelled the
      // corpus severity. The surviving finding must still gate a ship.
      expect(found[0].blocking).toBe(true)
      expect(strictExit).toBe(1)
    })
  }
})

describe('wildcard CORS still blocks --strict where only the legacy check fires', () => {
  const cases: Array<[string, string, string]> = [
    ['next.config.js headers()', 'next.config.js', "module.exports = { async headers() { return [{ source: '/(.*)', headers: [{ key: 'Access-Control-Allow-Origin', value: '*' }] }] } }\n"],
    ['JSON header map', 'server.json', '{"Access-Control-Allow-Origin": "*"}\n'],
    ['JSON5 unquoted key', 'cors.json5', "{ origin: '*' }\n"],
  ]
  for (const [label, file, content] of cases) {
    it(`${label} (${file})`, async () => {
      const { cors: found, strictExit } = await corsFindings(file, content)
      expect(found.length, JSON.stringify(found)).toBeGreaterThanOrEqual(1)
      expect(found.some((f) => f.blocking)).toBe(true)
      expect(strictExit).toBe(1)
    })
  }
})

describe('suppressed wildcard CORS does not fail --strict', () => {
  const REASON = '-- accepted for a public read-only API'
  it('corpus id suppressed only: the hidden legacy twin does not reappear as blocking', async () => {
    const { cors: found, strictExit } = await corsFindings(
      'server.ts',
      `// shipguard-ignore: generic.cors.wildcard-origin ${REASON}\napp.use(cors({ origin: '*' }))\n`,
    )
    expect(found.filter((f) => f.blocking), JSON.stringify(found)).toHaveLength(0)
    expect(strictExit).toBe(0)
  })

  it('both ids suppressed: recorded once (not double-counted), --strict exits 0', async () => {
    const { cors: found, strictExit } = await corsFindings(
      'server.ts',
      `// shipguard-ignore: generic.cors.wildcard-origin ${REASON}\n` +
        `app.use(cors({ origin: '*' })) // shipguard-ignore: deployment_config_cors_wildcard_origin ${REASON}\n`,
    )
    expect(found, JSON.stringify(found)).toHaveLength(1)
    expect(found[0].blocking).toBe(false)
    expect(found[0]).toMatchObject({ suppressed: true })
    expect(strictExit).toBe(0)
  })
})

describe('res.setHeader wildcard (same rule id matched by two corpus patterns on one line)', () => {
  // EXPECTED after rebasing onto the finding dedupe: exactly ONE finding for the line, and a
  // single non-blocking `high` scores 30 (REVIEW_BEFORE_SHIP), so --strict exits 0. Before that
  // branch the two same-rule findings score 60 (DO_NOT_SHIP): --strict exits 1 with 0 blocking.
  // `it.fails` documents the known gap and turns RED the moment the rebase fixes it - at which
  // point delete the `.fails` so this becomes a normal passing test.
  it("res.setHeader('Access-Control-Allow-Origin', '*') alone: one finding, --strict exit 0", async () => {
    const { cors: found, strictExit } = await corsFindings(
      'server.js',
      "res.setHeader('Access-Control-Allow-Origin', '*')\n",
    )
    expect(found, JSON.stringify(found)).toHaveLength(1)
    expect(strictExit).toBe(0)
  })
})
