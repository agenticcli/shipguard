/**
 * QA (2026-11-02, qa-final on ed3a6ae9): the branch goal, end to end, on BOTH read paths.
 *
 * "No SAFE_TO_SHIP / degraded:false on readable text that was not scanned." For every file below
 * that holds a credential as contiguous ASCII bytes (and is under the size cap), the CLI must either
 * report the credential in THAT file, or name the file as not scanned in a DEGRADING way
 * (coverage.files.unknownBinary, or the INVALID_UTF8 detail). A file that is neither is a silent miss.
 *
 * Inputs: seeded random encoding mixes (tests/helpers/encoding-mix.ts) plus fixed rows for the
 * mixed-encoding case of judge R3 MAJOR 2 with an ODD-length ASCII part (the build fixture uses an
 * even length; with an odd length the whole buffer is no longer valid UTF-16 in either byte order).
 */
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, degradeCodes, ENV_KEY_LINE, keyFoundIn, mkTree, scanJson, utf16le, type FileMap, type ScanJson } from '../helpers/cli-fixture.js'
import { makeMixCase } from '../helpers/encoding-mix.js'

vi.setConfig({ testTimeout: 120_000 })
afterAll(cleanupTrees)

/** Names of files that hold the key but were neither reported nor named as a degraded skip. */
function silentMisses(json: ScanJson, names: string[]): string[] {
  const unknown: string[] = json.coverage.files.unknownBinary
  const invalidDetail = (json.degradedReasons ?? []).find((r: { code: string }) => r.code === 'INVALID_UTF8')?.detail ?? ''
  return names.filter((n) => !keyFoundIn(json, n) && !unknown.includes(n) && !invalidDetail.includes(n))
}

async function bothPaths(files: FileMap): Promise<Array<['full' | 'changed', ScanJson]>> {
  const full = await scanJson(mkTree(files), ['--strict'])
  const changed = await scanJson(mkTree(files, { git: true }), ['--strict', '--changed'])
  expect(full.json, full.stderr.slice(0, 500)).toBeDefined()
  expect(changed.json, changed.stderr.slice(0, 500)).toBeDefined()
  expect(full.code).toBe(1)
  expect(changed.code).toBe(1)
  return [['full', full.json!], ['changed', changed.json!]]
}

describe('QA: a credential is found or its file degrades the scan (never a silent SAFE)', () => {
  // 4 trees x 8 files (at most 10 per tree, so the INVALID_UTF8 detail names every file).
  for (const start of [101, 201, 301, 401]) {
    it(`seeded encoding mixes ${start}..${start + 7}: no silent miss on either read path`, async () => {
      const files: FileMap = {}
      const recipes: Record<string, string> = {}
      for (let seed = start; seed < start + 8; seed++) {
        const { buf, recipe } = makeMixCase(seed)
        files[`m${seed}.txt`] = buf
        recipes[`m${seed}.txt`] = recipe
      }
      for (const [mode, json] of await bothPaths(files)) {
        const missed = silentMisses(json, Object.keys(files))
        expect(missed.map((n) => `${mode} ${n}: ${recipes[n]}`)).toEqual([])
        // Every file holds a key: found (blocking) or degraded, so the verdict can never be SAFE.
        expect(json.recommendation).not.toBe('SAFE_TO_SHIP')
      }
    })
  }

  const asciiPart = (len: number, withKey: boolean): Buffer => {
    const body = (withKey ? ENV_KEY_LINE : '') + 'APP_NAME=demo\nDEBUG=false\nPORT=3000\n'.repeat(200)
    return Buffer.from(body.slice(0, len))
  }
  const ps51Append = utf16le('EXTRA=1\nMORE=2\nSTILL=3\nAND=4\nX=5\nY=6\nZ=7\n')
  const ps51AppendWithKey = utf16le('EXTRA=1\n' + ENV_KEY_LINE + 'MORE=2\n')

  const fixed: Array<[string, Buffer]> = [
    ['odd ASCII .env with key + appended UTF-16LE block', Buffer.concat([asciiPart(1999, true), ps51Append])],
    ['odd ASCII .env + appended UTF-16LE block that holds the key', Buffer.concat([asciiPart(1999, false), ps51AppendWithKey])],
    ['even ASCII .env + appended UTF-16LE block that holds the key', Buffer.concat([asciiPart(2000, false), ps51AppendWithKey])],
  ]
  for (const [name, buf] of fixed) {
    it(`mixed encoding: ${name}: key found or degraded, on both read paths`, async () => {
      expect(buf.includes(Buffer.from('AKIA')) || buf.includes(Buffer.from('A\0K\0I\0A\0'))).toBe(true)
      for (const [mode, json] of await bothPaths({ 'cfg.env': buf })) {
        const found = keyFoundIn(json, 'cfg.env')
        expect(found || json.degraded === true, `${mode}: ${JSON.stringify({ codes: degradeCodes(json), cov: json.coverage.decoded })}`).toBe(true)
        // One blocking finding is REVIEW_BEFORE_SHIP (strict exit 1, asserted in bothPaths); a degrade is DO_NOT_SHIP.
        expect(json.recommendation).not.toBe('SAFE_TO_SHIP')
      }
    })
  }
})
