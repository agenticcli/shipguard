/**
 * A-08 (2026-11-22 e2e): a hand-formatted `.claude/settings.json` (spaces inside braces, mixed lines, odd indents,
 * a hooks block of its own) is handed back BYTE FOR BYTE by setup then uninstall when ShipGuard's entry was the only
 * change. Setup adds its entry as text and uninstall cuts exactly that text out; nothing else is re-serialised.
 * FAIL-BEFORE: a layout the old code could not copy ("recognised: false") came back re-serialised with 2 spaces
 * (47 B in, 67 B out in the e2e run).
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { runSetup, type SetupDeps } from '../../src/commands/setup.js'
import { runUninstall } from '../../src/commands/uninstall.js'
import { appendToList, parseJsonSpans, removeFromList } from '../../src/utils/json-text.js'

const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))
const mk = (prefix: string): string => {
  const d = mkdtempSync(join(tmpdir(), prefix))
  roots.push(d)
  return d
}

const MINE = '{"matcher":"Edit","hooks":[{"type":"command","command":"echo mine"}]}'

const HAND: Array<[string, string]> = [
  ['spaces inside braces, one line', '{ "permissions": { "allow": ["Bash(ls)"] } }\n'],
  ['mixed: first member on the brace line', '{ "permissions": { "allow": ["Bash(ls)"] },\n  "model": "x" }\n'],
  ['odd 3-space indent', '{\n   "permissions": {\n      "allow": ["Bash(ls)"]\n   }\n}\n'],
  ['comma first style', '{\n  "permissions": { "allow": [] }\n  , "model": "x"\n}\n'],
  ['hooks with other events only', '{ "hooks": { "Stop": [] } }\n'],
  ['hooks with a PreToolUse of its own, spaced', `{ "hooks": { "PreToolUse": [ ${MINE} ] } }\n`],
  ['hooks with a PreToolUse of its own, pretty', `{\n  "hooks": {\n    "PreToolUse": [\n      ${MINE}\n    ]\n  }\n}\n`],
  ['two groups already, tabs', `{\n\t"hooks": {\n\t\t"PreToolUse": [\n\t\t\t${MINE},\n\t\t\t${MINE}\n\t\t]\n\t}\n}\n`],
  ['no final newline, CRLF, odd', '{\r\n    "a": 1,\r\n    "b": [1, 2, 3]\r\n}'],
]

async function roundTrip(settings: string, between?: (path: string) => void): Promise<{ afterSetup: string; afterUninstall: string }> {
  const dir = mk('sg-hf-')
  execFileSync('git', ['init', '-q'], { cwd: dir })
  mkdirSync(join(dir, '.claude'), { recursive: true })
  const file = join(dir, '.claude', 'settings.json')
  writeFileSync(file, settings)
  const setupDeps: SetupDeps = {
    cwd: dir, out: () => undefined, isTty: true, confirm: async () => true, env: { PATH: process.env['PATH'] ?? '' },
    now: () => 1_800_000_000_000, configDir: mk('sg-hf-cfg-'), cliVersion: '0.13.0', claudeVersion: () => '2.1.326',
    findCli: () => ({ where: 'local', version: '0.13.0', path: './node_modules/.bin/shipguard' }),
    installDependency: () => undefined, signedIn: () => false, sandbox: false, prime: async () => ({ attempted: false }) as never,
  }
  expect(await runSetup({ agent: 'claude' }, setupDeps)).toBe(0)
  const afterSetup = readFileSync(file, 'utf-8')
  between?.(file)
  expect(await runUninstall({ yes: true }, { cwd: dir, out: () => undefined, isTty: true, confirm: async () => true, configDir: mk('sg-hf-home-') })).toBe(0)
  return { afterSetup, afterUninstall: readFileSync(file, 'utf-8') }
}

describe('A-08: hand-formatted settings.json comes back byte for byte', () => {
  for (const [name, text] of HAND) {
    it(name, async () => {
      const { afterSetup, afterUninstall } = await roundTrip(text)
      expect(afterSetup).toContain('shipguard-gate')
      expect(() => JSON.parse(afterSetup)).not.toThrow()
      expect(afterUninstall).toBe(text)
    })
  }

  it('a file that held nothing but an empty object or an empty hooks block is deleted by uninstall (nothing of the user\'s is left)', async () => {
    for (const text of ['{}\n', '{ }', '{\n  "hooks": {\n    "PreToolUse": []\n  }\n}\n']) {
      const dir = mk('sg-hf-empty-')
      execFileSync('git', ['init', '-q'], { cwd: dir })
      mkdirSync(join(dir, '.claude'), { recursive: true })
      writeFileSync(join(dir, '.claude', 'settings.json'), text)
      const setupDeps: SetupDeps = {
        cwd: dir, out: () => undefined, isTty: true, confirm: async () => true, env: { PATH: process.env['PATH'] ?? '' },
        now: () => 1_800_000_000_000, configDir: mk('sg-hf-cfg-'), cliVersion: '0.13.0', claudeVersion: () => '2.1.326',
        findCli: () => ({ where: 'local', version: '0.13.0', path: 'x' }), installDependency: () => undefined,
        signedIn: () => false, sandbox: false, prime: async () => ({ attempted: false }) as never,
      }
      expect(await runSetup({ agent: 'claude' }, setupDeps)).toBe(0)
      expect(JSON.parse(readFileSync(join(dir, '.claude', 'settings.json'), 'utf-8')).hooks.PreToolUse).toHaveLength(1)
      expect(await runUninstall({ yes: true }, { cwd: dir, out: () => undefined, isTty: true, confirm: async () => true, configDir: mk('sg-hf-home-') })).toBe(0)
      expect(existsSync(join(dir, '.claude', 'settings.json'))).toBe(false)
    }
  })

  it('setup keeps the user\'s own bytes: the text before our entry is unchanged', async () => {
    const text = '{ "permissions": { "allow": ["Bash(ls)"] } }\n'
    const { afterSetup } = await roundTrip(text)
    expect(afterSetup.startsWith('{ "permissions": { "allow": ["Bash(ls)"] }, "hooks":')).toBe(true)
  })

  it('an unrelated edit the user made after setup is kept, byte for byte, and only our entry goes', async () => {
    const text = '{ "permissions": { "allow": ["Bash(ls)"] } }\n'
    const { afterUninstall } = await roundTrip(text, (file) => {
      writeFileSync(file, readFileSync(file, 'utf-8').replace('"Bash(ls)"', '"Bash(ls)",   "Bash(pwd)"'))
    })
    expect(afterUninstall).toBe('{ "permissions": { "allow": ["Bash(ls)",   "Bash(pwd)"] } }\n')
  })
})

describe('json-text helper', () => {
  const style = { unit: '  ', multiline: true, crlf: false }
  it('append then remove is the identity for every container shape', () => {
    for (const t of ['[]', '[1]', '[1,2]', '[ 1 , 2 ]', '[\n  1,\n  2\n]', '{}', '{"a":1}', '{ "a": 1, "b": [1] }', '{\n  "a": 1,\n  "b": 2\n}']) {
      const root = parseJsonSpans(t)
      const key = root.type === 'object' ? 'zz' : null
      const added = appendToList(t, root, key, { x: [1, { y: 2 }] }, style)
      expect(() => JSON.parse(added)).not.toThrow()
      const again = parseJsonSpans(added)
      const n = again.members.length
      expect(removeFromList(added, again, n - 1)).toBe(t)
    }
  })
  it('removing a first or middle element keeps the rest as written', () => {
    const t = '[ 1 ,  2,3 ]'
    expect(removeFromList(t, parseJsonSpans(t), 0)).toBe('[ 2,3 ]')
    expect(removeFromList(t, parseJsonSpans(t), 1)).toBe('[ 1 ,  3 ]')
  })
  it('text JSON.parse rejects is rejected (the caller falls back)', () => {
    expect(() => parseJsonSpans('{"a":}')).toThrow()
    expect(() => parseJsonSpans('{"a":1} x')).toThrow()
    expect(() => parseJsonSpans('{"a":"unterminated}')).toThrow()
  })
})
