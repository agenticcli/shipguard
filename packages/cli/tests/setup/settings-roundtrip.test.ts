/**
 * QA fix 5 (QA-CLI-0130 FAIL 5): setup then uninstall hands `.claude/settings.json` back BYTE FOR BYTE when ShipGuard's
 * entry was the only change: the file keeps its own indent (compact one-liner, 4 spaces, tabs), final newline and
 * line ends. FAIL-BEFORE: a compact file came back pretty-printed and a 4-space file came back 2-space + newline.
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { runSetup, type SetupDeps } from '../../src/commands/setup.js'
import { runUninstall } from '../../src/commands/uninstall.js'
import { detectJsonLayout, writeJsonLayout } from '../../src/utils/json-layout.js'

const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))
const mk = (prefix: string): string => {
  const d = mkdtempSync(join(tmpdir(), prefix))
  roots.push(d)
  return d
}

const USER = {
  permissions: { allow: ['Bash(ls)'] },
  hooks: { PreToolUse: [{ matcher: 'Edit', hooks: [{ type: 'command', command: 'echo mine' }] }] },
}

const LAYOUTS: Array<[string, string]> = [
  ['2 spaces + final newline', JSON.stringify(USER, null, 2) + '\n'],
  ['2 spaces, no final newline', JSON.stringify(USER, null, 2)],
  ['4 spaces + final newline', JSON.stringify(USER, null, 4) + '\n'],
  ['tabs + final newline', JSON.stringify(USER, null, '\t') + '\n'],
  ['compact one line, no final newline', JSON.stringify(USER)],
  ['compact one line + final newline', JSON.stringify(USER) + '\n'],
  ['CRLF line ends, 2 spaces', JSON.stringify(USER, null, 2).replace(/\n/g, '\r\n') + '\r\n'],
]

async function roundTrip(settings: string): Promise<{ afterSetup: string; afterUninstall: string }> {
  const dir = mk('sg-rt-')
  execFileSync('git', ['init', '-q'], { cwd: dir })
  mkdirSync(join(dir, '.claude'), { recursive: true })
  writeFileSync(join(dir, '.claude', 'settings.json'), settings)
  const config = mk('sg-rt-cfg-')
  const setupDeps: SetupDeps = {
    cwd: dir, out: () => undefined, isTty: true, confirm: async () => true, env: { PATH: process.env['PATH'] ?? '' },
    now: () => 1_800_000_000_000, configDir: config, cliVersion: '0.13.0', claudeVersion: () => '2.1.326',
    findCli: () => ({ where: 'local', version: '0.13.0', path: './node_modules/.bin/shipguard' }),
    installDependency: () => undefined, signedIn: () => false, sandbox: false, prime: async () => ({ attempted: false }) as never,
  }
  expect(await runSetup({ agent: 'claude' }, setupDeps)).toBe(0)
  const afterSetup = readFileSync(join(dir, '.claude', 'settings.json'), 'utf-8')
  const lines: string[] = []
  expect(await runUninstall({ yes: true }, { cwd: dir, out: (l) => lines.push(l), isTty: true, confirm: async () => true, configDir: mk('sg-rt-home-') })).toBe(0)
  return { afterSetup, afterUninstall: readFileSync(join(dir, '.claude', 'settings.json'), 'utf-8') }
}

describe('setup then uninstall: settings.json comes back byte for byte', () => {
  for (const [name, text] of LAYOUTS) {
    it(name, async () => {
      const { afterSetup, afterUninstall } = await roundTrip(text)
      expect(afterSetup).toContain('shipguard-gate')
      // setup itself keeps the layout: same kind of file, only the entry added
      expect(detectJsonLayout(afterSetup)).toMatchObject({ indent: detectJsonLayout(text).indent, finalNewline: text.endsWith('\n') })
      expect(afterUninstall).toBe(text)
    })
  }
})

describe('json-layout helper', () => {
  it('detects compact, 4 spaces, tabs; an empty object gets the usual 2 spaces; a hand-made layout is flagged', () => {
    expect(detectJsonLayout('{"a":1}').indent).toBeUndefined()
    expect(detectJsonLayout('{\n    "a": 1\n}\n').indent).toBe('    ')
    expect(detectJsonLayout('{\n\t"a": 1\n}').indent).toBe('\t')
    expect(detectJsonLayout('{}\n')).toMatchObject({ indent: '  ', recognised: true })
    expect(detectJsonLayout('{ "a": 1,\n  "b": 2 }').recognised).toBe(false)
  })
  it('write is the inverse of detect for the layouts it recognises', () => {
    for (const [, text] of LAYOUTS) expect(writeJsonLayout(JSON.parse(text), detectJsonLayout(text))).toBe(text)
  })
})
