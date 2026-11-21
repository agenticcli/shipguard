/** W2a acceptance tests: the Not scanned collector, shell quoting, and the read-only screen facts. */
import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { collectNotScanned, shellQuote } from '../../src/core/not-scanned.js'
import { probeGate, detectNextAgent, detectManifest } from '../../src/core/screen-context.js'
import { coverage, result } from './_fixtures.js'

const dirs: string[] = []
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }) })
const tmp = () => { const d = mkdtempSync(join(tmpdir(), 'sg-w2a-ctx-')); dirs.push(d); return d }

describe('collectNotScanned', () => {
  it('reads the real size of a too-large file and quotes a path with spaces in the ignore command', () => {
    const dir = tmp()
    writeFileSync(join(dir, 'big dump.txt'), 'a'.repeat(700 * 1024))
    const r = result([], {
      degraded: true,
      coverage: coverage({
        discovered: 2, scanned: 1,
        skipped: { binary: 0, tooLarge: 1, symlink: 0, unknownBinary: 0, invalidUtf8: 0, unreadable: 0, special: 0, binaryHeadOnly: 0 },
        files: { binary: [], tooLarge: ['big dump.txt'], symlink: [], unknownBinary: [], special: [], nulSubstituted: [], selfArtifacts: [] },
      }),
    })
    const ns = collectNotScanned(r, { cwd: dir, maxFileSizeBytes: 512 * 1024 })
    expect(ns.fileCount).toBe(1)
    expect(ns.entries[0].reason).toBe('too large (700 KB, limit 512 KB)')
    expect(ns.entries[0].fix[0]).toContain(`shipguard ignore 'big dump.txt' --reason`)
  })

  it('counts without names (invalid text, unreadable, truncated) still get an entry with a fix', () => {
    const r = result([], {
      degraded: true,
      coverage: coverage({
        skipped: { binary: 0, tooLarge: 0, symlink: 0, unknownBinary: 0, invalidUtf8: 2, unreadable: 1, special: 0, binaryHeadOnly: 0 },
        truncated: { by: 'maxFiles', notReached: 40 },
      }),
    })
    const ns = collectNotScanned(r)
    expect(ns.entries.map((e) => e.code)).toEqual(['INVALID_UTF8', 'UNREADABLE_FILE', 'OUTPUT_TRUNCATED'])
    expect(ns.fileCount).toBe(3)
    expect(ns.entries.every((e) => e.fix.length > 0)).toBe(true)
  })

  it('degraded reasons that are not about files are kept as other reasons', () => {
    const r = result([], { degraded: true, degradedReasons: [{ code: 'PRO_RULES_UNAVAILABLE' }, { code: 'FILE_TOO_LARGE' }] })
    const ns = collectNotScanned(r)
    expect(ns.otherReasons).toEqual([{ code: 'PRO_RULES_UNAVAILABLE', text: 'the full rulebook was not available for this scan' }])
  })
})

describe('shellQuote', () => {
  it('leaves safe paths alone and single-quotes everything else', () => {
    expect(shellQuote('app/api/x.ts')).toBe('app/api/x.ts')
    expect(shellQuote('a b.txt')).toBe("'a b.txt'")
    expect(shellQuote("it's.txt")).toBe(`'it'\\''s.txt'`)
    expect(shellQuote('a;rm -rf x')).toBe("'a;rm -rf x'")
  })
})

describe('probeGate / detectNextAgent / detectManifest (read-only)', () => {
  it('no files: no gate, no signal, no manifest', () => {
    const d = tmp()
    expect(probeGate(d)).toEqual({ state: 'none', label: null })
    expect(detectNextAgent(d, {})).toBeNull()
    expect(detectManifest(d)).toBeNull()
  })

  it('a hook entry naming shipguard counts as an installed gate; garbage never counts as one', () => {
    const d = tmp()
    mkdirSync(join(d, '.claude'))
    writeFileSync(join(d, '.claude', 'settings.json'), '{"hooks":{"PreToolUse":[{"hooks":[{"command":"npx shipguard gate"}]}]}}')
    expect(probeGate(d).state).toBe('current')
    const e = tmp()
    mkdirSync(join(e, '.shipguard'))
    writeFileSync(join(e, '.shipguard', 'installed.json'), 'not json')
    expect(probeGate(e).state).toBe('none')
    writeFileSync(join(e, '.shipguard', 'installed.json'), '{}')
    expect(probeGate(e).state).toBe('none')
  })

  it('agent: the running agent first, then repo signals', () => {
    const d = tmp()
    expect(detectNextAgent(d, { CLAUDECODE: '1' })).toBe('claude')
    expect(detectNextAgent(d, { CODEX_SANDBOX: '1' })).toBe('codex')
    mkdirSync(join(d, '.cursor'))
    expect(detectNextAgent(d, {})).toBe('cursor')
  })

  it('manifest names the file that made it a project', () => {
    const d = tmp()
    writeFileSync(join(d, 'go.mod'), 'module x')
    expect(detectManifest(d)).toBe('go.mod')
  })
})
