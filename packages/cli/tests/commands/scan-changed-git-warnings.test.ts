/**
 * `--changed` must not trust a git listing that git itself warned about.
 *
 * A fake `git` is put first on PATH. It forwards every call to the real git, except that the
 * untracked-file listing (`ls-files --others`) also prints a warning on stderr and records the
 * LC_ALL / LANGUAGE it was started with.
 *  - Test 1: a GERMAN warning (no English phrase in it) still degrades the scan as UNREADABLE_FILE,
 *    and the CLI started git with LC_ALL=C and LANGUAGE=C.
 *  - Test 2: any `warning:` line degrades, whatever it says.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, degradeCodes, mkTree, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 60_000 })
afterAll(cleanupTrees)

const realGit = execFileSync('sh', ['-c', 'command -v git'], { encoding: 'utf-8' }).trim()

function fakeGit(warning: string): { binDir: string; envLog: string } {
  const root = mkTree({})
  const binDir = join(root, 'bin')
  mkdirSync(binDir)
  const envLog = join(root, 'env.log')
  const script = [
    '#!/bin/sh',
    `case "$*" in *"ls-files --others"*) echo "LC_ALL=$LC_ALL LANGUAGE=$LANGUAGE" >> '${envLog}'; echo '${warning}' >&2;; esac`,
    `exec '${realGit}' "$@"`,
    '',
  ].join('\n')
  writeFileSync(join(binDir, 'git'), script)
  chmodSync(join(binDir, 'git'), 0o755)
  return { binDir, envLog }
}

describe.skipIf(process.platform === 'win32')('--changed degrades on any git warning', () => {
  it('a German-worded warning degrades (UNREADABLE_FILE) and git was started with LC_ALL=C, LANGUAGE=C', async () => {
    const { binDir, envLog } = fakeGit("Warnung: Verzeichnis 'gesperrt/' konnte nicht geoeffnet werden")
    const dir = mkTree({ 'ok.js': 'const a = 1\n' }, { git: true })
    const r = await scanJson(dir, ['--strict', '--changed'], { env: { PATH: `${binDir}:${process.env.PATH}` } })
    expect(existsSync(envLog)).toBe(true)
    expect(readFileSync(envLog, 'utf-8')).toContain('LC_ALL=C LANGUAGE=C')
    expect(r.json?.degraded).toBe(true)
    expect(degradeCodes(r.json)).toContain('UNREADABLE_FILE')
    expect(r.code).toBe(1)
  })

  it('any `warning:` line degrades, whatever it says', async () => {
    const { binDir } = fakeGit('warning: something we have never seen before')
    const dir = mkTree({ 'ok.js': 'const a = 1\n' }, { git: true })
    const r = await scanJson(dir, ['--strict', '--changed'], { env: { PATH: `${binDir}:${process.env.PATH}` } })
    expect(r.json?.degraded).toBe(true)
    expect(degradeCodes(r.json)).toContain('UNREADABLE_FILE')
    expect(r.code).toBe(1)
  })
})
