/**
 * B11: FIFOs, sockets and devices (BR S4) are counted, never silently dropped, and never block the
 * scan. A deleted-mid-scan file is UNREADABLE_FILE (degraded): pinned with a mocked read.
 */
import { execSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { readFiles } from '../../src/utils/fs.js'

const dirs: string[] = []
afterEach(() => {
  vi.restoreAllMocks()
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})
const mk = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'sg-special-'))
  dirs.push(d)
  return d
}

describe.skipIf(process.platform === 'win32')('special files', () => {
  it('a FIFO is counted under skipped.special, named, fast, and not an error', async () => {
    const dir = mk()
    writeFileSync(join(dir, 'ok.js'), 'const a = 1\n')
    execSync('mkfifo pipe1', { cwd: dir })
    const t0 = Date.now()
    const res = await readFiles(dir, ['**/*'], [])
    expect(Date.now() - t0).toBeLessThan(5000)
    expect(res.skippedSpecial).toBe(1)
    expect(res.skippedSpecialFiles).toEqual(['pipe1'])
    expect(res.unreadableFiles).toEqual([])
    expect(res.files.map((f) => f.relativePath)).toEqual(['ok.js'])
    expect(res.discovered).toBe(2)
  })
})

describe('deleted mid-scan', () => {
  it('a file that disappears between listing and reading is UNREADABLE_FILE (degraded input)', async () => {
    const dir = mk()
    writeFileSync(join(dir, 'gone.txt'), 'x')
    writeFileSync(join(dir, 'ok.txt'), 'y')
    const real = await import('node:fs/promises')
    vi.doMock('node:fs/promises', () => ({
      ...real,
      readFile: async (p: string, ...rest: unknown[]) => {
        if (String(p).endsWith('gone.txt')) throw Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' })
        return (real.readFile as (...a: unknown[]) => Promise<unknown>)(p, ...rest)
      },
    }))
    vi.resetModules()
    const { readFiles: mocked } = await import('../../src/utils/fs.js')
    const res = await mocked(dir, ['**/*'], [])
    expect(res.unreadableFiles).toEqual(['gone.txt'])
    expect(res.files.map((f) => f.relativePath)).toEqual(['ok.txt'])
    vi.doUnmock('node:fs/promises')
  })
})
