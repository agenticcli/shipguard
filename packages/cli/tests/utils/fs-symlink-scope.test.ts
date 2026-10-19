/**
 * Symlink scope-guard regression tests.
 *
 * Symptom: fast-glob's fg() in readFiles() ran with the default
 * followSymbolicLinks:true. A symlink inside the project pointing OUT of the
 * project root (e.g. `ln -s /home escape`) caused the scan to descend through
 * the symlink, READ and REPORT out-of-tree file content (secrets), and risk a
 * hang on huge external trees. This breaks the privacy moat: the user's scan
 * must never read or report files outside the project root.
 *
 * The fix sets followSymbolicLinks:false on the fg() call so symlinked
 * directories are never traversed.
 *
 * DISCIPLINE: the bug is behavioral — the unit test below builds a
 * real symlink fixture and asserts the scanned file set EXCLUDES the out-of-tree
 * target. A spawned-binary assertion (no hang, out-of-tree path absent from
 * findings) lives in tests/commands/cli-exit-codes.test.ts.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { readFiles } from '../../src/utils/fs.js'

const tempDirs: string[] = []

function mkTemp(prefix = 'shipguard-symlink-test-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // ignore cleanup errors
    }
  }
})

describe('readFiles — symlink scope guard ', () => {
  it('does NOT follow a symlinked directory pointing outside the project root', async () => {
    // Project root with one in-tree file.
    const project = mkTemp()
    writeFileSync(join(project, 'in-tree.ts'), 'const a = 1', 'utf-8')

    // A SEPARATE directory outside the project, holding a "secret".
    const outside = mkTemp('shipguard-outside-')
    const secretName = 'out-of-tree-secret.ts'
    writeFileSync(join(outside, secretName), "const k = 'AKIAIOSFODNN7EXAMPLE'", 'utf-8')

    // Symlink inside the project that escapes the root.
    symlinkSync(outside, join(project, 'escape'))

    const { files } = await readFiles(project, ['**/*'])

    const paths = files.map((f) => f.relativePath)
    // The in-tree file is scanned.
    expect(paths).toContain('in-tree.ts')
    // The out-of-tree secret reached via the symlink must NOT be scanned.
    expect(paths.some((p) => p.includes(secretName))).toBe(false)
    expect(paths.some((p) => p.startsWith('escape/'))).toBe(false)
    // And its content must never appear in any scanned file's content.
    expect(files.some((f) => f.content.includes('AKIAIOSFODNN7EXAMPLE'))).toBe(false)
  })

  it('does NOT follow a symlinked FILE pointing outside the project root', async () => {
    const project = mkTemp()
    writeFileSync(join(project, 'real.ts'), 'const b = 2', 'utf-8')

    const outside = mkTemp('shipguard-outside-')
    const outsideFile = join(outside, 'external.ts')
    writeFileSync(outsideFile, "const t = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", 'utf-8')

    // A symlinked file inside the project pointing at an out-of-tree file.
    symlinkSync(outsideFile, join(project, 'linked.ts'))

    const { files } = await readFiles(project, ['**/*'])
    const paths = files.map((f) => f.relativePath)
    expect(paths).toContain('real.ts')
    // The symlinked file's out-of-tree content must not be ingested.
    expect(files.some((f) => f.content.includes('ghp_'))).toBe(false)
  })

  it('still scans ordinary nested real directories (no false suppression)', async () => {
    const project = mkTemp()
    mkdirSync(join(project, 'src'), { recursive: true })
    writeFileSync(join(project, 'src', 'nested.ts'), 'const c = 3', 'utf-8')

    const { files } = await readFiles(project, ['**/*'])
    expect(files.some((f) => f.relativePath === 'src/nested.ts')).toBe(true)
  })
})
