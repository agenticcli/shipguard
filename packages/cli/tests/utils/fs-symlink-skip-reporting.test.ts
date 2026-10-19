/**
 * Symlink/binary skip LOUD-reporting regression tests — symlink reporting.
 *
 * Symptom (RCA, EDGE-1): followSymbolicLinks:false in fs.ts's fg call (the
 * correct, documented privacy-moat decision) is enforced by
 * fast-glob's own deep/entry filters, which silently DROP a symlink entry with
 * zero signal: a symlinked directory's entire subtree is never even enumerated.
 * A project whose `src/` is a symlink previously scanned filesScanned=1,
 * degraded=false, stderr empty — a near-clean verdict over a tree ShipGuard
 * never opened.
 *
 * This file asserts the fix at the `readFiles()` level: a second, metadata-only
 * fast-glob pass names every symlink the primary pass refused, and an
 * unconditional console.warn fires (fs.ts, matching the existing unreadable-file
 * precedent in the same function). The full-verdict (degraded=true,
 * SYMLINK_SKIPPED in degradedReasons) integration test lives in
 * tests/core/scanner-edge1-symlink-degradation.test.ts.
 *
 * DISCIPLINE: fail-before/pass-after — before this fix, `skippedSymlinks`
 * and `skippedSymlinkFiles` did not exist on ReadFilesResult at all (a TypeScript
 * compile failure), and no warning was ever printed for a skipped symlink.
 */
import { describe, it, expect, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { readFiles } from '../../src/utils/fs.js'

const tempDirs: string[] = []

function mkTemp(prefix = 'shipguard-symlink-report-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  vi.restoreAllMocks()
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // ignore cleanup errors
    }
  }
})

describe('readFiles — symlink skip is named + loud (symlink reporting)', () => {
  it('names a symlinked directory in skippedSymlinkFiles and reports its count', async () => {
    const project = mkTemp()
    // Real, identical "elsewhere" tree the symlink points at — planted secret inside,
    // exactly like EDGE-1's repro (a symlinked `src/`).
    const elsewhere = mkTemp('shipguard-symlink-report-elsewhere-')
    mkdirSync(join(elsewhere, 'nested'), { recursive: true })
    writeFileSync(
      join(elsewhere, 'nested', 'secret.ts'),
      "const k = 'AKIAIOSFODNN7EXAMPLE'",
      'utf-8',
    )

    writeFileSync(join(project, 'package.json'), '{"name":"fixture"}', 'utf-8')
    symlinkSync(elsewhere, join(project, 'src'))

    const result = await readFiles(project, ['**/*'])

    // The symlinked subtree was never opened — no file from it was scanned, and the
    // secret it contains never entered the scan.
    expect(result.files.some((f) => f.relativePath.startsWith('src/'))).toBe(false)
    expect(result.files.some((f) => f.content.includes('AKIAIOSFODNN7EXAMPLE'))).toBe(false)

    // But it MUST be named, not silent.
    expect(result.skippedSymlinks).toBe(1)
    expect(result.skippedSymlinkFiles).toContain('src')
  })

  it('names a symlinked FILE in skippedSymlinkFiles', async () => {
    const project = mkTemp()
    const outside = mkTemp('shipguard-symlink-report-file-')
    const outsideFile = join(outside, 'external.ts')
    writeFileSync(outsideFile, "const t = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", 'utf-8')
    symlinkSync(outsideFile, join(project, 'linked.ts'))
    writeFileSync(join(project, 'real.ts'), 'const b = 2', 'utf-8')

    const result = await readFiles(project, ['**/*'])

    expect(result.files.map((f) => f.relativePath)).toContain('real.ts')
    expect(result.skippedSymlinks).toBe(1)
    expect(result.skippedSymlinkFiles).toContain('linked.ts')
  })

  it('does NOT report a skipped symlink when there is none (no false positives)', async () => {
    const project = mkTemp()
    mkdirSync(join(project, 'src'), { recursive: true })
    writeFileSync(join(project, 'src', 'nested.ts'), 'const c = 3', 'utf-8')

    const result = await readFiles(project, ['**/*'])

    expect(result.skippedSymlinks).toBe(0)
    expect(result.skippedSymlinkFiles).toEqual([])
  })

  it('fires an unconditional console.warn naming the skipped symlink (loud, not silent)', async () => {
    const project = mkTemp()
    const elsewhere = mkTemp('shipguard-symlink-report-warn-')
    writeFileSync(join(elsewhere, 'a.ts'), 'const a = 1', 'utf-8')
    symlinkSync(elsewhere, join(project, 'src'))

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await readFiles(project, ['**/*'])

    const symlinkWarnings = warnSpy.mock.calls
      .map((args) => String(args[0]))
      .filter((msg) => msg.includes('symlink'))
    expect(symlinkWarnings.length).toBeGreaterThan(0)
    expect(symlinkWarnings.some((msg) => msg.includes('src'))).toBe(true)
  })
})

describe('readFiles — binary skip is named (symlink reporting, informational only)', () => {
  it('names a skipped binary file in skippedBinaryFiles', async () => {
    const project = mkTemp()
    // A NUL byte anywhere in the buffer trips detectBinary() (fs.ts Gate 3).
    writeFileSync(join(project, 'data.bin'), Buffer.from([0x00, 0x01, 0x02, 0x03]))
    writeFileSync(join(project, 'real.ts'), 'const a = 1', 'utf-8')

    const result = await readFiles(project, ['**/*'])

    expect(result.files.map((f) => f.relativePath)).toContain('real.ts')
    expect(result.skippedBinary).toBe(1)
    expect(result.skippedBinaryFiles).toContain('data.bin')

    // Deliberate scope note (see scanner-edge1-symlink-degradation.test.ts for the
    // full rationale): a binary skip is NORMAL, not an incomplete-scan condition —
    // a binary file has no source text to pattern-match. Naming it here is a pure
    // loudness improvement; it must NOT, by itself, make anything "degraded".
  })
})
