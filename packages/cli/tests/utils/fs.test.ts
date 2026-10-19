import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { readFiles } from '../../src/utils/fs.js'

const tempDirs: string[] = []

function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-fs-test-'))
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

describe('readFiles', () => {
  it('reads files matching patterns', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'foo.ts'), 'const x = 1', 'utf-8')
    writeFileSync(join(dir, 'bar.ts'), 'const y = 2', 'utf-8')

    const { files } = await readFiles(dir, ['**/*.ts'])
    expect(files.length).toBe(2)
    expect(files.some((f) => f.relativePath === 'foo.ts')).toBe(true)
    expect(files.some((f) => f.relativePath === 'bar.ts')).toBe(true)
    expect(files[0].content).toBeTruthy()
    expect(files[0].path).toBeTruthy()
  })

  it('respects ignore patterns', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'foo.ts'), 'const x = 1', 'utf-8')
    mkdirSync(join(dir, 'node_modules'), { recursive: true })
    writeFileSync(join(dir, 'node_modules', 'lib.ts'), 'const z = 3', 'utf-8')

    // node_modules is ignored by default
    const { files } = await readFiles(dir, ['**/*.ts'])
    expect(files.some((f) => f.relativePath.includes('node_modules'))).toBe(false)
    expect(files.some((f) => f.relativePath === 'foo.ts')).toBe(true)
  })

  it('applies custom ignore patterns', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'foo.ts'), 'const x = 1', 'utf-8')
    writeFileSync(join(dir, 'secret.ts'), 'const s = 0', 'utf-8')

    const { files } = await readFiles(dir, ['**/*.ts'], ['secret.ts'])
    expect(files.some((f) => f.relativePath === 'secret.ts')).toBe(false)
    expect(files.some((f) => f.relativePath === 'foo.ts')).toBe(true)
  })

  it('ignores .shipguard/** by default (tool must not scan its own report output)', async () => {
    const dir = mkTemp()
    // Create a regular source file
    writeFileSync(join(dir, 'index.ts'), 'const x = 1', 'utf-8')
    // Create .shipguard/reports/latest.md (ShipGuard report output)
    const shipguardDir = join(dir, '.shipguard', 'reports')
    mkdirSync(shipguardDir, { recursive: true })
    writeFileSync(join(shipguardDir, 'latest.md'), '# ShipGuard Report\nsome content', 'utf-8')

    const { files } = await readFiles(dir)
    // .shipguard/reports/latest.md must NOT appear in scanned files
    expect(files.some((f) => f.relativePath.includes('.shipguard'))).toBe(false)
    // The real source file should still be scanned
    expect(files.some((f) => f.relativePath === 'index.ts')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// invalid UTF-8: degrade loudly, never scan with garbage
// ---------------------------------------------------------------------------

describe('readFiles — invalid UTF-8 handling', () => {
  it('accumulates a file with invalid UTF-8 in invalidUtf8Files and does NOT scan it', async () => {
    const dir = mkTemp()

    // Valid UTF-8 file — must be scanned normally
    writeFileSync(join(dir, 'valid.ts'), 'const x = 1', 'utf-8')

    // Invalid UTF-8: lone continuation byte (0x80 is never valid as a first byte)
    // This simulates the "secret straddling an invalid-UTF-8 boundary" bug.
    const badContent = Buffer.concat([
      Buffer.from('const secret = "'),
      Buffer.from([0x80, 0xbf]), // invalid UTF-8 sequence
      Buffer.from('"'),
    ])
    writeFileSync(join(dir, 'bad-utf8.ts'), badContent)

    const result = await readFiles(dir, ['**/*.ts'])

    // The valid file is scanned
    expect(result.files.some((f) => f.relativePath === 'valid.ts')).toBe(true)

    // The invalid-UTF-8 file is NOT in the scanned set
    expect(result.files.some((f) => f.relativePath === 'bad-utf8.ts')).toBe(false)

    // It is accumulated in invalidUtf8Files
    expect(result.invalidUtf8Files.some((f) => f.relativePath === 'bad-utf8.ts')).toBe(true)
    expect(result.invalidUtf8Files[0].reason).toBeTruthy()
  })

  it('returns empty invalidUtf8Files when all files are valid UTF-8', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'clean.ts'), 'const hello = "world"', 'utf-8')

    const result = await readFiles(dir, ['**/*.ts'])

    expect(result.invalidUtf8Files).toHaveLength(0)
    expect(result.files.some((f) => f.relativePath === 'clean.ts')).toBe(true)
  })

  it('strips BOM from valid UTF-8 files before returning content', async () => {
    const dir = mkTemp()
    // UTF-8 BOM (EF BB BF) followed by content
    const bomContent = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from('const x = 1'),
    ])
    writeFileSync(join(dir, 'bom.ts'), bomContent)

    const result = await readFiles(dir, ['**/*.ts'])

    const bomFile = result.files.find((f) => f.relativePath === 'bom.ts')
    expect(bomFile).toBeDefined()
    // BOM must be stripped — content starts with 'const', not U+FEFF
    expect(bomFile!.content.charCodeAt(0)).not.toBe(0xfeff)
    expect(bomFile!.content).toBe('const x = 1')
  })

  it('normalizes CRLF line endings to LF before returning content', async () => {
    const dir = mkTemp()
    // CRLF line endings (Windows-authored file)
    writeFileSync(join(dir, 'crlf.ts'), 'line1\r\nline2\r\nline3')

    const result = await readFiles(dir, ['**/*.ts'])

    const crlfFile = result.files.find((f) => f.relativePath === 'crlf.ts')
    expect(crlfFile).toBeDefined()
    // All \r must be stripped — no \r in the normalized content
    expect(crlfFile!.content).not.toContain('\r')
    expect(crlfFile!.content).toBe('line1\nline2\nline3')
  })
})

// ---------------------------------------------------------------------------
// unreadable file handling: degrade loudly, never silently skip
// ---------------------------------------------------------------------------

describe('readFiles — unreadable file handling', () => {
  it('accumulates unreadable files in unreadableFiles and continues scanning others', async () => {
    const dir = mkTemp()

    // A readable file
    writeFileSync(join(dir, 'readable.ts'), 'const x = 1', 'utf-8')

    // A file made unreadable via permissions (skip on CI if running as root)
    const unreadablePath = join(dir, 'unreadable.ts')
    writeFileSync(unreadablePath, 'const secret = "oops"', 'utf-8')
    // Remove read permission — only works on non-root; skip if we can still read it
    chmodSync(unreadablePath, 0o000)

    const result = await readFiles(dir, ['**/*.ts'])

    // If we can't reliably make a file unreadable (e.g. running as root), skip assertion
    if (result.unreadableFiles.length === 0 && result.files.some(f => f.relativePath === 'unreadable.ts')) {
      // Running as root — skip the permission check
      return
    }

    // The readable file is scanned
    expect(result.files.some((f) => f.relativePath === 'readable.ts')).toBe(true)

    // The unreadable file is NOT in the scanned set and IS in unreadableFiles
    expect(result.files.some((f) => f.relativePath === 'unreadable.ts')).toBe(false)
    expect(result.unreadableFiles).toContain('unreadable.ts')
  })

  it('returns empty unreadableFiles when all files are readable', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'fine.ts'), 'const ok = true', 'utf-8')

    const result = await readFiles(dir, ['**/*.ts'])

    expect(result.unreadableFiles).toHaveLength(0)
  })
})
