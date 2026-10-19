/**
 * TDD tests for readFiles() robustness bounds (Part A — OOM fix, issue #2)
 *
 * Tests written FIRST — they drive the implementation in utils/fs.ts.
 * All tests are deterministic and use tiny limits to avoid real allocations.
 */

import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, createWriteStream } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { readFiles } from '../../src/utils/fs.js'

const tempDirs: string[] = []

function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-fs-bounds-test-'))
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

// ---------------------------------------------------------------------------
// A1: File-size cap — files over maxFileSizeBytes are skipped
// ---------------------------------------------------------------------------

describe('readFiles — maxFileSizeBytes cap', () => {
  it('skips a file larger than maxFileSizeBytes and increments skippedTooLarge', async () => {
    const dir = mkTemp()
    // Small cap: 100 bytes
    const cap = 100
    // File over cap
    writeFileSync(join(dir, 'big.ts'), 'x'.repeat(200), 'utf-8')
    // File under cap
    writeFileSync(join(dir, 'small.ts'), 'const x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*.ts'], [], { maxFileSizeBytes: cap })

    expect(result.files.some(f => f.relativePath === 'small.ts')).toBe(true)
    expect(result.files.some(f => f.relativePath === 'big.ts')).toBe(false)
    expect(result.skippedTooLarge).toBe(1)
  })

  it('includes files exactly at the size limit', async () => {
    const dir = mkTemp()
    const cap = 100
    // File exactly at cap (100 bytes)
    writeFileSync(join(dir, 'exact.ts'), 'x'.repeat(100), 'utf-8')

    const result = await readFiles(dir, ['**/*.ts'], [], { maxFileSizeBytes: cap })

    expect(result.files.some(f => f.relativePath === 'exact.ts')).toBe(true)
    expect(result.skippedTooLarge).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// A2: Binary detection — files with NUL bytes are skipped
// ---------------------------------------------------------------------------

describe('readFiles — binary file detection', () => {
  it('skips a file containing a NUL byte and increments skippedBinary', async () => {
    const dir = mkTemp()
    // Create a binary file with NUL byte in first 8192 bytes
    const binaryContent = Buffer.concat([
      Buffer.from('some text '),
      Buffer.from([0x00]),  // NUL byte
      Buffer.from(' more text'),
    ])
    writeFileSync(join(dir, 'binary.bin'), binaryContent)
    writeFileSync(join(dir, 'text.ts'), 'const x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*'], [], {})

    expect(result.files.some(f => f.relativePath === 'text.ts')).toBe(true)
    expect(result.files.some(f => f.relativePath === 'binary.bin')).toBe(false)
    expect(result.skippedBinary).toBe(1)
  })

  it('reads a normal text file without NUL bytes without skipping', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'code.ts'), 'export const hello = "world"', 'utf-8')

    const result = await readFiles(dir, ['**/*.ts'], [], {})

    expect(result.files.some(f => f.relativePath === 'code.ts')).toBe(true)
    expect(result.skippedBinary).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// A3: Total-bytes cap — stops collecting and sets truncated=true
// ---------------------------------------------------------------------------

describe('readFiles — maxTotalBytes cap (truncated/degraded)', () => {
  it('stops collecting files once maxTotalBytes is exceeded and sets truncated=true', async () => {
    const dir = mkTemp()
    // maxTotalBytes = 50 bytes; each file is ~30 bytes → 2nd file pushes over
    const cap = 50
    writeFileSync(join(dir, 'a.ts'), 'a'.repeat(30), 'utf-8')
    writeFileSync(join(dir, 'b.ts'), 'b'.repeat(30), 'utf-8')
    writeFileSync(join(dir, 'c.ts'), 'c'.repeat(30), 'utf-8')

    const result = await readFiles(dir, ['**/*.ts'], [], { maxTotalBytes: cap })

    // Fewer than 3 files read (stopped early)
    expect(result.files.length).toBeLessThan(3)
    expect(result.truncated).toBe(true)
  })

  it('does NOT set truncated=true when under the total-bytes limit', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'a.ts'), 'const x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*.ts'], [], { maxTotalBytes: 1024 * 1024 })

    expect(result.truncated).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// A3b: Max-files cap — stops collecting and sets truncated=true
// ---------------------------------------------------------------------------

describe('readFiles — maxFiles cap (truncated/degraded)', () => {
  it('stops collecting once maxFiles is reached and sets truncated=true', async () => {
    const dir = mkTemp()
    for (let i = 0; i < 5; i++) {
      writeFileSync(join(dir, `file${i}.ts`), `const x${i} = ${i}`, 'utf-8')
    }

    const result = await readFiles(dir, ['**/*.ts'], [], { maxFiles: 3 })

    expect(result.files.length).toBe(3)
    expect(result.truncated).toBe(true)
  })

  it('does NOT set truncated=true when under maxFiles', async () => {
    const dir = mkTemp()
    for (let i = 0; i < 3; i++) {
      writeFileSync(join(dir, `file${i}.ts`), `const x${i} = ${i}`, 'utf-8')
    }

    const result = await readFiles(dir, ['**/*.ts'], [], { maxFiles: 5 })

    expect(result.files.length).toBe(3)
    expect(result.truncated).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// A4: Extended default ignore patterns
// ---------------------------------------------------------------------------

describe('readFiles — extended default ignore patterns', () => {
  it('excludes .cache/** by default', async () => {
    const dir = mkTemp()
    mkdirSync(join(dir, '.cache'), { recursive: true })
    writeFileSync(join(dir, '.cache', 'cached.ts'), 'cached', 'utf-8')
    writeFileSync(join(dir, 'real.ts'), 'const x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*'], [], {})

    expect(result.files.some(f => f.relativePath.includes('.cache'))).toBe(false)
    expect(result.files.some(f => f.relativePath === 'real.ts')).toBe(true)
  })

  it('excludes .turbo/** by default', async () => {
    const dir = mkTemp()
    mkdirSync(join(dir, '.turbo'), { recursive: true })
    writeFileSync(join(dir, '.turbo', 'build.json'), '{}', 'utf-8')
    writeFileSync(join(dir, 'real.ts'), 'const x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*'], [], {})

    expect(result.files.some(f => f.relativePath.includes('.turbo'))).toBe(false)
    expect(result.files.some(f => f.relativePath === 'real.ts')).toBe(true)
  })

  it('excludes *.min.js by default', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'bundle.min.js'), 'x.x.x.x.x', 'utf-8')
    writeFileSync(join(dir, 'real.js'), 'const x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*'], [], {})

    expect(result.files.some(f => f.relativePath === 'bundle.min.js')).toBe(false)
    expect(result.files.some(f => f.relativePath === 'real.js')).toBe(true)
  })

  it('excludes *.map files by default', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'bundle.js.map'), '{"version":3}', 'utf-8')
    writeFileSync(join(dir, 'real.ts'), 'const x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*'], [], {})

    expect(result.files.some(f => f.relativePath === 'bundle.js.map')).toBe(false)
    expect(result.files.some(f => f.relativePath === 'real.ts')).toBe(true)
  })

  it('does NOT exclude real source files (.ts, .js, .py, .env)', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'app.ts'), 'const x = 1', 'utf-8')
    writeFileSync(join(dir, 'app.js'), 'const x = 1', 'utf-8')
    writeFileSync(join(dir, 'app.py'), 'x = 1', 'utf-8')
    writeFileSync(join(dir, '.env'), 'SECRET=xxx', 'utf-8')

    const result = await readFiles(dir, ['**/*'], [], {})

    expect(result.files.some(f => f.relativePath === 'app.ts')).toBe(true)
    expect(result.files.some(f => f.relativePath === 'app.js')).toBe(true)
    expect(result.files.some(f => f.relativePath === 'app.py')).toBe(true)
    expect(result.files.some(f => f.relativePath === '.env')).toBe(true)
  })

  it('excludes vendor/** by default', async () => {
    const dir = mkTemp()
    mkdirSync(join(dir, 'vendor'), { recursive: true })
    writeFileSync(join(dir, 'vendor', 'lib.js'), 'vendored lib', 'utf-8')
    writeFileSync(join(dir, 'real.ts'), 'const x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*'], [], {})

    expect(result.files.some(f => f.relativePath.includes('vendor'))).toBe(false)
    expect(result.files.some(f => f.relativePath === 'real.ts')).toBe(true)
  })

  it('excludes *.log files by default', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'app.log'), 'INFO: started', 'utf-8')
    writeFileSync(join(dir, 'real.ts'), 'const x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*'], [], {})

    expect(result.files.some(f => f.relativePath === 'app.log')).toBe(false)
    expect(result.files.some(f => f.relativePath === 'real.ts')).toBe(true)
  })

  it('excludes .venv/** by default', async () => {
    const dir = mkTemp()
    mkdirSync(join(dir, '.venv', 'lib'), { recursive: true })
    writeFileSync(join(dir, '.venv', 'lib', 'module.py'), 'x = 1', 'utf-8')
    writeFileSync(join(dir, 'real.py'), 'x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*'], [], {})

    expect(result.files.some(f => f.relativePath.includes('.venv'))).toBe(false)
    expect(result.files.some(f => f.relativePath === 'real.py')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Return type: new ReadFilesResult shape
// ---------------------------------------------------------------------------

describe('readFiles — return type shape', () => {
  it('returns the full ReadFilesResult shape (files, skippedTooLarge, skippedBinary, truncated)', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'a.ts'), 'const x = 1', 'utf-8')

    const result = await readFiles(dir, ['**/*.ts'], [], {})

    expect(result).toHaveProperty('files')
    expect(result).toHaveProperty('skippedTooLarge')
    expect(result).toHaveProperty('skippedBinary')
    expect(result).toHaveProperty('truncated')
    expect(Array.isArray(result.files)).toBe(true)
    expect(typeof result.skippedTooLarge).toBe('number')
    expect(typeof result.skippedBinary).toBe('number')
    expect(typeof result.truncated).toBe('boolean')
  })
})
