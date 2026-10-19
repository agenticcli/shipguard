/**
 * EDGE-1 — silent near-clean verdict over a symlinked source tree.
 *
 * RCA (triage, EDGE-1): a symlinked `src/` makes the CLI report a near-clean
 * verdict over a tree it never opened — filesScanned=1, degraded=false, stderr
 * empty — because followSymbolicLinks:false (fs.ts, a correct and documented
 * privacy decision from) skips the symlink SILENTLY, while
 * FILE_TOO_LARGE one branch away already uses the degradedReasons machinery.
 * followSymbolicLinks:false is kept exactly as-is; the defect was the silence.
 *
 * This is the battery's two-run fixture: a REAL directory vs a SYMLINK to an
 * identical tree, both carrying the same planted secret. The real-dir run must
 * scan normally and stay clean; the symlink run must set degraded=true with a
 * SYMLINK_SKIPPED reason naming `src`.
 *
 * DISCIPLINE: fail-before/pass-after. Before this fix, `degraded` was
 * `false`/`undefined` and `degradedReasons` had no SYMLINK_SKIPPED entry for the
 * symlink run — reverting scanner.ts's SYMLINK_SKIPPED block (keeping fs.ts's
 * skippedSymlinks plumbing) reproduces the pre-fix FAIL.
 */
import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

// ---------------------------------------------------------------------------
// Mocks — must be hoisted before any import of scanner
// ---------------------------------------------------------------------------

vi.mock('../../src/core/git.js', () => ({
  isGitRepo: vi.fn(() => false),
  getChangedFiles: vi.fn(() => []),
}))

const { scan } = await import('../../src/core/scanner.js')

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = []
const PLANTED_SECRET = 'AKIAIOSFODNN7EXAMPLE'

function mkTemp(prefix = 'shipguard-edge1-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  tempDirs.push(dir)
  return dir
}

/** Builds a `src/nested/secret.ts` tree carrying the planted secret. */
function plantSrcTree(root: string): void {
  mkdirSync(join(root, 'src', 'nested'), { recursive: true })
  writeFileSync(
    join(root, 'src', 'nested', 'secret.ts'),
    `const key = '${PLANTED_SECRET}'`,
    'utf-8',
  )
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

describe('scan() — EDGE-1: symlinked src/ no longer scans silently near-clean', () => {
  it('REAL directory run: scans src/ normally, finds the secret, is not degraded', async () => {
    const project = mkTemp('shipguard-edge1-real-')
    writeFileSync(join(project, 'package.json'), '{"name":"fixture"}', 'utf-8')
    plantSrcTree(project)

    const originalCwd = process.cwd()
    process.chdir(project)
    try {
      const result = await scan({
        changedOnly: false,
        generateReport: false,
        strict: false,
        json: false,
        reportPath: '.shipguard/reports/latest.md',
      })

      expect(result.filesScanned).toBeGreaterThan(1)
      // Evidence is redacted centrally (core/redact.ts) — the finding is identified by its
      // visible 8-char prefix; the full key must never appear.
      expect(
        result.findings.some((f) => f.evidence?.includes(PLANTED_SECRET.slice(0, 8))),
      ).toBe(true)
      expect(
        result.findings.some((f) => f.evidence?.includes(PLANTED_SECRET)),
      ).toBe(false)
      expect(result.degraded).toBeFalsy()
      expect(result.degradedReasons?.some((r) => r.code === 'SYMLINK_SKIPPED')).toBeFalsy()
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('SYMLINK run: src/ is a symlink to an identical tree — scan is INCOMPLETE and LOUDLY degraded, not near-clean', async () => {
    // The real tree lives OUTSIDE the project root, exactly like the EDGE-1 repro
    // (a shared package checked out once, symlinked into the project as `src/`).
    const realTreeHolder = mkTemp('shipguard-edge1-target-')
    plantSrcTree(realTreeHolder)

    const project = mkTemp('shipguard-edge1-symlink-')
    writeFileSync(join(project, 'package.json'), '{"name":"fixture"}', 'utf-8')
    symlinkSync(join(realTreeHolder, 'src'), join(project, 'src'))

    const originalCwd = process.cwd()
    process.chdir(project)
    try {
      const result = await scan({
        changedOnly: false,
        generateReport: false,
        strict: false,
        json: false,
        reportPath: '.shipguard/reports/latest.md',
      })

      // The pre-fix symptom, verbatim from the RCA: filesScanned=1 (just
      // package.json), degraded=false. This must no longer be a near-clean
      // verdict — the secret behind the symlink was never opened, and the
      // scan must say so.
      expect(result.filesScanned).toBe(1)
      expect(
        result.findings.some((f) => f.evidence?.includes(PLANTED_SECRET)),
      ).toBe(false)

      // THE FIX: degraded=true, with a SYMLINK_SKIPPED reason naming `src`.
      expect(result.degraded).toBe(true)
      const symlinkReason = result.degradedReasons?.find((r) => r.code === 'SYMLINK_SKIPPED')
      expect(symlinkReason).toBeDefined()
      expect(symlinkReason?.detail).toContain('src')

      // Fail-closed verdict: a degraded scan is never SAFE .
      expect(result.recommendation).toBe('DO_NOT_SHIP')
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('SYMLINK run: stderr is no longer empty — the console.warn from fs.ts names src', async () => {
    const realTreeHolder = mkTemp('shipguard-edge1-target-warn-')
    plantSrcTree(realTreeHolder)

    const project = mkTemp('shipguard-edge1-symlink-warn-')
    writeFileSync(join(project, 'package.json'), '{"name":"fixture"}', 'utf-8')
    symlinkSync(join(realTreeHolder, 'src'), join(project, 'src'))

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const originalCwd = process.cwd()
    process.chdir(project)
    try {
      await scan({
        changedOnly: false,
        generateReport: false,
        strict: false,
        json: false,
        reportPath: '.shipguard/reports/latest.md',
      })

      const symlinkWarnings = warnSpy.mock.calls
        .map((args) => String(args[0]))
        .filter((msg) => msg.toLowerCase().includes('symlink'))
      expect(symlinkWarnings.length).toBeGreaterThan(0)
      expect(symlinkWarnings.some((msg) => msg.includes('src'))).toBe(true)
    } finally {
      process.chdir(originalCwd)
    }
  })
})

describe('scan() — binary-file fixture: named but NOT wired into degraded (scope decision)', () => {
  it('a binary file is skipped, named internally, but does NOT flip degraded/recommendation', async () => {
    const project = mkTemp('shipguard-edge1-binary-')
    writeFileSync(join(project, 'asset.bin'), Buffer.from([0x00, 0x01, 0x02, 0xff]))
    writeFileSync(join(project, 'clean.ts'), 'const a = 1', 'utf-8')

    const originalCwd = process.cwd()
    process.chdir(project)
    try {
      const result = await scan({
        changedOnly: false,
        generateReport: false,
        strict: false,
        json: false,
        reportPath: '.shipguard/reports/latest.md',
      })

      // Named internally (loud) — see the scanner's _skippedBinaryFiles metadata,
      // asserted directly against readFiles() in
      // tests/utils/fs-symlink-skip-reporting.test.ts.
      //
      // NOT wired into degraded/degradedReasons: scanner.ts documents this as a
      // DELIBERATE, pre-existing product decision ("a binary file legitimately has
      // no source to scan"). Making BINARY_SKIPPED a degraded reason would flip
      // `recommendation` to DO_NOT_SHIP for almost any real repo that contains an
      // unlisted binary asset (fonts, sqlite DBs, compiled artifacts, etc. are not
      // all in DEFAULT_IGNORE) — a wide-blast-radius guard/product change that
      // is a product decision, not something this fix silently does.
      expect(result.degraded).toBeFalsy()
      expect(result.degradedReasons?.some((r) => r.code === 'SYMLINK_SKIPPED')).toBeFalsy()
      expect((result as Record<string, unknown>).degradedReasons ?? []).not.toEqual(
        expect.arrayContaining([expect.objectContaining({ code: 'BINARY_SKIPPED' })]),
      )
    } finally {
      process.chdir(originalCwd)
    }
  })
})
