import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { secretsCheck } from '../../src/checks/secrets.js'

// ---------------------------------------------------------------------------
// Mocks — must be hoisted before any import of scanner
// ---------------------------------------------------------------------------

vi.mock('../../src/core/git.js', () => ({
  isGitRepo: vi.fn(() => false),
  getChangedFiles: vi.fn(() => []),
}))

// Dynamic import after mocks are set up
const { scan } = await import('../../src/core/scanner.js')
const gitModule = await import('../../src/core/git.js')

const mockIsGitRepo = vi.mocked(gitModule.isGitRepo)
const mockGetChangedFiles = vi.mocked(gitModule.getChangedFiles)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = []

function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-scanner-test-'))
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  vi.restoreAllMocks()
  mockIsGitRepo.mockReturnValue(false)
  mockGetChangedFiles.mockReturnValue([])

  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // ignore
    }
  }
})

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('scan()', () => {
  it('returns a valid ScanResult shape', async () => {
    const dir = mkTemp()
    // Write a clean file so scanner has something to read
    writeFileSync(join(dir, 'index.ts'), 'export const hello = "world"\n', 'utf-8')

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })

      expect(result).toHaveProperty('findings')
      expect(result).toHaveProperty('riskScore')
      expect(result).toHaveProperty('filesScanned')
      expect(result).toHaveProperty('timestamp')
      expect(result).toHaveProperty('policyUsed')
      expect(Array.isArray(result.findings)).toBe(true)
      expect(typeof result.filesScanned).toBe('number')
      expect(typeof result.riskScore.score).toBe('number')
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('runs all 5 check modules (secrets detected in known-bad file)', async () => {
    const dir = mkTemp()
    // Plant a file with a hardcoded secret that secretsCheck will catch
    writeFileSync(
      join(dir, 'bad.ts'),
      `const key = 'sk_live_abcdefghijklmnopqrstuvwx'\n`,
      'utf-8',
    )

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      const secretsFindings = result.findings.filter((f) => f.category === 'secrets')
      expect(secretsFindings.length).toBeGreaterThan(0)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('changedOnly filters to changed files when git repo', async () => {
    const dir = mkTemp()
    // Two files — only one returned by getChangedFiles
    writeFileSync(join(dir, 'changed.ts'), 'const x = 1\n', 'utf-8')
    writeFileSync(join(dir, 'unchanged.ts'), 'const y = 2\n', 'utf-8')

    mockIsGitRepo.mockReturnValue(true)
    mockGetChangedFiles.mockReturnValue(['changed.ts'])

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: true, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      // Only 1 file should be scanned
      expect(result.filesScanned).toBe(1)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('changedOnly falls back to full scan when not a git repo', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'file-a.ts'), 'const a = 1\n', 'utf-8')
    writeFileSync(join(dir, 'file-b.ts'), 'const b = 2\n', 'utf-8')

    mockIsGitRepo.mockReturnValue(false)

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: true, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      // Full scan → both files present
      expect(result.filesScanned).toBeGreaterThanOrEqual(2)
    } finally {
      process.chdir(originalCwd)
    }
  })

  // -------------------------------------------------------------------------
  // Regression: a git FAILURE during
  // --changed collection must propagate loudly (scan() throws → scan.ts's
  // existing catch maps it to exit 3, RUNTIME_ERROR), never be silently
  // treated as "0 changed files, SAFE." This is the scanner-level half of the
  // fix — git.test.ts covers getChangedFiles() itself throwing GitCommandError.
  // -------------------------------------------------------------------------
  it('FAIL-BEFORE regression: getChangedFiles() throwing (genuine git failure) ' +
     'propagates out of scan() — is NOT swallowed into an empty/safe result', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'file-a.ts'), 'const a = 1\n', 'utf-8')

    mockIsGitRepo.mockReturnValue(true)
    mockGetChangedFiles.mockImplementation(() => {
      throw new Error('git command failed: git diff --name-only HEAD — fatal: index file corrupt')
    })

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      await expect(
        scan({ changedOnly: true, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      ).rejects.toThrow(/index file corrupt/)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('changedOnly + git succeeds with genuinely zero changed files → filesScanned=0, ' +
     'NOT an error (distinguishable from the git-failure case above)', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'file-a.ts'), 'const a = 1\n', 'utf-8')

    mockIsGitRepo.mockReturnValue(true)
    mockGetChangedFiles.mockReturnValue([])  // git ran fine, nothing changed

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: true, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(result.filesScanned).toBe(0)
      expect(result.degraded).toBeFalsy()  // genuinely clean, not degraded
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('riskScore is computed from findings', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'clean.ts'), 'export const value = 42\n', 'utf-8')

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(result.riskScore.score).toBeGreaterThanOrEqual(0)
      expect(result.riskScore.score).toBeLessThanOrEqual(100)
      expect(['SAFE_TO_SHIP', 'REVIEW_BEFORE_SHIP', 'DO_NOT_SHIP']).toContain(result.riskScore.recommendation)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('timestamp is an ISO string', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'a.ts'), 'const x = 1\n', 'utf-8')

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan({ changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' })
      expect(() => new Date(result.timestamp)).not.toThrow()
      expect(new Date(result.timestamp).toISOString()).toBe(result.timestamp)
    } finally {
      process.chdir(originalCwd)
    }
  })
})

// ---------------------------------------------------------------------------
// ScanId idempotency — e2e shipguard-ignore suppression through scan + pro rules
// ---------------------------------------------------------------------------

describe('scan() — e2e shipguard-ignore suppression (scanId idempotency)', () => {
  it('suppressed pro finding: suppressed=true, blocking=false, finding still present in output', async () => {
    // Verify suppression works end-to-end through the full scanner stack:
    //   scan() → runProRulesWithDispatch() → runProRules() → isLineSuppressed()
    // The suppression comment honors format: // shipguard-ignore: <rule-id> -- <reason>
    const dir = mkTemp()
    writeFileSync(
      join(dir, 'service.ts'),
      [
        '// shipguard-ignore: test-suppress-rule -- intentional in this context',
        'const dangerousCall = process.env.DANGER_MODE',
      ].join('\n'),
      'utf-8',
    )

    const proRule = {
      id: 'test-suppress-rule',
      framework: ['generic'],
      category: 'secrets' as const,
      tier: 'pro' as const,
      severity: 'high' as const,
      matcher: {
        type: 'pattern' as const,
        fileGlob: '**/*.ts',
        patterns: ['DANGER_MODE'],
        antiPatterns: [],
      },
      explanation: 'Dangerous mode flag detected.',
      recommendation: 'Remove DANGER_MODE usage.',
    }

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan(
        { changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' },
        [proRule],
      )

      // The finding MUST be present in output (suppression does not silently drop it)
      const suppressed = result.findings.filter(f => f.id === 'test-suppress-rule')
      expect(suppressed.length).toBe(1)

      // The finding MUST have suppressed=true
      expect(suppressed[0].suppressed).toBe(true)

      // The finding MUST NOT be blocking (suppressed findings can't block the gate)
      expect(suppressed[0].blocking).toBe(false)

      // blockingCount in riskScore must not include the suppressed finding
      expect(result.riskScore.blockingCount).toBe(0)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('unsuppressed pro finding: blocking=true, blockingCount=1', async () => {
    // Counterpart: without suppression comment, the same finding IS blocking.
    const dir = mkTemp()
    writeFileSync(
      join(dir, 'service.ts'),
      'const dangerousCall = process.env.DANGER_MODE\n',
      'utf-8',
    )

    const proRule = {
      id: 'test-suppress-rule',
      framework: ['generic'],
      category: 'secrets' as const,
      tier: 'pro' as const,
      severity: 'high' as const,
      matcher: {
        type: 'pattern' as const,
        fileGlob: '**/*.ts',
        patterns: ['DANGER_MODE'],
        antiPatterns: [],
      },
      explanation: 'Dangerous mode flag detected.',
      recommendation: 'Remove DANGER_MODE usage.',
    }

    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const result = await scan(
        { changedOnly: false, generateReport: false, strict: false, json: false, reportPath: '.shipguard/reports/latest.md' },
        [proRule],
      )

      const found = result.findings.filter(f => f.id === 'test-suppress-rule')
      expect(found.length).toBe(1)
      expect(found[0].suppressed).toBeFalsy()
      // deriveBlocking: severity='high' → blocking=true
      expect(found[0].blocking).toBe(true)
      expect(result.riskScore.blockingCount).toBe(1)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('suppression does NOT work for free-tier check modules (documented architecture gap)', () => {
    // Free-tier checks (secretsCheck etc.) have no isLineSuppressed() logic.
    // Suppression is a pro-tier/scanner feature per architecture docs.
    // This test documents the gap and will fail if suppression is accidentally added
    // to free-tier modules without updating this test.
    const content = [
      '// shipguard-ignore: hardcoded_secret -- intentional',
      `const key = 'sk-proj-SuppressMe0000000000000000000000000000000000'`,
    ].join('\n')
    const f = { path: '/test/lib/ai.ts', relativePath: 'lib/ai.ts', content }
    const policy = {
      version: 1,
      project: { name: 'test', framework: 'auto', risk_profile: 'standard' },
      scan: { changed_files_only: false, generate_report: false },
      block: ['hardcoded_secret'],
      warn: [],
      ignore: { paths: [] },
      report: { output: 'report.md', format: 'markdown' },
    }
    const findings = secretsCheck.run([f], policy)
    // Suppression comment is NOT honored — finding still emitted (free-tier gap)
    expect(findings.filter(x => x.id === 'hardcoded_secret').length).toBeGreaterThan(0)
  })
})
