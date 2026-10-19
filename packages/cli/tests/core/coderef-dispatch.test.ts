/**
 * Unit tests for coderef rule dispatch (Suricata model).
 *
 * All dispatch functions accept injectable cliVersion + table + manifest
 * so no filesystem access is needed — fast, deterministic, zero mocking.
 */
import { describe, it, expect, vi } from 'vitest'
import {
  semverLt,
  runCoderefRules,
  DEFAULT_DISPATCH_TABLE,
  type CodeRef,
  type ChecksumManifest,
} from '../../src/core/coderef-dispatch.js'
import { runProRulesWithDispatch } from '../../src/core/pro-scanner.js'
import type { QualityGateRule, FileInfo, Policy, CheckModule, Finding } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const POLICY: Policy = { maxHighFindings: 0 } as unknown as Policy

const FILES: FileInfo[] = []

/** Build a minimal QualityGateRule with optional coderef extensions. */
function makeRule(
  id: string,
  implType?: 'declarative' | 'coderef',
  codeRef?: CodeRef,
  overrides: Partial<QualityGateRule> = {},
): QualityGateRule {
  const base: QualityGateRule = {
    id,
    framework: ['generic'],
    category: 'secrets',
    tier: 'pro',
    severity: 'high',
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['console\\.log'],
      antiPatterns: [],
    },
    explanation: 'Test rule.',
    recommendation: 'Fix it.',
    ...overrides,
  }
  // Attach coderef extension fields (CLI-local augmentation)
  if (implType !== undefined) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WHY: adding Phase-1 fields not yet in shared types
    ;(base as any).implType = implType
  }
  if (codeRef !== undefined) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WHY: same as above
    ;(base as any).codeRef = codeRef
  }
  return base
}

/** A stub CheckModule that always returns a single finding. */
const stubFinding: Finding = {
  id: 'stub-finding',
  title: 'Stub finding',
  severity: 'high',
  category: 'secrets',
  file: 'stub.ts',
  explanation: 'Stub.',
  recommendation: 'Fix stub.',
  blocking: false,
}

const stubModule: CheckModule = {
  id: 'stub',
  name: 'Stub',
  run: vi.fn((_files, _policy) => [stubFinding]),
}

const STUB_TABLE = { 'stub:stubCheck': stubModule }

// ---------------------------------------------------------------------------
// semverLt
// ---------------------------------------------------------------------------

describe('semverLt', () => {
  it('returns false when versions are equal', () => {
    expect(semverLt('1.0.0', '1.0.0')).toBe(false)
  })
  it('returns true when a < b (major)', () => {
    expect(semverLt('0.9.0', '1.0.0')).toBe(true)
  })
  it('returns false when a > b (major)', () => {
    expect(semverLt('2.0.0', '1.0.0')).toBe(false)
  })
  it('returns true when a < b (minor)', () => {
    expect(semverLt('1.0.0', '1.1.0')).toBe(true)
  })
  it('returns true when a < b (patch)', () => {
    expect(semverLt('1.0.0', '1.0.1')).toBe(true)
  })
  it('returns false when a > b (patch)', () => {
    expect(semverLt('1.0.1', '1.0.0')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// runCoderefRules — version-too-old → skip + degraded
// ---------------------------------------------------------------------------

describe('runCoderefRules — version skip', () => {
  it('skips a coderef rule when installed CLI version < minCliVersion and sets degraded=true', () => {
    const rule = makeRule('rule-needs-newer', 'coderef', {
      moduleId: 'stub',
      exportName: 'stubCheck',
      minCliVersion: '2.0.0',  // newer than installed
    })

    const result = runCoderefRules(
      [rule],
      FILES,
      POLICY,
      '0.1.0',  // installed — older than required
      STUB_TABLE,
    )

    expect(result.findings).toHaveLength(0)
    expect(result.degraded).toBe(true)
    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]).toMatch(/minCliVersion|requires CLI/)
  })

  it('does NOT skip when installed version === minCliVersion (equal → runs)', () => {
    const rule = makeRule('rule-exact', 'coderef', {
      moduleId: 'stub',
      exportName: 'stubCheck',
      minCliVersion: '1.0.0',
    })

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE)

    expect(result.degraded).toBe(false)
    expect(result.findings).toHaveLength(1)
  })

  it('does NOT skip when installed version > minCliVersion', () => {
    const rule = makeRule('rule-ok', 'coderef', {
      moduleId: 'stub',
      exportName: 'stubCheck',
      minCliVersion: '0.1.0',
    })

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE)

    expect(result.degraded).toBe(false)
    expect(result.findings).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// runCoderefRules — unknown moduleId/exportName → skip + warn, not crash
// ---------------------------------------------------------------------------

describe('runCoderefRules — unknown dispatch key', () => {
  it('skips and warns (not crash) when moduleId:exportName is not in table', () => {
    const rule = makeRule('rule-unknown', 'coderef', {
      moduleId: 'nonexistent',
      exportName: 'ghostCheck',
      minCliVersion: '0.1.0',
    })

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE)

    expect(result.findings).toHaveLength(0)
    // FIXED: unknown module → degraded=true (same as version-skip, coverage incomplete)
    expect(result.degraded).toBe(true)
    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]).toMatch(/Unknown coderef/)
  })

  it('skips and warns when codeRef pointer is missing on implType:coderef rule', () => {
    const rule = makeRule('rule-no-coderef', 'coderef', undefined)

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE)

    expect(result.findings).toHaveLength(0)
    expect(result.degraded).toBe(false)
    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]).toMatch(/no codeRef pointer/)
  })
})

// ---------------------------------------------------------------------------
// runCoderefRules — successful dispatch to stub function
// ---------------------------------------------------------------------------

describe('runCoderefRules — successful dispatch', () => {
  it('dispatches to a stub CheckModule and returns its findings', () => {
    const rule = makeRule('rule-stub', 'coderef', {
      moduleId: 'stub',
      exportName: 'stubCheck',
      minCliVersion: '0.1.0',
    })

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE)

    expect(result.degraded).toBe(false)
    expect(result.warnings).toHaveLength(0)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].id).toBe('stub-finding')
  })

  it('calls the stub module run() with files and policy', () => {
    const run = vi.fn((_files: FileInfo[], _policy: Policy) => [] as Finding[])
    const localStubModule: CheckModule = { id: 'tbl', name: 'Tbl', run }
    const localTable = { 'tbl:tblCheck': localStubModule }

    const rule = makeRule('rule-call-verify', 'coderef', {
      moduleId: 'tbl',
      exportName: 'tblCheck',
      minCliVersion: '0.1.0',
    })

    runCoderefRules([rule], FILES, POLICY, '1.0.0', localTable)

    expect(run).toHaveBeenCalledOnce()
    expect(run).toHaveBeenCalledWith(FILES, POLICY)
  })
})

// ---------------------------------------------------------------------------
// runCoderefRules — checksum guard
// ---------------------------------------------------------------------------

describe('runCoderefRules — checksum guard', () => {
  it('sets degraded=true + zero findings on checksum mismatch when manifest is provided (fail closed, not silent skip)', () => {
    const rule = makeRule('rule-checksum-mismatch', 'coderef', {
      moduleId: 'stub',
      exportName: 'stubCheck',
      minCliVersion: '0.1.0',
      checksum: 'aaa',
    })
    const manifest: ChecksumManifest = { stub: 'bbb' }  // mismatch

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE, manifest)

    expect(result.findings).toHaveLength(0)
    // mismatch must set degraded=true (was a silent continue before)
    expect(result.degraded).toBe(true)
    expect(result.warnings[0]).toMatch(/CODEREF_CHECKSUM_MISMATCH/)
  })

  it('runs normally when checksum matches manifest', () => {
    const rule = makeRule('rule-checksum-ok', 'coderef', {
      moduleId: 'stub',
      exportName: 'stubCheck',
      minCliVersion: '0.1.0',
      checksum: 'correct-hash',
    })
    const manifest: ChecksumManifest = { stub: 'correct-hash' }

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE, manifest)

    expect(result.findings).toHaveLength(1)
    expect(result.warnings).toHaveLength(0)
  })

  it('runs normally when no manifest is provided (skip checksum check gracefully)', () => {
    const rule = makeRule('rule-no-manifest', 'coderef', {
      moduleId: 'stub',
      exportName: 'stubCheck',
      minCliVersion: '0.1.0',
      checksum: 'some-hash',
    })

    // No manifest arg → checksum check skipped
    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE)

    expect(result.findings).toHaveLength(1)
    expect(result.warnings).toHaveLength(0)
    expect(result.degraded).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// runCoderefRules — rules with no implType or implType:"declarative" are not dispatched
// ---------------------------------------------------------------------------

describe('runCoderefRules — declarative rules are not dispatched', () => {
  it('does not invoke stub module for rules without implType', () => {
    const rule = makeRule('rule-no-impltype')  // no implType
    const run = vi.fn(() => [] as Finding[])
    const localTable = { 'stub:stubCheck': { id: 'stub', name: 'Stub', run } }

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', localTable)

    expect(run).not.toHaveBeenCalled()
    expect(result.findings).toHaveLength(0)
    expect(result.degraded).toBe(false)
  })

  it('does not dispatch rules with implType:"declarative"', () => {
    const rule = makeRule('rule-declarative', 'declarative')
    const run = vi.fn(() => [] as Finding[])
    const localTable = { 'stub:stubCheck': { id: 'stub', name: 'Stub', run } }

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', localTable)

    expect(run).not.toHaveBeenCalled()
    expect(result.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// runProRulesWithDispatch — declarative path untouched
// ---------------------------------------------------------------------------

describe('runProRulesWithDispatch — declarative path', () => {
  it('returns declarative findings for declarative rules', () => {
    const rule = makeRule('declarative-rule', 'declarative', undefined, {
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['console\\.log'],
        antiPatterns: [],
      },
    })
    const files: FileInfo[] = [
      { path: '/proj/app.ts', content: 'console.log("hi")', relativePath: 'app.ts' },
    ]

    const result = runProRulesWithDispatch([rule], files, POLICY, '1.0.0', {})

    expect(result.findings).toHaveLength(1)
    expect(result.degraded).toBe(false)
  })

  it('returns empty findings for declarative rules with no match', () => {
    const rule = makeRule('declarative-no-match', 'declarative', undefined, {
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['console\\.log'],
        antiPatterns: [],
      },
    })
    const files: FileInfo[] = [
      { path: '/proj/app.ts', content: 'const x = 1', relativePath: 'app.ts' },
    ]

    const result = runProRulesWithDispatch([rule], files, POLICY, '1.0.0', {})

    expect(result.findings).toHaveLength(0)
    expect(result.degraded).toBe(false)
  })

  it('returns no findings when no rules given', () => {
    const result = runProRulesWithDispatch([], FILES, POLICY, '1.0.0', {})
    expect(result.findings).toHaveLength(0)
    expect(result.degraded).toBe(false)
    expect(result.warnings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// runProRulesWithDispatch — coderef + declarative mixed
// ---------------------------------------------------------------------------

describe('runProRulesWithDispatch — mixed rules', () => {
  it('merges declarative and coderef findings correctly', () => {
    const declRule = makeRule('decl-rule', 'declarative', undefined, {
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['console\\.log'],
        antiPatterns: [],
      },
    })
    const coderefRule = makeRule('coderef-rule', 'coderef', {
      moduleId: 'stub',
      exportName: 'stubCheck',
      minCliVersion: '0.1.0',
    })

    const files: FileInfo[] = [
      { path: '/proj/app.ts', content: 'console.log("hi")', relativePath: 'app.ts' },
    ]

    const result = runProRulesWithDispatch(
      [declRule, coderefRule],
      files,
      POLICY,
      '1.0.0',
      STUB_TABLE,
    )

    // 1 from declarative + 1 from coderef stub
    expect(result.findings).toHaveLength(2)
    expect(result.degraded).toBe(false)
  })

  it('degrades when coderef rule version is too high, declarative findings still returned', () => {
    const declRule = makeRule('decl-rule-2', 'declarative', undefined, {
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['console\\.log'],
        antiPatterns: [],
      },
    })
    const coderefRule = makeRule('coderef-needs-newer-2', 'coderef', {
      moduleId: 'stub',
      exportName: 'stubCheck',
      minCliVersion: '99.0.0',  // will be skipped
    })

    const files: FileInfo[] = [
      { path: '/proj/app.ts', content: 'console.log("hi")', relativePath: 'app.ts' },
    ]

    const result = runProRulesWithDispatch(
      [declRule, coderefRule],
      files,
      POLICY,
      '0.1.0',
      STUB_TABLE,
    )

    expect(result.findings).toHaveLength(1)  // only declarative finding
    expect(result.degraded).toBe(true)
    expect(result.warnings[0]).toMatch(/requires CLI|minCliVersion/)
  })
})

// ---------------------------------------------------------------------------
// DEFAULT_DISPATCH_TABLE — sanity check the built-in entries
// ---------------------------------------------------------------------------

describe('DEFAULT_DISPATCH_TABLE', () => {
  it('contains all 5 bundled check modules', () => {
    const keys = Object.keys(DEFAULT_DISPATCH_TABLE)
    expect(keys).toContain('secrets:secretsCheck')
    expect(keys).toContain('auth:authCheck')
    expect(keys).toContain('database:databaseCheck')
    expect(keys).toContain('deployment:deploymentCheck')
    expect(keys).toContain('payments:payments')
  })

  it('each entry has a run function', () => {
    for (const [key, mod] of Object.entries(DEFAULT_DISPATCH_TABLE)) {
      expect(typeof mod.run, `${key}.run should be a function`).toBe('function')
    }
  })
})
