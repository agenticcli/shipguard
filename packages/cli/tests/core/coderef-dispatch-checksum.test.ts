/**
 * GC.12 — coderef checksum fail-closed tests (C.10 fix)
 *
 * Verifies that a tampered (checksum-mismatched) or manifest-absent coderef
 * module sets degraded=true and produces zero findings — NOT a silent skip.
 *
 * Cryptographic signing of the manifest is deferred (Codex E1 scope).
 * This covers integrity/fail-closed only.
 */
import { describe, it, expect, vi } from 'vitest'
import {
  runCoderefRules,
  type CodeRef,
  type ChecksumManifest,
} from '../../src/core/coderef-dispatch.js'
import type { QualityGateRule, FileInfo, Policy, CheckModule, Finding } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const POLICY: Policy = { maxHighFindings: 0 } as unknown as Policy
const FILES: FileInfo[] = []

function makeCoderefRule(
  id: string,
  codeRef: CodeRef,
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
    explanation: 'GC.12 test rule.',
    recommendation: 'Fix it.',
    ...overrides,
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WHY: Phase-1 fields not yet in shared types
  ;(base as any).implType = 'coderef'
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WHY: same as above
  ;(base as any).codeRef = codeRef
  return base
}

/** A stub CheckModule that returns one finding when run. */
const STUB_FINDING: Finding = {
  id: 'gc12-stub-finding',
  title: 'GC.12 stub finding',
  severity: 'high',
  category: 'secrets',
  file: 'stub.ts',
  explanation: 'Stub.',
  recommendation: 'Fix stub.',
  blocking: false,
}

const stubRun = vi.fn((_files: FileInfo[], _policy: Policy) => [STUB_FINDING])
const STUB_MODULE: CheckModule = { id: 'gc12-stub', name: 'GC12Stub', run: stubRun }
const STUB_TABLE = { 'gc12mod:gc12Check': STUB_MODULE }

// ---------------------------------------------------------------------------
// GC.12-A: checksum mismatch → degraded=true + no findings (fail closed)
// ---------------------------------------------------------------------------

describe('GC.12-A — checksum mismatch → fail closed (degraded=true, non-safe)', () => {
  it('sets degraded=true when module checksum does NOT match the manifest entry', () => {
    const rule = makeCoderefRule('gc12-mismatch', {
      moduleId: 'gc12mod',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'aaa111',  // rule claims this hash
    })
    const manifest: ChecksumManifest = { gc12mod: 'bbb222' }  // manifest says different hash

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE, manifest)

    // FAIL CLOSED: must be degraded, no findings
    expect(result.degraded).toBe(true)
    expect(result.findings).toHaveLength(0)
  })

  it('emits a CODEREF_CHECKSUM_MISMATCH warning on mismatch', () => {
    const rule = makeCoderefRule('gc12-mismatch-warn', {
      moduleId: 'gc12mod',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'aaa111',
    })
    const manifest: ChecksumManifest = { gc12mod: 'bbb222' }

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE, manifest)

    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]).toMatch(/CODEREF_CHECKSUM_MISMATCH/)
  })

  it('does NOT silently skip — the module run() is never called on mismatch', () => {
    const localRun = vi.fn((_files: FileInfo[], _policy: Policy) => [] as Finding[])
    const localTable = { 'gc12mod:gc12Check': { id: 'gc12mod', name: 'Gc12', run: localRun } }

    const rule = makeCoderefRule('gc12-no-run', {
      moduleId: 'gc12mod',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'tampered',
    })
    const manifest: ChecksumManifest = { gc12mod: 'correct-hash' }

    runCoderefRules([rule], FILES, POLICY, '1.0.0', localTable, manifest)

    // The module must never be invoked when checksum is wrong
    expect(localRun).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// GC.12-B: module ABSENT from manifest → degraded=true + no findings (fail closed)
// ---------------------------------------------------------------------------

describe('GC.12-B — module absent from manifest → fail closed (degraded=true, non-safe)', () => {
  it('sets degraded=true when moduleId is NOT present in the manifest at all', () => {
    const rule = makeCoderefRule('gc12-absent', {
      moduleId: 'gc12mod',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'some-hash',
    })
    // manifest is present but does NOT contain gc12mod
    const manifest: ChecksumManifest = { 'other-module': 'other-hash' }

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE, manifest)

    expect(result.degraded).toBe(true)
    expect(result.findings).toHaveLength(0)
  })

  it('emits a CODEREF_CHECKSUM_MISMATCH warning when module is absent from manifest', () => {
    const rule = makeCoderefRule('gc12-absent-warn', {
      moduleId: 'gc12mod',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'some-hash',
    })
    const manifest: ChecksumManifest = {}  // empty manifest

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE, manifest)

    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]).toMatch(/CODEREF_CHECKSUM_MISMATCH/)
    expect(result.warnings[0]).toMatch(/absent from the checksum manifest/)
  })

  it('does NOT run the module when absent from manifest', () => {
    const localRun = vi.fn((_files: FileInfo[], _policy: Policy) => [] as Finding[])
    const localTable = { 'gc12mod:gc12Check': { id: 'gc12mod', name: 'Gc12', run: localRun } }

    const rule = makeCoderefRule('gc12-absent-no-run', {
      moduleId: 'gc12mod',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'some-hash',
    })
    const manifest: ChecksumManifest = {}

    runCoderefRules([rule], FILES, POLICY, '1.0.0', localTable, manifest)

    expect(localRun).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// GC.12-C: matching checksum → NOT degraded, module runs normally
// ---------------------------------------------------------------------------

describe('GC.12-C — matching checksum → runs normally (not degraded)', () => {
  it('does NOT degrade when checksum matches manifest', () => {
    const rule = makeCoderefRule('gc12-match', {
      moduleId: 'gc12mod',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'correct-hash',
    })
    const manifest: ChecksumManifest = { gc12mod: 'correct-hash' }

    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE, manifest)

    expect(result.degraded).toBe(false)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].id).toBe('gc12-stub-finding')
    expect(result.warnings).toHaveLength(0)
  })

  it('runs the module when checksum matches', () => {
    const localRun = vi.fn((_files: FileInfo[], _policy: Policy) => [] as Finding[])
    const localTable = { 'gc12mod:gc12Check': { id: 'gc12mod', name: 'Gc12', run: localRun } }

    const rule = makeCoderefRule('gc12-match-run', {
      moduleId: 'gc12mod',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'correct-hash',
    })
    const manifest: ChecksumManifest = { gc12mod: 'correct-hash' }

    runCoderefRules([rule], FILES, POLICY, '1.0.0', localTable, manifest)

    expect(localRun).toHaveBeenCalledOnce()
    expect(localRun).toHaveBeenCalledWith(FILES, POLICY)
  })
})

// ---------------------------------------------------------------------------
// GC.12-D: no manifest → checksum check skipped gracefully (pre-build artifact)
// ---------------------------------------------------------------------------

describe('GC.12-D — no manifest → checksum check gracefully skipped', () => {
  it('does not degrade when no manifest is provided', () => {
    const rule = makeCoderefRule('gc12-no-manifest', {
      moduleId: 'gc12mod',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'any-hash',
    })

    // No manifest arg → checksum check is skipped
    const result = runCoderefRules([rule], FILES, POLICY, '1.0.0', STUB_TABLE)

    expect(result.degraded).toBe(false)
    expect(result.findings).toHaveLength(1)
    expect(result.warnings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// GC.12-E: multiple rules, partial mismatch → only mismatched rule degraded
// ---------------------------------------------------------------------------

describe('GC.12-E — partial mismatch in a multi-rule set', () => {
  it('degrades when ONE of two rules has a checksum mismatch; the other rule still runs', () => {
    const goodRule = makeCoderefRule('gc12-good', {
      moduleId: 'gc12mod',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'correct-hash',
    })
    const badRule = makeCoderefRule('gc12-bad', {
      moduleId: 'bad-module',
      exportName: 'gc12Check',
      minCliVersion: '0.1.0',
      checksum: 'wrong',
    })
    const localRun = vi.fn((_files: FileInfo[], _policy: Policy) => [STUB_FINDING] as Finding[])
    const localTable = {
      'gc12mod:gc12Check': { id: 'gc12mod', name: 'Good', run: localRun },
      'bad-module:gc12Check': { id: 'bad-module', name: 'Bad', run: vi.fn() },
    }
    const manifest: ChecksumManifest = {
      'gc12mod': 'correct-hash',
      'bad-module': 'expected-hash',  // mismatch with 'wrong'
    }

    const result = runCoderefRules([goodRule, badRule], FILES, POLICY, '1.0.0', localTable, manifest)

    // Overall degraded because one rule failed
    expect(result.degraded).toBe(true)
    // The good rule still produced a finding
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].id).toBe('gc12-stub-finding')
    // One warning for the mismatch
    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]).toMatch(/CODEREF_CHECKSUM_MISMATCH/)
  })
})
