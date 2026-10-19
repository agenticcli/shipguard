/**
 * Shared suppression helper unit tests.
 *
 * The suppression logic (parse `// shipguard-ignore: <ruleId> -- <reason>`,
 * honor same-line and line-above) was factored out of pro-scanner.ts into a
 * shared module so both the free CheckModules and the pro engine apply identical
 * semantics. These tests pin that shared contract directly.
 */
import { describe, it, expect } from 'vitest'
import type { Finding, FileInfo } from '@agenticcli/shared'
import { isLineSuppressed, applySuppressions } from '../../src/core/suppression.js'

function mkFinding(over: Partial<Finding> = {}): Finding {
  return {
    id: 'hardcoded_secret',
    title: 'AWS key',
    severity: 'high',
    category: 'secrets',
    file: 'config.js',
    line: 2,
    explanation: 'x',
    recommendation: 'y',
    blocking: true,
    ...over,
  }
}

describe('isLineSuppressed', () => {
  it('matches a same-line suppression for the right rule id', () => {
    const lines = ["const k = 'AKIA...' // shipguard-ignore: hardcoded_secret -- qa"]
    expect(isLineSuppressed(lines, 0, 'hardcoded_secret')).toBe(true)
  })

  it('matches a line-above suppression', () => {
    const lines = ['// shipguard-ignore: hardcoded_secret -- qa', "const k = 'AKIA...'"]
    expect(isLineSuppressed(lines, 1, 'hardcoded_secret')).toBe(true)
  })

  it('does NOT match a different rule id', () => {
    const lines = ["const k = 'AKIA...' // shipguard-ignore: other_rule -- qa"]
    expect(isLineSuppressed(lines, 0, 'hardcoded_secret')).toBe(false)
  })

  it('requires a reason after `--` (malformed comment does not suppress)', () => {
    const lines = ["const k = 'AKIA...' // shipguard-ignore: hardcoded_secret"]
    expect(isLineSuppressed(lines, 0, 'hardcoded_secret')).toBe(false)
  })
})

describe('applySuppressions', () => {
  const files: FileInfo[] = [
    {
      path: '/abs/config.js',
      relativePath: 'config.js',
      content:
        '// shipguard-ignore: hardcoded_secret -- reviewed\n' +
        "const k = 'AKIAIOSFODNN7EXAMPLE'\n",
    },
  ]

  it('marks a matching finding suppressed and non-blocking, but KEEPS it (recorded)', () => {
    const findings = [mkFinding({ line: 2 })]
    const out = applySuppressions(findings, files)
    // Still present — suppressed findings are counted/recorded, not dropped.
    expect(out).toHaveLength(1)
    expect(out[0].suppressed).toBe(true)
    expect(out[0].blocking).toBe(false)
  })

  it('leaves a non-suppressed finding untouched (still blocking)', () => {
    const otherFiles: FileInfo[] = [
      { path: '/abs/x.js', relativePath: 'x.js', content: "const k = 'AKIA...'\n" },
    ]
    const findings = [mkFinding({ file: 'x.js', line: 1, blocking: true })]
    const out = applySuppressions(findings, otherFiles)
    expect(out[0].suppressed).toBeFalsy()
    expect(out[0].blocking).toBe(true)
  })

  it('does not throw when a finding has no line (file-level finding)', () => {
    const findings = [mkFinding({ line: undefined })]
    expect(() => applySuppressions(findings, files)).not.toThrow()
  })

  it('does not throw when the finding references an unknown file', () => {
    const findings = [mkFinding({ file: 'missing.js', line: 1 })]
    expect(() => applySuppressions(findings, files)).not.toThrow()
  })
})
