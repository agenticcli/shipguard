import { describe, it, expect } from 'vitest'
import { runProRules } from '../../src/core/pro-scanner.js'
import type { QualityGateRule, FileInfo, Policy } from '@agenticcli/shared'

const BASE_FILES: FileInfo[] = [
  { path: '/project/src/index.ts', content: 'export const x = 1;', relativePath: 'src/index.ts' },
]

const BASE_POLICY: Policy = {
  version: 1,
  project: { name: 'test', framework: 'generic', risk_profile: 'standard' },
  scan: { changed_files_only: false, generate_report: false },
  block: [],
  warn: [],
  ignore: { paths: [] },
  report: { output: 'report.md', format: 'markdown' },
}

const PRO_RULE: QualityGateRule = {
  id: 'pro-test-rule',
  framework: 'generic',
  category: 'secrets',
  tier: 'pro',
  severity: 'high',
  matcher: {
    type: 'pattern',
    fileGlob: '**/*.ts',
    patterns: ['export const x'],
    antiPatterns: [],
  },
  explanation: 'Test pro rule match.',
  recommendation: 'Fix it.',
}

describe('runProRules integration', () => {
  it('produces findings when pro rules match', () => {
    const findings = runProRules([PRO_RULE], BASE_FILES, BASE_POLICY)
    const proFinding = findings.find(f => f.id === 'pro-test-rule')
    expect(proFinding).toBeDefined()
  })

  it('produces no findings when no pro rules provided', () => {
    const findings = runProRules([], BASE_FILES, BASE_POLICY)
    expect(findings).toHaveLength(0)
  })
})
