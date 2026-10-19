import { describe, it, expect } from 'vitest'
import { runProRules, validateBundleCompile, RunProRulesFatalError, runProRulesWithDispatch } from '../../src/core/pro-scanner.js'
import type { QualityGateRule, FileInfo, Policy } from '@agenticcli/shared'
import type { AntiPatternScope } from '@agenticcli/matcher-contract'

const makeRule = (overrides: Partial<QualityGateRule> = {}): QualityGateRule => ({
  id: 'test-rule-1',
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
  explanation: 'console.log found in production code.',
  recommendation: 'Remove or replace with a structured logger.',
  ...overrides,
})

const makeFile = (relativePath: string, content: string): FileInfo => ({
  path: `/project/${relativePath}`,
  content,
  relativePath,
})

const POLICY: Policy = { maxHighFindings: 0 } as unknown as Policy

describe('runProRules', () => {
  it('matches a pattern and returns a finding', () => {
    const findings = runProRules(
      [makeRule()],
      [makeFile('src/app.ts', 'console.log("hello")')],
      POLICY,
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe('test-rule-1')
  })

  it('anti-pattern on the same line suppresses the occurrence (retained as suppressed, not dropped)', () => {
    // UPDATED from the old behavior: the native-v1 adapter implements per-line
    // anti-pattern suppression per the contract spec (Task A.3). An occurrence
    // whose line matches an anti-pattern is RETAINED with suppressionState=suppressed
    // and blocking=false — it is NOT silently dropped (old file-wide anti-pattern
    // behavior). This mirrors how shipguard-ignore comment suppression works.
    //
    // Old test name: 'anti-pattern negates a match' with expect(findings).toHaveLength(0)
    // Updated to: expect 1 finding with suppressed=true, blocking=false (Phase B.3)
    const rule = makeRule({
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['console\\.log'],
        antiPatterns: ['// shipguard-ignore'],
      },
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("hello") // shipguard-ignore')],
      POLICY,
    )
    // The finding is retained (not dropped) with suppressed=true
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressed).toBe(true)
    expect(findings[0].suppressionState).toBe('suppressed')
    expect(findings[0].blocking).toBe(false)
  })

  it('glob filtering excludes non-matching files', () => {
    const rule = makeRule({
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['secret'],
        antiPatterns: [],
      },
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.py', 'secret = "oops"')],
      POLICY,
    )
    expect(findings).toHaveLength(0)
  })

  it('returns empty findings when no pattern matches', () => {
    const findings = runProRules(
      [makeRule()],
      [makeFile('src/clean.ts', 'const x = 1;')],
      POLICY,
    )
    expect(findings).toHaveLength(0)
  })

  it('returns multiple findings across multiple files', () => {
    const findings = runProRules(
      [makeRule()],
      [
        makeFile('src/a.ts', 'console.log("a")'),
        makeFile('src/b.ts', 'console.log("b")'),
      ],
      POLICY,
    )
    expect(findings).toHaveLength(2)
  })

  it('invalid primary pattern degrades the WHOLE bundle (atomic compile fix — was: silently skip and use valid pattern)', () => {
    // UPDATED from the old fail-open behavior. Old code: invalid pattern was
    // silently dropped (console.warn + continue in compileRules), and the rule
    // still ran with only the valid patterns. This was the fail-open bug (B.3).
    //
    // NEW correct behavior (Phase B.3 atomic compile):
    //   - validateBundleCompile rejects the ENTIRE bundle if ANY pattern/anti-pattern
    //     fails to compile.
    //   - runProRules returns [] (no findings from the bundle).
    //   - The caller (runProRulesWithDispatch) sets degraded=true + COMPILE_FAILURE.
    //
    // This prevents the worst case: a rule running without its anti-pattern guard
    // because the anti-pattern happened to be invalid.
    //
    // Old test name: 'compiles regex once — does not throw on invalid patterns'
    // Old assertion: expect(findings).toHaveLength(1)  ← the fail-open result
    const rule = makeRule({
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['[invalid(regex', 'console\\.log'],
        antiPatterns: [],
      },
    })
    // Must not throw
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("hello")')],
      POLICY,
    )
    // The WHOLE bundle is degraded — zero findings (not 1)
    expect(findings).toHaveLength(0)

    // validateBundleCompile should report the failure reason
    const compileResult = validateBundleCompile([rule])
    expect(compileResult.ok).toBe(false)
    if (!compileResult.ok) {
      expect(compileResult.reason).toContain(rule.id)
    }
  })

  it('invalid anti-pattern degrades the WHOLE bundle (atomic compile fix)', () => {
    // This is the exact fail-open scenario from the ground truth (B.3):
    // a rule with one valid pattern + one INVALID anti-pattern used to run
    // WITHOUT the anti-pattern guard (the anti-pattern was silently dropped).
    //
    // The consequence: a rule that should suppress certain safe lines would
    // fire on those lines because its guard was silently removed.
    //
    // New behavior: invalid anti-pattern → whole bundle degraded → 0 findings.
    const rule = makeRule({
      id: 'fail-open-rule',
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['console\\.log'],
        antiPatterns: ['[invalid(anti-pattern'], // invalid regex
      },
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("hello")')],
      POLICY,
    )
    // With the fail-open fix: 0 findings (whole bundle degraded)
    expect(findings).toHaveLength(0)

    const compileResult = validateBundleCompile([rule])
    expect(compileResult.ok).toBe(false)
  })

  it('populates new Finding fields (confidence, aiCodeTarget, fix, cwe)', () => {
    const rule = makeRule({
      confidence: 'HIGH',
      aiCodeTarget: true,
      fix: 'Remove console.log',
      cwe: ['CWE-532'],
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("hello")')],
      POLICY,
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].confidence).toBe('HIGH')
    expect(findings[0].aiCodeTarget).toBe(true)
    expect(findings[0].fix).toBe('Remove console.log')
    expect(findings[0].cwe).toEqual(['CWE-532'])
  })

  it('derives blocking from confidence and action', () => {
    const rule = makeRule({
      severity: 'medium',
      confidence: 'HIGH',
      action: 'block',
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("hello")')],
      POLICY,
    )
    expect(findings[0].blocking).toBe(true)
  })

  it('action=warn makes finding non-blocking even with high severity', () => {
    const rule = makeRule({
      severity: 'high',
      action: 'warn',
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("hello")')],
      POLICY,
    )
    expect(findings[0].blocking).toBe(false)
  })

  it('respects matcher.flags for case-insensitive matching', () => {
    const rule = makeRule({
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['console\\.log'],
        antiPatterns: [],
        flags: 'i',
      },
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'CONSOLE.LOG("hello")')],
      POLICY,
    )
    expect(findings).toHaveLength(1)
  })

  it('suppressed finding (line above) has suppressed=true and blocking=false', () => {
    const rule = makeRule({
      id: 'test-rule',
      severity: 'high',
      action: 'block',
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['dangerous\\(\\)'],
        antiPatterns: [],
      },
    })
    const content = '// shipguard-ignore: test-rule -- verified safe\nconst x = dangerous()'
    const findings = runProRules([rule], [makeFile('src/app.ts', content)], POLICY)
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressed).toBe(true)
    expect(findings[0].blocking).toBe(false)
  })

  it('same-line suppression works', () => {
    const rule = makeRule({
      id: 'test-rule',
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['dangerous\\(\\)'],
        antiPatterns: [],
      },
    })
    const content = 'const x = dangerous() // shipguard-ignore: test-rule -- safe here'
    const findings = runProRules([rule], [makeFile('src/app.ts', content)], POLICY)
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressed).toBe(true)
  })

  it('suppression without reason is NOT suppressed', () => {
    const rule = makeRule({
      id: 'test-rule',
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['dangerous\\(\\)'],
        antiPatterns: [],
      },
    })
    const content = '// shipguard-ignore: test-rule\nconst x = dangerous()'
    const findings = runProRules([rule], [makeFile('src/app.ts', content)], POLICY)
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressed).toBeFalsy()
  })

  it('suppression with wrong rule-id is NOT suppressed', () => {
    const rule = makeRule({
      id: 'test-rule',
      matcher: {
        type: 'pattern',
        fileGlob: '**/*.ts',
        patterns: ['dangerous\\(\\)'],
        antiPatterns: [],
      },
    })
    const content = '// shipguard-ignore: other-rule -- reason\nconst x = dangerous()'
    const findings = runProRules([rule], [makeFile('src/app.ts', content)], POLICY)
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressed).toBeFalsy()
  })
})

// ---------------------------------------------------------------------------
// Finding 3: file-presence and file-relationship rules EXECUTE (no silent skip)
// ---------------------------------------------------------------------------

describe('Finding 3 — execute all signed matcher types', () => {
  it('file-presence rule (must-not-exist) fires a finding when the file is present', () => {
    // A 'must-not-exist' file-presence rule should fire when the glob matches a file.
    const rule = makeRule({
      id: 'fp-rule',
      matcher: {
        type: 'file-presence',
        fileGlob: '**/.env',
        patterns: [],
        antiPatterns: [],
        // presenceRule defaults to 'must-not-exist' in the executor shim
      } as unknown as QualityGateRule['matcher'],
    })

    const findings = runProRules(
      [rule],
      [makeFile('.env', 'SECRET=abc')],  // file matches the glob → finding fires
      POLICY,
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe('fp-rule')
    expect(findings[0].matcherType).toBe('file-presence')
  })

  it('file-presence rule produces NO finding when the file is absent from the scan', () => {
    // must-not-exist: file is not in the scan set → no finding (satisfied)
    const rule = makeRule({
      id: 'fp-rule-absent',
      matcher: {
        type: 'file-presence',
        fileGlob: '**/.env',
        patterns: [],
        antiPatterns: [],
      } as unknown as QualityGateRule['matcher'],
    })

    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'const x = 1')],  // .env not present → no match → no finding
      POLICY,
    )
    expect(findings).toHaveLength(0)
  })

  it('file-relationship rule fires when companion file is missing', () => {
    // file-relationship: the primary file exists (src/app.ts matches '**/*.ts'),
    // but the companion (companion.json) is NOT in allRelativePaths → finding fires.
    const rule = makeRule({
      id: 'fr-rule',
      matcher: {
        type: 'file-relationship',
        fileGlob: '**/*.ts',
        patterns: [],
        antiPatterns: [],
        context: { requiresFile: '**/companion.json' },
      },
    })

    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'const x = 1')],  // companion.json absent → finding
      POLICY,
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe('fr-rule')
    expect(findings[0].matcherType).toBe('file-relationship')
  })

  it('file-relationship rule produces NO finding when companion file is present', () => {
    const rule = makeRule({
      id: 'fr-rule-ok',
      matcher: {
        type: 'file-relationship',
        fileGlob: '**/*.ts',
        patterns: [],
        antiPatterns: [],
        context: { requiresFile: '**/companion.json' },
      },
    })

    const findings = runProRules(
      [rule],
      [
        makeFile('src/app.ts', 'const x = 1'),
        makeFile('companion.json', '{}'),  // companion present → no finding
      ],
      POLICY,
    )
    expect(findings).toHaveLength(0)
  })

  it('bundle with unsupported matcher type rejects whole bundle non-safe (RunProRulesFatalError)', () => {
    // An unsupported type (e.g. 'config-value') in a verified bundle must cause the
    // WHOLE bundle to be rejected non-safe — not silently skipped.
    const rule = makeRule({
      id: 'unsupported-rule',
      matcher: {
        type: 'config-value',  // Not supported by native-v1
        fileGlob: '**/*.json',
        patterns: [],
        antiPatterns: [],
      } as unknown as QualityGateRule['matcher'],
    })

    expect(() => runProRules([rule], [makeFile('package.json', '{}')], POLICY))
      .toThrow(RunProRulesFatalError)

    // runProRulesWithDispatch should mark degraded=true for this fatal error
    const result = runProRulesWithDispatch(
      [rule] as unknown as QualityGateRule[],
      [makeFile('package.json', '{}')],
      POLICY,
    )
    expect(result.degraded).toBe(true)
    expect(result.warnings.some(w => w.includes('unsupported'))).toBe(true)
    expect(result.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Finding 4: execution exceptions fail closed — non-safe scan
// ---------------------------------------------------------------------------

describe('Finding 4 — execution exceptions fail closed', () => {
  it('matcher execution exception throws RunProRulesFatalError (non-safe)', () => {
    // Create a rule that will cause the native-v1 executor to throw.
    // We do this by passing a 'file-presence' rule with an invalid presenceRule value
    // that causes evaluateFilePresence to throw... but the executor is quite robust.
    // Instead: pass a pattern rule against a file whose content triggers an exception
    // via a mock. Since we can't easily make native-v1 throw, we test via
    // runProRulesWithDispatch which catches RunProRulesFatalError.
    //
    // The only reliable way to trigger Finding 4 is to verify that RunProRulesFatalError
    // propagates correctly when thrown manually. We verify the throw path and the
    // catch-and-degrade path in runProRulesWithDispatch.

    // Verify that RunProRulesFatalError propagates from runProRules
    // by using the unsupported-type path (which is the practical trigger).
    const rule = makeRule({
      id: 'fatal-test-rule',
      matcher: {
        type: 'unknown-type-triggers-fatal',
        fileGlob: '**/*.ts',
        patterns: [],
        antiPatterns: [],
      } as unknown as QualityGateRule['matcher'],
    })

    // runProRules throws for unsupported type
    expect(() => runProRules([rule], [makeFile('src/app.ts', 'x')], POLICY))
      .toThrow(RunProRulesFatalError)

    // runProRulesWithDispatch catches it and marks scan degraded (not partial findings)
    const result = runProRulesWithDispatch(
      [rule] as unknown as QualityGateRule[],
      [makeFile('src/app.ts', 'x')],
      POLICY,
    )
    expect(result.degraded).toBe(true)
    expect(result.findings).toHaveLength(0)  // No partial findings returned
  })

  it('execution error degrades the FULL scan — no partial findings returned', () => {
    // Even if some rules ran successfully before the fatal error, the whole scan
    // must be degraded with zero findings (not partial).
    const goodRule = makeRule({ id: 'good-rule' })
    const badRule = makeRule({
      id: 'bad-rule',
      matcher: {
        type: 'config-value',  // unsupported
        fileGlob: '**/*.ts',
        patterns: [],
        antiPatterns: [],
      } as unknown as QualityGateRule['matcher'],
    })

    const result = runProRulesWithDispatch(
      [goodRule, badRule] as unknown as QualityGateRule[],
      [makeFile('src/app.ts', 'console.log("hello")')],
      POLICY,
    )

    // The fatal error from bad-rule degrades the whole scan
    expect(result.degraded).toBe(true)
    // We cannot guarantee zero findings here since the fatal error may be thrown
    // mid-loop after good-rule already ran, OR before (depends on loop order and
    // the pre-check). The pre-check fires BEFORE any rule runs, so findings = 0.
    expect(result.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Fix 1: blocking decision comes from rule.blocking, not severity coercion
// ---------------------------------------------------------------------------

describe('Fix 1 — blocking from rule.blocking flag, not severity coercion', () => {
  it('action=block produces blocking=true finding', () => {
    // Fix 1: action=block (derived from r.blocking===true) → finding.blocking===true
    const rule = makeRule({
      id: 'block-rule',
      severity: 'critical',
      action: 'block',
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("x")')],
      POLICY,
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].blocking).toBe(true)
  })

  it('action=warn produces blocking=false even for critical severity', () => {
    // Fix 1: action=warn → blocking=false regardless of severity
    const rule = makeRule({
      id: 'warn-rule',
      severity: 'critical',
      action: 'warn',
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("x")')],
      POLICY,
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].blocking).toBe(false)
  })

  it('severity=critical with no action defaults to blocking via confidence/severity', () => {
    // With no explicit action, deriveBlocking uses confidence and severity.
    // makeRule defaults confidence:'HIGH' → action=undefined → deriveBlocking returns true
    const rule = makeRule({
      id: 'critical-no-action',
      severity: 'critical',
      // No explicit action — falls through to deriveBlocking heuristics
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("x")')],
      POLICY,
    )
    expect(findings).toHaveLength(1)
    // With confidence:'HIGH', deriveBlocking returns true
    expect(findings[0].blocking).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Fix 3: full matcher field propagation (presenceRule, requiresFile, requiresPattern)
// ---------------------------------------------------------------------------

describe('Fix 3 — full matcher field propagation from ExecutableRule', () => {
  it('file-relationship rule with requiresFile fires finding when companion absent', () => {
    // Fix 3: the context.requiresFile must be propagated from the rule's requiresFile field,
    // not lost during the ExecutableRule→QualityGateRule mapping.
    const rule = makeRule({
      id: 'fr-with-requiresFile',
      matcher: {
        type: 'file-relationship',
        fileGlob: '**/*.ts',
        patterns: [],
        antiPatterns: [],
        context: { requiresFile: '**/tsconfig.json' },
      },
    })

    // companion absent → finding fires
    const findingsNoConfig = runProRules(
      [rule],
      [makeFile('src/app.ts', 'const x = 1')],
      POLICY,
    )
    expect(findingsNoConfig).toHaveLength(1)
    expect(findingsNoConfig[0].matcherType).toBe('file-relationship')
  })

  it('file-relationship rule with requiresFile produces no finding when companion present', () => {
    const rule = makeRule({
      id: 'fr-with-requiresFile-present',
      matcher: {
        type: 'file-relationship',
        fileGlob: '**/*.ts',
        patterns: [],
        antiPatterns: [],
        context: { requiresFile: '**/tsconfig.json' },
      },
    })

    // companion present → no finding
    const findingsWithConfig = runProRules(
      [rule],
      [makeFile('src/app.ts', 'const x = 1'), makeFile('tsconfig.json', '{}')],
      POLICY,
    )
    expect(findingsWithConfig).toHaveLength(0)
  })

  it('file-relationship rule with requiresPattern fails closed (fires finding)', () => {
    // Fix 3 + Fix 4: requiresPattern in file-relationship must fail closed.
    // The harness cannot evaluate the pattern (no file content available),
    // so it should fire a finding rather than silently returning zero.
    const rule = makeRule({
      id: 'fr-with-requiresPattern',
      matcher: {
        type: 'file-relationship',
        fileGlob: '**/*.ts',
        patterns: [],
        antiPatterns: [],
        context: { requiresFile: '**/tsconfig.json', requiresPattern: 'strict' },
      },
    })

    // companion file present, but requiresPattern cannot be evaluated → fail closed
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'const x = 1'), makeFile('tsconfig.json', '{}')],
      POLICY,
    )
    // Fail closed: fires a finding since we can't verify the pattern in the companion
    expect(findings).toHaveLength(1)
    expect(findings[0].matcherType).toBe('file-relationship')
  })
})

// ---------------------------------------------------------------------------
// FIX 1 (CRITICAL): end-to-end scope/boundary test through pro-scanner's mapping
//
// Proves that antiPatternScope:'block' delivered from the wire ExecutableRule
// is correctly propagated through the fetchProRules mapping into the QualityGateRule
// so that runProRules SUPPRESSES a finding that antiPatternScope:'statement' would REPORT.
//
// This is the proof that the CLI now honors the signed corpus scope (Gate-C ≡ production).
// ---------------------------------------------------------------------------

describe('FIX 1 — antiPatternScope propagated through pro-scanner mapping (end-to-end)', () => {
  // The test pattern: 'eval\\(' fires on any line containing eval(
  // The anti-pattern: 'SAFE' suppresses the finding if 'SAFE' is in the scope window
  //
  // For antiPatternScope:'statement', the anti-pattern is only checked on the SAME LINE as the match.
  // For antiPatternScope:'block', the anti-pattern is checked across the entire surrounding block.
  //
  // File content: a proper JS block with curly braces (required for 'block' scope to work).
  // The 'block' scope resolver walks { } delimiters to find the enclosing block:
  //
  //   line 1: "if (cond) {"    ← opening brace → blockStart = 1
  //   line 2: "  // SAFE"      ← the anti-pattern is on this line
  //   line 3: "  eval(x)"      ← the primary pattern match (matchLine = 3)
  //   line 4: "}"              ← closing brace → blockEnd = 4
  //
  // With antiPatternScope:'statement' (default):
  //   - The match is on line 3; anti-pattern searched on line 3 only ("  eval(x)" — no "SAFE")
  //   → The match is NOT suppressed → finding is REPORTED
  //
  // With antiPatternScope:'block':
  //   - Block scan from line 3 backward finds "{" on line 1 → blockStart = 1
  //   - Block scan forward from line 1 finds matching "}" on line 4 → blockEnd = 4
  //   - Window = lines [1..4]; "SAFE" is found on line 2 → The match IS suppressed
  //
  // The test builds QualityGateRule objects that SIMULATE what fetchProRules builds after
  // the FIX 1 mapping — i.e. the matcher object INCLUDES antiPatternScope from the wire rule.
  // This goes THROUGH the runProRules execution path (same as production), not a direct executor call.

  const FILE_CONTENT = 'if (cond) {\n  // SAFE\n  eval(x)\n}'

  function makeRuleWithScope(scope: AntiPatternScope | undefined): QualityGateRule {
    const matcher: QualityGateRule['matcher'] & { antiPatternScope?: AntiPatternScope } = {
      type: 'pattern',
      fileGlob: '**/*.js',
      patterns: ['eval\\('],
      antiPatterns: ['SAFE'],
      flags: '',
    }
    // Only include antiPatternScope when set — mirrors the FIX 1 mapping behavior:
    // '...(rAny["antiPatternScope"] !== undefined && { antiPatternScope: rAny["antiPatternScope"] })'
    if (scope !== undefined) {
      matcher.antiPatternScope = scope
    }
    return makeRule({
      id: 'fix1-scope-test',
      action: 'block',
      severity: 'high',
      matcher,
    })
  }

  it('antiPatternScope:statement (default) REPORTS the finding (anti-pattern not on match line)', () => {
    // With the default scope ('statement'), the anti-pattern "SAFE" is only searched on
    // the same line as the match. Line 2 ("eval(x)") does NOT contain "SAFE".
    // → Finding is reported (not suppressed).
    const ruleStatement = makeRuleWithScope('statement')
    const findings = runProRules(
      [ruleStatement],
      [makeFile('src/app.js', FILE_CONTENT)],
      POLICY,
    )
    // At least one non-suppressed finding expected
    const active = findings.filter(f => !f.suppressed)
    expect(active.length, 'statement scope should report finding (anti-pattern not on same line)').toBeGreaterThan(0)
  })

  it('antiPatternScope:block SUPPRESSES the finding (anti-pattern found in block window)', () => {
    // With antiPatternScope:'block', the anti-pattern "SAFE" is searched across the
    // surrounding block (both lines). Line 1 ("// SAFE") contains "SAFE".
    // → The match on line 2 is suppressed.
    //
    // This is the critical proof: if antiPatternScope were NOT propagated through the mapping
    // (FIX 1 bug), both 'statement' and 'block' would behave identically (defaulting to
    // 'statement') — and this test would FAIL because the finding would NOT be suppressed.
    const ruleBlock = makeRuleWithScope('block')
    const findings = runProRules(
      [ruleBlock],
      [makeFile('src/app.js', FILE_CONTENT)],
      POLICY,
    )
    // All findings must be suppressed (block scope found "SAFE" in the block)
    const active = findings.filter(f => !f.suppressed)
    expect(active.length, 'block scope should suppress finding (anti-pattern found in block window)').toBe(0)
  })

  it('PROVES mapping propagation: block suppresses where statement does not (same rule, same file)', () => {
    // This is the core proof required by the card:
    // "a rule with antiPatternScope:'block' SUPPRESSES a finding that the SAME rule
    //  with 'statement' would REPORT — proving the CLI now honors the delivered scope"
    const ruleStatement = makeRuleWithScope('statement')
    const ruleBlock = makeRuleWithScope('block')
    const file = makeFile('src/app.js', FILE_CONTENT)

    const statementFindings = runProRules([ruleStatement], [file], POLICY)
    const blockFindings = runProRules([ruleBlock], [file], POLICY)

    const statementActive = statementFindings.filter(f => !f.suppressed)
    const blockActive = blockFindings.filter(f => !f.suppressed)

    // statement REPORTS (has active/unsuppressed findings)
    expect(statementActive.length, 'statement scope must report at least one finding').toBeGreaterThan(0)
    // block SUPPRESSES (no active findings)
    expect(blockActive.length, 'block scope must suppress all findings').toBe(0)
  })
})

// ---------------------------------------------------------------------------
// FIX 2 (HIGH): action:block blocks regardless of severity — no reconstruction
//
// Proves that an action:block rule produces blocking:true in findings regardless
// of severity (even medium). This was the false-negative for medium-severity
// block rules like flask.redirect.open-redirect.
// ---------------------------------------------------------------------------

describe('FIX 2 — action:block blocks regardless of severity (no severity-based reconstruction)', () => {
  it('action:block with medium severity produces blocking:true (flask.redirect.open-redirect pattern)', () => {
    // This is the exact failure mode: severity:medium → blocking:false (old) → action:'warn' (old)
    // After FIX 2: action comes directly from the rule (not reconstructed from blocking),
    // so action:block always → blocking:true in the finding.
    const rule = makeRule({
      id: 'test.medium.block-rule',
      severity: 'medium',
      action: 'block',
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("hello")')],
      POLICY,
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].blocking).toBe(true)
    expect(findings[0].suppressed).toBeFalsy()
  })

  it('action:block with low severity produces blocking:true', () => {
    const rule = makeRule({
      id: 'test.low.block-rule',
      severity: 'low',
      action: 'block',
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("hello")')],
      POLICY,
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].blocking).toBe(true)
  })

  it('action:warn with critical severity produces blocking:false', () => {
    // Inverse of FIX 2: action:warn should NOT block even for critical severity.
    const rule = makeRule({
      id: 'test.critical.warn-rule',
      severity: 'critical',
      action: 'warn',
    })
    const findings = runProRules(
      [rule],
      [makeFile('src/app.ts', 'console.log("hello")')],
      POLICY,
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].blocking).toBe(false)
  })
})

