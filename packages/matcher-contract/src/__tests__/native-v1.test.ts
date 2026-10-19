// Phase B.1 — native-v1 executor behavioral tests
//
// Tests the matching behavior of the nativeV1Executor against all Matcher types.
// Also covers the B.4 boundary mode behaviors (none/word/token).

import { describe, it, expect } from 'vitest'
import { nativeV1Executor } from '../adapters/native-v1.js'
import type { ExecCtx } from '../matcher.js'
import type { CanonicalFinding } from '../finding.js'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const BASE_CTX: ExecCtx = {
  allRelativePaths: ['src/config.ts'],
  releaseId: 'test-release',
}

function ctx(paths: string[]): ExecCtx {
  return { allRelativePaths: paths, releaseId: 'test-release' }
}

// ---------------------------------------------------------------------------
// 1. PatternMatcher — 2 occurrences both active
// ---------------------------------------------------------------------------

describe('native-v1: PatternMatcher — basic multiple occurrences', () => {
  it('finds 2 occurrences of SECRET_KEY on separate lines (both active)', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET_KEY'],
      antiPatterns: [],
      flags: '',
    }
    const file = {
      relativePath: 'src/config.ts',
      content: 'const SECRET_KEY = "abc"\nconst SECRET_KEY = "xyz"\n',
    }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(2)
    expect(findings[0].suppressionState).toBe('active')
    expect(findings[1].suppressionState).toBe('active')
    expect(findings[0].line).toBe(1)
    expect(findings[1].line).toBe(2)
    expect(findings[0].evidence).toBe('SECRET_KEY')
    expect(findings[1].evidence).toBe('SECRET_KEY')
  })

  it('returns correct column for the match start', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: '',
    }
    const file = {
      relativePath: 'src/test.ts',
      content: 'const SECRET = 1\n',
    }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    // 'const ' = 6 chars, so SECRET starts at offset 6 → column 7
    expect(findings[0].column).toBe(7)
  })
})

// ---------------------------------------------------------------------------
// 2. Anti-pattern per-line scoping
// ---------------------------------------------------------------------------

describe('native-v1: PatternMatcher — anti-pattern per-line scoping', () => {
  it('suppresses occurrence on the safe line, leaves other occurrence active', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET_KEY'],
      antiPatterns: ['// safe:'],
      flags: '',
    }
    const file = {
      relativePath: 'src/mixed.ts',
      // Line 1: safe — anti-pattern matches → suppressed
      // Line 2: unsafe — no anti-pattern → active
      content: 'const x = SECRET_KEY // safe: this is ok\nconst y = SECRET_KEY\n',
    }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(2)

    // Find by line
    const line1 = findings.find((f) => f.line === 1)
    const line2 = findings.find((f) => f.line === 2)
    expect(line1).toBeDefined()
    expect(line2).toBeDefined()
    expect(line1!.suppressionState).toBe('suppressed')
    expect(line2!.suppressionState).toBe('active')
  })

  it('anti-pattern on a different line does NOT suppress the occurrence on another line', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['DANGER'],
      antiPatterns: ['// safe:'],
      flags: '',
    }
    const file = {
      relativePath: 'src/test.ts',
      // Line 1: has anti-pattern but no DANGER match
      // Line 2: has DANGER, no anti-pattern → must be active
      content: 'const ok = 1 // safe: no danger here\nconst x = DANGER\n',
    }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].line).toBe(2)
    expect(findings[0].suppressionState).toBe('active')
  })
})

// ---------------------------------------------------------------------------
// 3. FileRelationshipMatcher
// ---------------------------------------------------------------------------

describe('native-v1: FileRelationshipMatcher', () => {
  it('fires when companion file is missing from allRelativePaths', () => {
    const matcher = {
      type: 'file-relationship' as const,
      fileGlob: '**/.env',
      context: { requiresFile: '**/.env.example' },
    }
    const file = { relativePath: '.env', content: 'SECRET=abc' }
    // .env.example is NOT present
    const findings = nativeV1Executor.evaluate(
      matcher, file,
      ctx(['.env', 'src/index.ts']),
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].matcherType).toBe('file-relationship')
    expect(findings[0].suppressionState).toBe('active')
  })

  it('does NOT fire when companion file IS present in allRelativePaths', () => {
    const matcher = {
      type: 'file-relationship' as const,
      fileGlob: '**/.env',
      context: { requiresFile: '**/.env.example' },
    }
    const file = { relativePath: '.env', content: 'SECRET=abc' }
    // .env.example IS present
    const findings = nativeV1Executor.evaluate(
      matcher, file,
      ctx(['.env', '.env.example', 'src/index.ts']),
    )
    expect(findings).toHaveLength(0)
  })

  it('companion glob with deep path matches nested file', () => {
    const matcher = {
      type: 'file-relationship' as const,
      fileGlob: '**/.env',
      context: { requiresFile: '**/secrets/.env.example' },
    }
    const file = { relativePath: '.env', content: '' }
    const findings = nativeV1Executor.evaluate(
      matcher, file,
      ctx(['.env', 'secrets/.env.example']),
    )
    expect(findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// 4. FilePresenceMatcher — must-not-exist triggers when file is present
// ---------------------------------------------------------------------------

describe('native-v1: FilePresenceMatcher', () => {
  it('must-not-exist: fires one finding when file is in allRelativePaths', () => {
    const matcher = {
      type: 'file-presence' as const,
      fileGlob: '**/.env',
      presenceRule: 'must-not-exist' as const,
    }
    const file = { relativePath: '.env', content: 'SECRET=abc' }
    const findings = nativeV1Executor.evaluate(
      matcher, file,
      ctx(['.env', 'src/index.ts']),
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].line).toBe(1)
    expect(findings[0].column).toBe(1)
    expect(findings[0].matcherType).toBe('file-presence')
    expect(findings[0].suppressionState).toBe('active')
  })

  it('must-exist: does NOT fire (file is present — satisfied)', () => {
    const matcher = {
      type: 'file-presence' as const,
      fileGlob: '**/.gitignore',
      presenceRule: 'must-exist' as const,
    }
    const file = { relativePath: '.gitignore', content: 'node_modules' }
    const findings = nativeV1Executor.evaluate(
      matcher, file,
      ctx(['.gitignore']),
    )
    expect(findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// 5. Boundary mode — 'none' (default)
// ---------------------------------------------------------------------------

describe('native-v1: boundary mode — none (default)', () => {
  it("boundary:'none' matches sk- + 20 chars even when a 21st alphanumeric char follows", () => {
    // 'sk-' + 21 A's. The regex matches 'sk-' + first 20 A's.
    // With boundary:'none', the match is accepted despite the 21st A following.
    const content = 'sk-' + 'A'.repeat(21)
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['sk-[A-Za-z0-9]{20}'],
      antiPatterns: [],
      flags: '',
      boundary: 'none' as const,
    }
    const file = { relativePath: 'src/test.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    // Should find the match (boundary not enforced)
    expect(findings).toHaveLength(1)
    expect(findings[0].evidence).toBe('sk-' + 'A'.repeat(20))
  })

  it('omitting boundary is identical to boundary:none', () => {
    const content = 'sk-' + 'A'.repeat(21)
    const matcherNone = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['sk-[A-Za-z0-9]{20}'],
      antiPatterns: [],
      flags: '',
      boundary: 'none' as const,
    }
    const matcherOmitted = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['sk-[A-Za-z0-9]{20}'],
      antiPatterns: [],
      flags: '',
      // boundary absent
    }
    const file = { relativePath: 'src/test.ts', content }
    const findingsNone = nativeV1Executor.evaluate(matcherNone, file, BASE_CTX)
    const findingsOmitted = nativeV1Executor.evaluate(matcherOmitted, file, BASE_CTX)
    expect(findingsNone).toHaveLength(1)
    expect(findingsOmitted).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// 6. Boundary mode — 'token'
// ---------------------------------------------------------------------------

describe('native-v1: boundary mode — token', () => {
  it("boundary:'token' rejects match when next char is alphanumeric (21-char sequence)", () => {
    // 'sk-' + 21 A's. Regex matches sk- + 20 A's, but the 21st A follows → reject.
    const content = 'sk-' + 'A'.repeat(21)
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['sk-[A-Za-z0-9]{20}'],
      antiPatterns: [],
      flags: '',
      boundary: 'token' as const,
    }
    const file = { relativePath: 'src/test.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(0)
  })

  it("boundary:'token' accepts match when next char is NOT a token char (exact 20 chars)", () => {
    // 'sk-' + exactly 20 A's followed by a space (not a token char).
    const content = 'sk-' + 'A'.repeat(20) + ' other'
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['sk-[A-Za-z0-9]{20}'],
      antiPatterns: [],
      flags: '',
      boundary: 'token' as const,
    }
    const file = { relativePath: 'src/test.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].evidence).toBe('sk-' + 'A'.repeat(20))
  })

  it("boundary:'token' accepts match at end of string (no following char)", () => {
    // 'sk-' + exactly 20 A's, nothing after.
    const content = 'sk-' + 'A'.repeat(20)
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['sk-[A-Za-z0-9]{20}'],
      antiPatterns: [],
      flags: '',
      boundary: 'token' as const,
    }
    const file = { relativePath: 'src/test.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
  })

  it("boundary:'token' rejects match when followed by '-' (hyphen is a token char)", () => {
    const content = 'PREFIX-suffix'
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['PREFIX'],
      antiPatterns: [],
      flags: '',
      boundary: 'token' as const,
    }
    const file = { relativePath: 'src/test.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    // '-' follows 'PREFIX' → token char → reject
    expect(findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// 7. Boundary mode — 'word'
// ---------------------------------------------------------------------------

describe('native-v1: boundary mode — word', () => {
  it("boundary:'word' — SECRET on SECRETS is rejected (S follows, a word char)", () => {
    const content = 'const SECRETS = 1\n'
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: '',
      boundary: 'word' as const,
    }
    const file = { relativePath: 'src/test.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(0)
  })

  it("boundary:'word' — SECRET on 'SECRET ' is accepted (space follows, not a word char)", () => {
    const content = 'const SECRET = 1\n'
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: '',
      boundary: 'word' as const,
    }
    const file = { relativePath: 'src/test.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].evidence).toBe('SECRET')
  })

  it("boundary:'word' — hyphen does NOT count as a word char (unlike 'token')", () => {
    // 'word' only rejects on \w = [A-Za-z0-9_]; '-' is NOT in \w.
    const content = 'PREFIX-suffix'
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['PREFIX'],
      antiPatterns: [],
      flags: '',
      boundary: 'word' as const,
    }
    const file = { relativePath: 'src/test.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    // '-' is not \w → boundary:'word' ACCEPTS the match
    expect(findings).toHaveLength(1)
  })

  it("boundary:'token' vs boundary:'word': hyphen causes difference", () => {
    // 'PREFIX-suffix': with boundary:'word' it's accepted (- not \w);
    // with boundary:'token' it's rejected (- IS in [a-zA-Z0-9_-]).
    const content = 'PREFIX-suffix'
    const fileView = { relativePath: 'src/test.ts', content }
    const base = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['PREFIX'],
      antiPatterns: [],
      flags: '',
    }
    const wordFindings = nativeV1Executor.evaluate({ ...base, boundary: 'word' }, fileView, BASE_CTX)
    const tokenFindings = nativeV1Executor.evaluate({ ...base, boundary: 'token' }, fileView, BASE_CTX)
    expect(wordFindings).toHaveLength(1)  // accepted
    expect(tokenFindings).toHaveLength(0)  // rejected
  })
})

// ---------------------------------------------------------------------------
// 8. Zero-width match advancement
// ---------------------------------------------------------------------------

describe('native-v1: zero-width match advancement', () => {
  it('lookahead pattern records one occurrence and does not infinite-loop', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['(?=SECRET)'],
      antiPatterns: [],
      flags: '',
    }
    const file = { relativePath: 'src/test.ts', content: 'const SECRET = 1\n' }
    let findings: CanonicalFinding[] = []
    // If there's an infinite loop, this will time-out; otherwise it completes.
    expect(() => {
      findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    }).not.toThrow()
    // The lookahead matches at offset 6 (before SECRET)
    expect(findings).toHaveLength(1)
    expect(findings[0].evidence).toBe('') // zero-width
    expect(findings[0].line).toBe(1)
    expect(findings[0].column).toBe(7) // offset 6 → col 7
  })
})

// ---------------------------------------------------------------------------
// 9. Flags — case-insensitive, multiline, dotAll
// ---------------------------------------------------------------------------

describe('native-v1: PatternMatcher flags', () => {
  it('flags="i": case-insensitive match', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['secret_key'],
      antiPatterns: [],
      flags: 'i',
    }
    const file = { relativePath: 'src/config.ts', content: 'const SECRET_KEY = "abc"\n' }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].evidence).toBe('SECRET_KEY')
  })

  it('flags="m": multiline anchor match', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['^SECRET'],
      antiPatterns: [],
      flags: 'm',
    }
    const file = { relativePath: 'src/config.ts', content: 'const x = 1\nSECRET_KEY = "abc"\nconst y = 2\n' }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].line).toBe(2)
    expect(findings[0].column).toBe(1)
  })

  it('flags="s": dotAll — pattern spans newlines', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['begin.+end'],
      antiPatterns: [],
      flags: 's',
    }
    const file = { relativePath: 'src/config.ts', content: 'begin\nsome content\nend\n' }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].evidence).toBe('begin\nsome content\nend')
  })

  it('invalid flags produce zero findings (graceful degrade)', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: 'g', // 'g' is invalid per parseFlags
    }
    const file = { relativePath: 'src/test.ts', content: 'SECRET=abc' }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// 10. CanonicalFinding field invariants
// ---------------------------------------------------------------------------

describe('native-v1: CanonicalFinding field invariants', () => {
  it('every finding has all 10 mandatory CanonicalFinding fields', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: '',
    }
    const file = { relativePath: 'src/config.ts', content: 'SECRET=abc' }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    const f = findings[0]
    // All 10 fields must be present (not undefined)
    expect(f.id).toBeDefined()
    expect(f.file).toBeDefined()
    expect(typeof f.line).toBe('number')
    expect(typeof f.column).toBe('number')
    // evidence is string | null — both valid per contract
    expect(f.evidence === null || typeof f.evidence === 'string').toBe(true)
    expect(f.severity).toBeDefined()
    expect(typeof f.blocking).toBe('boolean')
    expect(f.suppressionState).toBeDefined()
    expect(f.releaseId).toBeDefined()
    expect(f.matcherType).toBeDefined()
  })

  it('file field matches the FileView.relativePath', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: '',
    }
    const file = { relativePath: 'packages/cli/src/secret.ts', content: 'SECRET=abc' }
    const findings = nativeV1Executor.evaluate(matcher, file, ctx(['packages/cli/src/secret.ts']))
    expect(findings[0].file).toBe('packages/cli/src/secret.ts')
  })

  it('releaseId matches ExecCtx.releaseId', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: [],
      flags: '',
    }
    const file = { relativePath: 'src/test.ts', content: 'SECRET=abc' }
    const myCtx: ExecCtx = { allRelativePaths: ['src/test.ts'], releaseId: 'my-frozen-release-v3' }
    const findings = nativeV1Executor.evaluate(matcher, file, myCtx)
    expect(findings[0].releaseId).toBe('my-frozen-release-v3')
  })

  it('returns empty array when no match (never null/undefined)', () => {
    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['NEVER_MATCHES_XYZ_12345'],
      antiPatterns: [],
      flags: '',
    }
    const file = { relativePath: 'src/test.ts', content: 'const x = 1\n' }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(Array.isArray(findings)).toBe(true)
    expect(findings).toHaveLength(0)
  })
})


// ---------------------------------------------------------------------------
// 11. Anti-pattern scope modes — context window (TDD: written before impl)
// ---------------------------------------------------------------------------

describe('native-v1: antiPatternScope — context window modes', () => {
  // -------------------------------------------------------------------------
  // scope: "function" — auth-in-body pattern (route-handler-no-auth shape)
  // -------------------------------------------------------------------------

  it('scope=function: suppresses when anti-pattern is in function body but NOT on match line', () => {
    // Realistic route-handler fixture:
    //   Line 1: export async function POST(req: Request) {    ← MATCH here
    //   Line 2:   const body = await req.json()
    //   Line 3:   const session = await getServerSession(authOptions)  ← ANTI-PATTERN
    //   Line 4:   if (!session) return Response.json({error:'Unauthorized'}, {status:401})
    //   Line 5:   return Response.json({ ok: true })
    //   Line 6: }
    //
    // With scope=function the anti-pattern on line 3 should suppress the match on line 1.
    const content = [
      'export async function POST(req: Request) {',
      '  const body = await req.json()',
      '  const session = await getServerSession(authOptions)',
      '  if (!session) return Response.json({error:"Unauthorized"},{status:401})',
      '  return Response.json({ ok: true })',
      '}',
    ].join('\n') + '\n'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['export async function POST'],
      antiPatterns: ['getServerSession'],
      flags: '',
      antiPatternScope: 'function' as const,
    }
    const file = { relativePath: 'src/app/api/route.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressionState).toBe('suppressed')
  })

  it('scope=function: does NOT suppress when anti-pattern is in a DIFFERENT function', () => {
    // Two functions; anti-pattern only in the second one.
    // Match is on line 1 (in first function) → should be ACTIVE (not suppressed).
    const content = [
      'export async function POST(req: Request) {',  // line 1 — MATCH
      '  const body = await req.json()',
      '  return Response.json({ ok: true })',         // NO getServerSession here
      '}',
      '',
      'export async function GET(req: Request) {',
      '  const session = await getServerSession(authOptions)',  // anti-pattern in DIFFERENT function
      '  return Response.json({ session })',
      '}',
    ].join('\n') + '\n'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['export async function POST'],
      antiPatterns: ['getServerSession'],
      flags: '',
      antiPatternScope: 'function' as const,
    }
    const file = { relativePath: 'src/app/api/route.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressionState).toBe('active')
  })

  it('scope=function: default statement scope does NOT suppress when auth is in body (false positive prevention)', () => {
    // Same route-handler fixture, but with default scope ("statement").
    // With statement scope, auth on line 3 should NOT suppress match on line 1.
    const content = [
      'export async function POST(req: Request) {',
      '  const body = await req.json()',
      '  const session = await getServerSession(authOptions)',
      '  return Response.json({ ok: true })',
      '}',
    ].join('\n') + '\n'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['export async function POST'],
      antiPatterns: ['getServerSession'],
      flags: '',
      // No antiPatternScope → defaults to "statement"
    }
    const file = { relativePath: 'src/app/api/route.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    // With default scope, getServerSession on line 3 is NOT within the statement
    // starting on line 1, so the match is ACTIVE (not suppressed)
    expect(findings[0].suppressionState).toBe('active')
  })

  // -------------------------------------------------------------------------
  // scope: "file" — import-based anti-pattern
  // -------------------------------------------------------------------------

  it('scope=file: suppresses when anti-pattern is at line 1, match is at line 40', () => {
    // Import-based rule: the safe import is at the top of the file, match is deep.
    const lines: string[] = []
    lines.push('import { sanitize } from "./sanitize"')  // line 1 — ANTI-PATTERN
    for (let i = 2; i <= 39; i++) {
      lines.push(`// line ${i}`)
    }
    lines.push('const result = sanitize(userInput)')  // line 40 — this would be the match
    // Actually let's use a simpler pattern: match "userInput" and anti-pattern "sanitize" import
    // The import at line 1 should suppress the usage at line 40 when scope=file
    const content = lines.join('\n') + '\n'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['userInput'],
      antiPatterns: ['import.*sanitize'],
      flags: '',
      antiPatternScope: 'file' as const,
    }
    const file = { relativePath: 'src/handler.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressionState).toBe('suppressed')
  })

  it('scope=file: does NOT suppress when the anti-pattern is absent anywhere in the file', () => {
    const content = [
      '// no sanitize import here',
      'const result = process(userInput)',
    ].join('\n') + '\n'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['userInput'],
      antiPatterns: ['import.*sanitize'],
      flags: '',
      antiPatternScope: 'file' as const,
    }
    const file = { relativePath: 'src/handler.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressionState).toBe('active')
  })

  // -------------------------------------------------------------------------
  // scope: { lines: N } — sliding window
  // -------------------------------------------------------------------------

  it('scope={lines:2}: suppresses when anti-pattern is within 2 lines of the match', () => {
    // match on line 3, anti-pattern on line 5 → distance = 2 → within window → suppressed
    const content = [
      'const a = 1',
      'const b = 2',
      'const SECRET = getValue()',  // line 3 — MATCH
      'const c = 3',
      'const check = validate(SECRET)',  // line 5 — ANTI-PATTERN
    ].join('\n') + '\n'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: ['validate\\('],
      flags: '',
      antiPatternScope: { lines: 2 } as const,
    }
    const file = { relativePath: 'src/test.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    // The match on line 3 sees "validate(" on line 5 (distance 2) → suppressed
    // The match on line 5 (if pattern matches "SECRET" in "validate(SECRET)") would check lines 3-7
    // Actually the pattern 'SECRET' matches line 3 and line 5 ("validate(SECRET)")
    const line3 = findings.find((f) => f.line === 3)
    expect(line3).toBeDefined()
    expect(line3!.suppressionState).toBe('suppressed')
  })

  it('scope={lines:0}: equivalent to strict per-line (anti-pattern on different line does not suppress)', () => {
    const content = [
      'const SECRET = getValue()',  // line 1 — MATCH, no anti-pattern here
      'const check = validate()',   // line 2 — ANTI-PATTERN but on different line
    ].join('\n') + '\n'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: ['validate'],
      flags: '',
      antiPatternScope: { lines: 0 } as const,
    }
    const file = { relativePath: 'src/test.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    const line1 = findings.find((f) => f.line === 1)
    expect(line1).toBeDefined()
    expect(line1!.suppressionState).toBe('active')
  })

  // -------------------------------------------------------------------------
  // scope: "block" — enclosing brace block
  // -------------------------------------------------------------------------

  it('scope=block: suppresses when anti-pattern is in the same brace block', () => {
    // Cookie options span lines:
    //   if (condition) {     ← block opens
    //     setCookie(...)     ← MATCH
    //     httpOnly: true     ← ANTI-PATTERN (makes it safe)
    //   }
    const content = [
      'if (condition) {',
      '  setCookie(name, value, {',  // line 2 — MATCH
      '    httpOnly: true,',          // line 3 — ANTI-PATTERN (safe cookie option)
      '    secure: true,',
      '  })',
      '}',
    ].join('\n') + '\n'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['setCookie'],
      antiPatterns: ['httpOnly'],
      flags: '',
      antiPatternScope: 'block' as const,
    }
    const file = { relativePath: 'src/middleware.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressionState).toBe('suppressed')
  })

  it('scope=block: does NOT suppress when anti-pattern is in a DIFFERENT block', () => {
    const content = [
      'if (a) {',
      '  setCookie(name, value)',   // line 2 — MATCH in first block
      '}',
      'if (b) {',
      '  httpOnly = true',          // line 5 — ANTI-PATTERN in DIFFERENT block
      '}',
    ].join('\n') + '\n'

    const matcher = {
      type: 'pattern' as const,
      fileGlob: '**/*.ts',
      patterns: ['setCookie'],
      antiPatterns: ['httpOnly'],
      flags: '',
      antiPatternScope: 'block' as const,
    }
    const file = { relativePath: 'src/middleware.ts', content }
    const findings = nativeV1Executor.evaluate(matcher, file, BASE_CTX)
    expect(findings).toHaveLength(1)
    expect(findings[0].suppressionState).toBe('active')
  })
})

// ---------------------------------------------------------------------------
// 12. requiresPattern fail-closed behavior
// ---------------------------------------------------------------------------

describe('native-v1: requiresPattern fails closed (fires finding, not silent zero)', () => {
  it('requiresFile found + requiresPattern set → fails closed (fires finding)', () => {
    // The harness cannot read companion file content to evaluate requiresPattern.
    // fail closed — fire a finding rather than silently returning zero.
    const matcher = {
      type: 'file-relationship' as const,
      fileGlob: '**/.env',
      context: {
        requiresFile: '**/.env.example',
        requiresPattern: 'DB_PASSWORD=',
      },
    }
    const file = { relativePath: '.env', content: 'SECRET=abc' }
    // .env.example IS present, requiresPattern IS set → can't evaluate → fail closed
    const findings = nativeV1Executor.evaluate(
      matcher, file,
      ctx(['.env', '.env.example', 'src/index.ts']),
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].matcherType).toBe('file-relationship')
    expect(findings[0].suppressionState).toBe('active')
    expect(findings[0].evidence).toMatch(/requiresPattern.*fail closed/)
  })

  it('requiresFile absent (missing companion) still fires finding as before', () => {
    // When companion file is missing, fire finding (existing behavior unchanged)
    const matcher = {
      type: 'file-relationship' as const,
      fileGlob: '**/.env',
      context: {
        requiresFile: '**/.env.example',
        requiresPattern: 'DB_PASSWORD=',
      },
    }
    const file = { relativePath: '.env', content: 'SECRET=abc' }
    // .env.example is NOT present → fire finding for missing companion
    const findings = nativeV1Executor.evaluate(
      matcher, file,
      ctx(['.env', 'src/index.ts']),
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].matcherType).toBe('file-relationship')
  })

  it('requiresPattern without requiresFile → fails closed (fires finding)', () => {
    // requiresPattern without requiresFile: can't evaluate content → fail closed
    const matcher = {
      type: 'file-relationship' as const,
      fileGlob: '**/*.ts',
      context: {
        requiresPattern: 'import.*crypto',
      },
    }
    const file = { relativePath: 'src/app.ts', content: 'const x = 1' }
    const findings = nativeV1Executor.evaluate(
      matcher, file,
      ctx(['src/app.ts']),
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].matcherType).toBe('file-relationship')
    expect(findings[0].suppressionState).toBe('active')
    expect(findings[0].evidence).toMatch(/requiresPattern.*fail closed/)
  })
})
