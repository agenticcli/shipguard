// Task A.12 — Conformance vector data
//
// A STRUCTURED set of input fixtures → expected canonical findings +
// expected canonical-JSON hashes. Used by the conformance harness.
//
// DESIGN DECISIONS
// ================
// 1. Vectors are typed objects (not raw JSON files) so TypeScript enforces
//    schema correctness at compile time and editors provide autocomplete.
//
// 2. expectedFindingHash is the SHA-256 of canonicalJson(canonicalizeFinding(f))
//    for each expected finding, computed deterministically. The harness verifies
//    that a real executor produces findings whose canonical hashes match these
//    stored values exactly (byte-identical).
//
// 3. Executor-INDEPENDENT vectors (tested now, Phase A):
//    - canonicalJson determinism over expected finding sets
//    - selectExpected correctness
//    - caps profile
//    - flag rejection
//    - normalization edge cases (invalid-UTF-8 reject, CRLF, BOM)
//    These can be tested without a real MatcherExecutor.
//
// 4. Executor-DEPENDENT vectors (harness skeleton only, Phase B/D):
//    - PatternMatcher with each flag combo
//    - zero-width match advancement
//    - anti-pattern per-line scoping (safe + unsafe in same file)
//    - file-presence trigger
//    - file-relationship trigger
//    The harness function accepts an injected executor; Phase B.1 and D.1
//    will call runConformance() with the real adapters.
//
// 5. Hash values for executor-dependent vectors are stored as null here
//    (the executor has not been implemented yet). Phase B/D will fill them
//    in by running the real executor and freezing the computed hashes.
//
// 6. Vector IDs are stable identifiers used in test output for traceability.
//    Format: <category>-<seq> (e.g. "pattern-1", "normalization-1").

import type { CanonicalFinding } from '../finding.js'
import type { Matcher } from '../matcher.js'

// ---------------------------------------------------------------------------
// Vector types
// ---------------------------------------------------------------------------

/**
 * A single conformance vector.
 *
 * Each vector specifies:
 * - id: stable identifier for this test case
 * - description: human-readable description
 * - category: the aspect being tested
 * - input: the file content and matcher to apply
 * - expectedFindings: the canonical findings the executor should produce
 *   (null = executor-dependent, not yet frozen)
 * - expectedCanonicalHash: SHA-256 of canonicalJson(set of expectedFindings)
 *   (null = executor-dependent)
 * - executorDependent: true means this vector cannot run without a real executor
 */
export interface ConformanceVector {
  id: string
  description: string
  category: ConformanceCategory
  input: VectorInput
  expectedFindings: CanonicalFinding[] | null
  expectedCanonicalHash: string | null
  executorDependent: boolean
}

export type ConformanceCategory =
  | 'pattern'          // PatternMatcher — one per flag combo
  | 'file-presence'    // FilePresenceMatcher
  | 'file-relationship' // FileRelationshipMatcher
  | 'normalization'    // Input normalization edge cases
  | 'caps'             // Cap-exceeded cases
  | 'flags'            // Flag validation rejection
  | 'anti-pattern'     // Anti-pattern line-scoping (safe+unsafe in one file)
  | 'zero-width'       // Zero-width match advancement

/** The input to a conformance vector run. */
export interface VectorInput {
  /** The matcher to apply (null for normalization/flags/caps vectors). */
  matcher: Matcher | null
  /** File path used in the FileView (root-relative). */
  relativePath: string
  /**
   * Raw file bytes as a Uint8Array (for normalization vectors that need to
   * test the UTF-8 decoding path) — OR decoded string (for executor vectors
   * that assume pre-normalized content).
   *
   * When rawBytes is set, the harness decodes via decodeUtf8Strict +
   * stripBom + normalizeNewlines before passing to the executor.
   * When content is set, it is passed directly to the executor.
   */
  rawBytes?: Uint8Array
  content?: string
  /** All file paths present in the scan (for file-relationship + caps vectors). */
  allRelativePaths?: string[]
  /** The releaseId to embed in expected findings. */
  releaseId: string
}

// ---------------------------------------------------------------------------
// Pre-computed canonical-finding hash helper (executor-independent)
// ---------------------------------------------------------------------------

// The canonical hashes for executor-independent findings are computed using
// canonicalJson + SHA-256 over the finding fields, identical to what Phase C
// signing will use. For this module (zero runtime deps), we store the hashes
// as pre-computed constants.
//
// HOW HASHES WERE DERIVED (documented for auditability):
// Each hash is SHA-256(canonicalJson(canonicalizeFinding(f))).
// canonicalizeFinding selects the 10 mandatory fields in any order;
// canonicalJson sorts them by UTF-16 key order and removes whitespace.
// The sorted key order for CanonicalFinding is:
//   blocking, column, evidence, file, id, line, matcherType, releaseId,
//   severity, suppressionState
// (alphabetic UTF-16 code-unit order)
//
// Phase B.1 / D.1 will freeze the executor-dependent hashes by running
// the real adapter and recording the SHA-256 of each finding set.

// ---------------------------------------------------------------------------
// Executor-INDEPENDENT vectors
// ---------------------------------------------------------------------------

/**
 * Normalization vector 1: invalid UTF-8 MUST be rejected loudly.
 *
 * A file with a lone 0xFF byte (never valid in UTF-8) must cause
 * decodeUtf8Strict to return {ok:false}. The harness tests this directly
 * against the normalization function, not the executor.
 */
const NORM_VECTOR_INVALID_UTF8: ConformanceVector = {
  id: 'normalization-1',
  description: 'Invalid UTF-8 (lone 0xFF byte) → decodeUtf8Strict returns ok=false',
  category: 'normalization',
  executorDependent: false,
  input: {
    matcher: null,
    relativePath: 'src/invalid.ts',
    rawBytes: new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xff, 0x77, 0x6f, 0x72, 0x6c, 0x64]),
    releaseId: 'test-release',
  },
  expectedFindings: null, // normalization test — no findings expected (rejects before scan)
  expectedCanonicalHash: null,
}

/**
 * Normalization vector 2: CRLF line endings → normalized to LF.
 *
 * A file with CRLF line endings must have \r stripped so that line-level
 * operations produce correct results. This is an executor-independent test
 * of normalizeNewlines().
 */
const NORM_VECTOR_CRLF: ConformanceVector = {
  id: 'normalization-2',
  description: 'CRLF line endings → normalizeNewlines strips \\r, producing LF-only content',
  category: 'normalization',
  executorDependent: false,
  input: {
    matcher: null,
    relativePath: 'src/windows-file.ts',
    rawBytes: new Uint8Array([
      // "line1\r\nline2\r\n" in UTF-8
      0x6c, 0x69, 0x6e, 0x65, 0x31, 0x0d, 0x0a,
      0x6c, 0x69, 0x6e, 0x65, 0x32, 0x0d, 0x0a,
    ]),
    releaseId: 'test-release',
  },
  expectedFindings: null, // normalization test — expected normalized content is "line1\nline2\n"
  expectedCanonicalHash: null,
}

/**
 * Normalization vector 3: UTF-8 BOM → stripped by stripBom().
 *
 * A file beginning with EF BB BF (the UTF-8 BOM) must have the BOM stripped
 * before scanning. This is an executor-independent test of stripBom().
 */
const NORM_VECTOR_BOM: ConformanceVector = {
  id: 'normalization-3',
  description: 'UTF-8 BOM (EF BB BF) → stripBom removes the leading U+FEFF',
  category: 'normalization',
  executorDependent: false,
  input: {
    matcher: null,
    relativePath: 'src/bom-file.ts',
    rawBytes: new Uint8Array([
      // BOM = EF BB BF, then "hello"
      0xef, 0xbb, 0xbf, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
    ]),
    releaseId: 'test-release',
  },
  expectedFindings: null, // normalization test — expected content is "hello" without BOM
  expectedCanonicalHash: null,
}

/**
 * Flags vector 1: a rule with flags="g" MUST be rejected at schema validation.
 *
 * parseFlags("g") → {ok:false}. The harness tests this directly against
 * parseFlags, not the executor.
 */
const FLAGS_VECTOR_REJECT_G: ConformanceVector = {
  id: 'flags-1',
  description: 'flags="g" → parseFlags rejects with ok=false (unsupported flag)',
  category: 'flags',
  executorDependent: false,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['test'],
      antiPatterns: [],
      flags: 'g', // INVALID — must be rejected
    },
    relativePath: 'src/test.ts',
    content: 'const test = 1',
    releaseId: 'test-release',
  },
  expectedFindings: null, // rejection test — no findings expected
  expectedCanonicalHash: null,
}

/**
 * Flags vector 2: a rule with flags="ims" (all valid) MUST be accepted.
 *
 * parseFlags("ims") → {ok:true, flags: Set{"i","m","s"}}.
 */
const FLAGS_VECTOR_ACCEPT_IMS: ConformanceVector = {
  id: 'flags-2',
  description: 'flags="ims" → parseFlags accepts all three valid flags',
  category: 'flags',
  executorDependent: false,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['test'],
      antiPatterns: [],
      flags: 'ims', // valid combination
    },
    relativePath: 'src/test.ts',
    content: 'const test = 1',
    releaseId: 'test-release',
  },
  expectedFindings: null, // executor-dependent for actual match result
  expectedCanonicalHash: null,
}

/**
 * Caps vector 1: maxRules exceeded → selectExpected throws FAIL_INCOMPLETE.
 *
 * Tests the cap enforcement in selectExpected when there are more candidates
 * than manifest.capProfile.maxRules.
 */
const CAPS_VECTOR_MAXRULES: ConformanceVector = {
  id: 'caps-1',
  description: 'selectExpected throws FAIL_INCOMPLETE when candidates > maxRules',
  category: 'caps',
  executorDependent: false,
  input: {
    matcher: null,
    relativePath: 'src/test.ts',
    content: 'const x = 1',
    releaseId: 'test-release',
  },
  expectedFindings: null, // cap test — throws before producing findings
  expectedCanonicalHash: null,
}

// ---------------------------------------------------------------------------
// Executor-DEPENDENT vectors (skeleton — Phase B.1 / D.1 fills hashes)
// ---------------------------------------------------------------------------

/**
 * Pattern vector 1: PatternMatcher, no flags.
 *
 * A basic pattern match with no flags. The executor must find the match
 * at the correct offset, line, and column.
 *
 * Phase B.1 / D.1: run the real executor, record the canonical finding hash.
 */
const PATTERN_VECTOR_NO_FLAGS: ConformanceVector = {
  id: 'pattern-1',
  description: 'PatternMatcher flags="" — basic pattern match, no flags',
  category: 'pattern',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['SECRET_KEY'],
      antiPatterns: [],
      flags: '',
    },
    relativePath: 'src/config.ts',
    content: 'const SECRET_KEY = "abc123"\n',
    releaseId: 'test-release',
  },
  // Frozen by Phase B.1 (native-v1 executor, 2026-06-25)
  expectedFindings: null,
  expectedCanonicalHash: 'd2d2b68c73d5fc06343323edac63d306b79f7942cfa9a09d91b322179eea632d',
}

/**
 * Pattern vector 2: PatternMatcher, flags="i" (case-insensitive).
 *
 * The pattern "secret_key" with flag "i" must match "SECRET_KEY" in the file.
 */
const PATTERN_VECTOR_FLAG_I: ConformanceVector = {
  id: 'pattern-2',
  description: 'PatternMatcher flags="i" — case-insensitive match',
  category: 'pattern',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['secret_key'],
      antiPatterns: [],
      flags: 'i',
    },
    relativePath: 'src/config.ts',
    content: 'const SECRET_KEY = "abc123"\n',
    releaseId: 'test-release',
  },
  // Frozen by Phase B.1 (native-v1 executor, 2026-06-25)
  expectedFindings: null,
  expectedCanonicalHash: 'd2d2b68c73d5fc06343323edac63d306b79f7942cfa9a09d91b322179eea632d',
}

/**
 * Pattern vector 3: PatternMatcher, flags="m" (multiline).
 *
 * The pattern "^SECRET" with flag "m" must match at line boundaries
 * in a multi-line file.
 */
const PATTERN_VECTOR_FLAG_M: ConformanceVector = {
  id: 'pattern-3',
  description: 'PatternMatcher flags="m" — multiline anchor match',
  category: 'pattern',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['^SECRET'],
      antiPatterns: [],
      flags: 'm',
    },
    relativePath: 'src/config.ts',
    content: 'const x = 1\nSECRET_KEY = "abc"\nconst y = 2\n',
    releaseId: 'test-release',
  },
  // Frozen by Phase B.1 (native-v1 executor, 2026-06-25)
  expectedFindings: null,
  expectedCanonicalHash: 'ea8b323d240ba9fc7db805bce32a343d6cb66294ae1c854732f86e30333c9649',
}

/**
 * Pattern vector 4: PatternMatcher, flags="s" (dotAll — . matches \n).
 *
 * The pattern "begin.+end" with flag "s" must match across newlines.
 */
const PATTERN_VECTOR_FLAG_S: ConformanceVector = {
  id: 'pattern-4',
  description: 'PatternMatcher flags="s" — dotAll, pattern spans newlines',
  category: 'pattern',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['begin.+end'],
      antiPatterns: [],
      flags: 's',
    },
    relativePath: 'src/config.ts',
    content: 'begin\nsome content\nend\n',
    releaseId: 'test-release',
  },
  // Frozen by Phase B.1 (native-v1 executor, 2026-06-25)
  expectedFindings: null,
  expectedCanonicalHash: 'bcf11d7a3a1611058df0afca8875d528a7f62a8f361084f7788854c079048a05',
}

/**
 * Pattern vector 5: PatternMatcher, flags="im" (case-insensitive + multiline).
 */
const PATTERN_VECTOR_FLAG_IM: ConformanceVector = {
  id: 'pattern-5',
  description: 'PatternMatcher flags="im" — case-insensitive multiline',
  category: 'pattern',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['^secret'],
      antiPatterns: [],
      flags: 'im',
    },
    relativePath: 'src/config.ts',
    content: 'const x = 1\nSECRET_KEY = "abc"\n',
    releaseId: 'test-release',
  },
  // Frozen by Phase B.1 (native-v1 executor, 2026-06-25)
  expectedFindings: null,
  expectedCanonicalHash: 'ea8b323d240ba9fc7db805bce32a343d6cb66294ae1c854732f86e30333c9649',
}

/**
 * Pattern vector 6: FilePresenceMatcher — file present (must-not-exist trigger).
 *
 * A file-presence rule with presenceRule="must-not-exist" triggers when
 * the file IS present in the scan snapshot.
 */
const FILE_PRESENCE_VECTOR: ConformanceVector = {
  id: 'file-presence-1',
  description: 'FilePresenceMatcher presenceRule=must-not-exist — triggers when file exists',
  category: 'file-presence',
  executorDependent: true,
  input: {
    matcher: {
      type: 'file-presence',
      fileGlob: '**/.env',
      presenceRule: 'must-not-exist',
    },
    relativePath: '.env',
    content: 'SECRET=abc',
    allRelativePaths: ['.env', 'src/index.ts'],
    releaseId: 'test-release',
  },
  // Frozen by Phase B.1 (native-v1 executor, 2026-06-25)
  expectedFindings: null,
  expectedCanonicalHash: 'e827fd2dce5bd45b62a211a5b92a783b3d406e0a33be77e98361df5a6f61a3be',
}

/**
 * Pattern vector 7: anti-pattern per-line scoping.
 *
 * A file with one SAFE line (anti-pattern matches) and one UNSAFE line
 * (anti-pattern does NOT match on that line). The executor must report
 * only the unsafe occurrence as "active" — the safe occurrence is "suppressed".
 *
 * This tests the fix to the file-wide anti-pattern suppression bug:
 * a safe line elsewhere in the file must NOT suppress findings on other lines.
 */
const ANTI_PATTERN_VECTOR: ConformanceVector = {
  id: 'anti-pattern-1',
  description: 'Anti-pattern per-line scoping: safe line suppressed, unsafe line active',
  category: 'anti-pattern',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['SECRET_KEY'],
      antiPatterns: ['// safe:'],
      flags: '',
    },
    relativePath: 'src/mixed.ts',
    // Line 1: safe (anti-pattern matches) → suppressed
    // Line 2: unsafe (no anti-pattern) → active finding
    content: 'const x = SECRET_KEY // safe: this is ok\nconst y = SECRET_KEY\n',
    releaseId: 'test-release',
  },
  // Frozen by Phase B.1 (native-v1 executor, 2026-06-25)
  expectedFindings: null,
  expectedCanonicalHash: '62e6c66067ad113a6efde1e8821d68173d226050b75ebae42a66340f9add3b95',
}

/**
 * Pattern vector 8: zero-width match advancement.
 *
 * A zero-width pattern (e.g. "(?=x)") must advance lastIndex by 1 to avoid
 * an infinite loop. The executor must still record the zero-width occurrence.
 */
const ZERO_WIDTH_VECTOR: ConformanceVector = {
  id: 'zero-width-1',
  description: 'Zero-width match: executor advances lastIndex by 1 to prevent infinite loop',
  category: 'zero-width',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['(?=SECRET)'],
      antiPatterns: [],
      flags: '',
    },
    relativePath: 'src/test.ts',
    content: 'const SECRET = 1\n',
    releaseId: 'test-release',
  },
  // Frozen by Phase B.1 (native-v1 executor, 2026-06-25)
  expectedFindings: null,
  expectedCanonicalHash: '3b73dd36f79009f27ec6551c4519fc4166c07008bc62655960b5f4ed9ab12bc3',
}

/**
 * File-relationship vector 1.
 *
 * A file-relationship rule triggers when a primary file matches and a companion
 * file exists (or also matches a pattern).
 */
const FILE_RELATIONSHIP_VECTOR: ConformanceVector = {
  id: 'file-relationship-1',
  description: 'FileRelationshipMatcher — companion file must exist alongside primary',
  category: 'file-relationship',
  executorDependent: true,
  input: {
    matcher: {
      type: 'file-relationship',
      fileGlob: '**/.env',
      context: {
        requiresFile: '**/.env.example',
      },
    },
    relativePath: '.env',
    content: 'SECRET=abc',
    // .env exists but .env.example does NOT — should trigger a finding
    allRelativePaths: ['.env', 'src/index.ts'],
    releaseId: 'test-release',
  },
  // Frozen by Phase B.1 (native-v1 executor, 2026-06-25)
  expectedFindings: null,
  expectedCanonicalHash: 'bca83c88305d62652e11e6bc6163841181bd2e0e28c4b94c795cf02f605d41b5',
}

// ---------------------------------------------------------------------------
// Anti-pattern scope conformance vectors (new — Phase B.1 scope-window impl)
// ---------------------------------------------------------------------------

/**
 * Anti-pattern scope vector 1: scope="function" — auth-in-body suppression.
 *
 * A route-handler-no-auth shaped rule. The match is on the `export async function POST`
 * line (line 1), the anti-pattern `getServerSession` is in the function body (line 3).
 * With scope="function", the occurrence on line 1 must be suppressed.
 */
const ANTI_PATTERN_SCOPE_FUNCTION_SUPPRESSED: ConformanceVector = {
  id: 'anti-pattern-scope-function-1',
  description: 'antiPatternScope="function": auth-in-body suppresses match on function declaration line',
  category: 'anti-pattern',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['export async function POST'],
      antiPatterns: ['getServerSession'],
      flags: '',
      antiPatternScope: 'function',
    },
    relativePath: 'src/app/api/route.ts',
    content: [
      'export async function POST(req: Request) {',
      '  const body = await req.json()',
      '  const session = await getServerSession(authOptions)',
      '  if (!session) return Response.json({error:"Unauthorized"},{status:401})',
      '  return Response.json({ ok: true })',
      '}',
    ].join('\n') + '\n',
    releaseId: 'test-release',
  },
  expectedFindings: null,
  expectedCanonicalHash: 'f671c66d296f554c889f7563aa285fdc8ededf7e113ed91b0265ea2b808c377a',
}

/**
 * Anti-pattern scope vector 2: scope="file" — import-at-top suppresses match at line 40.
 *
 * An import-based anti-pattern rule. The suppressing import is at line 1,
 * the match `userInput` is at line 40. With scope="file", the occurrence is suppressed.
 */
const ANTI_PATTERN_SCOPE_FILE_SUPPRESSED: ConformanceVector = {
  id: 'anti-pattern-scope-file-1',
  description: 'antiPatternScope="file": import at line 1 suppresses match at line 40',
  category: 'anti-pattern',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['userInput'],
      antiPatterns: ['import.*sanitize'],
      flags: '',
      antiPatternScope: 'file',
    },
    relativePath: 'src/handler.ts',
    content: (() => {
      const ls: string[] = ['import { sanitize } from "./sanitize"']
      for (let i = 2; i <= 39; i++) ls.push(`// line ${i}`)
      ls.push('const result = sanitize(userInput)')
      return ls.join('\n') + '\n'
    })(),
    releaseId: 'test-release',
  },
  expectedFindings: null,
  expectedCanonicalHash: '5c8f008880f0828156ed1ae1bdd28c14aaa2645cbef39e26c3e6c9e194877582',
}

/**
 * Anti-pattern scope vector 3: scope={lines:0} — strict per-line (no suppression from adjacent line).
 *
 * Anti-pattern is on line 2; match is on line 1. With {lines:0} the anti-pattern
 * is outside the window → occurrence remains active.
 */
const ANTI_PATTERN_SCOPE_LINES0_ACTIVE: ConformanceVector = {
  id: 'anti-pattern-scope-lines0-1',
  description: 'antiPatternScope={lines:0}: anti-pattern on adjacent line does NOT suppress',
  category: 'anti-pattern',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['SECRET'],
      antiPatterns: ['validate'],
      flags: '',
      antiPatternScope: { lines: 0 },
    },
    relativePath: 'src/test.ts',
    content: 'const SECRET = getValue()\nconst check = validate()\n',
    releaseId: 'test-release',
  },
  expectedFindings: null,
  expectedCanonicalHash: '9354567a60d370bd25a3578cc236917540f9c6a608dde03d2c2bec015f88f39a',
}

/**
 * Anti-pattern scope vector 4: scope="statement" (default) — cookie option on next line.
 *
 * A cookie-options rule. The match `setCookie` is on line 1, the safe option
 * `httpOnly` is on line 2 (inside the same multi-line call expression opened on line 1).
 * With scope="statement", the match line has an unclosed `(` → expands to include
 * line 2 → suppressed.
 */
const ANTI_PATTERN_SCOPE_STATEMENT_SUPPRESSED: ConformanceVector = {
  id: 'anti-pattern-scope-statement-1',
  description: 'antiPatternScope="statement" (default): cookie option on next line suppresses match',
  category: 'anti-pattern',
  executorDependent: true,
  input: {
    matcher: {
      type: 'pattern',
      fileGlob: '**/*.ts',
      patterns: ['setCookie'],
      antiPatterns: ['httpOnly'],
      flags: '',
      // no antiPatternScope → defaults to "statement"
    },
    relativePath: 'src/middleware.ts',
    content: [
      'setCookie(name, value, {',
      '  httpOnly: true,',
      '  secure: true,',
      '})',
    ].join('\n') + '\n',
    releaseId: 'test-release',
  },
  expectedFindings: null,
  expectedCanonicalHash: 'd893dbebdc1ca35b703871d7e9482d9ce36a6cd348c5ebe2e2e8e03ce73df8db',
}

// ---------------------------------------------------------------------------
// The exported vector set
// ---------------------------------------------------------------------------

/**
 * All conformance vectors.
 *
 * Split into:
 * - executorIndependentVectors: can be run in Phase A against pure contract functions.
 * - executorDependentVectors: skeleton; Phase B.1 / D.1 runs these with real adapters.
 */
export const executorIndependentVectors: ConformanceVector[] = [
  NORM_VECTOR_INVALID_UTF8,
  NORM_VECTOR_CRLF,
  NORM_VECTOR_BOM,
  FLAGS_VECTOR_REJECT_G,
  FLAGS_VECTOR_ACCEPT_IMS,
  CAPS_VECTOR_MAXRULES,
]

export const executorDependentVectors: ConformanceVector[] = [
  PATTERN_VECTOR_NO_FLAGS,
  PATTERN_VECTOR_FLAG_I,
  PATTERN_VECTOR_FLAG_M,
  PATTERN_VECTOR_FLAG_S,
  PATTERN_VECTOR_FLAG_IM,
  FILE_PRESENCE_VECTOR,
  ANTI_PATTERN_VECTOR,
  ZERO_WIDTH_VECTOR,
  FILE_RELATIONSHIP_VECTOR,
  ANTI_PATTERN_SCOPE_FUNCTION_SUPPRESSED,
  ANTI_PATTERN_SCOPE_FILE_SUPPRESSED,
  ANTI_PATTERN_SCOPE_LINES0_ACTIVE,
  ANTI_PATTERN_SCOPE_STATEMENT_SUPPRESSED,
]

/** All vectors combined. */
export const allConformanceVectors: ConformanceVector[] = [
  ...executorIndependentVectors,
  ...executorDependentVectors,
]
