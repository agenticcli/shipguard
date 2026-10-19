// Discriminated matcher-type union + executor interfaces.
// Matching logic is intentionally deferred to Phase B adapters.
// See Task A.2 in the matcher spec.

// ---------------------------------------------------------------------------
// File view & execution context
// ---------------------------------------------------------------------------

/**
 * A snapshot of a single file as the executor sees it.
 * `content` is guaranteed to be valid UTF-8 (TextDecoder fatal-mode, Task A.5).
 */
export interface FileView {
  /** Path relative to the scan root, normalised with forward slashes, no leading slash. */
  relativePath: string
  /** UTF-8 decoded file content with BOM stripped and CRLF normalised to LF (Task A.5). */
  content: string
}

/**
 * Execution context threaded through a scan.
 * Populated by the adapter layer (Phase B); opaque to the contract types.
 */
export interface ExecCtx {
  /** Root-relative paths of every file present in the scan snapshot (for file-relationship checks). */
  allRelativePaths: ReadonlyArray<string>
  /** The resolved `releaseId` of the rule bundle being evaluated (for MatchResult provenance). */
  releaseId: string
}

// ---------------------------------------------------------------------------
// Match result — full model (Task A.3)
// ---------------------------------------------------------------------------

/**
 * Suppression state for a single occurrence.
 *
 * - `"active"`: the occurrence is a real finding — no anti-pattern matched the
 *   context window of this occurrence.
 * - `"suppressed"`: an anti-pattern matched the context window of this specific
 *   occurrence's line; the occurrence is recorded but excluded from the
 *   blocking-finding count (NOT file-wide suppression — fixes the live bug
 *   where a single safe line swallowed all findings in the file).
 */
export type SuppressionState = 'active' | 'suppressed'

/**
 * One non-overlapping occurrence of a match within a file.
 *
 * ## Offset unit — UTF-16 code units (Codex E3)
 * ALL positional fields use **UTF-16 code units**, matching JavaScript's
 * `String` indexing and the re2js engine's offset semantics.  Byte offsets
 * and Unicode code-point offsets are intentionally absent: the triple-offset
 * representation adds substantial bug surface for no benefit in this stack.
 *
 * ## Line and column — 1-based, UTF-16 code units
 * `line` is 1-based.  `column` is 1-based and measured in UTF-16 code units
 * from the start of the line (after the preceding `\n`).  For BMP characters
 * (U+0000–U+FFFF) column equals the character index; for supplementary
 * characters (e.g. emoji) each surrogate pair counts as 2 code units.
 *
 * ## Zero-width match advancement
 * When the pattern matches a zero-width string at offset N the executor MUST
 * advance `lastIndex` to N+1 (1 UTF-16 code unit) before attempting the next
 * match, avoiding an infinite loop.  The zero-width occurrence itself is still
 * recorded.
 *
 * ## Anti-pattern scope — context window
 * Anti-patterns are evaluated within the context window defined by the rule's
 * `antiPatternScope` field (default: `"statement"`).  Per-occurrence semantics:
 * each occurrence is evaluated against its own scope window computed from the
 * match line.  A safe occurrence elsewhere in the file does NOT suppress
 * findings on other lines (no file-wide suppression).
 */
export interface MatchResultOccurrence {
  /**
   * Start position of the match in UTF-16 code units from the start of
   * `FileView.content` (0-based absolute offset within the normalised string).
   */
  offset: number

  /** 1-based line number of the match start (UTF-16 code-unit lines, split on `\n`). */
  line: number

  /**
   * 1-based column of the match start on its line, in UTF-16 code units
   * from the first code unit after the preceding `\n` (or from the start of
   * the string for line 1).
   */
  column: number

  /**
   * The matched text as it appears in `FileView.content`.
   *
   * Redaction policy: evidence is preserved verbatim at the contract layer.
   * The CLI display layer is responsible for truncating or masking secrets
   * before rendering to the terminal or writing to a log — the contract does
   * not truncate here so that downstream consumers (canonical finding hash,
   * Phase C attestation) see the full matched string.
   */
  evidence: string

  /**
   * A stable, per-occurrence key used to identify a suppression directive.
   * Format: `<relativePath>:<line>` (e.g. `"src/app.ts:42"`).
   *
   * Scoped to the matched line — two matches on the same line share the same
   * suppression key (intentional: a single `// shipguard-ignore` comment on a
   * line suppresses all findings on that line, not just the first).
   */
  suppressionKey: string

  /** Whether this occurrence is suppressed by an anti-pattern on the same line. */
  suppressionState: SuppressionState
}

/**
 * All non-overlapping matches produced by one rule against one file.
 *
 * The executor collects every pattern's matches, deduplicates overlapping
 * ones, and returns them all in a single `MatchResult`.  The caller (Gate C /
 * CLI) is responsible for sorting across rules.
 *
 * `occurrences` may be empty (no matches).  The result itself is always
 * returned — never null/undefined.
 */
export interface MatchResult {
  /**
   * The rule `id` that produced this result.
   * Mirrors `Finding.id` in `@agenticcli/shared` (`shared/src/types.ts:6`).
   * NOTE: deliberately named `ruleId` here (NOT `id`) so the contract type
   * is self-describing; `canonicalizeFinding` in `src/finding.ts` maps it to
   * the `Finding.id` field when emitting the canonical DTO.
   */
  ruleId: string

  /**
   * File path relative to the scan root, with forward-slash separators and
   * no leading slash.  Mirrors `FileView.relativePath`.
   */
  file: string

  /** The `releaseId` from `ExecCtx` — binds this result to a specific attested release. */
  releaseId: string

  /** The `Matcher.type` discriminant of the rule that produced this result. */
  matcherType: string

  /** Every non-overlapping occurrence found; empty array means no matches. */
  occurrences: readonly MatchResultOccurrence[]
}

// ---------------------------------------------------------------------------
// Matcher variant shapes
// ---------------------------------------------------------------------------

/**
 * Controls how wide a context window the executor searches for anti-patterns
 * relative to each primary match occurrence.
 *
 * ## Modes
 *
 * - `"statement"` (default): the enclosing statement — expand outward from the
 *   match line by following opening/closing braces and parentheses until they
 *   balance, OR (for indent languages like Python/YAML/SQL) until the surrounding
 *   non-blank run at the same or greater indentation ends.  A pragmatic heuristic;
 *   see LIMITATIONS below.
 *
 * - `"block"`: the enclosing `{...}` block.  Walk backward from the match line to
 *   find the opening `{` and forward to the matching `}`.  For rules where the
 *   anti-pattern is expected anywhere in the same brace block as the match.
 *
 * - `"function"`: the enclosing function/method body.  Walk backward to the
 *   nearest `function`, arrow `=>`, or `def` keyword and forward to its closing
 *   `}` / de-indented line.  For rules like `route-handler-no-auth` where the
 *   auth check (`getServerSession`) lives anywhere in the function body.
 *
 * - `"file"`: the entire file.  For import-based anti-patterns (e.g. a safe
 *   import at line 1 suppresses a match at line 40).
 *
 * - `{ lines: N }`: the match line ± N lines (simple sliding window).
 *   `{ lines: 0 }` is equivalent to strict per-line (the previous default).
 *
 * ## HEURISTIC LIMITATIONS (documented per matcher spec — not a guarantee)
 *
 * The scope heuristics are pragmatic approximations of syntactic structure
 * derived from the raw text without a full parse tree.  Known limitations:
 *
 * 1. **String/comment contamination** — brace characters inside string literals
 *    or multi-line comments are counted as structural braces, which can cause
 *    the computed scope to be wider or narrower than the true syntactic scope.
 *    Mitigation: use `{ lines: N }` or `"file"` for rules where this is a
 *    concern; or ensure anti-patterns are specific enough that false matches
 *    inside comments are harmless.
 *
 * 2. **Mixed-brace languages (JSX, template literals)** — JSX `{}` expressions
 *    intermixed with `<>` tags may confuse the brace-balancing walker.
 *
 * 3. **Nested functions** — `"function"` scope finds the NEAREST enclosing
 *    function keyword walking backward from the match line.  For nested lambdas,
 *    this may be the inner function, not the outer handler.  In practice, for
 *    `route-handler-no-auth`-shaped rules the auth check is typically in the
 *    same lexical function as the export, so this is acceptable.
 *
 * 4. **`"statement"` boundary detection** — the statement heuristic uses brace
 *    balance + indentation, which is a reasonable approximation for most
 *    TypeScript/JavaScript code but is not a formal parser.  For exotic
 *    one-liners or concatenated statements, it may include an extra line.
 *
 * Per-rule override (`antiPatternScope`) is the recommended escape hatch when
 * the default `"statement"` scope produces false positives or false negatives
 * for a specific rule.
 */
export type AntiPatternScope =
  | 'statement'
  | 'block'
  | 'function'
  | 'file'
  | { lines: number }

/**
 * Pattern-based matcher (218 / 222 corpus rules).
 * Patterns are RE2-compatible regular expressions; flags are validated by parseFlags().
 */
export interface PatternMatcher {
  type: 'pattern'
  /** Glob that restricts which files this rule applies to. */
  fileGlob: string
  /** One or more RE2-compatible patterns — ALL must be non-empty. */
  patterns: readonly string[]
  /**
   * Anti-patterns evaluated within the context window defined by `antiPatternScope`.
   * When an anti-pattern matches within the resolved window of an occurrence, that
   * occurrence is suppressed (retained with `suppressionState: "suppressed"`).
   * See `AntiPatternScope` for scope modes and heuristic limitations.
   */
  antiPatterns: readonly string[]
  /**
   * Validated subset of { "i", "m", "s" } as a plain string, e.g. "im".
   * Empty string means no flags. Validated by parseFlags() — "g"/"y"/"u"/"x" and
   * unknown/duplicate chars are rejected at schema, Gate B, Gate C, and runtime.
   */
  flags: string
  /**
   * Optional post-match boundary check applied AFTER the regex finds a match.
   * Controls whether the character immediately following the matched text is
   * examined. When absent the behaviour is identical to `'none'`.
   *
   * - `'none'` (default) — raw match; no post-match boundary check.
   *   Every occurrence the regex produces is accepted as-is.
   *
   * - `'word'` — require a word-boundary after the match end.
   *   An occurrence is REJECTED when the character at
   *   `match.index + match[0].length` satisfies `/\w/` (i.e. is `[A-Za-z0-9_]`).
   *   This is equivalent to appending `\b` conceptually but without re-compiling
   *   the regex; instead the executor inspects the next character inline.
   *
   * - `'token'` — the Gate-C opt-in heuristic; stricter than `'word'`.
   *   An occurrence is REJECTED when the character immediately following the
   *   matched text is `[a-zA-Z0-9_-]` (adds `-` to the word-char set).
   *   Originally the Gate-C global default; now an opt-in per-rule knob so
   *   that rules can explicitly request the old Gate-C behaviour without it
   *   applying to every pattern unconditionally.
   *
   * The old Gate-C `[a-zA-Z0-9_-]` check is NOT the universal default.
   * Default is `'none'` — the boundary field is purely additive and opt-in.
   */
  boundary?: 'none' | 'word' | 'token'

  /**
   * Controls the context window in which anti-patterns are searched relative
   * to each primary match occurrence.
   *
   * Default: `"statement"` — the enclosing statement (brace-balanced or
   * indentation-bounded run around the match line).  See `AntiPatternScope`
   * for full documentation of each mode and the heuristic limitations.
   *
   * Per-occurrence semantics: each occurrence is evaluated against its own
   * scope window.  A suppressed occurrence is retained in `MatchResult` with
   * `suppressionState: "suppressed"` and excluded from the active finding count.
   */
  antiPatternScope?: AntiPatternScope
}

/**
 * File-presence matcher (1 / 222 corpus rules).
 * Triggers when the glob matches (or does not match) a file path.
 */
export interface FilePresenceMatcher {
  type: 'file-presence'
  /** Glob that the rule checks for presence. */
  fileGlob: string
  /** Whether the rule fires when the file IS present or IS absent. */
  presenceRule: 'must-exist' | 'must-not-exist'
}

/**
 * File-relationship matcher (3 / 222 corpus rules).
 * Fires when a pattern match in one file implies a required companion file or pattern.
 */
export interface FileRelationshipMatcher {
  type: 'file-relationship'
  /** Glob that identifies the primary file to scan. */
  fileGlob: string
  context: {
    /** If set, the companion file (relative-path glob) must exist alongside the matched file. */
    requiresFile?: string
    /** If set, the companion file must also contain this RE2-compatible pattern. */
    requiresPattern?: string
  }
}

// TODO(config-value): a 4th variant for config-value matchers is defined in the
// authoring schema (scripts/schema.ts) but 0 of 222 corpus rules use it.
// Defer to a future minor version once corpus rules actually require it.
// See 2026-06-25-re2-IMPLEMENTATION-PLAN.md Task A.2.

// ---------------------------------------------------------------------------
// Discriminated union
// ---------------------------------------------------------------------------

/** All concrete matcher types supported by the v1 contract. Discriminated on `type`. */
export type Matcher = PatternMatcher | FilePresenceMatcher | FileRelationshipMatcher

// ---------------------------------------------------------------------------
// Executor interface
// ---------------------------------------------------------------------------

/**
 * The contract every Phase-B adapter must satisfy.
 * Adapters are engine-specific (native-v1, re2js-v1) and provide the actual match logic;
 * this interface is the engine-agnostic boundary.
 *
 * @typeParam T - The specific Matcher variant this executor handles.
 */
export interface MatcherExecutor<T extends Matcher> {
  /**
   * Evaluate `matcher` against a single `file` within `ctx`.
   *
   * CONTRACT:
   *   - Returns an empty array when there are no matches (never null/undefined).
   *   - Must NOT throw on a well-formed input; degrade via caller-level try/catch.
   *   - Results are unordered; the caller is responsible for sorting/dedup.
   */
  evaluate(matcher: T, file: FileView, ctx: ExecCtx): MatchResult[]
}
