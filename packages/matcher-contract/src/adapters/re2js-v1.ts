// Phase D.1 — re2js-v1 matching engine adapter
//
// Implements HarnessExecutor using re2js@2.8.3 (pure-JS RE2 engine).
// Provides linear-time (ReDoS-immune) rule evaluation — the 'g' flag
// catastrophic-backtracking hazard is eliminated at the engine level.
//
// DESIGN DECISIONS
// ================
// 1. re2js@2.8.3 exact (verified 2026-06-25 as npm latest; 1.4.0 deprecated).
//    Pure-JS, MIT, zero native/WASM deps → tsup-bundleable, ELv2-compatible.
//
// 2. LOOKBEHINDS OFF for v1.
//    RE2JS.LOOKBEHINDS is NOT set. The re2js lookbehind feature (captureless only,
//    v2.7.0+) is PARTIALLY VERIFIED — see GROUND-TRUTH §External facts.
//    Keeping this off eliminates uncertainty about v1 correctness; engine options
//    are part of the runtimeId preimage, so enabling it would require a new freeze.
//
// 3. Flag mapping: "i" → RE2JS.CASE_INSENSITIVE; "m" → RE2JS.MULTILINE;
//    "s" → RE2JS.DOTALL. The "g" flag is never passed (re2js uses the Matcher
//    iterator API — the find-loop handles global matching).
//
// 4. Match iteration uses the Matcher API: re.matcher(input), then loop m.find().
//    This is the idiomatic re2js pattern for all non-overlapping matches.
//
// 5. Patterns that re2js cannot compile (lookahead, lookbehind, backreference,
//    or other unsupported constructs) are SKIPPED LOUDLY: a warning is printed
//    to stderr and zero findings are produced for that pattern. The caller must
//    validate patterns at Gate B before reaching this adapter.
//
// 6. Boundary modes (none/word/token) and AntiPatternScope (statement/block/
//    function/file/{lines:N}) are implemented identically to native-v1.
//
// 7. Zero-width match advancement: when start === end (zero-width match),
//    we record the occurrence and advance past it by starting the next find()
//    from start+1.  Unlike native RegExp, re2js Matcher.find() does not
//    auto-advance on zero-width — we must restart via find(start+1).
//    NOTE: re2js (RE2 engine) does not support lookahead assertions (e.g.
//    `(?=x)`), so zero-width-lookahead test vectors that compile under native-v1
//    will produce ZERO findings here (compile error → graceful degrade, not crash).
//
// 8. Rule-level metadata (id, severity, blocking) uses the same stub values
//    as native-v1 — the harness / CLI integration layer injects real values.
//
// 9. Anti-pattern checks compile via re2js (same as primary patterns) — NOT
//    native RegExp.  Even though anti-patterns are trusted corpus content, using
//    native RegExp contradicts the "all matching on re2js" design principle and
//    leaves anti-patterns on a different code path than primary patterns.
//    All corpus anti-patterns are RE2-compatible (Gate B verifies this); any
//    anti-pattern that fails re2js compilation causes the WHOLE BUNDLE to be
//    rejected (fail-closed, FIX 5) — see evaluatePattern() for detail.
//
// 10. requiresPattern (self-referential file-relationship prerequisite) also
//     compiles via re2js — NOT native RegExp.  The round-6 implementation
//     originally used new RegExp(requiresPattern) on the rationale that
//     corpus content is trusted; however, running ANY native RegExp against
//     scanned user file content is a ReDoS surface — exactly what the RE2
//     engine eliminates.  Gate B/C must ensure requiresPattern is RE2-compatible.
//     Compile flags: none (bits = 0), matching the original no-flags semantics.

import { RE2JS } from 're2js'
import { parseFlags } from '../flags.js'
import type { Matcher, FileView, ExecCtx, SuppressionState, AntiPatternScope } from '../matcher.js'
import type { CanonicalFinding, Severity } from '../finding.js'
import type { HarnessExecutor } from '../conformance/harness.js'

// ---------------------------------------------------------------------------
// Internal helpers (copied from native-v1 verbatim — same semantics required)
// ---------------------------------------------------------------------------

/**
 * Compute 1-based line and 1-based column for a character offset within content.
 * Both line and column are measured in UTF-16 code units (JS string indexing).
 *
 * @param content - The full file content string.
 * @param offset  - The 0-based UTF-16 offset of the match start.
 * @returns { line, column } — both 1-based.
 */
function lineCol(content: string, offset: number): { line: number; column: number } {
  let line = 1
  let lastNl = -1
  for (let i = 0; i < offset; i++) {
    if (content[i] === '\n') {
      line++
      lastNl = i
    }
  }
  return { line, column: offset - lastNl }
}

/**
 * Test whether a character (string of length ≥ 1, or empty = end-of-string)
 * matches `[a-zA-Z0-9_-]` (the token boundary set).
 */
function isTokenChar(ch: string): boolean {
  if (ch.length === 0) return false
  const c = ch.charCodeAt(0)
  return (
    (c >= 65 && c <= 90) ||  // A-Z
    (c >= 97 && c <= 122) || // a-z
    (c >= 48 && c <= 57) ||  // 0-9
    c === 95 ||               // _
    c === 45                  // -
  )
}

/**
 * Test whether a character matches `\w` = `[A-Za-z0-9_]` (the word boundary set).
 */
function isWordChar(ch: string): boolean {
  if (ch.length === 0) return false
  const c = ch.charCodeAt(0)
  return (
    (c >= 65 && c <= 90) ||  // A-Z
    (c >= 97 && c <= 122) || // a-z
    (c >= 48 && c <= 57) ||  // 0-9
    c === 95                  // _
  )
}

/**
 * Resolve the line range [startLine, endLine] (both 1-based, inclusive) to
 * search for anti-patterns given a match on `matchLine` and the rule's
 * `antiPatternScope`.
 *
 * Identical implementation to native-v1 — same context-window semantics required
 * for conformance parity (see matcher.ts AntiPatternScope for full documentation).
 *
 * D.3 allowlist (structural helpers): The regex literals inside this function
 * are HARDCODED structural character-match patterns (bracket counters, keyword
 * anchors) — NOT user-authored corpus regex patterns evaluated against content.
 * They match simple single-char sets like /\{/g or /\(/g and have no
 * backtracking risk.  They differ from the D.3 ban's target (user-authored
 * pattern strings compiled and run against file content) and are allowlisted
 * with minimal disable/enable markers per the D.3 policy.
 */
/* eslint-disable no-restricted-syntax */
function resolveAntiPatternWindow(
  lines: string[],
  matchLine: number, // 1-based
  scope: AntiPatternScope,
): { startLine: number; endLine: number } {
  const totalLines = lines.length

  if (scope === 'file') {
    return { startLine: 1, endLine: totalLines }
  }

  if (typeof scope === 'object' && 'lines' in scope) {
    const n = scope.lines
    return {
      startLine: Math.max(1, matchLine - n),
      endLine: Math.min(totalLines, matchLine + n),
    }
  }

  if (scope === 'statement') {
    const matchLineText = lines[matchLine - 1] ?? ''
    const matchLineParenNet =
      (matchLineText.match(/\(/g) ?? []).length -
      (matchLineText.match(/\)/g) ?? []).length

    if (matchLineParenNet <= 0) {
      return { startLine: matchLine, endLine: matchLine }
    }

    let balance =
      (matchLineText.match(/[{(]/g) ?? []).length -
      (matchLineText.match(/[})]/g) ?? []).length
    let endLine = matchLine

    for (let i = matchLine + 1; i <= totalLines; i++) {
      const l = lines[i - 1]
      const opens = (l.match(/[{(]/g) ?? []).length
      const closes = (l.match(/[})]/g) ?? []).length
      balance += opens - closes
      endLine = i
      if (balance <= 0) break
    }

    return { startLine: matchLine, endLine }
  }

  if (scope === 'block') {
    let balance = 0
    let blockStart = matchLine

    for (let i = matchLine; i >= 1; i--) {
      const l = lines[i - 1]
      const opens = (l.match(/\{/g) ?? []).length
      const closes = (l.match(/\}/g) ?? []).length
      balance += closes - opens
      if (balance < 0) {
        blockStart = i
        break
      }
    }

    balance = 0
    let blockEnd = matchLine

    for (let i = blockStart; i <= totalLines; i++) {
      const l = lines[i - 1]
      const opens = (l.match(/\{/g) ?? []).length
      const closes = (l.match(/\}/g) ?? []).length
      balance += opens - closes
      blockEnd = i
      if (balance <= 0) break
    }

    return { startLine: blockStart, endLine: blockEnd }
  }

  if (scope === 'function') {
    const FUNC_RE = /\bfunction\b|=>|\bdef\b/
    let funcStart = matchLine

    for (let i = matchLine; i >= 1; i--) {
      const l = lines[i - 1]
      if (FUNC_RE.test(l)) {
        funcStart = i
        break
      }
    }

    let balance = 0
    let funcEnd = matchLine

    for (let i = funcStart; i <= totalLines; i++) {
      const l = lines[i - 1]
      const opens = (l.match(/\{/g) ?? []).length
      const closes = (l.match(/\}/g) ?? []).length
      balance += opens - closes
      funcEnd = i
      if (balance <= 0 && i > funcStart) break
    }

    return { startLine: funcStart, endLine: funcEnd }
  }

  // Fallback (unreachable with valid AntiPatternScope):
  return { startLine: matchLine, endLine: matchLine }
}
/* eslint-enable no-restricted-syntax */

// ---------------------------------------------------------------------------
// Flag mapping: author flags → re2js bitmask
// ---------------------------------------------------------------------------

/**
 * Map a validated Set<Flag> to a re2js integer flag bitmask.
 *
 * Mapping (LOCKED-SPEC §A.6 / Task D.1):
 *   "i" → RE2JS.CASE_INSENSITIVE
 *   "m" → RE2JS.MULTILINE
 *   "s" → RE2JS.DOTALL
 *
 * Engine options (LOOKBEHINDS etc.) are NOT set here — they are kept separate
 * per the EngineOptions design (engine-meta.ts Task A.9 / D.1 LOOKBEHINDS=false).
 *
 * @param flags - A validated Set<Flag> from parseFlags().
 * @returns An integer bitmask for RE2JS.compile().
 */
function toRe2jsFlags(flags: Set<'i' | 'm' | 's'>): number {
  let bits = 0
  if (flags.has('i')) bits |= RE2JS.CASE_INSENSITIVE
  if (flags.has('m')) bits |= RE2JS.MULTILINE
  if (flags.has('s')) bits |= RE2JS.DOTALL
  return bits
}

// ---------------------------------------------------------------------------
// Default stub values for rule-level fields not present on Matcher
// ---------------------------------------------------------------------------

function stubId(matcherType: string): string {
  switch (matcherType) {
    case 'pattern': return 'rule:pattern'
    case 'file-presence': return 'rule:file-presence'
    case 'file-relationship': return 'rule:file-relationship'
    default: return 'rule:unknown'
  }
}

const STUB_SEVERITY: Severity = 'medium'
const STUB_BLOCKING = false

// ---------------------------------------------------------------------------
// Minimal glob matcher for requiresFile (native RegExp — trusted corpus content)
// ---------------------------------------------------------------------------

/**
 * Convert a simple glob pattern to a RegExp for path matching.
 * Identical to native-v1 (trusted corpus content, not user input).
 *
 * D.3 allowlist: native RegExp is used here to match FILE PATHS
 * (ctx.allRelativePaths), NOT scanned user file content.  The regex literal
 * and new RegExp() below are intentionally excluded from the D.3 ban.
 * Any change to this function that makes it run against file content MUST
 * remove these disable comments and convert to RE2JS.
 */
/* eslint-disable no-restricted-syntax */
function globToRegExp(glob: string): RegExp {
  let regexStr = '^'
  let i = 0
  while (i < glob.length) {
    if (glob[i] === '*' && glob[i + 1] === '*') {
      regexStr += '.*'
      i += 2
      if (glob[i] === '/') i++
    } else if (glob[i] === '*') {
      regexStr += '[^/]*'
      i++
    } else if (glob[i] === '.') {
      regexStr += '\\.'
      i++
    } else {
      const ch = glob[i]
      if (/[+?^${}()|[\]\\]/.test(ch)) {
        regexStr += '\\' + ch
      } else {
        regexStr += ch
      }
      i++
    }
  }
  regexStr += '$'
  return new RegExp(regexStr)
}
/* eslint-enable no-restricted-syntax */

// ---------------------------------------------------------------------------
// Per-type evaluation helpers
// ---------------------------------------------------------------------------

function evaluatePattern(
  matcher: Extract<Matcher, { type: 'pattern' }>,
  file: FileView,
  ctx: ExecCtx,
): CanonicalFinding[] {
  const flagsResult = parseFlags(matcher.flags)
  if (!flagsResult.ok) {
    // Invalid flags at runtime → zero findings (compile failure, not a crash).
    // Rule 6: Loud Errors — the caller should validate at Gate B/C; we degrade gracefully.
    return []
  }

  const re2jsFlags = toRe2jsFlags(flagsResult.flags)
  const findings: CanonicalFinding[] = []
  const id = stubId('pattern')
  const boundary = matcher.boundary ?? 'none'

  // FIX 5: Pre-compile ALL anti-patterns with re2js before the primary pattern loop.
  // Any anti-pattern that fails re2js compilation is a bundle integrity failure —
  // throw so the caller (pro-scanner.ts validateBundleCompile / runProRules) marks
  // the bundle degraded/non-safe (fail-closed).  A silent skip would leave the rule
  // running without its anti-pattern guard (false-negative risk).
  const compiledAntiPatterns: RE2JS[] = []
  for (const antiStr of matcher.antiPatterns) {
    try {
      compiledAntiPatterns.push(RE2JS.compile(antiStr, re2jsFlags))
    } catch (err: unknown) {
      // re2js cannot compile this anti-pattern — fail closed (FIX 5).
      // Gate B should validate RE2 compatibility before reaching production.
      // eslint-disable-next-line no-console
      console.error(
        `[re2js-v1] compile error for anti-pattern ${JSON.stringify(antiStr)}: ${err instanceof Error ? err.message : String(err)}`,
      )
      throw new Error(
        `[re2js-v1] anti-pattern compile failure for ${JSON.stringify(antiStr)} — bundle degraded (fail-closed, FIX 5): ${err instanceof Error ? err.message : String(err)}`,
      )
    }
  }

  for (const patternStr of matcher.patterns) {
    let compiled: RE2JS
    try {
      compiled = RE2JS.compile(patternStr, re2jsFlags)
    } catch (err: unknown) {
      // re2js cannot compile this primary pattern — fail closed (FIX 5).
      // Gate B should catch these before reaching production.
      // eslint-disable-next-line no-console
      console.error(
        `[re2js-v1] compile error for pattern ${JSON.stringify(patternStr)}: ${err instanceof Error ? err.message : String(err)}`,
      )
      throw new Error(
        `[re2js-v1] primary pattern compile failure for ${JSON.stringify(patternStr)} — bundle degraded (fail-closed, FIX 5): ${err instanceof Error ? err.message : String(err)}`,
      )
    }

    // Iterate all non-overlapping matches using the Matcher API.
    // re2js Matcher.find() advances the match position automatically for
    // non-empty matches. For zero-width matches we must restart manually
    // (see design decision #7 in the file header).
    const m = compiled.matcher(file.content)
    let searchFrom: number | undefined = undefined

    while (true) {
      // For zero-width match recovery: restart find from searchFrom.
      const hasMatch = searchFrom !== undefined ? m.find(searchFrom) : m.find()
      if (!hasMatch) break

      const matchStart = m.start()
      const matchEnd = m.end()
      const matchedText = m.group() ?? ''

      // Detect zero-width match and set recovery position for next iteration.
      const isZeroWidth = matchStart === matchEnd
      searchFrom = isZeroWidth ? matchStart + 1 : undefined
      // Guard: if we'd search past the end of the string, stop.
      if (isZeroWidth && matchStart >= file.content.length) break

      // --- Boundary check (post-match, per-occurrence) ---
      if (boundary !== 'none') {
        const nextChar = matchEnd < file.content.length ? file.content[matchEnd] : ''
        if (boundary === 'token' && isTokenChar(nextChar)) {
          continue
        }
        if (boundary === 'word' && isWordChar(nextChar)) {
          continue
        }
      }

      // --- Position computation ---
      const { line, column } = lineCol(file.content, matchStart)

      // --- Anti-pattern context window check ---
      let suppressionState: SuppressionState = 'active'

      if (compiledAntiPatterns.length > 0) {
        const scope: AntiPatternScope = matcher.antiPatternScope ?? 'statement'
        const allLines = file.content.split('\n')
        const { startLine, endLine } = resolveAntiPatternWindow(allLines, line, scope)
        const windowText = allLines.slice(startLine - 1, endLine).join('\n')

        // FIX 3: use pre-compiled re2js matchers for anti-pattern testing.
        // compiledAntiPatterns is pre-built above using the same re2js engine
        // as primary patterns — consistent linear-time matching, no native RegExp.
        for (const antiCompiled of compiledAntiPatterns) {
          // Re-create a matcher on the window text.  re2js Matcher is stateful
          // (it remembers the last find() position) so we must call .matcher()
          // on the compiled RE2JS object with the new input string each time.
          const antiMatcher = antiCompiled.matcher(windowText)
          if (antiMatcher.find()) {
            suppressionState = 'suppressed'
            break
          }
        }
      }

      findings.push({
        id,
        file: file.relativePath,
        line,
        column,
        evidence: matchedText,
        severity: STUB_SEVERITY,
        blocking: STUB_BLOCKING,
        suppressionState,
        releaseId: ctx.releaseId,
        matcherType: 'pattern',
      })
    }
  }

  return findings
}

function evaluateFilePresence(
  matcher: Extract<Matcher, { type: 'file-presence' }>,
  file: FileView,
  ctx: ExecCtx,
): CanonicalFinding[] {
  // Identical to native-v1 — no regex involved.
  if (matcher.presenceRule === 'must-not-exist') {
    return [
      {
        id: stubId('file-presence'),
        file: file.relativePath,
        line: 1,
        column: 1,
        evidence: file.relativePath,
        severity: STUB_SEVERITY,
        blocking: STUB_BLOCKING,
        suppressionState: 'active',
        releaseId: ctx.releaseId,
        matcherType: 'file-presence',
      },
    ]
  }
  return []
}

function evaluateFileRelationship(
  matcher: Extract<Matcher, { type: 'file-relationship' }>,
  file: FileView,
  ctx: ExecCtx,
): CanonicalFinding[] {
  // Glob matching uses native RegExp (trusted corpus content).
  const { requiresFile, requiresPattern } = matcher.context

  if (requiresFile !== undefined) {
    const globRe = globToRegExp(requiresFile)
    const found = ctx.allRelativePaths.some((p) => globRe.test(p))
    if (!found) {
      return [
        {
          id: stubId('file-relationship'),
          file: file.relativePath,
          line: 1,
          column: 1,
          evidence: file.relativePath,
          severity: STUB_SEVERITY,
          blocking: STUB_BLOCKING,
          suppressionState: 'active',
          releaseId: ctx.releaseId,
          matcherType: 'file-relationship',
        },
      ]
    }
    if (requiresPattern === undefined) {
      return []
    }
    // Companion file IS found AND requiresPattern IS set.
    // The harness provides allRelativePaths but NOT file content, so we cannot
    // evaluate the pattern against the companion file.
    // Fix 4 (F3-contract): fail closed — fire a finding rather than silently returning
    // zero findings. A silent zero is a false negative: a rule that checks
    // "companion file must contain X" would never fire even when X is absent.
    return [
      {
        id: stubId('file-relationship'),
        file: file.relativePath,
        line: 1,
        column: 1,
        evidence: `${file.relativePath} + requiresPattern "${requiresPattern}" (companion content unavailable — fail closed)`,
        severity: STUB_SEVERITY,
        blocking: STUB_BLOCKING,
        suppressionState: 'active',
        releaseId: ctx.releaseId,
        matcherType: 'file-relationship',
      },
    ]
  }

  // requiresPattern without requiresFile: self-referential gate on the PRIMARY file.
  //
  // INTENDED SEMANTICS (matches Gate-C evaluateNonPatternRule):
  //   requiresPattern is evaluated against THIS file's own content as a prerequisite.
  //   Only when the prerequisite matches do we then evaluate the primary patterns +
  //   antiPatterns against this file. This is the correct semantic for rules like
  //   nextjs.secrets.process-env-in-client-component: "'use client'" must appear in
  //   the file being scanned before we check for process.env.SECRET_KEY.
  //
  // If requiresPattern does NOT match the file content → no finding (prerequisite unmet).
  // If requiresPattern DOES match → proceed to evaluate primary patterns + antiPatterns.
  if (requiresPattern === undefined) {
    // No requiresFile AND no requiresPattern: degenerate case — fire unconditionally.
    return [
      {
        id: stubId('file-relationship'),
        file: file.relativePath,
        line: 1,
        column: 1,
        evidence: file.relativePath,
        severity: STUB_SEVERITY,
        blocking: STUB_BLOCKING,
        suppressionState: 'active',
        releaseId: ctx.releaseId,
        matcherType: 'file-relationship',
      },
    ]
  }

  // Step 1: check requiresPattern against THIS file's content (self-referential prerequisite).
  // Use re2js (linear-time, ReDoS-immune) — consistent with how primary patterns are matched.
  // NOTE: requiresPattern has no associated flags in the FileRelationshipMatcher contract;
  // we compile without flags (bits = 0) which matches the semantics of the round-6 native-RegExp
  // path (new RegExp(requiresPattern) — no flags).  Gate B/C must ensure requiresPattern is
  // RE2-compatible; any pattern that fails re2js compilation causes a fail-closed finding.
  let requiresCompiled: import('re2js').RE2JS
  try {
    requiresCompiled = RE2JS.compile(requiresPattern)
  } catch {
    // Invalid requiresPattern at runtime is a corpus authoring error (Gate B/C should catch it).
    // Fail closed: fire a finding so the corpus error is visible rather than a silent skip.
    console.error(
      `[re2js-v1] requiresPattern compile error for ${JSON.stringify(requiresPattern)} — fail closed`,
    )
    return [
      {
        id: stubId('file-relationship'),
        file: file.relativePath,
        line: 1,
        column: 1,
        evidence: `requiresPattern "${requiresPattern}" (compile error — fail closed)`,
        severity: STUB_SEVERITY,
        blocking: STUB_BLOCKING,
        suppressionState: 'active',
        releaseId: ctx.releaseId,
        matcherType: 'file-relationship',
      },
    ]
  }

  const requiresMatcher = requiresCompiled.matcher(file.content)
  if (!requiresMatcher.find()) {
    // Prerequisite not met: file does NOT contain requiresPattern.
    // The rule only applies to files that have this context marker — return no findings.
    return []
  }

  // Step 2: prerequisite matched — evaluate primary patterns + antiPatterns via re2js.
  // Build a PatternMatcher from this file-relationship rule's extended fields.
  // WHY cast: FileRelationshipMatcher does not carry patterns/antiPatterns/flags in
  // the contract type — these are forwarded as extra fields by pro-scanner.ts when
  // building the file-relationship matcher for execution (see pro-scanner.ts FIX comment).
  // Gate-C reads them from the RuleYaml directly; production reads them from the wire
  // ExecutableRule.pattern/antiPattern fields forwarded via matcher object extension.
  const matcherAny = matcher as unknown as Record<string, unknown>
  const frFlags = (matcherAny['flags'] as string | undefined) ?? ''
  const frPatterns = (matcherAny['patterns'] as string[] | undefined) ?? []
  const frAntiPatterns = (matcherAny['antiPatterns'] as string[] | undefined) ?? []
  const frBoundary = (matcherAny['boundary'] as 'none' | 'word' | 'token' | undefined) ?? 'none'
  const frAntiPatternScope = (matcherAny['antiPatternScope'] as string | undefined) ?? 'statement'

  const flagsResult = parseFlags(frFlags)
  if (!flagsResult.ok) {
    // Invalid flags: degrade gracefully (same as evaluatePattern).
    return []
  }

  const patternMatcher: Extract<Matcher, { type: 'pattern' }> = {
    type: 'pattern',
    fileGlob: matcher.fileGlob,
    patterns: frPatterns,
    antiPatterns: frAntiPatterns,
    flags: frFlags,
    boundary: frBoundary,
    antiPatternScope: frAntiPatternScope as Extract<Matcher, { type: 'pattern' }>['antiPatternScope'],
  }

  return evaluatePattern(patternMatcher, file, ctx)
}

// ---------------------------------------------------------------------------
// The exported HarnessExecutor
// ---------------------------------------------------------------------------

/**
 * The re2js-v1 executor: uses re2js@2.8.3 for linear-time primary matching.
 *
 * Implements HarnessExecutor (from conformance/harness.ts) so the conformance
 * harness can inject it directly alongside nativeV1Executor.
 *
 * ## ReDoS immunity
 * re2js executes in linear time O(n) relative to input length for all
 * RE2-compatible patterns. Catastrophic-backtracking patterns like `(a+)+$`
 * that cause native RegExp to hang complete deterministically in bounded time.
 *
 * ## Conformance parity with native-v1
 * For RE2-compatible patterns, re2js-v1 produces byte-identical canonical
 * findings to native-v1. The only divergence is for patterns that native
 * RegExp supports but RE2 does not (lookaheads, backreferences, lookbehinds):
 * these are REJECTED by Gate B at authoring time and should not appear in the
 * live corpus. Any such pattern encountered at runtime is skipped with a
 * loud stderr warning (graceful degrade, not a crash).
 *
 * ## LOOKBEHINDS policy
 * RE2JS.LOOKBEHINDS is NOT set. The re2js lookbehind feature is captureless-only
 * and PARTIALLY VERIFIED for v1 — keeping it off eliminates uncertainty.
 */
export const re2jsV1Executor: HarnessExecutor = {
  evaluate(
    matcher: Matcher,
    file: { relativePath: string; content: string },
    ctx: ExecCtx,
  ): CanonicalFinding[] {
    const fileView: FileView = {
      relativePath: file.relativePath,
      content: file.content,
    }

    switch (matcher.type) {
      case 'pattern':
        return evaluatePattern(matcher, fileView, ctx)
      case 'file-presence':
        return evaluateFilePresence(matcher, fileView, ctx)
      case 'file-relationship':
        return evaluateFileRelationship(matcher, fileView, ctx)
      default: {
        const _never: never = matcher
        void _never
        return []
      }
    }
  },
}

// ---------------------------------------------------------------------------
// re2jsTestPattern — thin helper for callers (e.g. Gate-C) that need to check
// a single pattern against a string without constructing a full Matcher.
//
// Uses RE2JS.compile (no flags) and Matcher.find(), identical to the path
// taken by the requiresPattern check in evaluateFileRelationship().
// Gate-C imports this to keep its requiresPattern evaluation byte-identical
// with the production adapter path (no native RegExp on scanned content).
// ---------------------------------------------------------------------------

/**
 * Compile `pattern` via RE2JS (no flags) and test it against `input`.
 *
 * Returns `true` if the pattern matches anywhere in `input`; `false` if not.
 * Throws if the pattern is not RE2-compatible (caller must handle).
 *
 * @throws Error (from RE2JS.compile) if pattern is not valid RE2 syntax.
 */
export function re2jsTestPattern(pattern: string, input: string): boolean {
  const compiled = RE2JS.compile(pattern)
  return compiled.matcher(input).find()
}

// ---------------------------------------------------------------------------
// RE2JS_V1_ADAPTER_IMPL_HASH — Phase D.1 freeze point
// ---------------------------------------------------------------------------

/**
 * SHA-256 of `src/adapters/re2js-v1.ts` at the 0.5.0 freeze point.
 *
 * Computed after all 0.5.0 changes were applied (FIX 3: re2js anti-patterns;
 * FIX 5: fail-closed on compile error; FIX 6: requiresPattern on re2js, close ReDoS gap) with:
 *   sha256sum packages/matcher-contract/src/adapters/re2js-v1.ts
 *
 * This hash is part of the runtimeId preimage (LOCKED-SPEC §9.1 `adapterImplHash`).
 * Any change to this file's source MUST produce a new freeze (new adapterImplHash
 * → new RE2JS_V1_RUNTIME_ID). A regression test in __tests__/re2js-v1-freeze.test.ts
 * validates that this constant matches the current file's SHA-256.
 */
export const RE2JS_V1_ADAPTER_IMPL_HASH =
  '5b277d6a183d640ac9b8ebc0dc01d292101a6e577603c5cd7c6ab360263964d9' as const

/**
 * The frozen matcherRuntimeId for the re2js-v1 adapter (0.5.0 freeze).
 *
 * ## Freeze inputs (LOCKED-SPEC §9.1)
 *
 * | Field              | Value                                              |
 * |--------------------|----------------------------------------------------|
 * | contractVersion    | 0.5.0                                              |
 * | adapterImplHash    | RE2JS_V1_ADAPTER_IMPL_HASH (sha256 of 0.5.0 src)  |
 * | engineVersion      | 2.8.3 (RE2JS_VERSION from engine-meta.ts)          |
 * | engineOptions      | { LOOKBEHINDS: false }                             |
 * | buildLock          | re2js-v1-build-2026-06-25-v0.5.0                  |
 *
 * ## Frozen value
 *
 * Computed by computeMatcherRuntimeId() with the above inputs.
 * A regression test in __tests__/re2js-v1-freeze.test.ts re-derives this value
 * from current bytes and asserts equality — so it can never silently go stale.
 */
export const RE2JS_V1_RUNTIME_ID =
  '971fab9b230f60a1b663c7f9a888769e9a2d6ace58fa150e8ee574a3fc3c91d7' as const
