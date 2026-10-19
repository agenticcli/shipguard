// Phase B.1 — native-v1 matching engine adapter
//
// Implements HarnessExecutor using Node.js built-in RegExp (zero new deps).
// Also satisfies MatcherExecutor<T> semantics per matcher variant.
// Exports NATIVE_V1_RUNTIME_ID frozen in this commit (Phase B.1 freeze point).
//
// DESIGN DECISIONS
// ================
// 1. Zero new runtime deps: native RegExp only (constraint §Global Constraints).
//
// 2. HarnessExecutor interface (harness.ts) is satisfied: evaluate() accepts any
//    Matcher variant and returns CanonicalFinding[].
//
// 3. Rule-level metadata (id, severity, blocking) is NOT on the Matcher type —
//    it lives on the Rule in the corpus. When the harness calls the executor
//    per-matcher (without rule metadata), stub values are used so the
//    CanonicalFinding shape is satisfied. Real adapters wired into the CLI will
//    inject the rule's id/severity/blocking before calling evaluate().
//
// 4. Anti-pattern check uses a CONTEXT WINDOW around the match (not per-line,
//    not file-wide). The window is determined by `PatternMatcher.antiPatternScope`
//    (default "statement"). Each occurrence is evaluated against its own window.
//    See AntiPatternScope in matcher.ts for scope modes and heuristic limitations.
//
// 5. Boundary mode is applied POST-MATCH (inspecting the character immediately
//    following the matched text), NOT by re-compiling the regex.
//
// 6. Zero-width matches advance lastIndex by 1 (UTF-16 code unit) to avoid
//    infinite loops; the zero-width occurrence is still recorded.
//
// 7. The 'g' flag is added internally for the exec loop; user flags (i/m/s)
//    are passed through. The 'g' flag must NOT appear in the rule's flags string.

import { parseFlags } from '../flags.js'
import type { Matcher, FileView, ExecCtx, SuppressionState, AntiPatternScope } from '../matcher.js'
import type { CanonicalFinding, Severity } from '../finding.js'
import type { HarnessExecutor } from '../conformance/harness.js'
// computeMatcherRuntimeId and makeNativeEngineMeta are no longer needed here —
// NATIVE_V1_RUNTIME_ID is now a frozen literal constant (CW-1 freeze).

// ---------------------------------------------------------------------------
// Internal helpers
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
 * Extract the text of a single 1-based line from content.
 * Lines are separated by '\n'. Returns '' if lineNum is out of range.
 *
 * Retained for potential future use by callers; currently unused after
 * the context-window scope implementation replaced the per-line check.
 */
function getLine(content: string, lineNum: number): string {
  // Split once and index — acceptable for the file sizes the scanner handles.
  const lines = content.split('\n')
  return lines[lineNum - 1] ?? ''
}

/**
 * Resolve the line range [startLine, endLine] (both 1-based, inclusive) to
 * search for anti-patterns given a match on `matchLine` and the rule's
 * `antiPatternScope`.
 *
 * All lines are 1-based. `totalLines` is the total number of lines in the file.
 *
 * ## Scope heuristics
 *
 * ### "statement" (default)
 * Expand from the match line by tracking brace/paren balance until balanced,
 * plus any continuation lines at the same or greater indentation.  The window
 * covers from the first imbalanced-open line back to the matching close, or
 * ±1 line if no braces are found.  This is a pragmatic approximation — see
 * AntiPatternScope LIMITATIONS.
 *
 * ### "block"
 * Walk backward from the match line to the nearest `{` that opens a block,
 * then forward to its matching `}`.
 *
 * ### "function"
 * Walk backward from the match line to the nearest line containing `function`,
 * `=>`, or `def`, then forward to the matching `}` (or de-indented line for
 * indent languages).
 *
 * ### "file"
 * Return [1, totalLines] — the full file.
 *
 * ### { lines: N }
 * Return [max(1, matchLine - N), min(totalLines, matchLine + N)].
 */
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
    // "statement" scope: the match line itself, plus any forward continuation
    // lines needed to balance UNCLOSED PARENTHESES `(` on the match line.
    //
    // ## Gating on parentheses only (not braces)
    //
    // We use net-open PARENTHESES as the expansion gate:
    //   - If net parens on match line <= 0: window = [matchLine, matchLine].
    //     This handles single-line statements and function/block declarations
    //     (e.g. `export async function POST(req: Request) {` has balanced parens
    //     on line 1, so the function body is NOT included in the statement scope).
    //   - If net parens > 0: the match line has an unclosed function call (e.g.
    //     `setCookie(name, value, {`). Expand forward tracking ALL brackets
    //     (parens + braces) until the total balance returns to <= 0.
    //
    // ## Why parens, not braces?
    //
    // A trailing `{` on a function/if/for DECLARATION line opens a BLOCK BODY.
    // The pattern match is on the declaration, not the body. We do not want the
    // statement scope to pull in the body contents — use scope="function" for
    // that. By gating on paren balance only, we distinguish:
    //   - `function POST(req) {` — parens balanced → no expansion (body not in scope)
    //   - `setCookie(name, value, {` — unclosed paren → expand to cover the args
    //
    // LIMITATION: template literals, destructuring, and JSX may confuse the count.
    const matchLineText = lines[matchLine - 1] ?? ''
    const matchLineParenNet =
      (matchLineText.match(/\(/g) ?? []).length -
      (matchLineText.match(/\)/g) ?? []).length

    if (matchLineParenNet <= 0) {
      // No unclosed parens on match line → statement is the match line itself.
      return { startLine: matchLine, endLine: matchLine }
    }

    // Unclosed paren(s) on match line → multi-line expression; expand forward.
    // Track combined paren+brace balance until it returns to <= 0.
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
    // Walk backward to find the nearest `{` that opens a block.
    // Count net brace opens/closes — stop when we find an enclosing `{`.
    let balance = 0
    let blockStart = matchLine

    for (let i = matchLine; i >= 1; i--) {
      const l = lines[i - 1]
      const opens = (l.match(/\{/g) ?? []).length
      const closes = (l.match(/\}/g) ?? []).length
      balance += closes - opens
      if (balance < 0) {
        // We found the enclosing `{`
        blockStart = i
        break
      }
    }

    // Walk forward to find the matching `}`.
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
    // Walk backward from the match line to find the nearest function keyword.
    // Matches: `function`, `=>` (arrow), or `def` (Python).
    const FUNC_RE = /\bfunction\b|=>|\bdef\b/
    let funcStart = matchLine

    for (let i = matchLine; i >= 1; i--) {
      const l = lines[i - 1]
      if (FUNC_RE.test(l)) {
        funcStart = i
        break
      }
    }

    // Walk forward from funcStart to find the closing `}` (brace languages)
    // or de-indented line (indent languages — approximated as a blank/lower-indent line).
    let balance = 0
    let funcEnd = matchLine

    for (let i = funcStart; i <= totalLines; i++) {
      const l = lines[i - 1]
      const opens = (l.match(/\{/g) ?? []).length
      const closes = (l.match(/\}/g) ?? []).length
      balance += opens - closes
      funcEnd = i
      // For brace languages: balance reaches 0 after at least one open
      if (balance <= 0 && i > funcStart) break
    }

    return { startLine: funcStart, endLine: funcEnd }
  }

  // Fallback (should be unreachable with valid AntiPatternScope):
  return { startLine: matchLine, endLine: matchLine }
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
// Minimal glob matcher for requiresFile
// ---------------------------------------------------------------------------

/**
 * Convert a simple glob pattern to a RegExp for path matching.
 *
 * Supports:
 *   `**` → matches any sequence of characters including '/' (any path prefix/suffix)
 *   `*`  → matches any sequence of characters NOT including '/'
 *   `.`  → literal dot
 *   Everything else: literal character.
 *
 * Anchored at both ends (full path match).
 */
function globToRegExp(glob: string): RegExp {
  let regexStr = '^'
  let i = 0
  while (i < glob.length) {
    if (glob[i] === '*' && glob[i + 1] === '*') {
      regexStr += '.*'
      i += 2
      // Consume an optional leading or trailing slash to allow matching
      // paths like '.env.example' from glob '**/.env.example'.
      if (glob[i] === '/') i++
    } else if (glob[i] === '*') {
      regexStr += '[^/]*'
      i++
    } else if (glob[i] === '.') {
      regexStr += '\\.'
      i++
    } else {
      // Escape regex metacharacters in the literal part.
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
    // Invalid flags at runtime → produce zero findings (compile failure, not a crash).
    // the adapter caller must validate flags at Gate B/C;
    // here we degrade silently at runtime to avoid crashing the whole scan.
    return []
  }

  // Build the internal flags string: user flags + 'g' for the exec loop.
  // 'd' (indices) is available in Node 20+ but we do NOT need it — we compute
  // line/col from the match offset directly.
  const internalFlagsStr = [...flagsResult.flags].join('') + 'g'

  const findings: CanonicalFinding[] = []
  const id = stubId('pattern')
  const boundary = matcher.boundary ?? 'none'

  for (const patternStr of matcher.patterns) {
    let re: RegExp
    try {
      re = new RegExp(patternStr, internalFlagsStr)
    } catch (err: unknown) {
      // FAIL CLOSED, do not skip (routed from the 2026-08-04 silent-failure sweep).
      //
      // This used to `continue`, which meant an uncompilable pattern produced ZERO findings
      // for that rule and the scan reported a clean result over a rule that never ran. The
      // fallback is dormant today — re2js-v1 is the active executor — but it is one
      // rule-corpus change away from being armed, and the failure would be invisible: a
      // green scan is exactly what a skipped rule looks like.
      //
      // The re2js executor already throws here (its FIX 5 atomic-compile contract). This
      // brings the native fallback to the same behaviour, so which executor is active can
      // never change whether a broken rule is loud or silent.
      const detail = err instanceof Error ? err.message : String(err)
      // eslint-disable-next-line no-console
      console.error(
        `[native-v1] compile error for pattern ${JSON.stringify(patternStr)}: ${detail}`,
      )
      throw new Error(
        `[native-v1] pattern compile failure for ${JSON.stringify(patternStr)} — bundle ` +
          `degraded (fail-closed): ${detail}`,
      )
    }

    let match: RegExpExecArray | null
    while ((match = re.exec(file.content)) !== null) {
      const matchStart = match.index
      const matchEnd = matchStart + match[0].length

      // Zero-width match: advance lastIndex to avoid an infinite loop.
      if (match[0].length === 0) {
        re.lastIndex = matchStart + 1
      }

      // --- Boundary check (post-match, per-occurrence) ---
      if (boundary !== 'none') {
        const nextChar = matchEnd < file.content.length ? file.content[matchEnd] : ''
        if (boundary === 'token' && isTokenChar(nextChar)) {
          // Next char is [a-zA-Z0-9_-] → reject this occurrence.
          continue
        }
        if (boundary === 'word' && isWordChar(nextChar)) {
          // Next char is \w → reject this occurrence.
          continue
        }
      }

      // --- Position computation ---
      const { line, column } = lineCol(file.content, matchStart)

      // --- Anti-pattern context window check ---
      // Resolve the search window for this occurrence based on antiPatternScope.
      // Default: "statement" (enclosing statement heuristic).
      // See AntiPatternScope in matcher.ts for modes and heuristic limitations.
      let suppressionState: SuppressionState = 'active'

      if (matcher.antiPatterns.length > 0) {
        const scope: AntiPatternScope = matcher.antiPatternScope ?? 'statement'
        const allLines = file.content.split('\n')
        const { startLine, endLine } = resolveAntiPatternWindow(allLines, line, scope)
        // Extract the window text (inclusive, 1-based → 0-based slice).
        const windowText = allLines.slice(startLine - 1, endLine).join('\n')

        for (const antiStr of matcher.antiPatterns) {
          let antiRe: RegExp
          try {
            // Anti-pattern uses the same user flags (but NOT 'g' — we just test).
            antiRe = new RegExp(antiStr, [...flagsResult.flags].join(''))
          } catch (err: unknown) {
            // FAIL CLOSED, do not skip (routed from the 2026-08-04 silent-failure sweep).
            //
            // Skipping a broken anti-pattern is WORSE than skipping a broken pattern: the
            // rule keeps firing but without the guard that stops it firing on legitimate
            // code, so the user gets false positives with no indication that the rule is
            // running half-configured. Same reasoning as re2js-v1's FIX 5, which already
            // refuses to run a rule whose anti-pattern would not compile.
            const detail = err instanceof Error ? err.message : String(err)
            // eslint-disable-next-line no-console
            console.error(
              `[native-v1] compile error for anti-pattern ${JSON.stringify(antiStr)}: ${detail}`,
            )
            throw new Error(
              `[native-v1] anti-pattern compile failure for ${JSON.stringify(antiStr)} — the ` +
                `rule would run without its guard (fail-closed): ${detail}`,
            )
          }
          if (antiRe.test(windowText)) {
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
        evidence: match[0],
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
  // The executor is called for each file matched by the glob.
  // For must-not-exist: the file exists (it matched the glob + is in allRelativePaths)
  //   → fire one finding.
  // For must-exist: the file exists (it was passed to us) → no finding.

  if (matcher.presenceRule === 'must-not-exist') {
    // File is present (executor was called on it) → must-not-exist violated.
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

  // presenceRule === 'must-exist': the file was found → satisfied → no finding.
  return []
}

function evaluateFileRelationship(
  matcher: Extract<Matcher, { type: 'file-relationship' }>,
  file: FileView,
  ctx: ExecCtx,
): CanonicalFinding[] {
  const { requiresFile, requiresPattern } = matcher.context

  // requiresFile: a companion glob must match at least one path in allRelativePaths.
  if (requiresFile !== undefined) {
    const globRe = globToRegExp(requiresFile)
    const found = ctx.allRelativePaths.some((p) => globRe.test(p))
    if (!found) {
      // Companion file is missing → finding.
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
    // Companion file found and requiresPattern not set → no finding.
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

  // requiresPattern without requiresFile: the harness provides only paths, not content.
  // Fix 4 (F3-contract): fail closed — fire a finding instead of returning zero.
  // A silent zero is a false negative on a signed rule that requires a content check.
  return [
    {
      id: stubId('file-relationship'),
      file: file.relativePath,
      line: 1,
      column: 1,
      evidence: `requiresPattern "${requiresPattern}" (file content unavailable — fail closed)`,
      severity: STUB_SEVERITY,
      blocking: STUB_BLOCKING,
      suppressionState: 'active',
      releaseId: ctx.releaseId,
      matcherType: 'file-relationship',
    },
  ]
}

// ---------------------------------------------------------------------------
// The exported HarnessExecutor
// ---------------------------------------------------------------------------

/**
 * The native-v1 executor: uses Node.js built-in RegExp, zero new runtime deps.
 *
 * Implements HarnessExecutor (from conformance/harness.ts) so the conformance
 * harness can inject it directly.
 *
 * Rule-level fields (id, severity, blocking) that are not present on the Matcher
 * type use stable stub values:
 *   id       → 'rule:pattern' | 'rule:file-presence' | 'rule:file-relationship'
 *   severity → 'medium'
 *   blocking → false
 *
 * The CLI integration layer (Task A-CLI-INT.2) will wrap this executor with
 * a rule-aware shim that injects the real id/severity/blocking before delegating
 * to evaluate().
 */
export const nativeV1Executor: HarnessExecutor = {
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
        // Exhaustiveness guard — TypeScript enforces this at compile time;
        // this branch is unreachable with well-typed callers.
        const _never: never = matcher
        void _never
        return []
      }
    }
  },
}

// ---------------------------------------------------------------------------
// NATIVE_V1_RUNTIME_ID — Phase B.1 freeze point
// ---------------------------------------------------------------------------

/**
 * SHA-256 of `src/adapters/native-v1.ts` at the CW-1 (antiPatternScope context
 * windows) freeze commit.
 *
 * Computed at freeze time with:
 *   sha256sum packages/matcher-contract/src/adapters/native-v1.ts
 *
 * This hash is part of the runtimeId preimage (matcher spec §9.1 `adapterImplHash`).
 * Any change to this file's source after this commit MUST produce a new freeze
 * (new adapterImplHash → new NATIVE_V1_RUNTIME_ID).
 *
 * CW-1 change: antiPatternScope context windows added to evaluatePattern() —
 * the adapter now resolves per-occurrence scope windows (statement/block/function/
 * file/{ lines: N }) instead of per-line anti-pattern checks.
 */
export const NATIVE_V1_ADAPTER_IMPL_HASH =
  'cf2b2cceadfeee49c106630ff4bdf640e3a68286d3fb6dab9c43888ec6adf252' as const

/**
 * The frozen matcherRuntimeId for the native-v1 adapter after the CW-1 freeze.
 *
 * ## Freeze inputs (matcher spec §9.1 — all values are stable constants)
 *
 * | Field              | Value                                             |
 * |--------------------|---------------------------------------------------|
 * | contractVersion    | 0.2.0                                             |
 * | adapterImplHash    | NATIVE_V1_ADAPTER_IMPL_HASH (sha256 of CW-1 src) |
 * | engineVersion      | 20 (Node.js major — minimum supported per engines)|
 * | engineOptions      | { LOOKBEHINDS: false }                            |
 * | buildLock          | native-v1-build-2026-06-25                        |
 *
 * ## Frozen value
 *
 * This constant is a FROZEN LITERAL set at the CW-1 (antiPatternScope context
 * windows) commit.  It reflects the updated adapterImplHash (sha256 of the CW-1
 * native-v1.ts source) and contractVersion 0.2.0.
 *
 * Phase C.2 imports this constant to embed the runtimeId in signed manifests.
 * Phase D.1 will produce a separate RE2JS_V1_RUNTIME_ID from the re2js adapter.
 */
export const NATIVE_V1_RUNTIME_ID =
  'e8b0dd347f200a329d0ca6f6ba4e30e1911cecbf083e6218031667aee5c2e018' as const
