// Phase D.4 — shared re2js-backed regex engine for free-tier content detectors.
//
// PURPOSE
// =======
// Provides a minimal drop-in API surface for compiling and executing regex
// patterns in detector files (src/checks/**). Uses re2js@2.8.3 (pure-JS RE2
// engine) for linear-time, ReDoS-immune matching — identical engine as the
// Pro path (re2jsV1Executor in @agenticcli/matcher-contract).
//
// DESIGN CONSTRAINTS
// ==================
// 1. re2js does NOT support lookahead (?=)/(?!), lookbehind (?<=)/(?<!), or
//    backreferences (\1 etc.). Any such pattern MUST be rewritten before
//    calling compileDetectorRegex(), or the helper will THROW loudly (never
//    silently fall back to native RegExp — that would defeat ReDoS-immunity).
//
// 2. Flag mapping: 'i' → RE2JS.CASE_INSENSITIVE, 'm' → RE2JS.MULTILINE,
//    's' → RE2JS.DOTALL. The 'g' flag is NOT passed; the helper handles
//    multi-match iteration via the Matcher API internally.
//
// 3. exec() returns { match, index, groups } shaped identically to native
//    RegExpExecArray so call-site changes are minimal.
//
// 4. The helper is ONLY for content-scanning detectors. Do NOT use it for
//    path/filename classifiers (native RegExp is fine there).
//
// 5. replace(input, replacement) performs a GLOBAL replace (equivalent to
//    native String.prototype.replace with a /g regex). The replacement string
//    supports JS-style special patterns: $& (full match), $1/$2/…(groups),
//    $` (pre-match), $' (post-match), $$ (literal $). This is backed by the
//    re2js Matcher.replaceAll() API which uses JS-mode replacement semantics.
//
// API
// ===
//   compileDetectorRegex(source: string, flags?: string): CompiledDetectorRegex
//
// Where CompiledDetectorRegex exposes:
//   test(input: string): boolean
//   exec(input: string): DetectorExecResult | null
//   matchAll(input: string): DetectorExecResult[]   — all non-overlapping matches
//   replace(input: string, replacement: string): string  — global replace (all matches)
//
// DetectorExecResult:
//   match:  string   — full match text (equivalent to native exec()[0])
//   index:  number   — 0-based start position in input
//   groups: (string | undefined)[]  — capturing groups [1..n] (no index 0)

import { RE2JS } from 're2js'
import { parseFlags } from '@agenticcli/matcher-contract'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * The result shape returned by exec() / matchAll(), mirroring the useful
 * fields of a native RegExpExecArray without the prototype chain.
 *
 * - match:  the full matched text (native exec()[0])
 * - index:  0-based start position in the input string
 * - groups: capturing-group texts, 1-indexed by offset in the array
 *           (groups[0] = group 1, groups[1] = group 2, …).
 *           Unmatched optional groups are undefined.
 */
export interface DetectorExecResult {
  match: string
  index: number
  groups: (string | undefined)[]
}

/**
 * The compiled detector regex returned by compileDetectorRegex().
 * A single instance is compiled once and reused across many inputs.
 */
export interface CompiledDetectorRegex {
  /**
   * Returns true if the pattern matches anywhere in the input.
   * Equivalent to native RegExp.test().
   */
  test(input: string): boolean

  /**
   * Finds the FIRST match of the pattern in the input.
   * Returns null if no match. Equivalent to native RegExp.exec()
   * (without global lastIndex tracking — each call is stateless).
   */
  exec(input: string): DetectorExecResult | null

  /**
   * Finds ALL non-overlapping matches of the pattern in the input.
   * Returns an array (empty if no matches). Equivalent to [...str.matchAll(re)].
   */
  matchAll(input: string): DetectorExecResult[]

  /**
   * Replaces the FIRST occurrence of the pattern in the input with `replacement`.
   * Equivalent to `input.replace(nativeRegExp, replacement)` (non-global).
   * Returns the original string unchanged if there is no match.
   *
   * Capture group references ($1, $2, …) in `replacement` are NOT supported —
   * pass a plain string (no $ placeholders).  If you need group-based
   * substitution, use exec() and build the replacement string yourself.
   */
  replaceFirst(input: string, replacement: string): string

  /**
   * Replaces ALL non-overlapping matches of the pattern in the input with
   * the given replacement string. Equivalent to native
   * String.prototype.replace(/<pattern>/g, replacement).
   *
   * The replacement string supports JS-style special patterns:
   *   $$  — inserts a literal '$'
   *   $&  — inserts the entire matched substring
   *   $`  — inserts the portion before the match
   *   $'  — inserts the portion after the match
   *   $n  — inserts the nth capturing group (1-based)
   *
   * Backed by re2js Matcher.replaceAll() in JS-mode (javaMode=false), which
   * implements the same replacement semantics as native JS String.replace with /g.
   */
  replace(input: string, replacement: string): string
}

// ---------------------------------------------------------------------------
// Flag mapping helper (local — mirrors re2js-v1.ts toRe2jsFlags)
// ---------------------------------------------------------------------------

function toRe2jsFlags(flags: Set<'i' | 'm' | 's'>): number {
  let bits = 0
  if (flags.has('i')) bits |= RE2JS.CASE_INSENSITIVE
  if (flags.has('m')) bits |= RE2JS.MULTILINE
  if (flags.has('s')) bits |= RE2JS.DOTALL
  return bits
}

// ---------------------------------------------------------------------------
// Core implementation
// ---------------------------------------------------------------------------

/**
 * Compile a regex pattern string using the re2js engine.
 *
 * @param source - The regex pattern source (without surrounding slashes).
 * @param flags  - Optional flag string containing any combination of 'i', 'm', 's'.
 *                 'g' is NOT allowed (matchAll is handled internally).
 *                 Defaults to '' (no flags).
 *
 * @throws {Error} If the flags string is invalid (unknown/duplicate chars).
 * @throws {Error} If re2js cannot compile the pattern (lookahead, backreference,
 *                 or other RE2-unsupported construct). NEVER falls back to native
 *                 RegExp — a thrown error surfaces patterns that need rewriting.
 *
 * @example
 *   const re = compileDetectorRegex('sk-proj-[a-zA-Z0-9_\\-]{20,}', 'im')
 *   re.test("const key = 'sk-proj-abc123...'")   // → true
 *   re.exec("const key = 'sk-proj-abc123...'")   // → { match, index, groups }
 */
export function compileDetectorRegex(source: string, flags = ''): CompiledDetectorRegex {
  // 1. Validate and parse flags (reuse the contract's flag parser for consistency).
  //    'g' is explicitly banned in this helper — it's unnecessary (matchAll handles it).
  if (flags.includes('g')) {
    throw new Error(
      `[re2-detector-engine] 'g' flag is not allowed — use matchAll() for all-matches iteration. ` +
      `Pattern: ${JSON.stringify(source)}`,
    )
  }

  const parsed = parseFlags(flags)
  if (!parsed.ok) {
    throw new Error(
      `[re2-detector-engine] Invalid flags ${JSON.stringify(flags)}: ${parsed.reason}. ` +
      `Pattern: ${JSON.stringify(source)}`,
    )
  }

  const re2jsFlags = toRe2jsFlags(parsed.flags)

  // 2. Compile with re2js. Throws on unsupported constructs — never silently falls back.
  let compiled: RE2JS
  try {
    compiled = RE2JS.compile(source, re2jsFlags)
  } catch (err: unknown) {
    throw new Error(
      `[re2-detector-engine] re2js compilation failed for pattern ${JSON.stringify(source)} ` +
      `(flags: ${JSON.stringify(flags)}). Lookaheads, lookbehinds, and backreferences are ` +
      `not supported by re2js — rewrite the pattern to a RE2-compatible equivalent. ` +
      `Original error: ${err instanceof Error ? err.message : String(err)}`,
    )
  }

  // 3. Build the CompiledDetectorRegex wrapper.
  return {
    test(input: string): boolean {
      return compiled.matcher(input).find()
    },

    exec(input: string): DetectorExecResult | null {
      const m = compiled.matcher(input)
      if (!m.find()) return null
      // Group count: re2js groupCount() returns the number of capturing groups.
      const groupCount = compiled.groupCount()
      const groups: (string | undefined)[] = []
      for (let g = 1; g <= groupCount; g++) {
        // m.group(n) returns null for an unmatched optional group.
        const gv = m.group(g)
        groups.push(gv === null ? undefined : gv)
      }
      return {
        match: m.group() ?? '',
        index: m.start(),
        groups,
      }
    },

    matchAll(input: string): DetectorExecResult[] {
      const results: DetectorExecResult[] = []
      const m = compiled.matcher(input)
      const groupCount = compiled.groupCount()
      let searchFrom: number | undefined = undefined

      while (true) {
        const found = searchFrom !== undefined ? m.find(searchFrom) : m.find()
        if (!found) break

        const start = m.start()
        const end = m.end()

        const groups: (string | undefined)[] = []
        for (let g = 1; g <= groupCount; g++) {
          const gv = m.group(g)
          groups.push(gv === null ? undefined : gv)
        }

        results.push({
          match: m.group() ?? '',
          index: start,
          groups,
        })

        // Zero-width match guard (mirrors re2js-v1.ts design decision #7).
        if (start === end) {
          searchFrom = start + 1
          if (start >= input.length) break
        } else {
          searchFrom = undefined
        }
      }

      return results
    },

    replaceFirst(input: string, replacement: string): string {
      const m = compiled.matcher(input)
      if (!m.find()) return input
      const start = m.start()
      const end = m.end()
      return input.slice(0, start) + replacement + input.slice(end)
    },

    replace(input: string, replacement: string): string {
      // re2js Matcher.replaceAll() with javaMode=false uses JS-style replacement
      // semantics: $& = full match, $1/$2/... = groups, $` = pre, $' = post, $$ = literal $.
      // This is EXACTLY equivalent to native String.prototype.replace(/<re>/g, replacement).
      return compiled.matcher(input).replaceAll(replacement)
    },
  }
}
