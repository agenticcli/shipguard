// Free-tier checks — governance + tiering basis: /rules.md. Source of truth is migrating to the Convex rule registry.
/**
 * Auth & Session Protection check module.
 *
 * Detects unprotected admin/dashboard/billing routes in Next.js App Router,
 * Express, and Fastify projects. Framework-aware pattern matching with
 * explicit webhook exclusion.
 */

import type { CheckModule, FileInfo, Finding, Policy } from '@agenticcli/shared'
import { compileDetectorRegex } from '../core/re2-detector-engine.js'
import { logger } from '../utils/logger.js'

// ─── Path classifiers — native RegExp is fine (non-content) ──────────────────
// These match FILE PATHS / ROUTE STRINGS, not arbitrary user-controlled content.
// They are not ReDoS targets. eslint-disable is used because the ESLint ban covers
// all of src/checks/** but the intent is to ban CONTENT-SCANNING regex only.
/* eslint-disable no-restricted-syntax */

// ─── Sensitive route segments ─────────────────────────────────────────────────
//
// WHY `debug|internal|env|_debug|dev` ARE IN THIS LIST (added 2026-08-04)
// The benchmark in the platform repo (content-pipeline/benchmarks/RESULTS.md, FX-11)
// found a debug endpoint returning the entire `process.env` that ShipGuard did not
// flag. Root cause: `auth_route_without_guard` fired correctly for `/api/admin` and
// never for `/api/debug`, because this keyword list named five business-y segments
// and nothing else. A debug/internal/env route is at least as sensitive as a billing
// route — it is the segment developers reach for when they want to inspect live state,
// which is exactly the state an attacker wants.
//
// This widening is the SECONDARY fix. The primary one is a governed corpus rule
// (`generic.config.debug-endpoint-env-dump`) that detects the SINK — a response body
// containing the whole environment object — so a route called `/api/tmp2` is caught
// too. Path keywords can only ever catch what someone happened to name well; both
// layers ship because they fail in different directions.
//
// `internal` and `dev` are included alongside `debug`/`env` because they are the same
// class of "not meant for the public, guarded by nothing but obscurity" segment, and
// all four are conventional enough that a real route using them genuinely should carry
// an auth check. Deliberately NOT included: `api`, `test`, `health`, `status` — `api`
// is every route, and the other three are commonly, legitimately public.

// Matches Next.js App Router paths with or without a leading src/ prefix.
const SENSITIVE_NEXTJS_PAGE_PATTERN =
  /^(?:src\/)?app\/(admin|dashboard|billing|account|settings|management|debug|internal)(\/|$)/

// Next.js API route handlers (route.ts / route.js) under sensitive segments.
const SENSITIVE_API_ROUTE_PATTERN =
  /^(?:src\/)?app\/api\/(admin|users|billing|account|management|debug|internal|env|_debug)(\/|$)/

// Sensitive URL segments used in Express routes (path-fragment classifier, not content).
const SENSITIVE_EXPRESS_PATHS =
  /\/(admin|users|billing|account|management|debug|internal|env|_debug|dev)(\/|$)/

// Webhook paths — user auth is not expected here (path classifier, not content).
const WEBHOOK_PATH_PATTERN = /\/webhooks?\//

/* eslint-enable no-restricted-syntax */

// ─── Content-scanning patterns — re2js engine (ReDoS-immune) ──────────────────
//
// Express / Fastify route definitions — catches all HTTP verbs.
// re2js: 'i' flag applied; 'g' omitted (matchAll() handles iteration internally).
// No lookahead/lookbehind/backreference → RE2-safe, no rewrite needed.
// group[0] = HTTP verb (e.g. "get"), group[1] = route path string.
const RE2_EXPRESS_ROUTE_DEFINITION = compileDetectorRegex(
  `(?:router|app)\\.(get|post|put|patch|delete|all)\\s*\\(\\s*['"\`]([^'"\`,)]+)['"\`]`,
  'i',
)

// Active auth calls — applied ONLY over EXECUTABLE spans produced by the lexer.
// The variable-width lookbehinds (?<!\/{2}.*?)(?<!\*.*?) that were in the original
// AUTH_CALL_PATTERN are REMOVED: they were ReDoS-prone (backtracking on adversarial
// input), not RE2-translatable, and REDUNDANT because the lexer already excludes
// comment and string spans before this pattern runs.
// The dead AUTH_CALL_SITE_PATTERN (with a /g stale-lastIndex hazard and a
// variable-width lookbehind (?<!\/{2}[^\n]*?)) is also DELETED.
// No lookahead/lookbehind/backreference → RE2-safe.
const RE2_AUTH_CALL_PATTERN = compileDetectorRegex(
  `(?:auth|getServerSession|requireAuth|verifyToken|withAuth|clerkMiddleware|authMiddleware)\\s*\\(`,
)

// Commented-out auth — matches lines where a comment marker precedes an auth call.
// The [^\n]* allows tokens like `const session = await` between the marker and the call.
// No lookahead/lookbehind/backreference → RE2-safe.
const RE2_COMMENTED_AUTH_PATTERN = compileDetectorRegex(
  `^\\s*(?:\\/\\/|\\/\\*|\\*)[^\\n]*(?:auth|getServerSession|requireAuth|verifyToken)\\s*\\(`,
  'm',
)

// Express auth middleware attached before/around a route:
//   router.use(isAuthenticated)  or  router.use(authMiddleware)
// No lookahead/lookbehind/backreference → RE2-safe.
const RE2_EXPRESS_AUTH_MIDDLEWARE_PATTERN = compileDetectorRegex(
  `(?:router|app)\\.use\\s*\\([^)]*(?:auth|requireAuth|verifyToken|isAuth|isLogged|passport)\\w*`,
  'i',
)

// Middleware content coverage — checks whether middleware.ts references sensitive routes.
// No lookahead/lookbehind/backreference → RE2-safe.
const RE2_MIDDLEWARE_ADMIN_COVERAGE = compileDetectorRegex(
  `(?:admin|dashboard|billing|account|management)`,
)

// Inline auth check — verifies whether a 300-char route call slice contains auth middleware.
// No lookahead/lookbehind/backreference → RE2-safe.
const RE2_INLINE_AUTH_CHECK = compileDetectorRegex(
  `requireAuth|verifyToken|isAuth|isLogged|passport\\.authenticate`,
  'i',
)

// ─── Middleware file matchers ─────────────────────────────────────────────────
// Path classifier — native RegExp is fine (non-content).
// eslint-disable-next-line no-restricted-syntax
const MIDDLEWARE_FILE_PATTERN = /^(?:src\/)?middleware\.[tj]s$/

// ─── Next.js detection ───────────────────────────────────────────────────────
// Detect Next.js without reading disk (checks are pure (files, policy) → findings).
// Signals: App Router file paths, next.config.*, package.json with next dep.
// eslint-disable-next-line no-restricted-syntax
const NEXT_APP_ROUTER_PATH = /^(?:src\/)?(?:app\/|app$)/
// eslint-disable-next-line no-restricted-syntax
const NEXT_CONFIG_FILE = /^(?:src\/)?next\.config\.[cm]?[jt]s$/

/**
 * Returns true if the file list contains evidence that this is a Next.js project.
 *
 * Uses only file paths and package.json content — no disk access — so the
 * check remains a pure function. Signals checked (any one is sufficient):
 *   1. An App Router directory path (app/ or src/app/)
 *   2. A next.config.* file
 *   3. A package.json whose dependencies include "next"
 */
function isNextjsProject(files: FileInfo[]): boolean {
  for (const f of files) {
    if (NEXT_APP_ROUTER_PATH.test(f.relativePath)) return true
    if (NEXT_CONFIG_FILE.test(f.relativePath)) return true
    if (f.relativePath === 'package.json' || f.relativePath.endsWith('/package.json')) {
      try {
        const pkg = JSON.parse(f.content)
        const deps = { ...pkg.dependencies, ...pkg.devDependencies }
        if ('next' in deps) return true
      } catch (err: unknown) {
        // Malformed package.json — genuinely NOT conclusive here (unlike
        // database.ts/deployment.ts's checkPackageJson): isNextjsProject()
        // is an OR across THREE independent signals (app-router path,
        // next.config.*, package.json dep), so a broken package.json does
        // not disable the whole auth-check class — the other two signals
        // still run. Still loud (every catch block must log)
        // a malformed package.json is itself worth knowing about even when
        // it isn't fatal to this particular detection.
        const detail = err instanceof Error ? err.message : String(err)
        logger.warn(`[auth] Could not parse ${f.relativePath} as JSON — Next.js dependency signal skipped for this file (app-router path / next.config.* signals still apply): ${detail}`)
      }
    }
  }
  return false
}

// ─── Lexical scanner ─────────────────────────────────────────────────────────

/**
 * Extract the executable (non-comment, non-string-literal) text from a
 * TypeScript/JavaScript source string.
 *
 * The function walks the source character by character, classifying spans as:
 *   - EXECUTABLE  : code that can contain real function calls
 *   - LINE_COMMENT : `// … <EOL>` — not executable
 *   - BLOCK_COMMENT: `/* … *\/` — not executable
 *   - STRING       : `'…'`, `"…"`, or `` `…` `` — not executable
 *   - REGEX        : `/…/flags` — body emitted as NON-EXECUTABLE (same as STRING; see note)
 *
 * Conservative on uncertainty (false negative = worst outcome):
 *   - Unterminated single/double-quoted string (hits \n): the opening quote char
 *     is emitted as EXECUTABLE and scanning resumes from the next character, so
 *     any auth() that follows is still detected.
 *   - Unterminated block comment (hits EOF): remainder emitted as BLOCK_COMMENT.
 *     Auth() inside it was behind `/*` so it's not executable; hasCommentedAuthCall
 *     will still catch it for the "commented-out" branch.
 *   - Unterminated template literal (hits EOF): remainder emitted as STRING.
 *   - A `/` that looks like a regex start but hits \n before closing `/`: the
 *     opening `/` is emitted as EXECUTABLE and scanning backtracks to start+1.
 *
 * Regex literal note: regex literals are emitted as NON-EXECUTABLE (a gap).
 * A regex body like /requireAuth()/ contains the text `requireAuth(` which would
 * match AUTH_CALL_PATTERN if emitted as executable — producing a false negative where
 * a decoy regex literal `const x = /requireAuth()/` suppresses an "unprotected route"
 * finding on a file that has no real auth call. Skipping the body (same as strings)
 * prevents this spoof. The conservative choice here is to exclude, not include:
 * a real auth call inside a regex body is syntactically inert code — it never executes.
 *
 * Regex literal detection heuristic: a `/` is a regex start if the last meaningful
 * (non-whitespace) character emitted by EXECUTABLE spans was NOT one of:
 * `)`, `]`, `}`, an identifier/number char (`a-z A-Z 0-9 _ $`), or `.`
 * After those, `/` is the division operator. After everything else (operators,
 * open brackets, `,;:` etc., or at start of file), `/` starts a regex.
 *
 * Template interpolation note: `${…}` bodies ARE lexed recursively so that string
 * literals inside `${"requireAuth()"}` are correctly classified as non-executable
 * (preventing interpolation-spoof false negatives). See FIX 3 comment below.
 */

/**
 * Recursively lex the body of a `${…}` interpolation expression.
 *
 * FIX 3 — Interpolation-spoof false negative:
 *
 * The previous implementation scanned the interpolation body with a simple
 * brace-depth counter, emitting the raw text (including any string literals
 * inside the interpolation) as executable. This meant `${"requireAuth()"}` was
 * treated as an active call — the string content `"requireAuth()"` was emitted
 * verbatim, and AUTH_CALL_PATTERN matched `requireAuth(` inside it — suppressing
 * the "unprotected route" finding even though no real auth call exists.
 *
 * This function correctly lexes the interpolation body by:
 *   1. Tracking brace depth for `{` / `}` — only the depth-0 `}` closes the
 *      interpolation; inner `}` inside strings / comments are NOT counted.
 *   2. Handling `'`, `"`, `` ` `` (including nested template literals with their
 *      own `${…}` sections) so that braces inside string literals do NOT affect
 *      depth — preventing premature truncation.
 *   3. Skipping line comments (//) and block comments (slash-star...star-slash).
 *   4. Returning only the EXECUTABLE fragments (code outside strings/comments)
 *      from within the interpolation body, plus the index of the closing brace.
 *
 * @param src    Full source string being lexed.
 * @param start  Index of the first character AFTER the opening dollar-brace
 *               interpolation start (i.e. start of the interpolation body).
 * @returns      Object with execText (executable text from the body) and end
 *               (index of the closing brace, or src.length if unterminated).
 */
function lexInterpolationBody(src: string, start: number): { execText: string; end: number } {
  const len = src.length
  let i = start
  let depth = 1 // we are already inside the opening `{`
  const execParts: string[] = []

  while (i < len && depth > 0) {
    const ch = src[i]

    // ── `{` — increases depth ────────────────────────────────────────────────
    if (ch === '{') {
      execParts.push(ch)
      depth++
      i++
      continue
    }

    // ── `}` — decreases depth; stop when depth reaches 0 ────────────────────
    if (ch === '}') {
      depth--
      if (depth > 0) {
        execParts.push(ch)
        i++
      }
      // depth === 0: this is the closing `}` of the interpolation — stop.
      break
    }

    // ── `//` line comment — skip to EOL, do NOT emit as executable ───────────
    if (ch === '/' && i + 1 < len && src[i + 1] === '/') {
      i += 2
      while (i < len && src[i] !== '\n') i++
      continue
    }

    // ── `/*` block comment — skip to `*/`, do NOT emit as executable ─────────
    if (ch === '/' && i + 1 < len && src[i + 1] === '*') {
      i += 2
      while (i < len - 1) {
        if (src[i] === '*' && src[i + 1] === '/') { i += 2; break }
        i++
      }
      if (i >= len - 1) i = len // unterminated block comment — consume to EOF
      continue
    }

    // ── Single-quoted string `'…'` — skip content, do NOT emit as executable ─
    if (ch === "'") {
      i++ // skip opening `'`
      while (i < len) {
        const sc = src[i]
        if (sc === '\\' && i + 1 < len) { i += 2; continue }
        if (sc === "'") { i++; break } // closing `'`
        if (sc === '\n') break         // unterminated — resume from here
        i++
      }
      continue
    }

    // ── Double-quoted string `"…"` — skip content, do NOT emit as executable ─
    if (ch === '"') {
      i++ // skip opening `"`
      while (i < len) {
        const sc = src[i]
        if (sc === '\\' && i + 1 < len) { i += 2; continue }
        if (sc === '"') { i++; break } // closing `"`
        if (sc === '\n') break         // unterminated — resume from here
        i++
      }
      continue
    }

    // ── Nested template literal `` `…` `` — recursively lex ─────────────────
    // A backtick inside an interpolation body starts a nested template literal.
    // Its `${…}` sections can contain their own `}` characters; we must not let
    // them accidentally close the outer interpolation. We handle this by scanning
    // the nested template until its closing `` ` ``, recursing for each inner
    // interpolation.
    if (ch === '`') {
      i++ // skip opening backtick
      while (i < len) {
        const tc = src[i]
        if (tc === '\\' && i + 1 < len) { i += 2; continue }
        if (tc === '`') { i++; break } // closing backtick
        if (tc === '$' && i + 1 < len && src[i + 1] === '{') {
          // Nested interpolation inside the nested template — recurse to lex it
          // correctly (so its `}` does not affect the outer depth counter).
          i += 2 // skip '${'
          const inner = lexInterpolationBody(src, i)
          // FIX 2: emit the inner interpolation body's EXECUTABLE text so that a
          // real auth call in a doubly-nested interpolation (e.g.
          //   `${`${requireAuth(req)}`}` ) is still recognised by the detector.
          // The recursive call already classifies strings/comments inside the inner
          // body as non-executable, so only genuine code is propagated here.
          if (inner.execText.length > 0) {
            execParts.push(inner.execText)
          }
          i = inner.end < len ? inner.end + 1 : len // skip past closing `}`
          continue
        }
        i++ // regular template text character — skip
      }
      continue
    }

    // ── All other characters — emit as executable ────────────────────────────
    execParts.push(ch)
    i++
  }

  return { execText: execParts.join(''), end: i }
}

function extractExecutableText(src: string): string {
  // We accumulate executable chars into a buffer. All non-executable spans
  // (comments, strings) are replaced by a single space to avoid accidentally
  // joining identifiers across the gap (e.g. `auth/**/()` → `auth()` unintended).
  // A single space is safe: auth_CALL_PATTERN requires the identifier immediately
  // followed by optional whitespace and `(`, so a space won't create a false match.
  const buf: string[] = []
  const len = src.length
  let i = 0

  // Last non-whitespace char emitted to buf. Used for regex-start detection.
  let lastMeaningfulChar = ''

  function canStartRegex(): boolean {
    const c = lastMeaningfulChar
    if (c === '') return true
    // These chars mean the preceding token is a value → `/` is division.
    if (c === ')' || c === ']' || c === '}') return false
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) return false
    if (c >= '0' && c <= '9') return false
    if (c === '_' || c === '$' || c === '.') return false
    return true
  }

  function appendExec(text: string): void {
    buf.push(text)
    for (let k = text.length - 1; k >= 0; k--) {
      const c = text[k]
      if (c !== ' ' && c !== '\t' && c !== '\r' && c !== '\n') {
        lastMeaningfulChar = c
        return
      }
    }
  }

  function appendNonExecGap(): void {
    // Replace non-executable span with a space to prevent identifier merging.
    // After a STRING, lastMeaningfulChar becomes '"' (not a regex-precede char),
    // so `/` after a string is still treated as division. Correct.
    buf.push(' ')
    lastMeaningfulChar = '"' // sentinel: not a regex-start predecessor
  }

  while (i < len) {
    const ch = src[i]

    // ── Slash: could be line comment, block comment, regex, or division ───────
    if (ch === '/') {
      const next = i + 1 < len ? src[i + 1] : ''

      // Line comment: `//`
      // If the previous token was a value (canStartRegex() === false), then `//`
      // would mean two division operators — but `//` as two divisions is rare and
      // ambiguous. We treat `//` conservatively as a line comment whenever seen,
      // because misidentifying a division as a comment discards a potential auth()
      // call (false negative), while misidentifying a comment as division and then
      // trying to run AUTH_CALL_PATTERN against it is harmless (no auth call there).
      // The only true risk is /regex/ where the `//` inside the regex body is
      // lexed as a comment — but the regex start is detected BEFORE we reach the `//`
      // inside it, so that case is handled by the regex branch below.
      if (next === '/') {
        // Line comment — skip to end of line.
        const start = i
        i += 2
        while (i < len && src[i] !== '\n') i++
        // Emit a gap (the comment is not executable)
        appendNonExecGap()
        // Suppress warning — start is used for correctness check only
        void start
        continue
      }

      // Block comment: `/*`
      if (next === '*') {
        i += 2
        let closed = false
        while (i < len - 1) {
          if (src[i] === '*' && src[i + 1] === '/') {
            i += 2
            closed = true
            break
          }
          i++
        }
        if (!closed) i = len // consume to EOF
        appendNonExecGap()
        continue
      }

      // Regex literal: `/` when it can start a regex.
      if (canStartRegex()) {
        const start = i
        i++ // skip opening `/`
        let inClass = false
        let closedRegex = false
        let hitNewline = false

        while (i < len) {
          const rc = src[i]
          if (rc === '\\' && i + 1 < len) { i += 2; continue }
          if (rc === '[') { inClass = true; i++; continue }
          if (rc === ']' && inClass) { inClass = false; i++; continue }
          if (rc === '/' && !inClass) {
            i++ // closing `/`
            // eslint-disable-next-line no-restricted-syntax
            while (i < len && /[a-z]/i.test(src[i])) i++ // flags — path parser utility, not content-scanning
            closedRegex = true
            break
          }
          if (rc === '\n') {
            // Not a valid regex literal — the `/` at `start` is division.
            hitNewline = true
            break
          }
          i++
        }

        if (hitNewline) {
          // The `/` was not a regex start. Emit it as executable and restart
          // scanning from start+1 (the `/` was already at `start`).
          appendExec('/')
          i = start + 1
        } else {
          // Valid regex literal span — emit as NON-EXECUTABLE (a gap).
          // FIX 1: regex bodies are skipped like string literals to prevent a decoy
          // like `const x = /requireAuth()/` from matching RE2_AUTH_CALL_PATTERN.
          // A regex body never executes, so excluding it is both correct and safe.
          appendNonExecGap()
        }
        continue
      }

      // Plain `/` (division operator) — emit as executable.
      appendExec(ch)
      i++
      continue
    }

    // ── Single-quoted string: '…' ────────────────────────────────────────────
    if (ch === "'") {
      // Scan to the closing `'`, handling escapes.
      // If a newline is encountered before closing: the string is malformed.
      // Conservative: emit the opening `'` as executable and resume scanning
      // from i+1 so that any auth() after the broken string is still found.
      let j = i + 1
      let terminated = false
      while (j < len) {
        const sc = src[j]
        if (sc === '\\' && j + 1 < len) { j += 2; continue }
        if (sc === "'") { j++; terminated = true; break }
        if (sc === '\n') break // unterminated
        j++
      }
      if (terminated) {
        // Properly closed string — skip it (non-executable).
        appendNonExecGap()
        i = j
      } else {
        // Malformed / unterminated — emit the `'` as exec, advance by 1.
        // The rest of the "string" will be re-lexed in subsequent iterations.
        appendExec("'")
        i++
      }
      continue
    }

    // ── Double-quoted string: "…" ────────────────────────────────────────────
    if (ch === '"') {
      let j = i + 1
      let terminated = false
      while (j < len) {
        const sc = src[j]
        if (sc === '\\' && j + 1 < len) { j += 2; continue }
        if (sc === '"') { j++; terminated = true; break }
        if (sc === '\n') break // unterminated
        j++
      }
      if (terminated) {
        appendNonExecGap()
        i = j
      } else {
        appendExec('"')
        i++
      }
      continue
    }

    // ── Template literal: `…` ────────────────────────────────────────────────
    // Template literals contain TEXT segments and ${…} INTERPOLATION expressions.
    // TEXT segments are non-executable (string content), but ${…} contents ARE
    // executable — e.g. `app.get('/x', ${requireAuth(req)})` executes requireAuth.
    // Dropping interpolation would cause active auth calls inside ${} to be missed,
    // producing a spurious "unprotected route" false positive.
    //
    // FIX 3 — Interpolation-spoof false negative:
    // The interpolation body is now lexed via lexInterpolationBody() which correctly
    // classifies strings / comments inside `${…}` as non-executable. This means
    // `${"requireAuth()"}` is no longer spoofed into a false "auth found" signal —
    // the string literal content is skipped, and only real code inside the
    // interpolation is emitted as executable.
    if (ch === '`') {
      i++ // skip opening backtick
      while (i < len) {
        const tc = src[i]
        if (tc === '\\' && i + 1 < len) {
          // Escape sequence in template text — skip both chars (non-executable text).
          i += 2
          continue
        }
        if (tc === '`') {
          // Closing backtick — end of template literal.
          i++
          appendNonExecGap()
          break
        }
        if (tc === '$' && i + 1 < len && src[i + 1] === '{') {
          // Start of interpolation: ${  …  }
          // Emit the text segment up to here as a non-exec gap.
          appendNonExecGap()
          i += 2 // skip '$' and '{'
          // Lex the interpolation body with full string/comment awareness (FIX 3).
          // lexInterpolationBody() returns only executable text from the body and
          // the index of the closing `}`, correctly ignoring strings/comments/nested
          // templates so that e.g. ${"requireAuth()"} does not spoof the detector.
          const interp = lexInterpolationBody(src, i)
          if (interp.execText.length > 0) {
            appendExec(interp.execText)
          }
          i = interp.end < len ? interp.end + 1 : len // advance past closing `}`
          // After emitting the interpolation, resume scanning the template text.
          continue
        }
        // Regular template text character — non-executable, skip it.
        i++
      }
      // If we exited the while loop without a break (unterminated at EOF):
      // appendNonExecGap() was already called for any text segments encountered.
      // Nothing more needed; outer loop continues from updated i.
      continue
    }

    // ── All other characters: executable ─────────────────────────────────────
    appendExec(ch)
    i++
  }

  return buf.join('')
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Returns true if the file content contains an active (non-commented) auth call.
 *
 * Uses a real lexical scanner (extractExecutableText) to classify the source
 * into executable vs. non-executable spans before running RE2_AUTH_CALL_PATTERN.
 * This replaces the previous approach of per-line regex comment-stripping with a
 * variable-width lookbehind (?<![:/])\/\/.*$ followed by testing the stripped text
 * against AUTH_CALL_PATTERN (which itself had variable-width lookbehinds
 * (?<!\/{2}.*?)(?<!\*.*?) — ReDoS-prone, not RE2-translatable, now removed).
 */
function hasActiveAuthCall(content: string): boolean {
  const execText = extractExecutableText(content)
  return RE2_AUTH_CALL_PATTERN.test(execText)
}

/**
 * Returns true if the file shows evidence of a commented-out auth call
 * (suggesting auth was intentionally removed).
 */
function hasCommentedAuthCall(content: string): boolean {
  return RE2_COMMENTED_AUTH_PATTERN.test(content)
}

/**
 * Returns true if any Express route in the file covers a sensitive URL segment
 * without a preceding auth middleware call.
 */
function hasUnsecuredExpressRoute(content: string): boolean {
  // If the file applies auth middleware globally, all routes are protected.
  if (RE2_EXPRESS_AUTH_MIDDLEWARE_PATTERN.test(content)) {
    return false
  }

  // matchAll() returns all non-overlapping matches — stateless, no lastIndex hazard.
  const matches = RE2_EXPRESS_ROUTE_DEFINITION.matchAll(content)

  for (const match of matches) {
    // group[0] = HTTP verb, group[1] = route path string.
    const routePath = match.groups[1]
    if (
      routePath !== undefined &&
      SENSITIVE_EXPRESS_PATHS.test(routePath) &&
      !WEBHOOK_PATH_PATTERN.test(routePath)
    ) {
      // Check if auth middleware is passed as an inline argument to this route.
      // e.g. router.get('/admin', requireAuth, handler)
      const routeCallStart = match.index
      // Grab the full route call text (up to first line break after match end, max 300 chars).
      const routeCall = content.slice(routeCallStart, routeCallStart + 300)
      if (!RE2_INLINE_AUTH_CHECK.test(routeCall)) {
        return true
      }
    }
  }

  return false
}

// ─── Main module ──────────────────────────────────────────────────────────────

export const authCheck: CheckModule = {
  id: 'auth',
  name: 'Auth & Session Protection',

  run(files: FileInfo[], policy: Policy): Finding[] {
    const findings: Finding[] = []

    // ── 1. Locate the middleware.ts file (one pass) ───────────────────────────
    // Only meaningful for Next.js App Router projects — gate behind framework detection
    // to avoid false positives in Express apps, libraries, and repos with no framework.
    const middlewareFile = files.find((f) => MIDDLEWARE_FILE_PATTERN.test(f.relativePath))

    if (isNextjsProject(files)) {
      if (!middlewareFile) {
        // No middleware.ts — any sensitive Next.js pages are doubly at risk.
        findings.push({
          id: 'public_admin_route',
          title: 'No Next.js middleware.ts found',
          severity: 'high',
          category: 'auth',
          file: 'middleware.ts',
          confidence: 'MEDIUM',
          explanation:
            'No middleware.ts file was found. Next.js App Router relies on middleware to enforce ' +
            'route-level auth for admin, dashboard, and billing routes. Without it, protection ' +
            'depends entirely on individual Server Components and Route Handlers, which is error-prone.',
          recommendation:
            'Create middleware.ts at the project root (or src/middleware.ts) and add a matcher ' +
            'that covers /admin, /dashboard, and /billing. Use auth() from next-auth/auth.js or ' +
            'clerkMiddleware() to redirect unauthenticated requests.',
          blocking: policy.block.includes('public_admin_route'),
        })
      } else if (!RE2_MIDDLEWARE_ADMIN_COVERAGE.test(middlewareFile.content)) {
        findings.push({
          id: 'public_admin_route',
          title: 'middleware.ts does not cover admin/dashboard routes',
          severity: 'high',
          category: 'auth',
          file: middlewareFile.relativePath,
          confidence: 'MEDIUM',
          explanation:
            'A middleware.ts file exists but its content does not reference admin, dashboard, ' +
            'billing, account, or management routes. Sensitive routes may not be protected at ' +
            'the edge/middleware layer.',
          recommendation:
            'Add a matcher config to middleware.ts that covers protected route prefixes:\n' +
            '  export const config = { matcher: ["/admin/:path*", "/dashboard/:path*"] }',
          blocking: policy.block.includes('public_admin_route'),
        })
      }
    }

    // ── 2. Per-file checks ────────────────────────────────────────────────────
    for (const file of files) {
      const { relativePath: rp, content } = file

      // Skip webhook paths — user auth is not required for webhook receivers.
      if (WEBHOOK_PATH_PATTERN.test(rp)) {
        continue
      }

      // ── 2a. Next.js App Router page / layout files ──────────────────────────
      if (SENSITIVE_NEXTJS_PAGE_PATTERN.test(rp)) {
        if (!hasActiveAuthCall(content)) {
          // Check if auth was recently removed (commented out).
          const wasRemoved = hasCommentedAuthCall(content)
          findings.push({
            id: 'public_admin_route',
            title: `Unprotected admin/dashboard page: ${rp}`,
            severity: 'high',
            category: 'auth',
            file: rp,
            confidence: 'MEDIUM',
            explanation:
              wasRemoved
                ? `${rp} previously had an auth call that appears to have been commented out. ` +
                  'This page is now accessible without authentication.'
                : `${rp} is in a sensitive route segment (admin/dashboard/billing) but contains ` +
                  'no active auth call (auth(), getServerSession(), requireAuth(), etc.). ' +
                  'Server Components must verify the session even when middleware is in place — ' +
                  'middleware is not a security boundary (see CVE-2025-29927).',
            recommendation:
              'Add `const session = await auth()` at the top of the Server Component and ' +
              'redirect unauthenticated users with `if (!session) redirect("/login")`.',
            blocking: policy.block.includes('public_admin_route'),
          })
        }
        continue
      }

      // ── 2b. Next.js API Route Handlers for sensitive endpoints ──────────────
      if (SENSITIVE_API_ROUTE_PATTERN.test(rp)) {
        if (!hasActiveAuthCall(content)) {
          const wasRemoved = hasCommentedAuthCall(content)
          findings.push({
            id: 'auth_route_without_guard',
            title: `Unprotected API route handler: ${rp}`,
            severity: 'high',
            category: 'auth',
            file: rp,
            confidence: 'MEDIUM',
            explanation:
              wasRemoved
                ? `${rp} previously had an auth call that appears to have been commented out. ` +
                  'This API route now responds to requests without verifying the caller.'
                : `${rp} is an API Route Handler under a sensitive path (admin/users/billing) ` +
                  'but contains no auth guard. Any caller — including unauthenticated requests — ' +
                  'can invoke it.',
            recommendation:
              'Add `const session = await auth()` (next-auth) or `const { userId } = await currentUser()` ' +
              '(Clerk) at the start of each exported HTTP handler. Return a 401 if no session.',
            blocking: policy.block.includes('auth_route_without_guard'),
          })
        }
        continue
      }

      // ── 2c. Express / Fastify route files with sensitive paths ──────────────
      if (
        // eslint-disable-next-line no-restricted-syntax
        /\.(ts|js)$/.test(rp) && // path classifier — matches file extension only
        !SENSITIVE_NEXTJS_PAGE_PATTERN.test(rp) &&
        !SENSITIVE_API_ROUTE_PATTERN.test(rp)
      ) {
        if (hasUnsecuredExpressRoute(content)) {
          findings.push({
            id: 'auth_route_without_guard',
            title: `Express route exposes sensitive path without auth middleware: ${rp}`,
            severity: 'medium',
            category: 'auth',
            file: rp,
            confidence: 'LOW',
            explanation:
              `${rp} registers a route on a sensitive URL segment (admin/users/billing) ` +
              'without an apparent auth middleware guard. In Express, protect routes by passing ' +
              'auth middleware before the handler or by calling router.use(authMiddleware) above ' +
              'the sensitive routes.',
            recommendation:
              'Use `router.use(requireAuth)` before sensitive routes, or pass it inline:\n' +
              '  router.get("/admin/users", requireAuth, handler)\n' +
              'For Fastify, use a `preHandler` hook or `onRequest` hook.',
            blocking: policy.block.includes('auth_route_without_guard'),
          })
        }
      }
    }

    return findings
  },
}

export default authCheck
