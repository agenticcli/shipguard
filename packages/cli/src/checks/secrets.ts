// Free-tier checks — governance + tiering basis: /rules.md. Source of truth is migrating to the Convex rule registry.
// Phase D.4: migrated to re2js engine via compileDetectorRegex() (ReDoS-immune, engine-consistent).
import type { CheckModule, FileInfo, Finding, Policy } from '@agenticcli/shared'
import { compileDetectorRegex } from '../core/re2-detector-engine.js'
// Single definition of the redaction format lives in core/redact.ts (also used centrally
// by scan() for corpus/Pro findings) — this alias keeps every call site below unchanged.
import { redactSecretValue as redact } from '../core/redact.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SECRET_SEVERITY_RANK: Readonly<Record<string, number>> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

/**
 * One issue = one finding, for every `hardcoded_secret` emitter in this file.
 *
 * Several patterns can hit the SAME secret on one line, each capturing a different-length
 * slice of it (e.g. `JWT Secret` captures the whole value, `High-Entropy Secret String`
 * captures the first 64 characters of it). Reported evidence is redacted to 8 characters, so
 * the output cannot tell "two patterns, one secret" from "two secrets" — only the check, which
 * still holds the raw text and the match offsets, can.
 *
 * RULE (span-based, offsets are available from the matcher — no prefix fallback is used):
 *   - two matches on one line whose [start, end) spans OVERLAP are the same secret;
 *   - two matches with an IDENTICAL raw value are the same secret repeated (the fix is the same:
 *     remove/rotate that value), even at non-overlapping offsets;
 *   - anything else (disjoint spans, different values) is a distinct secret and keeps its own
 *     finding — e.g. two different AWS keys on one line stay two findings.
 * The survivor is the higher-severity finding (first one wins a tie) and replaces the earlier
 * one in place, so a report is never softened and finding order is stable.
 */
interface SecretSpan { start: number; end: number; value: string; idx: number }

class SecretDedupe {
  private readonly byLine = new Map<number, SecretSpan[]>()

  /** Returns true when the finding was folded into an existing one (do not push it). */
  fold(findings: Finding[], lineIdx: number, start: number, value: string, candidate: Finding): boolean {
    const end = start + value.length
    let spans = this.byLine.get(lineIdx)
    if (!spans) {
      spans = []
      this.byLine.set(lineIdx, spans)
    }
    const hit = spans.find((sp) => (start < sp.end && sp.start < end) || sp.value === value)
    if (!hit) {
      spans.push({ start, end, value, idx: findings.length })
      return false
    }
    if ((SECRET_SEVERITY_RANK[candidate.severity] ?? 0) > (SECRET_SEVERITY_RANK[findings[hit.idx].severity] ?? 0)) {
      findings[hit.idx] = candidate
    }
    // Grow the tracked span so a later slice overlapping either half still folds in.
    hit.start = Math.min(hit.start, start)
    hit.end = Math.max(hit.end, end)
    return true
  }
}

/** Start offset of the captured secret within its line (falls back to the match start). */
function secretStart(lineMatch: { match: string; index: number }, secretValue: string): number {
  const off = lineMatch.match.indexOf(secretValue)
  return lineMatch.index + (off >= 0 ? off : 0)
}

// Path classifier regexes — compiled with re2js for engine consistency.
// These scan file paths (not user content) so ReDoS risk is low, but compiling
// them via the engine helper keeps secrets.ts fully native-regex-free.
const SAFE_EXCLUSIONS_RE = compileDetectorRegex(`\\.(example|sample|template|dist|tmpl|test)$`, 'i')
const FRONTEND_PATH_RE = compileDetectorRegex(`^(app|pages|components|src\\/(app|pages|components))\\/`)

/** Check if a .env filename should be flagged (not .example / .sample etc.) */
function isDotEnvFile(relativePath: string): boolean {
  const basename = relativePath.split('/').pop() ?? relativePath
  // Match .env, .env.local, .env.production, .env.development, .env.staging, etc.
  // But NOT .env.example, .env.sample, .env.template, .env.dist, .env.tmpl
  if (!basename.startsWith('.env')) return false
  return !SAFE_EXCLUSIONS_RE.test(basename)
}

/** Check if a path is in a frontend directory where NEXT_PUBLIC_ rules apply */
function isFrontendFile(relativePath: string): boolean {
  return FRONTEND_PATH_RE.test(relativePath)
}

// ---------------------------------------------------------------------------
// Pattern definitions — compiled with re2js (ReDoS-immune)
// ---------------------------------------------------------------------------

interface SecretPattern {
  id: 'hardcoded_secret' | 'exposed_env'
  name: string
  compiled: ReturnType<typeof compileDetectorRegex>
  severity: Finding['severity']
  confidence: Finding['confidence']
  explanation: string
  recommendation: string
  /**
   * Optional post-exec filter: when set, a match is suppressed when this
   * function returns true. The argument is the rest of the line starting at
   * the character immediately after the match end (may be an empty string when
   * the match ends at the line boundary). Used as a re2js-safe alternative to
   * negative-lookahead exclusions that re2js cannot compile.
   *
   * Implementations must use only plain string operations — no native RegExp.
   * post-exclusion is applied AFTER exec and inspects a bounded suffix, so it
   * is safe from ReDoS.
   */
  postExcludeFollowedBy?: (restAfterMatch: string) => boolean
}

// ---------------------------------------------------------------------------
// D.4 DIFFERENTIAL NOTE — pattern-by-pattern re2js compatibility:
//
//  #1  sk-proj-...          → no lookahead/backref → compiled as-is
//  #2  openai...sk-...      → no lookahead/backref → compiled as-is
//  #3  sk-ant-...           → no lookahead/backref → compiled as-is
//  #4  sk_live_...          → no lookahead/backref → compiled as-is
//  #5  sk_test_...          → no lookahead/backref → compiled as-is
//  #6  AKIA...              → no lookahead/backref → compiled as-is
//  #7  aws secret key       → no lookahead/backref → compiled as-is
//  #8  AIza...              → no lookahead/backref → compiled as-is
//  #9  ghp_/github_pat_     → no lookahead/backref → compiled as-is
//  #10 razorpay             → no lookahead/backref → compiled as-is
//  #11 jwt secret           → [^'"] is valid in RE2 → compiled as-is
//  #12 database URL         → no lookahead/backref → compiled as-is
//  #13 high-entropy string  → REWRITTEN: removed lookahead (?!\s*\+|\.)
//                             Added postExcludeFollowedBy() for equivalent behavior.
//                             Before: ['"](...){32,64}['"](?!\s*\+|\.)
//                             After:  ['"](...){32,64}['"]  + post-exclusion check
//                             Why: RE2 does not support negative lookahead.
//                             Equivalence: postExcludeFollowedBy() receives the
//                             REST of the line after the match end and replicates
//                             the lookahead exactly:
//                             - immediate '.' at rest[0] -> suppress (matches \.)
//                             - skip JS \s* chars; if first non-ws = '+' -> suppress
//                             - otherwise -> KEEP (flag the secret)
//                             This is a FULL replication, not a single-char check,
//                             so '...' followed by whitespace then non-'+' is KEPT
//                             (the bug that motivated this fix).
// ---------------------------------------------------------------------------

const SECRET_PATTERNS: SecretPattern[] = [
  // OpenAI — sk-proj-... (new format)
  {
    id: 'hardcoded_secret',
    name: 'OpenAI API Key',
    compiled: compileDetectorRegex(`['"]?(sk-proj-[a-zA-Z0-9_\\-]{20,})['"]?`, 'm'),
    severity: 'high',
    confidence: 'HIGH',
    explanation: 'Hardcoded OpenAI API key detected. Leaking this key allows unauthorized use of your OpenAI account, incurring charges.',
    recommendation: 'Remove the key from source code. Use process.env.OPENAI_API_KEY and store the value in a .env file that is gitignored.',
  },
  // OpenAI — sk-... (legacy format) via variable name context
  {
    id: 'hardcoded_secret',
    name: 'OpenAI Legacy API Key',
    compiled: compileDetectorRegex(
      `(?:openai[_\\-]?(?:api[_\\-]?)?key|OPENAI[_\\-]?(?:API[_\\-]?)?KEY)\\s*[=:]\\s*['"]?(sk-[a-zA-Z0-9]{20,})['"]?`,
      'im',
    ),
    severity: 'high',
    confidence: 'HIGH',
    explanation: 'Hardcoded OpenAI API key detected. Leaking this key allows unauthorized use of your OpenAI account, incurring charges.',
    recommendation: 'Remove the key from source code. Use process.env.OPENAI_API_KEY and store the value in a .env file that is gitignored.',
  },
  // Anthropic — sk-ant-api03-...
  {
    id: 'hardcoded_secret',
    name: 'Anthropic API Key',
    compiled: compileDetectorRegex(`['"]?(sk-ant-(?:api\\d+-)?[a-zA-Z0-9_\\-]{20,})['"]?`, 'im'),
    severity: 'high',
    confidence: 'HIGH',
    explanation: 'Hardcoded Anthropic API key detected. Leaking this key allows unauthorized use of Anthropic Claude, incurring charges.',
    recommendation: 'Remove the key from source code. Use process.env.ANTHROPIC_API_KEY and store the value in a .env file that is gitignored.',
  },
  // Stripe live secret key
  {
    id: 'hardcoded_secret',
    name: 'Stripe Live Secret Key',
    compiled: compileDetectorRegex(`['"]?(sk_live_[a-zA-Z0-9]{24,})['"]?`, 'im'),
    severity: 'critical',
    confidence: 'HIGH',
    explanation: 'Hardcoded Stripe live secret key detected. This key can be used to make charges, refunds, and access customer data in your live Stripe account.',
    recommendation: 'Remove immediately. Use process.env.STRIPE_SECRET_KEY. Rotate the key in the Stripe Dashboard.',
  },
  // Stripe test secret key
  {
    id: 'hardcoded_secret',
    name: 'Stripe Test Secret Key',
    compiled: compileDetectorRegex(`['"]?(sk_test_[a-zA-Z0-9]{24,})['"]?`, 'im'),
    severity: 'medium',
    confidence: 'HIGH',
    explanation: 'Hardcoded Stripe test secret key detected. While test keys cannot process real payments, committing them is a bad practice that often leads to live key exposure.',
    recommendation: 'Remove from source code. Use process.env.STRIPE_SECRET_KEY with a .env file that is gitignored.',
  },
  // AWS access key ID
  {
    id: 'hardcoded_secret',
    name: 'AWS Access Key ID',
    compiled: compileDetectorRegex(`['"]?(AKIA[0-9A-Z]{16})['"]?`, 'm'),
    severity: 'high',
    confidence: 'HIGH',
    explanation: 'Hardcoded AWS Access Key ID detected. Combined with the secret key, this allows full AWS API access under your account.',
    recommendation: 'Remove and rotate immediately via IAM. Use environment variables or AWS credential profiles instead.',
  },
  // AWS secret access key
  {
    id: 'hardcoded_secret',
    name: 'AWS Secret Access Key',
    compiled: compileDetectorRegex(
      `(?:aws[_\\-]?secret[_\\-]?(?:access[_\\-]?)?key|AWS_SECRET_ACCESS_KEY)\\s*[=:]\\s*['"]?([a-zA-Z0-9\\/+]{40})['"]?`,
      'im',
    ),
    severity: 'high',
    confidence: 'HIGH',
    explanation: 'Hardcoded AWS Secret Access Key detected. This credential enables full programmatic access to AWS services.',
    recommendation: 'Remove and rotate immediately via IAM. Use environment variables or AWS credential profiles instead.',
  },
  // Google API key
  {
    id: 'hardcoded_secret',
    name: 'Google API Key',
    compiled: compileDetectorRegex(`['"]?(AIza[0-9A-Za-z\\-_]{35})['"]?`, 'm'),
    severity: 'high',
    confidence: 'HIGH',
    explanation: 'Hardcoded Google API key detected. This key can be used to access Google Cloud services or Google Maps, incurring charges.',
    recommendation: 'Remove from source code. Restrict key usage in the Google Cloud Console and use environment variables.',
  },
  // GitHub personal access token (classic ghp_ and fine-grained github_pat_)
  {
    id: 'hardcoded_secret',
    name: 'GitHub Personal Access Token',
    compiled: compileDetectorRegex(`['"]?(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})['"]?`, 'm'),
    severity: 'high',
    confidence: 'HIGH',
    explanation: 'Hardcoded GitHub Personal Access Token detected. This token grants access to GitHub repositories and actions under your account.',
    recommendation: 'Remove and revoke the token at github.com/settings/tokens. Use environment variables.',
  },
  // Razorpay live secret key
  {
    id: 'hardcoded_secret',
    name: 'Razorpay Secret Key',
    compiled: compileDetectorRegex(
      `(?:razorpay[_\\-]?(?:key[_\\-]?)?secret|RAZORPAY_KEY_SECRET)\\s*[=:]\\s*['"]?([a-zA-Z0-9]{20,})['"]?`,
      'im',
    ),
    severity: 'high',
    confidence: 'HIGH',
    explanation: 'Hardcoded Razorpay secret key detected. This allows unauthorized access to your Razorpay payment account.',
    recommendation: 'Remove from source code. Use process.env.RAZORPAY_KEY_SECRET and store in a gitignored .env file.',
  },
  // JWT secret
  // Free-tier secret gaps: the opening quote used to be MANDATORY (`['"]([^'"]{16,})`),
  // which only matches source-file assignment style (`const x = "value"`). A .env
  // file's `JWT_SECRET=value` line has no quotes at all, so this pattern never
  // matched .env content. Quotes are now optional on both sides, and the capture
  // class excludes whitespace/quotes/`#` (env comment marker) so an unquoted value
  // still terminates correctly at end-of-value instead of swallowing trailing
  // content. Quoted-value behavior (source files) is unchanged.
  {
    id: 'hardcoded_secret',
    name: 'JWT Secret',
    compiled: compileDetectorRegex(
      `(?:jwt[_\\-]?secret|JWT_SECRET)\\s*[=:]\\s*['"]?([^\\s'"#]{16,})['"]?`,
      'im',
    ),
    severity: 'high',
    confidence: 'HIGH',
    explanation: 'Hardcoded JWT secret detected. Exposing this allows attackers to forge valid JWT tokens and bypass authentication.',
    recommendation: 'Remove from source code. Generate a strong random secret, store it in environment variables.',
  },
  // Supabase service-role key — current key format (2025+ rotation: sb_secret_...)
  // Free-tier secret gaps: the free tier had no Supabase-specific service-role pattern at
  // all — a variable literally named SERVICE_ROLE_KEY matched none of the generic
  // secret-name keywords (api_key/secret/token/password/auth_key/access_key) below,
  // per a miss seen on a real project.
  // This prefix match covers the current opaque key format; the legacy JWT format
  // (pre-2025 projects) is handled separately by checkSupabaseServiceRoleJwt below,
  // which decodes the payload rather than pattern-matching the shape.
  {
    id: 'hardcoded_secret',
    name: 'Supabase Service-Role Key',
    compiled: compileDetectorRegex(`['"]?(sb_secret_[a-zA-Z0-9_\\-]{20,})['"]?`, 'm'),
    severity: 'critical',
    confidence: 'HIGH',
    explanation: 'Hardcoded Supabase service-role key detected (current sb_secret_ key format). This key bypasses Row Level Security entirely and grants full read/write access to every table.',
    recommendation: 'Remove from source code and any .env file committed to git. Use process.env.SUPABASE_SERVICE_ROLE_KEY server-side only — never a NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_-prefixed variable. Rotate the key in the Supabase dashboard (Project Settings → API).',
  },
  // Database URL with embedded credentials
  {
    id: 'hardcoded_secret',
    name: 'Database URL with Credentials',
    compiled: compileDetectorRegex(
      `(?:(?:database[_\\-]?url|DATABASE_URL|db[_\\-]?url|DB_URL|connection[_\\-]?string|CONNECTION_STRING)\\s*[=:]\\s*)?['"]?((?:postgres|postgresql|mysql|mongodb|mongodb\\+srv|redis|amqp|rabbitmq):\\/\\/[^:'"]+:[^@'"]+@[^'"]+)['"]?`,
      'im',
    ),
    severity: 'critical',
    confidence: 'HIGH',
    explanation: 'Database URL with embedded credentials detected. This exposes the database host, username, and password directly.',
    recommendation: 'Remove credentials from the URL. Use environment variables and ensure the .env file is gitignored.',
  },
  // Generic assignment: VAR = "long-base64/alphanumeric string"
  // D.4 REWRITE: Removed native negative-lookahead (?!\s*\+|\.) — not supported by re2js.
  // Equivalent behavior is achieved via postExcludeFollowedBy() which checks the
  // character immediately after the closing quote. See DIFFERENTIAL NOTE above.
  // Free-tier secret gaps: both quotes used to be MANDATORY (`['"](...)['"]`), which only
  // matches source-file assignment style (`const x = "value"`) and never a .env file's
  // unquoted `TOKEN=value` line — confirmed by a miss seen on a real project (INTERNAL_DEPLOY_TOKEN
  // caught when moved into config.ts, not when left in .env). Quotes are now optional;
  // the capture class already excludes whitespace and quote characters, so an unquoted
  // .env value still terminates correctly instead of over-capturing.
  {
    id: 'hardcoded_secret',
    name: 'High-Entropy Secret String',
    compiled: compileDetectorRegex(
      `(?:api[_\\-]?key|secret|token|password|passwd|auth[_\\-]?key|access[_\\-]?key)\\s*[=:]\\s*['"]?([a-zA-Z0-9\\/+_\\-]{32,64})['"]?`,
      'im',
    ),
    severity: 'medium',
    confidence: 'MEDIUM',
    explanation: 'A variable with a secret-sounding name is assigned a long literal string that resembles an API key or token.',
    recommendation: 'Move this value to a .env file and reference it via process.env. Never hardcode credentials.',
    // Exact equivalent of native negative-lookahead (?!\s*\+|\.) — suppress the
    // match iff the text immediately following it matches EITHER:
    //   (a) \s*\+ — zero or more JS-whitespace chars then a literal '+'
    //   (b) \. — an IMMEDIATE dot (no leading whitespace; the alternation has no \s*)
    // Algorithm uses plain string operations only (no native RegExp, no ReDoS risk):
    //   1. Immediate dot -> suppress.
    //   2. Skip JS \s chars (code points: 0x09 0x0a 0x0b 0x0c 0x0d 0x20 0xa0
    //      0x1680 0x2000-0x200a 0x2028 0x2029 0x202f 0x205f 0x3000 0xfeff);
    //      if the first non-ws char is '+' -> suppress.
    //   3. Otherwise -> KEEP (flag the secret).
    postExcludeFollowedBy: (restAfterMatch: string): boolean => {
      if (restAfterMatch.length === 0) return false          // end-of-line: KEEP
      if (restAfterMatch[0] === '.') return true             // immediate dot: suppress
      // Skip optional JS whitespace chars (replicates \s* in the native lookahead)
      let i = 0
      while (i < restAfterMatch.length) {
        const cp = restAfterMatch.codePointAt(i) ?? 0
        if (
          cp === 0x09 || cp === 0x0a || cp === 0x0b || cp === 0x0c || cp === 0x0d ||
          cp === 0x20 || cp === 0xa0 || cp === 0x1680 ||
          (cp >= 0x2000 && cp <= 0x200a) ||
          cp === 0x2028 || cp === 0x2029 || cp === 0x202f || cp === 0x205f ||
          cp === 0x3000 || cp === 0xfeff
        ) {
          i++ // all these code points are in BMP (single UTF-16 char unit)
        } else {
          break
        }
      }
      return restAfterMatch[i] === '+'                       // first non-ws = '+': suppress
    },
  },
]

// Private key block pattern (PEM headers) — compiled with re2js
const PRIVATE_KEY_RE = compileDetectorRegex(
  `-----BEGIN\\s(?:RSA\\s|EC\\s|DSA\\s|OPENSSH\\s|ENCRYPTED\\s)?PRIVATE KEY-----`,
  'm',
)

// NEXT_PUBLIC_ environment variable pattern — compiled with re2js
const NEXT_PUBLIC_SECRET_RE = compileDetectorRegex(
  `NEXT_PUBLIC_(?:[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|AUTH)[A-Z_]*)=['"']?([a-zA-Z0-9\\/+_\\-]{16,})['"']?`,
  'm',
)

// Env variable reference-only pattern (process.env.X) — compiled with re2js
// Used to skip lines that only reference env vars, not assign literal values.
const ENV_REFERENCE_ONLY_RE = compileDetectorRegex(`process\\.env\\.[A-Z_]+`)

// Literal-assignment guard — used alongside ENV_REFERENCE_ONLY_RE
const LITERAL_ASSIGN_RE = compileDetectorRegex(`=\\s*['"]`)

// Comment-skip patterns — applied per-line to filter out comment lines
// These two are also compiled with re2js for engine consistency.
const LINE_COMMENT_RE = compileDetectorRegex(`^\\s*(\\/\\/|#)`, 'm')

// ---------------------------------------------------------------------------
// Supabase service-role key — legacy JWT format (free-tier secret gaps)
// ---------------------------------------------------------------------------
//
// Pre-2025-key-rotation Supabase projects issue the `anon` and `service_role`
// keys as HS256 JWTs (header.payload.signature, each segment base64url —
// e.g. `eyJhbGci...`). Both keys share the EXACT same shape; the only
// structural difference is the `role` claim inside the base64url-decoded
// payload ("anon" vs "service_role"). A shape-only regex cannot tell them
// apart — this is exactly what the 2026-07-20 comparison article documented
// every scanner getting wrong: gitleaks' generic `jwt` rule "fires on BOTH
// service-role and anon keys — no role distinction" (a match without a
// meaning), TruffleHog and ShipGuard both missed it outright, and GitHub only
// documents the new sb_secret_ format.
//
// The precision guard here is a REAL decode, not a shape guess: base64url-
// decode the payload segment and JSON.parse it, and flag ONLY when the parsed
// `role` claim is EXACTLY "service_role". An anon-role JWT, an authenticated-
// role JWT, or any eyJ-shaped string that fails to decode/parse as JSON never
// fires — this is the specific false-positive class the article called out,
// and it's why this differs from (and is more precise than) a generic JWT
// pattern. Decoding base64 + parsing JSON is string/data parsing, not code
// AST parsing — compliant with the V1 regex/string-only, no-AST contract.
const JWT_SHAPE_RE = compileDetectorRegex(
  `(eyJ[A-Za-z0-9_\\-]{5,})\\.(eyJ[A-Za-z0-9_\\-]{5,})\\.([A-Za-z0-9_\\-]{10,})`,
)

/** Base64url-decode a JWT segment. Returns null (never throws) if it isn't valid base64url/UTF-8. */
function base64UrlDecodeJwtSegment(segment: string): string | null {
  try {
    const decoded = Buffer.from(segment, 'base64url').toString('utf8')
    // Buffer.from() never throws on non-base64url chars — it silently drops them,
    // which could turn garbage into an empty/short string. Guard against that.
    return decoded.length > 0 ? decoded : null
  } catch {
    return null
  }
}

/**
 * Returns the JWT payload's `role` claim, or null when this candidate isn't a
 * decodable JWT payload at all (not base64url, not valid JSON, or no string
 * `role` field). null is a filter signal, not an error — most eyJ-shaped
 * matches in a scan are legitimate non-Supabase JWTs (session tokens, etc.)
 * and this is expected to return null for the overwhelming majority of them.
 */
function extractJwtRoleClaim(payloadSegment: string): string | null {
  const decoded = base64UrlDecodeJwtSegment(payloadSegment)
  if (decoded === null) return null
  try {
    const parsed = JSON.parse(decoded) as Record<string, unknown>
    return typeof parsed['role'] === 'string' ? (parsed['role'] as string) : null
  } catch {
    return null // not valid JSON -> not a JWT payload we recognize; not an error condition
  }
}

function checkSupabaseServiceRoleJwt(file: FileInfo, findings: Finding[], policy: Policy, dedupe: SecretDedupe): void {
  const { content, relativePath } = file
  const lines = content.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (LINE_COMMENT_RE.test(line)) continue

    for (const m of JWT_SHAPE_RE.matchAll(line)) {
      const payloadSegment = m.groups[1] // groups[0]=header, groups[1]=payload, groups[2]=signature
      if (!payloadSegment) continue
      const role = extractJwtRoleClaim(payloadSegment)
      if (role !== 'service_role') continue // precision guard — anon/authenticated/undecodable: not flagged

      const id = 'hardcoded_secret'
      const jwtFinding: Finding = {
        id,
        title: 'Supabase Service-Role Key (legacy JWT format)',
        severity: 'critical',
        category: 'secrets',
        file: relativePath,
        line: i + 1,
        evidence: `...${redact(m.match)}...`,
        confidence: 'HIGH',
        explanation:
          'A legacy-format Supabase service-role key was found — a JWT whose decoded payload contains "role":"service_role". ' +
          'This key bypasses Row Level Security entirely and grants full read/write access to every table, regardless of any RLS policy.',
        recommendation:
          'Remove immediately, including from any .env file. Never reference it from a NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_-prefixed variable ' +
          'or client-side code. Use it only in server-only code via process.env.SUPABASE_SERVICE_ROLE_KEY, and rotate it in the Supabase ' +
          'dashboard (Project Settings → API) since any repo exposure must be treated as compromised.',
        blocking: policy.block.includes(id),
      }
      if (!dedupe.fold(findings, i, m.index, m.match, jwtFinding)) findings.push(jwtFinding)
    }
  }
}

// ---------------------------------------------------------------------------
// Main check implementation
// ---------------------------------------------------------------------------

function checkSecrets(files: FileInfo[], policy: Policy): Finding[] {
  const findings: Finding[] = []

  for (const file of files) {
    const { content, relativePath } = file

    // 1. Detect .env files tracked in git
    if (isDotEnvFile(relativePath)) {
      const id = 'exposed_env'
      findings.push({
        id,
        title: '.env file tracked in git',
        severity: 'high',
        category: 'secrets',
        file: relativePath,
        confidence: 'HIGH',
        explanation:
          'A .env file is tracked in the repository. These files often contain secrets such as API keys, database credentials, and tokens that should never be committed.',
        recommendation:
          'Add .env (and its variants like .env.local, .env.production) to .gitignore. Remove the file from git history using `git rm --cached .env`.',
        blocking: policy.block.includes(id),
      })
      // Still scan content inside .env files for specific key patterns below
    }

    // 2. Detect private key blocks
    const pkExec = PRIVATE_KEY_RE.exec(content)
    if (pkExec) {
      const lineNum = content.slice(0, pkExec.index).split('\n').length
      const id = 'hardcoded_secret'
      findings.push({
        id,
        title: 'Private key block in source',
        severity: 'critical',
        category: 'secrets',
        file: relativePath,
        line: lineNum,
        evidence: pkExec.match.trim(),
        confidence: 'HIGH',
        explanation:
          'A PEM private key block is embedded in the source file. This exposes cryptographic material that can be used to impersonate services, decrypt data, or forge signatures.',
        recommendation:
          'Remove the private key from the codebase immediately. Store keys in a secrets manager (e.g., AWS Secrets Manager, Vault) or as environment variables.',
        blocking: policy.block.includes(id),
      })
    }

    // 3. Check NEXT_PUBLIC_ secret exposure in frontend files AND .env files.
    //    Free-tier secret gaps: this used to be gated on isFrontendFile alone
    //    (app/, pages/, components/ paths only), so a NEXT_PUBLIC_-prefixed
    //    secret declared in .env/.env.local — the far more common place to
    //    declare it — was never scanned at all, regardless of quoting. A real
    //    repro: NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY sitting in .env.local produced no
    //    dedicated finding. A NEXT_PUBLIC_ variable is bundled into the client
    //    build wherever it's declared, so .env files are exactly as dangerous a
    //    source as a hardcoded assignment in a component file.
    const isEnvFileForNextPublicCheck = isDotEnvFile(relativePath)
    if (isFrontendFile(relativePath) || isEnvFileForNextPublicCheck) {
      const lines = content.split('\n')
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        const match = NEXT_PUBLIC_SECRET_RE.exec(line)
        if (match && match.groups[0]) {
          const id = 'exposed_env'
          findings.push({
            id,
            title: 'Secret exposed via NEXT_PUBLIC_ prefix',
            severity: 'critical',
            category: 'secrets',
            file: relativePath,
            line: i + 1,
            evidence: `${line.split('=')[0].trim()}=${redact(match.groups[0])}`,
            confidence: 'HIGH',
            explanation:
              'An environment variable with NEXT_PUBLIC_ prefix containing a secret-sounding name is declared ' +
              (isEnvFileForNextPublicCheck
                ? 'in a .env file. NEXT_PUBLIC_ variables are bundled into client-side JavaScript and exposed to all users regardless of which file declares them.'
                : 'in a frontend file. NEXT_PUBLIC_ variables are bundled into client-side JavaScript and exposed to all users.'),
            recommendation:
              'Move secret API calls to a server-side route (e.g., Next.js API route or Server Action). Never use NEXT_PUBLIC_ for keys, tokens, or secrets.',
            blocking: policy.block.includes(id),
          })
        }
      }
    }

    // 3b. Supabase service-role key — legacy JWT format (free-tier secret gaps).
    //     Runs against every file's content, mirroring the SECRET_PATTERNS loop
    //     below (which already scans .env content, not just source files).
    const secretDedupe = new SecretDedupe()
    checkSupabaseServiceRoleJwt(file, findings, policy, secretDedupe)

    // 4. Run all secret patterns against content
    //    Skip files that only contain process.env.X references (no literal assignments)
    const lines = content.split('\n')
    // Same-secret folding across patterns AND the Supabase JWT check: see SecretDedupe.
    for (const pattern of SECRET_PATTERNS) {
      // Test at the full-file level first for performance; then scan line by line for evidence
      if (!pattern.compiled.test(content)) continue

      // Scan line by line for evidence and exact line numbers
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]

        // Skip lines that are pure environment variable references with no quoted literal.
        // FIX 6 — env-ref line-skip too broad (false negative):
        // The previous check used LITERAL_ASSIGN_RE (`=\s*['"]`) which only matches the
        // form `= 'value'` / `= "value"`. A line like:
        //   `const url = process.env.DB_URL || "postgres://user:pass@host"`
        // has an env reference AND a hardcoded URL, but `LITERAL_ASSIGN_RE` does NOT match
        // because the quote is after `||`, not after `=`. The whole line was skipped, causing
        // the hardcoded credential to be missed (false negative).
        //
        // Fix: skip the line only when it contains an env reference AND NO quote characters
        // at all (i.e. no string literal of any kind). A line with any `'`, `"`, or `` ` ``
        // might carry a hardcoded secret elsewhere on it and must not be skipped wholesale.
        // This preserves the original intent (pure `x = process.env.SECRET` lines with no
        // quotes are still skipped) while allowing lines that also contain string literals
        // (including template literals) to be scanned normally.
        // FIX 3: include backtick in the guard — a line like
        //   `const k = process.env.KEY || \`sk_live_abc123...\``
        // has no `'` or `"` but does contain a backtick template secret; it must not be skipped.
        if (ENV_REFERENCE_ONLY_RE.test(line) && !line.includes("'") && !line.includes('"') && !line.includes('`')) continue
        // Skip comment lines
        if (LINE_COMMENT_RE.test(line)) continue

        // Iterate ALL matches on the line (not just the first) so that a later
        // genuine secret is not missed when an earlier match is excluded via
        // postExcludeFollowedBy (e.g. `'excl…' + x; 'real…'`).
        const lineMatches = pattern.compiled.matchAll(line)
        for (const lineMatch of lineMatches) {
          // Apply post-match exclusion (replaces negative lookahead in pattern #13)
          if (pattern.postExcludeFollowedBy !== undefined) {
            const charAfterIndex = lineMatch.index + lineMatch.match.length
            const restAfterMatch = line.slice(charAfterIndex)
            if (pattern.postExcludeFollowedBy(restAfterMatch)) continue
          }

          // Extract the captured group (the secret value) for redaction
          const secretValue = lineMatch.groups[0] ?? lineMatch.match
          const secretFinding: Finding = {
            id: pattern.id,
            title: pattern.name,
            severity: pattern.severity,
            category: 'secrets',
            file: relativePath,
            line: i + 1,
            evidence: `...${redact(secretValue)}...`,
            confidence: pattern.confidence,
            explanation: pattern.explanation,
            recommendation: pattern.recommendation,
            blocking: policy.block.includes(pattern.id),
          }
          if (!secretDedupe.fold(findings, i, secretStart(lineMatch, secretValue), secretValue, secretFinding)) {
            findings.push(secretFinding)
          }
        }
      }
    }
  }

  return findings
}

// ---------------------------------------------------------------------------
// Export as CheckModule
// ---------------------------------------------------------------------------

export const secretsCheck: CheckModule = {
  id: 'secrets',
  name: 'Secrets & Environment Leaks',
  run: checkSecrets,
}
