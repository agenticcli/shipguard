// Central secret redaction — the ONE place a finding's evidence is made safe to emit.
//
// WHY THIS FILE EXISTS
// ====================
// Free-tier findings from the hand-written `hardcoded_secret` check were always redacted
// at the source (`...sk_live_***...`), but findings from the governed corpus rules
// (`generic.secrets.*`, run through the declarative matcher in pro-scanner.ts) carry the
// MATCHED TEXT verbatim in `evidence` — the matcher contract deliberately preserves it
// (matcher-contract/src/matcher.ts: "the CLI display layer is responsible for truncating
// or masking secrets"). Nothing ever did. So `--json`, the default text view, the
// markdown/JSON reports under `.shipguard/reports/`, the `--strict` hook dump — every
// surface that renders `Finding.evidence` — printed live keys into CI logs, agent
// transcripts and files that get committed or uploaded.
//
// Redacting per check module / per renderer would be a whack-a-mole that the next new
// surface silently loses. Instead `scan()` (core/scanner.ts) calls
// `redactFindingsEvidence()` ONCE, on the fully assembled finding list (legacy checks +
// bundled corpus + Pro rules), before the list leaves the core. Every downstream surface
// (verdict, history, report, SARIF, JSON, text, hooks) then only ever sees safe text.
//
// FORMAT: the legacy `redact()` format — first 8 characters visible, then `***` — so a
// corpus finding and a legacy finding for the same key read the same.
//
// POLICY
// ======
// - findings from the LEGACY secrets check (`checks/secrets.ts`): already redacted at the
//   source in this exact format -> left alone (they keep e.g. the variable name in
//   `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_***`). scan() names them explicitly; nothing is
//   inferred from the evidence text, so a lookalike from a corpus/Pro rule is still masked.
// - every other finding, category `secrets`: the evidence IS (or contains) the secret ->
//   the whole evidence is masked. Exceptions are evidence that is provably not a value: a
//   PEM header line, and `"type": "service_account"`.
// - every other finding, any other category: evidence is a code/config line and may still
//   CONTAIN a secret (`"db:push": "DATABASE_URL=postgres://u:pw@host prisma db push"`), so
//   known secret shapes inside it are masked in place and the rest of the line is kept.

import { createHash } from 'node:crypto'
import type { Finding } from '@agenticcli/shared'
import { compileDetectorRegex } from './re2-detector-engine.js'

/** Redact a secret value — keep first 8 chars visible, mask the rest. (Legacy format.) */
export function redactSecretValue(value: string): string {
  if (value.length <= 8) return '***'
  return value.slice(0, 8) + '***'
}

// Evidence that is provably not a secret VALUE, so masking it would only cost signal:
// a PEM header line (both the corpus rule and the legacy check match the header only) and
// the GCP service-account marker.
const NON_SECRET_EVIDENCE_RE = compileDetectorRegex(
  `^(?:-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----|"type"\\s*:\\s*"service_account")$`,
)

// Credentials embedded in a URL: scheme://user:PASSWORD@host. The user may be empty
// (redis://:pw@h), the password may contain `/`, and it runs to the LAST `@` before the host.
const URL_CREDENTIAL_RE = compileDetectorRegex(
  `(://[^\\s:/@'"]*:)([^\\s'"]+)(@[^\\s@'"/]+)`,
)

// Well-known token shapes (same families the free-tier checks and the corpus detect).
const TOKEN_SHAPE_RE = compileDetectorRegex(
  '(' +
    '(?:rk|sk)_(?:live|test)_[A-Za-z0-9]{10,}' +
    '|whsec_[A-Za-z0-9]{20,}' +
    '|sk-[A-Za-z0-9_-]{20,}' +
    '|(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}' +
    '|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}' +
    '|github_pat_[A-Za-z0-9_]{20,}' +
    '|glpat-[A-Za-z0-9_-]{20,}' +
    '|xox[bpoas]-[0-9A-Za-z-]{10,}' +
    '|xapp-[0-9A-Za-z-]{20,}' +
    '|hf_[A-Za-z0-9]{30,}' +
    '|npm_[A-Za-z0-9]{30,}' +
    '|SG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}' +
    '|AIza[0-9A-Za-z_-]{35}' +
    '|sb_secret_[A-Za-z0-9_-]{20,}' +
    '|eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}' +
  ')',
)

// A secret-sounding name assigned a literal: API_KEY=..., DB_PASS=..., MYSQL_PWD=...,
// "password": "...", auth: '...'. The value is either a quoted string (may hold spaces) or a
// bare run of non-separator characters.
const SECRET_ASSIGNMENT_RE = compileDetectorRegex(
  `((?:api[_-]?key|secret|token|pass|passw(?:or)?d|pwd|credentials?|auth[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_]{0,40}['"]?\\s*[=:]\\s*)("[^"]{4,}"|'[^']{4,}'|[^\\s'",;]{6,})`,
  'i',
)
// `auth` / `authorization` only as the WHOLE name (else `author: "Jane"` would match).
const AUTH_ASSIGNMENT_RE = compileDetectorRegex(
  `(\\bauth(?:orization)?['"]?\\s*[=:]\\s*)("[^"]{4,}"|'[^']{4,}'|[^\\s'",;]{6,})`,
  'i',
)
// `Authorization: Bearer <token>` / `Basic <base64>`
const BEARER_RE = compileDetectorRegex(`(\\bBearer\\s+)([A-Za-z0-9._~+/=*-]{8,})`, 'i')
const BASIC_RE = compileDetectorRegex(`(\\bBasic\\s+)([A-Za-z0-9+/=]{16,})`, 'i')
// CLI flags that carry a password inline: `mysql -uroot -pSECRET`, `curl -u user:SECRET`
const MYSQL_P_FLAG_RE = compileDetectorRegex(`(\\s-p)(\\S{6,})`)
// Space- or =-separated secret flags: `docker login --password SECRET`, `--secret-access-key X`,
// `-token=X`. An optional `word-` prefix chain covers `--secret-access-key`. A bare
// `--password` with no value after it does not match.
const CLI_FLAG_SECRET_RE = compileDetectorRegex(
  `(\\s--?(?:[A-Za-z0-9]+[-_])*(?:password|passwd|pass|pwd|token|api[-_]?key|secret|access[-_]?key)(?:\\s+|=))([^\\s'"]{6,})`,
  'i',
)
const CURL_USER_RE = compileDetectorRegex(`(\\s(?:-u|--user)[\\s=]*[^\\s:]+:)(\\S+)`)
// SQL: ALTER USER x PASSWORD 'secret' / IDENTIFIED BY 'secret'
const SQL_PASSWORD_RE = compileDetectorRegex(
  `((?:password|identified\\s+by)\\s+(?:=\\s*)?['"])([^'"]+)`,
  'i',
)

/**
 * Replace a capture group inside each match of `re`, where the match is exactly the
 * concatenation of its groups (true for every pattern above). `mask` gets the group text.
 */
function replaceGroup(
  text: string,
  re: ReturnType<typeof compileDetectorRegex>,
  groupIndex: number,
  mask: (value: string) => string,
): string {
  let out = ''
  let cursor = 0
  for (const m of re.matchAll(text)) {
    const groups = m.groups.map((g) => g ?? '')
    const offsetInMatch = groups.slice(0, groupIndex).reduce((n, g) => n + g.length, 0)
    const start = m.index + offsetInMatch
    const value = groups[groupIndex]
    out += text.slice(cursor, start) + mask(value)
    cursor = start + value.length
  }
  return out + text.slice(cursor)
}

/** Mask an assignment value: a quoted value keeps its quotes; auth schemes are left to BEARER/BASIC. */
function maskAssignedValue(value: string): string {
  if (/^(bearer|basic|token)$/i.test(value)) return value
  const q = value[0]
  if ((q === '"' || q === "'") && value.length >= 2 && value.endsWith(q)) {
    return q + redactSecretValue(value.slice(1, -1)) + q
  }
  return redactSecretValue(value)
}

/** Mask known secret shapes inside free text, leaving the rest of the line intact. */
export function scrubSecretShapes(text: string): string {
  let out = replaceGroup(text, URL_CREDENTIAL_RE, 1, () => '***')
  out = replaceGroup(out, TOKEN_SHAPE_RE, 0, redactSecretValue)
  out = replaceGroup(out, BEARER_RE, 1, redactSecretValue)
  out = replaceGroup(out, BASIC_RE, 1, redactSecretValue)
  out = replaceGroup(out, MYSQL_P_FLAG_RE, 1, redactSecretValue)
  out = replaceGroup(out, CLI_FLAG_SECRET_RE, 1, redactSecretValue)
  out = replaceGroup(out, CURL_USER_RE, 1, () => '***')
  out = replaceGroup(out, SQL_PASSWORD_RE, 1, redactSecretValue)
  out = replaceGroup(out, SECRET_ASSIGNMENT_RE, 1, maskAssignedValue)
  return replaceGroup(out, AUTH_ASSIGNMENT_RE, 1, maskAssignedValue)
}

/**
 * The safe form of one finding's evidence. Always masks: callers that know the text is
 * already redacted at the source (the legacy secrets check) must not call this — see
 * `redactFindingsEvidence`'s `alreadyRedacted` set.
 */
export function redactEvidence(evidence: string, category: string): string {
  if (category === 'secrets') {
    const trimmed = evidence.trim()
    if (NON_SECRET_EVIDENCE_RE.test(trimmed)) return evidence
    return `...${redactSecretValue(trimmed)}...`
  }
  return scrubSecretShapes(evidence)
}

/**
 * Cross-run identity DIGEST of a finding: a truncated SHA-256 of the matched evidence text,
 * falling back to the title when there is none — NOT the line number, so code that shifts
 * keeps its identity. This value stays in memory only. History persists
 * HMAC(per-history salt, digest) instead (history/finding-key.ts), so a copy of the history
 * file cannot be used to test guesses for a weak secret.
 */
export function computeFindingKey(finding: Finding): string {
  const basis = finding.evidence && finding.evidence.length > 0 ? finding.evidence : finding.title
  return createHash('sha256').update(basis).digest('hex').slice(0, 16)
}

const FINDING_KEY_PROP = '_findingKey'

/**
 * The identity key stamped by `redactFindingsEvidence`, or (for a finding that never went
 * through scan(), e.g. a hand-built one in a test) computed from its evidence.
 */
export function getFindingKey(finding: Finding): string {
  const stamped = (finding as unknown as Record<string, unknown>)[FINDING_KEY_PROP]
  return typeof stamped === 'string' ? stamped : computeFindingKey(finding)
}

/**
 * Redact every finding's evidence in place. THE central call — `scan()` runs it once over
 * the fully assembled list (legacy + bundled corpus + Pro rules).
 *
 * Before masking, each finding's identity key is computed from the RAW evidence and stamped
 * on the finding as a NON-ENUMERABLE property, so it never reaches JSON.stringify, spread
 * copies of the public result, SARIF or the reports (the `--json` schema is untouched), yet
 * history can still tell two keys that share an 8-char prefix apart. Only the digest is ever
 * persisted, never the raw text.
 *
 * @param alreadyRedacted findings whose evidence was masked at the source (the legacy
 *   secrets check); their evidence is left exactly as they emitted it.
 */
export function redactFindingsEvidence(
  findings: Finding[],
  alreadyRedacted: ReadonlySet<Finding> = new Set(),
): Finding[] {
  for (const f of findings) {
    Object.defineProperty(f, FINDING_KEY_PROP, {
      value: computeFindingKey(f),
      enumerable: false,
      writable: true,
      configurable: true,
    })
    if (typeof f.evidence !== 'string' || f.evidence.length === 0) continue
    if (alreadyRedacted.has(f)) continue
    f.evidence = redactEvidence(f.evidence, f.category)
  }
  return findings
}
