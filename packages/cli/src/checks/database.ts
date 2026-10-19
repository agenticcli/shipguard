// Free-tier checks. The rule source of truth is migrating to a hosted rule registry.
import type { CheckModule, FileInfo, Finding, Policy } from '@agenticcli/shared'
import { compileDetectorRegex, type CompiledDetectorRegex } from '../core/re2-detector-engine.js'
import { logger } from '../utils/logger.js'

// Migration file patterns to target (path classifiers — non-content, native RegExp is fine).
// eslint-disable-next-line no-restricted-syntax
// These match FILE PATHS only, not user-controlled content — not ReDoS targets.
/* eslint-disable no-restricted-syntax */
const MIGRATION_PATTERNS = [
  /^prisma\/migrations\/.+\.sql$/i,
  /^drizzle\/.+\.sql$/i,
  /^migrations\/.+\.sql$/i,
  /^db\/.+\.sql$/i,
  // Supabase CLI default layout (`supabase init` / `supabase migration new`) —
  // free-tier secret gaps: this was missing entirely, so every DEFAULT Supabase project's
  // migrations silently skipped the destructive-migration checks below (DROP TABLE,
  // TRUNCATE, DELETE FROM without WHERE, etc.). A
  // real-world repro: `supabase/migrations/0001_create_orders.sql` went unclassified and unscanned.
  /^supabase\/migrations\/.+\.sql$/i,
  /^[^/]+\.sql$/i, // root-level .sql files
]
/* eslint-enable no-restricted-syntax */

function isMigrationFile(relativePath: string): boolean {
  return MIGRATION_PATTERNS.some((p) => p.test(relativePath))
}

// ---------------------------------------------------------------------------
// Compiled content-scanning patterns (re2js engine — ReDoS-immune)
// ---------------------------------------------------------------------------

// SQL comment stripping: /\/\*[\s\S]*?\*\//g and /--[^\n]*/g
// 's' (DOTALL) flag makes '.' match newlines — equivalent to [\s\S] without DOTALL.
// We use DOTALL here so '.' covers newlines inside block comments.
const BLOCK_COMMENT_RE = compileDetectorRegex('\\/\\*.*?\\*\\/', 's')
const LINE_COMMENT_RE = compileDetectorRegex('--[^\n]*')

// Newline counter: /\n/g — used in splitStatements and findLineNumber
const NEWLINE_RE = compileDetectorRegex('\n')

// WHERE guard: /\bWHERE\b/i
const WHERE_RE = compileDetectorRegex('\\bWHERE\\b', 'i')

// Tool identification: /prisma/i
const PRISMA_TOOL_RE = compileDetectorRegex('prisma', 'i')

// Remove SQL line comments (-- ...) and block comments (/* ... */) before pattern matching.
// This prevents commented-out destructive statements from triggering findings.
function stripSqlComments(sql: string): string {
  // Remove block comments first (re2js-backed replace), then line comments
  return LINE_COMMENT_RE.replace(BLOCK_COMMENT_RE.replace(sql, ' '), '')
}

// Split SQL into individual statements by semicolons, preserving roughly one statement per chunk.
function splitStatements(sql: string): Array<{ text: string; startLine: number }> {
  const statements: Array<{ text: string; startLine: number }> = []
  const parts = sql.split(';')
  let currentLine = 1

  for (const part of parts) {
    const trimmed = part.trim()
    if (trimmed.length > 0) {
      statements.push({ text: trimmed, startLine: currentLine })
    }
    // Count newlines consumed by this part + the separator (re2js-backed matchAll)
    currentLine += NEWLINE_RE.matchAll(part).length
  }

  return statements
}

// Find the approximate line number of a match within the original content
function findLineNumber(content: string, matchIndex: number): number {
  const before = content.slice(0, matchIndex)
  // Count newlines in the prefix (re2js-backed matchAll)
  return NEWLINE_RE.matchAll(before).length + 1
}

type PatternDef = {
  id: string
  title: string
  severity: Finding['severity']
  confidence: Finding['confidence']
  explanation: string
  recommendation: string
  pattern: CompiledDetectorRegex
  /**
   * If true, this pattern is only reported when there is NO WHERE clause
   * in the same statement (used for DELETE FROM).
   */
  requiresNoWhere?: boolean
  /**
   * If true, skip this match when a higher-priority pattern already matched
   * the same line (avoids double-flagging DROP COLUMN as both high and medium).
   */
  skipIfSiblingMatched?: string
}

const SQL_PATTERNS: PatternDef[] = [
  {
    id: 'db-drop-table',
    title: 'Destructive migration: DROP TABLE',
    severity: 'critical',
    confidence: 'HIGH',
    explanation:
      'DROP TABLE permanently deletes a table and all its data. In production this causes irreversible data loss and immediate application failure for any query targeting that table.',
    recommendation:
      'Never drop a table in the same migration that removes code references. Use an expand-contract strategy: deprecate code first, then drop in a later release after confirming no traffic.',
    pattern: compileDetectorRegex('\\bDROP\\s+TABLE\\b', 'i'),
  },
  {
    id: 'db-drop-column',
    title: 'Destructive migration: DROP COLUMN',
    severity: 'high',
    confidence: 'HIGH',
    explanation:
      'DROP COLUMN removes a column and its data permanently. Running this while old application code still reads the column causes immediate query failures.',
    recommendation:
      'Deprecate the column in code first, deploy, confirm no usage, then run the drop in a separate migration.',
    pattern: compileDetectorRegex('\\bDROP\\s+COLUMN\\b', 'i'),
  },
  {
    id: 'db-truncate',
    title: 'Destructive migration: TRUNCATE',
    severity: 'high',
    confidence: 'HIGH',
    explanation:
      'TRUNCATE deletes all rows in a table instantly without logging individual row deletions, making it very fast but also unrecoverable without a full backup restore.',
    recommendation:
      'Remove TRUNCATE from migration files. Data wipes should be explicit operational procedures, not automatic schema changes.',
    pattern: compileDetectorRegex('\\bTRUNCATE\\b', 'i'),
  },
  {
    id: 'db-delete-without-where',
    title: 'Unsafe migration: DELETE FROM without WHERE clause',
    severity: 'high',
    confidence: 'HIGH',
    explanation:
      'DELETE FROM without a WHERE clause deletes every row in the table. In a migration file this almost always indicates a copy-paste error or oversight.',
    recommendation:
      'Add a WHERE clause, or replace with TRUNCATE (and add a review gate) if a full wipe is truly intended.',
    pattern: compileDetectorRegex('\\bDELETE\\s+FROM\\b', 'i'),
    requiresNoWhere: true,
  },
  {
    id: 'db-alter-drop',
    title: 'Potentially destructive migration: ALTER TABLE DROP',
    severity: 'medium',
    confidence: 'MEDIUM',
    explanation:
      'ALTER TABLE … DROP (other than DROP COLUMN, which is flagged separately) can drop constraints, indexes, or partitions. Dropping a NOT NULL constraint or unique index affects data integrity and query plans.',
    recommendation:
      'Review what exactly is being dropped. Ensure application code is already compatible with the removed constraint before deploying.',
    // Avoid double-flagging lines that already match DROP COLUMN (handled above)
    // Note: /\bALTER\s+TABLE\b[^;]*\bDROP\b/i — [^;]* is RE2-compatible (no lookaround needed)
    pattern: compileDetectorRegex('\\bALTER\\s+TABLE\\b[^;]*\\bDROP\\b', 'i'),
    skipIfSiblingMatched: 'db-drop-column',
  },
]

// Checks for "db push" commands in package.json scripts — dangerous in CI/production
// Compiled as re2js patterns (content-scanning against script values)
const PUSH_PATTERNS: CompiledDetectorRegex[] = [
  compileDetectorRegex('prisma\\s+db\\s+push', 'i'),
  compileDetectorRegex('drizzle-kit\\s+push', 'i'),
]

function checkSqlFile(file: FileInfo, findings: Finding[]): void {
  const raw = file.content
  const stripped = stripSqlComments(raw)
  const statements = splitStatements(stripped)

  // Track which finding IDs have already fired on each line to avoid double-flagging
  const matchedLinesById = new Map<string, Set<number>>()

  for (const pattern of SQL_PATTERNS) {
    for (const stmt of statements) {
      if (!pattern.pattern.test(stmt.text)) continue

      // DELETE FROM: only flag when no WHERE present in same statement
      if (pattern.requiresNoWhere) {
        const hasWhere = WHERE_RE.test(stmt.text)
        if (hasWhere) continue
      }

      // ALTER TABLE DROP: skip if the same statement already triggered DROP COLUMN
      if (pattern.skipIfSiblingMatched) {
        const siblingId = pattern.skipIfSiblingMatched
        // Re-test sibling pattern against the same statement
        const siblingPattern = SQL_PATTERNS.find((p) => p.id === siblingId)
        if (siblingPattern && siblingPattern.pattern.test(stmt.text)) continue
      }

      // Find the actual match position in the stripped content for line calculation
      const matchInStripped = pattern.pattern.exec(stmt.text)
      const matchIndex = matchInStripped ? raw.indexOf(stmt.text.slice(0, 40)) : 0
      const lineNumber = matchIndex >= 0 ? findLineNumber(raw, matchIndex) : stmt.startLine

      // Deduplicate: same finding-id + line combo
      if (!matchedLinesById.has(pattern.id)) {
        matchedLinesById.set(pattern.id, new Set())
      }
      const lines = matchedLinesById.get(pattern.id)!
      if (lines.has(lineNumber)) continue
      lines.add(lineNumber)

      // Extract a short evidence snippet from the raw SQL at the approximate line
      const rawLines = raw.split('\n')
      const evidenceLine = rawLines[lineNumber - 1]?.trim().slice(0, 120) ?? stmt.text.slice(0, 120)

      findings.push({
        id: pattern.id,
        title: pattern.title,
        severity: pattern.severity,
        category: 'database',
        file: file.relativePath,
        line: lineNumber,
        evidence: evidenceLine,
        confidence: pattern.confidence,
        explanation: pattern.explanation,
        recommendation: pattern.recommendation,
        blocking: pattern.severity === 'critical' || pattern.severity === 'high',
      })
    }
  }
}

function checkPackageJson(file: FileInfo, findings: Finding[]): void {
  if (!file.relativePath.endsWith('package.json')) return

  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(file.content) as Record<string, unknown>
  } catch (err: unknown) {
    // Root cause: a
    // malformed package.json used to be swallowed here — the db-push-in-scripts
    // check silently produced zero findings with no warning, so a repo with a
    // syntactically broken package.json looked identical to one with no
    // dangerous scripts at all. every catch block must log.
    // logger.warn is stderr-only (never touches the --json stdout payload —
    // see utils/logger.ts), and this informational Finding makes the parse
    // failure visible in --json output too, since check modules have no other
    // channel back to the scan result (they are pure (files, policy) =>
    // Finding[] — see CheckModule in @agenticcli/shared).
    const detail = err instanceof Error ? err.message : String(err)
    logger.warn(`[database] Could not parse ${file.relativePath} as JSON — db-push-in-scripts check skipped for this file: ${detail}`)
    findings.push({
      id: 'pkg-json-unparseable-database',
      title: `Could not parse ${file.relativePath} — database checks skipped for this file`,
      severity: 'info',
      category: 'database',
      file: file.relativePath,
      evidence: detail.slice(0, 200),
      confidence: 'HIGH',
      explanation:
        'package.json is not valid JSON, so the db-push-in-scripts check (dangerous "prisma db push" / "drizzle-kit push" in scripts) could not run against this file.',
      recommendation: 'Fix the JSON syntax error in package.json so ShipGuard can scan its scripts.',
      blocking: false,
    })
    return
  }

  const scripts = parsed['scripts']
  if (!scripts || typeof scripts !== 'object') return

  for (const [scriptName, scriptValue] of Object.entries(scripts as Record<string, unknown>)) {
    if (typeof scriptValue !== 'string') continue

    for (const pushPattern of PUSH_PATTERNS) {
      if (!pushPattern.test(scriptValue)) continue

      const tool = PRISMA_TOOL_RE.test(scriptValue) ? 'prisma db push' : 'drizzle-kit push'
      findings.push({
        id: 'db-push-in-scripts',
        title: `Dangerous command in package.json scripts: ${tool}`,
        severity: 'medium',
        category: 'database',
        file: file.relativePath,
        evidence: `"${scriptName}": "${scriptValue.slice(0, 120)}"`,
        confidence: 'HIGH',
        explanation:
          `The "${tool}" command bypasses migration files and applies schema changes directly to the database without an audit trail. ` +
          'In production or CI this can silently drop columns, tables, or constraints with no rollback path.',
        recommendation:
          'Replace with "prisma migrate deploy" (Prisma) or "drizzle-kit migrate" (Drizzle) in all non-local scripts. ' +
          'Reserve db push for local prototype databases only.',
        blocking: false,
      })
      break // one finding per script entry is enough
    }
  }
}

/**
 * Checks whether a Prisma schema file was modified without a corresponding migration file
 * being present in the same file set. This is meaningful primarily when scanning only
 * changed files (--changed mode); in full-scan mode it may produce false positives when
 * the schema and migration changes land in different commits.
 */
function checkPrismaSchemaWithoutMigration(files: FileInfo[], findings: Finding[]): void {
  const hasSchemaChange = files.some((f) => f.relativePath === 'prisma/schema.prisma')
  if (!hasSchemaChange) return

  // eslint-disable-next-line no-restricted-syntax
  const hasMigration = files.some((f) => /^prisma\/migrations\/.+\.sql$/i.test(f.relativePath)) // path classifier
  if (hasMigration) return

  const schemaFile = files.find((f) => f.relativePath === 'prisma/schema.prisma')!
  findings.push({
    id: 'db-schema-without-migration',
    title: 'Prisma schema changed without a migration file',
    severity: 'medium',
    category: 'database',
    file: schemaFile.relativePath,
    confidence: 'MEDIUM',
    explanation:
      'The Prisma schema was modified but no migration file appears in the changed file set. ' +
      'In production you must run "prisma migrate dev" to generate a migration, then commit it before deploying.',
    recommendation:
      'Run "npx prisma migrate dev --name <description>" locally, commit the generated migration file in prisma/migrations/, and re-scan.',
    blocking: false,
  })
}

export const databaseCheck: CheckModule = {
  id: 'database',
  name: 'Database & Migration Safety',

  run(files: FileInfo[], _policy: Policy): Finding[] {
    const findings: Finding[] = []

    for (const file of files) {
      if (isMigrationFile(file.relativePath)) {
        checkSqlFile(file, findings)
      } else if (file.relativePath.endsWith('package.json')) {
        checkPackageJson(file, findings)
      }
    }

    checkPrismaSchemaWithoutMigration(files, findings)

    return findings
  },
}
