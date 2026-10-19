/**
 * database-migration.test.ts — Phase D.4 four-part migration proof
 *
 * Verifies that database.ts has been correctly migrated from native RegExp to
 * the re2js-backed compileDetectorRegex helper, with no change in detector
 * behavior (no false-negatives, no false-positives introduced).
 *
 * PART 1: STRENGTHENED FIXTURES — safe + unsafe cases exercising all 13 migrated
 *         regex sites, including comment-strip and statement-split paths.
 * PART 2: NATIVE↔RE2JS DIFFERENTIAL — every migrated pattern compared against
 *         native RegExp oracle on the same fixture inputs.
 * PART 3: PROPERTY-GENERATED INPUTS — SQL-ish strings tested against native oracle.
 * PART 4: TARGETED MUTATION — boundary/anchor, per-line vs whole-content, capture
 *         offsets, comment-strip/split edge cases.
 */

import { describe, it, expect } from 'vitest'
import { databaseCheck } from '../../src/checks/database.js'
import { compileDetectorRegex } from '../../src/core/re2-detector-engine.js'
import type { FileInfo, Policy } from '@agenticcli/shared'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const POLICY: Policy = {
  version: 1,
  project: { name: 'test', framework: 'next', risk_profile: 'standard' },
  scan: { changed_files_only: true, generate_report: false },
  block: [],
  warn: [],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}

function makeFile(relativePath: string, content: string): FileInfo {
  return { path: `/repo/${relativePath}`, relativePath, content }
}

function sqlFile(content: string): FileInfo {
  return makeFile('migrations/test.sql', content)
}

function pkgFile(scripts: Record<string, string>): FileInfo {
  return makeFile('package.json', JSON.stringify({ name: 'app', scripts }))
}

/** Run a native regex test (oracle for differential comparisons) */
function nativeTest(source: string, flags: string, input: string): boolean {
  return new RegExp(source, flags).test(input)
}

/** Run native global replace (oracle for differential comparisons) */
function nativeReplaceGlobal(source: string, flags: string, input: string, repl: string): string {
  return input.replace(new RegExp(source, 'g' + flags.replace('g', '')), repl)
}

/** Run native global matchAll count (oracle for differential comparisons) */
function nativeMatchCount(source: string, flags: string, input: string): number {
  return [...input.matchAll(new RegExp(source, 'g' + flags.replace('g', '')))].length
}

// ---------------------------------------------------------------------------
// PART 1: STRENGTHENED FIXTURES
// ---------------------------------------------------------------------------

describe('PART 1 — strengthened fixtures: unsafe cases MUST fire', () => {
  // --- SQL_PATTERNS[0]: DROP TABLE ---
  it('flags DROP TABLE (uppercase)', () => {
    const findings = databaseCheck.run([sqlFile('DROP TABLE users;')], POLICY)
    expect(findings.some(f => f.id === 'db-drop-table')).toBe(true)
  })
  it('flags drop table (lowercase, case-insensitive)', () => {
    const findings = databaseCheck.run([sqlFile('drop table sessions;')], POLICY)
    expect(findings.some(f => f.id === 'db-drop-table')).toBe(true)
  })
  it('flags DROP   TABLE (multiple spaces, \\s+)', () => {
    const findings = databaseCheck.run([sqlFile('DROP   TABLE orders;')], POLICY)
    expect(findings.some(f => f.id === 'db-drop-table')).toBe(true)
  })
  it('does NOT flag "DROPDOWN TABLE" (word boundary \\b)', () => {
    const findings = databaseCheck.run([sqlFile('DROPDOWN TABLE settings;')], POLICY)
    expect(findings.some(f => f.id === 'db-drop-table')).toBe(false)
  })

  // --- SQL_PATTERNS[1]: DROP COLUMN ---
  it('flags DROP COLUMN', () => {
    const findings = databaseCheck.run([sqlFile('ALTER TABLE t DROP COLUMN c;')], POLICY)
    expect(findings.some(f => f.id === 'db-drop-column')).toBe(true)
  })
  it('does NOT flag "DROPCOLUMN" (no space, no \\s+ match)', () => {
    // Actually this should not match because \s+ requires at least one space
    const findings = databaseCheck.run([sqlFile('ALTER TABLE t DROPCOLUMN c;')], POLICY)
    expect(findings.some(f => f.id === 'db-drop-column')).toBe(false)
  })

  // --- SQL_PATTERNS[2]: TRUNCATE ---
  it('flags TRUNCATE TABLE', () => {
    const findings = databaseCheck.run([sqlFile('TRUNCATE TABLE sessions;')], POLICY)
    expect(findings.some(f => f.id === 'db-truncate')).toBe(true)
  })
  it('flags bare TRUNCATE', () => {
    const findings = databaseCheck.run([sqlFile('TRUNCATE sessions;')], POLICY)
    expect(findings.some(f => f.id === 'db-truncate')).toBe(true)
  })
  it('does NOT flag "TRUNCATED" (word boundary)', () => {
    const findings = databaseCheck.run([sqlFile('SELECT TRUNCATED FROM t;')], POLICY)
    expect(findings.some(f => f.id === 'db-truncate')).toBe(false)
  })

  // --- SQL_PATTERNS[3]: DELETE FROM without WHERE ---
  it('flags DELETE FROM without WHERE', () => {
    const findings = databaseCheck.run([sqlFile('DELETE FROM sessions;')], POLICY)
    expect(findings.some(f => f.id === 'db-delete-without-where')).toBe(true)
  })
  it('does NOT flag DELETE FROM with WHERE (WHERE guard)', () => {
    const findings = databaseCheck.run([sqlFile('DELETE FROM users WHERE id = 1;')], POLICY)
    expect(findings.some(f => f.id === 'db-delete-without-where')).toBe(false)
  })
  it('does NOT flag delete from with where (case-insensitive WHERE guard)', () => {
    const findings = databaseCheck.run([sqlFile('delete from users where id = 1;')], POLICY)
    expect(findings.some(f => f.id === 'db-delete-without-where')).toBe(false)
  })

  // --- SQL_PATTERNS[4]: ALTER TABLE DROP (non-COLUMN) ---
  it('flags ALTER TABLE DROP CONSTRAINT', () => {
    const findings = databaseCheck.run([sqlFile('ALTER TABLE t DROP CONSTRAINT fk;')], POLICY)
    expect(findings.some(f => f.id === 'db-alter-drop')).toBe(true)
  })
  it('does NOT flag ALTER TABLE ADD COLUMN', () => {
    const findings = databaseCheck.run([sqlFile('ALTER TABLE t ADD COLUMN x TEXT;')], POLICY)
    expect(findings.some(f => f.id === 'db-alter-drop')).toBe(false)
  })
  it('does NOT double-flag DROP COLUMN as both db-drop-column and db-alter-drop', () => {
    const findings = databaseCheck.run([sqlFile('ALTER TABLE t DROP COLUMN x;')], POLICY)
    expect(findings.some(f => f.id === 'db-drop-column')).toBe(true)
    expect(findings.some(f => f.id === 'db-alter-drop')).toBe(false)
  })

  // --- PUSH_PATTERNS ---
  it('flags prisma db push in package.json scripts', () => {
    const findings = databaseCheck.run([pkgFile({ deploy: 'prisma db push' })], POLICY)
    expect(findings.some(f => f.id === 'db-push-in-scripts')).toBe(true)
  })
  it('flags drizzle-kit push in package.json scripts', () => {
    const findings = databaseCheck.run([pkgFile({ migrate: 'drizzle-kit push' })], POLICY)
    expect(findings.some(f => f.id === 'db-push-in-scripts')).toBe(true)
  })
  it('does NOT flag prisma migrate deploy', () => {
    const findings = databaseCheck.run([pkgFile({ deploy: 'prisma migrate deploy' })], POLICY)
    expect(findings.some(f => f.id === 'db-push-in-scripts')).toBe(false)
  })

  // --- Comment-stripping exercises (lines 22/23) ---
  it('does NOT flag DROP TABLE inside SQL line comment -- ...', () => {
    const findings = databaseCheck.run([sqlFile('-- DROP TABLE old;\nSELECT 1;')], POLICY)
    expect(findings.some(f => f.id === 'db-drop-table')).toBe(false)
  })
  it('does NOT flag DROP TABLE inside block comment /* ... */', () => {
    const findings = databaseCheck.run([sqlFile('/* DROP TABLE old; */\nSELECT 1;')], POLICY)
    expect(findings.some(f => f.id === 'db-drop-table')).toBe(false)
  })
  it('does NOT flag TRUNCATE inside multiline block comment', () => {
    const sql = '/*\n  TRUNCATE sessions;\n  This is disabled.\n*/\nSELECT 1;'
    const findings = databaseCheck.run([sqlFile(sql)], POLICY)
    expect(findings.some(f => f.id === 'db-truncate')).toBe(false)
  })
  it('DOES flag DROP TABLE after block comment is stripped (real code follows comment)', () => {
    const sql = '/* safe comment */\nDROP TABLE old_data;'
    const findings = databaseCheck.run([sqlFile(sql)], POLICY)
    expect(findings.some(f => f.id === 'db-drop-table')).toBe(true)
  })
  it('DOES flag DELETE FROM without WHERE after line comment on preceding line', () => {
    const sql = '-- housekeeping\nDELETE FROM sessions;'
    const findings = databaseCheck.run([sqlFile(sql)], POLICY)
    expect(findings.some(f => f.id === 'db-delete-without-where')).toBe(true)
  })

  // --- Statement-splitting exercises (line 29) ---
  it('flags issues in the second of two ;-separated statements', () => {
    const sql = 'ALTER TABLE t ADD COLUMN x TEXT;\nDROP TABLE old_data;'
    const findings = databaseCheck.run([sqlFile(sql)], POLICY)
    expect(findings.some(f => f.id === 'db-drop-table')).toBe(true)
  })
  it('flags DELETE without WHERE in a multi-statement file (others are safe)', () => {
    const sql = [
      'CREATE TABLE a (id INT);',
      'CREATE INDEX idx_a ON a (id);',
      'DELETE FROM a;',
    ].join('\n')
    const findings = databaseCheck.run([sqlFile(sql)], POLICY)
    expect(findings.some(f => f.id === 'db-delete-without-where')).toBe(true)
  })

  // --- Safe look-alikes that must NOT fire ---
  it('does NOT flag CREATE TABLE', () => {
    const findings = databaseCheck.run([sqlFile('CREATE TABLE products (id SERIAL);')], POLICY)
    expect(findings).toHaveLength(0)
  })
  it('does NOT flag SELECT with WHERE (safe)', () => {
    const findings = databaseCheck.run([sqlFile('SELECT id FROM users WHERE active = true;')], POLICY)
    expect(findings).toHaveLength(0)
  })
  it('does NOT flag ALTER TABLE RENAME COLUMN (safe ALTER)', () => {
    const findings = databaseCheck.run([sqlFile('ALTER TABLE t RENAME COLUMN x TO y;')], POLICY)
    expect(findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// PART 2: NATIVE↔RE2JS DIFFERENTIAL
// ---------------------------------------------------------------------------

describe('PART 2 — native↔re2js differential: every migrated pattern identical to native', () => {
  // SQL patterns — test/exec differential
  const SQL_PATTERN_CASES: Array<{ id: string; source: string; flags: string; inputs: string[] }> = [
    {
      id: 'db-drop-table: \\bDROP\\s+TABLE\\b (i)',
      source: '\\bDROP\\s+TABLE\\b',
      flags: 'i',
      inputs: [
        'DROP TABLE users',
        'drop   table sessions',
        'DROP  TABLE',
        'CREATE TABLE x',
        'DROPDOWN TABLE',
        '',
        'ALTER TABLE foo DROP TABLE bar',
      ],
    },
    {
      id: 'db-drop-column: \\bDROP\\s+COLUMN\\b (i)',
      source: '\\bDROP\\s+COLUMN\\b',
      flags: 'i',
      inputs: [
        'ALTER TABLE t DROP COLUMN x',
        'drop column y',
        'ALTER TABLE t ADD COLUMN z',
        'DROPCOLUMN x',
        '',
      ],
    },
    {
      id: 'db-truncate: \\bTRUNCATE\\b (i)',
      source: '\\bTRUNCATE\\b',
      flags: 'i',
      inputs: [
        'TRUNCATE sessions',
        'truncate TABLE foo',
        'TRUNCATED data',
        'PRETRUNCATE',
        '',
      ],
    },
    {
      id: 'db-delete-without-where: \\bDELETE\\s+FROM\\b (i)',
      source: '\\bDELETE\\s+FROM\\b',
      flags: 'i',
      inputs: [
        'DELETE FROM users',
        'delete   from sessions',
        'SELECT * FROM t',
        'DELETE_FROM x',
        '',
      ],
    },
    {
      id: 'db-alter-drop: \\bALTER\\s+TABLE\\b[^;]*\\bDROP\\b (i)',
      source: '\\bALTER\\s+TABLE\\b[^;]*\\bDROP\\b',
      flags: 'i',
      inputs: [
        'ALTER TABLE t DROP CONSTRAINT fk',
        'alter   table orders drop index idx',
        'ALTER TABLE t ADD COLUMN x',
        'ALTER TABLE t DROP COLUMN c',
        'alter table t drop',
        '',
        // Cross-statement: [^;]* must not cross semicolons
        'ALTER TABLE t ADD x; DROP TABLE other',
      ],
    },
    {
      id: 'push-pattern: prisma\\s+db\\s+push (i)',
      source: 'prisma\\s+db\\s+push',
      flags: 'i',
      inputs: [
        'prisma db push',
        'PRISMA DB PUSH',
        'prisma  db  push',
        'prisma migrate deploy',
        'npx prisma db push --force',
        '',
      ],
    },
    {
      id: 'push-pattern: drizzle-kit\\s+push (i)',
      source: 'drizzle-kit\\s+push',
      flags: 'i',
      inputs: [
        'drizzle-kit push',
        'DRIZZLE-KIT PUSH',
        'drizzle-kit  push:pg',
        'drizzle-kit migrate',
        '',
      ],
    },
    {
      id: 'WHERE guard: \\bWHERE\\b (i)',
      source: '\\bWHERE\\b',
      flags: 'i',
      inputs: [
        'DELETE FROM t WHERE id = 1',
        'delete from t where active = false',
        'DELETE FROM t',
        'ELSEWHERE is fine',
        '',
      ],
    },
    {
      id: 'tool identification: prisma (i)',
      source: 'prisma',
      flags: 'i',
      inputs: [
        'prisma db push',
        'PRISMA db push',
        'drizzle-kit push',
        '',
      ],
    },
  ]

  for (const { id, source, flags, inputs } of SQL_PATTERN_CASES) {
    describe(`pattern: ${id}`, () => {
      for (const input of inputs) {
        it(`test("${input.slice(0, 60)}") → native oracle`, () => {
          const re2 = compileDetectorRegex(source, flags)
          const native = nativeTest(source, flags, input)
          expect(re2.test(input)).toBe(native)
        })
      }
    })
  }

  // Replace differential for comment-stripping patterns
  const REPLACE_DIFF_CASES = [
    {
      id: 'block-comment strip: \\/\\*.*?\\*\\/ (s) → " "',
      source: '\\/\\*.*?\\*\\/',
      flags: 's',
      replacement: ' ',
      inputs: [
        '/* DROP TABLE foo; */ SELECT 1;',
        '/* line1\nline2 */\nSELECT 2;',
        'no comments here',
        '/* a *//* b *//* c */',
        '',
      ],
    },
    {
      id: 'line-comment strip: --[^\\n]* → ""',
      source: '--[^\n]*',
      flags: '',
      replacement: '',
      inputs: [
        '-- drop table old\nSELECT 1;',
        'SELECT 1; -- inline\nSELECT 2; -- another',
        'no comments',
        '-- only comment',
        '',
      ],
    },
  ]

  for (const { id, source, flags, replacement, inputs } of REPLACE_DIFF_CASES) {
    describe(`replace: ${id}`, () => {
      for (const input of inputs) {
        it(`replace("${input.slice(0, 50)}") → native oracle`, () => {
          const re2 = compileDetectorRegex(source, flags)
          const native = nativeReplaceGlobal(source, flags, input, replacement)
          expect(re2.replace(input, replacement)).toBe(native)
        })
      }
    })
  }

  // matchAll count differential for newline counting patterns
  describe('newline counter: \\n matchAll count', () => {
    const NEWLINE_INPUTS = [
      'line1\nline2\nline3',
      'no newlines',
      '\n\n\n',
      '',
      'a\nb',
      'DROP TABLE foo;\nALTER TABLE t DROP COLUMN c;\nTRUNCATE sessions;',
    ]
    for (const input of NEWLINE_INPUTS) {
      it(`matchAll count("${input.slice(0, 40)}") → native oracle`, () => {
        const re2 = compileDetectorRegex('\n')
        const nativeCount = nativeMatchCount('\n', '', input)
        expect(re2.matchAll(input).length).toBe(nativeCount)
      })
    }
  })
})

// ---------------------------------------------------------------------------
// PART 3: PROPERTY-GENERATED INPUTS (native oracle on safe subset)
// ---------------------------------------------------------------------------

describe('PART 3 — property-generated SQL-ish inputs vs native oracle', () => {
  // Generated SQL-ish strings: keyword variants + commentary + multi-statement
  const SQL_KEYWORDS = ['SELECT', 'INSERT', 'UPDATE', 'CREATE', 'ALTER', 'DELETE', 'DROP', 'TRUNCATE']
  const TARGETS = ['TABLE', 'COLUMN', 'INDEX', 'CONSTRAINT', 'DATABASE']
  const PATTERNS_UNDER_TEST: Array<{ source: string; flags: string }> = [
    { source: '\\bDROP\\s+TABLE\\b', flags: 'i' },
    { source: '\\bDROP\\s+COLUMN\\b', flags: 'i' },
    { source: '\\bTRUNCATE\\b', flags: 'i' },
    { source: '\\bDELETE\\s+FROM\\b', flags: 'i' },
    { source: '\\bALTER\\s+TABLE\\b[^;]*\\bDROP\\b', flags: 'i' },
    { source: '\\bWHERE\\b', flags: 'i' },
    { source: 'prisma\\s+db\\s+push', flags: 'i' },
    { source: 'drizzle-kit\\s+push', flags: 'i' },
  ]

  // Build a set of generated inputs
  const generatedInputs: string[] = []
  for (const kw of SQL_KEYWORDS) {
    for (const tgt of TARGETS) {
      generatedInputs.push(`${kw} ${tgt} foo;`)
      generatedInputs.push(`${kw.toLowerCase()} ${tgt.toLowerCase()} foo;`)
      generatedInputs.push(`ALTER TABLE t ${kw} ${tgt} x;`)
    }
  }
  // Add SQL-ish strings with comments
  generatedInputs.push('-- DROP TABLE foo\nSELECT 1;')
  generatedInputs.push('/* TRUNCATE x; */\nSELECT 2;')
  generatedInputs.push('DELETE FROM users WHERE id > 0;')
  generatedInputs.push('DELETE FROM users;')
  generatedInputs.push('prisma db push --force')
  generatedInputs.push('drizzle-kit push:pg')
  generatedInputs.push('')
  generatedInputs.push('  ')

  for (const { source, flags } of PATTERNS_UNDER_TEST) {
    describe(`pattern /${source}/${flags}`, () => {
      for (const input of generatedInputs) {
        it(`test("${input.slice(0, 50)}") === native`, () => {
          const re2 = compileDetectorRegex(source, flags)
          expect(re2.test(input)).toBe(nativeTest(source, flags, input))
        })
      }
    })
  }
})

// ---------------------------------------------------------------------------
// PART 4: TARGETED MUTATION — boundary/anchor, comment-strip, split edge cases
// ---------------------------------------------------------------------------

describe('PART 4 — targeted mutation: boundary, comment-strip, split edge cases', () => {
  // Word boundary anchors: \\b must not match partial words
  it('\\bDROP\\s+TABLE\\b does NOT match XDROP TABLE (left boundary)', () => {
    const re = compileDetectorRegex('\\bDROP\\s+TABLE\\b', 'i')
    expect(re.test('XDROP TABLE foo')).toBe(false)
  })
  it('\\bDROP\\s+TABLE\\b does NOT match DROP TABLEX (right boundary)', () => {
    const re = compileDetectorRegex('\\bDROP\\s+TABLE\\b', 'i')
    expect(re.test('DROP TABLEX')).toBe(false)
  })
  it('\\bTRUNCATE\\b does NOT match PRETRUNCATE', () => {
    const re = compileDetectorRegex('\\bTRUNCATE\\b', 'i')
    expect(re.test('PRETRUNCATE sessions')).toBe(false)
  })
  it('\\bTRUNCATE\\b does NOT match TRUNCATED', () => {
    const re = compileDetectorRegex('\\bTRUNCATE\\b', 'i')
    expect(re.test('TRUNCATED sessions')).toBe(false)
  })

  // [^;]* must not cross statement boundary in ALTER TABLE DROP
  it('ALTER TABLE DROP: [^;]* does not span semicolon (cross-statement false-positive prevented)', () => {
    const re = compileDetectorRegex('\\bALTER\\s+TABLE\\b[^;]*\\bDROP\\b', 'i')
    // Without [^;]* the pattern could cross the ; into the next DROP TABLE statement
    // but with [^;]*, it must stop at the first ; — so this should NOT match ALTER TABLE
    // for the DROP TABLE on the second statement
    const twoStmt = 'ALTER TABLE t ADD COLUMN x; DROP TABLE old;'
    // The pattern matches ALTER TABLE ... DROP but [^;]* won't cross the semicolon
    // So the first ALTER TABLE statement has no DROP (only ADD), and should not match
    expect(re.test('ALTER TABLE t ADD COLUMN x')).toBe(false)
    // But a single statement with DROP does match
    expect(re.test('ALTER TABLE t DROP CONSTRAINT fk')).toBe(true)
    // Verify native matches same result for the two-statement string
    expect(re.test(twoStmt)).toBe(nativeTest('\\bALTER\\s+TABLE\\b[^;]*\\bDROP\\b', 'i', twoStmt))
  })

  // Comment stripping edge cases
  it('block comment /* ... */ stripped before pattern matching', () => {
    const blockRe = compileDetectorRegex('\\/\\*.*?\\*\\/', 's')
    const input = '/* DROP TABLE foo; */'
    const stripped = blockRe.replace(input, ' ')
    // Native oracle — the single block comment is replaced with one space
    const nativeResult = nativeReplaceGlobal('\\/\\*.*?\\*\\/', 's', input, ' ')
    expect(stripped).toBe(nativeResult)
  })
  it('nested-like block comments: strips first /* ... */ only (non-greedy)', () => {
    const blockRe = compileDetectorRegex('\\/\\*.*?\\*\\/', 's')
    const input = '/* first */ REAL /* second */ CODE'
    const stripped = blockRe.replace(input, '')
    expect(stripped).toBe(nativeReplaceGlobal('\\/\\*.*?\\*\\/', 's', input, ''))
  })
  it('line comment -- stripped to end of line only (not next line)', () => {
    const lineRe = compileDetectorRegex('--[^\n]*')
    const stripped = lineRe.replace('-- comment\nACTUAL CODE', '')
    expect(stripped).toBe('\nACTUAL CODE')
    expect(stripped).toBe(nativeReplaceGlobal('--[^\n]*', '', '-- comment\nACTUAL CODE', ''))
  })
  it('line comment -- does NOT consume the newline character', () => {
    const lineRe = compileDetectorRegex('--[^\n]*')
    const stripped = lineRe.replace('x -- comment\ny', '')
    // newline must survive
    expect(stripped).toContain('\n')
  })

  // Newline counting correctness (per-line vs whole-content)
  it('NEWLINE_RE.matchAll counts newlines correctly for multi-line SQL', () => {
    const newlineRe = compileDetectorRegex('\n')
    const sql = 'line1\nline2\nline3\nline4'
    expect(newlineRe.matchAll(sql).length).toBe(3)
  })
  it('NEWLINE_RE.matchAll returns 0 for single-line content', () => {
    const newlineRe = compileDetectorRegex('\n')
    expect(newlineRe.matchAll('no newlines here').length).toBe(0)
  })
  it('NEWLINE_RE.matchAll returns 0 for empty string', () => {
    const newlineRe = compileDetectorRegex('\n')
    expect(newlineRe.matchAll('').length).toBe(0)
  })

  // Statement splitting: multi-statement file with comments
  it('full pipeline: comment-stripped multi-statement file reports correct findings', () => {
    const sql = [
      '-- This is a migration',
      '/* Remove legacy table */',
      'DROP TABLE legacy;',
      '-- Cleanup',
      'DELETE FROM sessions;',
      'CREATE TABLE new_table (id SERIAL);',
    ].join('\n')
    const findings = databaseCheck.run([sqlFile(sql)], POLICY)
    // DROP TABLE must fire
    expect(findings.some(f => f.id === 'db-drop-table')).toBe(true)
    // DELETE FROM without WHERE must fire
    expect(findings.some(f => f.id === 'db-delete-without-where')).toBe(true)
    // CREATE TABLE must NOT fire any finding
    const createFindings = findings.filter(f => f.evidence?.includes('CREATE TABLE new_table'))
    expect(createFindings).toHaveLength(0)
  })

  // Capture offset correctness: exec() on SQL patterns
  it('exec() returns correct match text for DROP TABLE pattern', () => {
    const re = compileDetectorRegex('\\bDROP\\s+TABLE\\b', 'i')
    const result = re.exec('ALTER TABLE x; DROP TABLE old;')
    expect(result).not.toBeNull()
    expect(result!.match.toUpperCase()).toContain('DROP')
    expect(result!.match.toUpperCase()).toContain('TABLE')
  })
  it('exec() returns correct index for WHERE guard', () => {
    const re = compileDetectorRegex('\\bWHERE\\b', 'i')
    const input = 'DELETE FROM t WHERE id = 1'
    const result = re.exec(input)
    expect(result).not.toBeNull()
    expect(result!.index).toBe(input.indexOf('WHERE'))
  })

  // PUSH_PATTERNS: \\s+ allows multiple spaces
  it('prisma\\s+db\\s+push matches "prisma  db  push" (multiple spaces)', () => {
    const re = compileDetectorRegex('prisma\\s+db\\s+push', 'i')
    expect(re.test('prisma  db  push')).toBe(true)
  })
  it('drizzle-kit\\s+push matches "drizzle-kit  push:pg"', () => {
    const re = compileDetectorRegex('drizzle-kit\\s+push', 'i')
    expect(re.test('drizzle-kit  push:pg')).toBe(true)
  })

  // replace() statelessness: calling replace() then test() must be consistent
  it('calling replace() does not corrupt state for subsequent test() calls', () => {
    const blockRe = compileDetectorRegex('\\/\\*.*?\\*\\/', 's')
    blockRe.replace('/* DROP TABLE foo; */ SELECT 1;', ' ')
    // After replace, test() must still work correctly
    expect(blockRe.test('/* something */')).toBe(true)
    expect(blockRe.test('no comment here')).toBe(false)
  })
})
