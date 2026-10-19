import { describe, it, expect, vi, afterEach } from 'vitest'
import { databaseCheck } from '../../src/checks/database.js'
import type { FileInfo, Policy } from '@agenticcli/shared'
import { logger } from '../../src/utils/logger.js'

// Minimal policy stub — the database check does not use policy values
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

// ---------------------------------------------------------------------------
// Module metadata
// ---------------------------------------------------------------------------

describe('databaseCheck module metadata', () => {
  it('has id="database"', () => {
    expect(databaseCheck.id).toBe('database')
  })

  it('has a descriptive name', () => {
    expect(databaseCheck.name).toBe('Database & Migration Safety')
  })
})

// ---------------------------------------------------------------------------
// DROP TABLE — critical
// ---------------------------------------------------------------------------

describe('DROP TABLE', () => {
  it('triggers critical finding in Prisma migration', () => {
    const files = [
      makeFile(
        'prisma/migrations/20240101_init/migration.sql',
        'DROP TABLE users;\nCREATE TABLE orders (id SERIAL PRIMARY KEY);',
      ),
    ]
    const findings = databaseCheck.run(files, POLICY)
    const f = findings.find((x) => x.id === 'db-drop-table')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('critical')
    expect(f!.blocking).toBe(true)
    expect(f!.category).toBe('database')
  })

  it('triggers critical finding in Drizzle migration', () => {
    const files = [
      makeFile('drizzle/0001_users.sql', 'DROP TABLE sessions;'),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-drop-table' && f.severity === 'critical')).toBe(true)
  })

  it('triggers in migrations/ directory', () => {
    const files = [makeFile('migrations/001.sql', 'DROP TABLE legacy_data;')]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-drop-table')).toBe(true)
  })

  it('triggers for root-level .sql file', () => {
    const files = [makeFile('seed.sql', 'DROP TABLE temp_data;')]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-drop-table')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// DROP COLUMN — high
// ---------------------------------------------------------------------------

describe('DROP COLUMN', () => {
  it('triggers high finding', () => {
    const files = [
      makeFile(
        'prisma/migrations/20240201/migration.sql',
        'ALTER TABLE users DROP COLUMN email;',
      ),
    ]
    const findings = databaseCheck.run(files, POLICY)
    const f = findings.find((x) => x.id === 'db-drop-column')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.blocking).toBe(true)
  })

  it('does NOT also emit ALTER TABLE DROP (medium) for the same statement', () => {
    // A DROP COLUMN should be high, not additionally flagged as medium ALTER DROP
    const files = [
      makeFile('migrations/drop.sql', 'ALTER TABLE orders DROP COLUMN total;'),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-drop-column')).toBe(true)
    // Should NOT double-flag with the generic alter-drop finding
    expect(findings.some((f) => f.id === 'db-alter-drop')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// TRUNCATE — high
// ---------------------------------------------------------------------------

describe('TRUNCATE', () => {
  it('triggers high finding for TRUNCATE TABLE', () => {
    const files = [makeFile('migrations/truncate.sql', 'TRUNCATE TABLE sessions;')]
    const findings = databaseCheck.run(files, POLICY)
    const f = findings.find((x) => x.id === 'db-truncate')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.blocking).toBe(true)
  })

  it('triggers high finding for bare TRUNCATE', () => {
    const files = [makeFile('migrations/truncate.sql', 'TRUNCATE sessions;')]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-truncate')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// DELETE FROM without WHERE — high
// ---------------------------------------------------------------------------

describe('DELETE FROM', () => {
  it('triggers when DELETE FROM has no WHERE clause', () => {
    const files = [
      makeFile('prisma/migrations/20240301/migration.sql', 'DELETE FROM users;'),
    ]
    const findings = databaseCheck.run(files, POLICY)
    const f = findings.find((x) => x.id === 'db-delete-without-where')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.blocking).toBe(true)
  })

  it('does NOT trigger when DELETE FROM has a WHERE clause', () => {
    const files = [
      makeFile(
        'prisma/migrations/20240302/migration.sql',
        'DELETE FROM users WHERE id = 1;',
      ),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-delete-without-where')).toBe(false)
  })

  it('does NOT trigger on DELETE FROM with a complex WHERE', () => {
    const files = [
      makeFile(
        'migrations/cleanup.sql',
        "DELETE FROM sessions WHERE expires_at < NOW() AND user_id IS NOT NULL;",
      ),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-delete-without-where')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// ALTER TABLE DROP — medium (non-COLUMN)
// ---------------------------------------------------------------------------

describe('ALTER TABLE DROP (non-COLUMN)', () => {
  it('triggers medium finding for ALTER TABLE DROP CONSTRAINT', () => {
    const files = [
      makeFile('migrations/alter.sql', 'ALTER TABLE orders DROP CONSTRAINT orders_user_fk;'),
    ]
    const findings = databaseCheck.run(files, POLICY)
    const f = findings.find((x) => x.id === 'db-alter-drop')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('medium')
    expect(f!.blocking).toBe(false)
  })

  it('does NOT trigger for safe ALTER TABLE ADD COLUMN', () => {
    const files = [
      makeFile('migrations/add_col.sql', 'ALTER TABLE users ADD COLUMN phone TEXT;'),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-alter-drop')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Safe migrations — should NOT trigger
// ---------------------------------------------------------------------------

describe('safe migrations that should NOT trigger', () => {
  it('does not flag CREATE TABLE', () => {
    const files = [
      makeFile('prisma/migrations/20240101/migration.sql', 'CREATE TABLE products (id SERIAL PRIMARY KEY, name TEXT);'),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings).toHaveLength(0)
  })

  it('does not flag SELECT queries', () => {
    const files = [makeFile('migrations/select.sql', 'SELECT * FROM users WHERE active = true;')]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings).toHaveLength(0)
  })

  it('does not flag CREATE INDEX', () => {
    const files = [
      makeFile('drizzle/0002_idx.sql', 'CREATE INDEX idx_users_email ON users (email);'),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings).toHaveLength(0)
  })

  it('does not flag commented-out DROP TABLE', () => {
    const files = [
      makeFile(
        'migrations/commented.sql',
        '-- DROP TABLE old_table;\n-- This is intentionally disabled\nCREATE TABLE new_table (id SERIAL);',
      ),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-drop-table')).toBe(false)
  })

  it('does not flag DROP TABLE inside block comment', () => {
    const files = [
      makeFile(
        'migrations/block_comment.sql',
        '/* DROP TABLE old_table; this was removed */\nCREATE TABLE new_table (id SERIAL);',
      ),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-drop-table')).toBe(false)
  })

  it('does not flag ALTER TABLE ADD COLUMN as drop', () => {
    const files = [makeFile('migrations/safe_alter.sql', 'ALTER TABLE users ADD COLUMN created_at TIMESTAMP;')]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// package.json db push detection — medium
// ---------------------------------------------------------------------------

describe('db push in package.json scripts', () => {
  it('triggers medium finding for "prisma db push" in scripts', () => {
    const pkg = JSON.stringify({
      name: 'my-app',
      scripts: {
        'db:push': 'prisma db push',
        build: 'next build',
      },
    })
    const files = [makeFile('package.json', pkg)]
    const findings = databaseCheck.run(files, POLICY)
    const f = findings.find((x) => x.id === 'db-push-in-scripts')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('medium')
    expect(f!.blocking).toBe(false)
  })

  it('triggers for "drizzle-kit push" in scripts', () => {
    const pkg = JSON.stringify({
      name: 'my-app',
      scripts: { migrate: 'drizzle-kit push' },
    })
    const files = [makeFile('package.json', pkg)]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-push-in-scripts')).toBe(true)
  })

  it('triggers for "drizzle-kit push:pg" variant', () => {
    const pkg = JSON.stringify({
      name: 'my-app',
      scripts: { migrate: 'drizzle-kit push:pg' },
    })
    const files = [makeFile('package.json', pkg)]
    const findings = databaseCheck.run(files, POLICY)
    // drizzle-kit push:pg contains "drizzle-kit push" so it should match
    expect(findings.some((f) => f.id === 'db-push-in-scripts')).toBe(true)
  })

  it('does NOT trigger for "prisma migrate deploy" in scripts', () => {
    const pkg = JSON.stringify({
      name: 'my-app',
      scripts: { migrate: 'prisma migrate deploy' },
    })
    const files = [makeFile('package.json', pkg)]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-push-in-scripts')).toBe(false)
  })

  it('does NOT trigger for unrelated package.json without db scripts', () => {
    const pkg = JSON.stringify({ name: 'my-app', scripts: { build: 'tsc', test: 'vitest' } })
    const files = [makeFile('package.json', pkg)]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-push-in-scripts')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Prisma schema without migration detection
// ---------------------------------------------------------------------------

describe('Prisma schema changed without migration', () => {
  it('triggers when schema.prisma changes but no migration file present', () => {
    const files = [
      makeFile('prisma/schema.prisma', 'model User { id Int @id }'),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-schema-without-migration')).toBe(true)
  })

  it('does NOT trigger when both schema.prisma and a migration are present', () => {
    const files = [
      makeFile('prisma/schema.prisma', 'model User { id Int @id }'),
      makeFile('prisma/migrations/20240401_add_user/migration.sql', 'CREATE TABLE "User" (id SERIAL PRIMARY KEY);'),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-schema-without-migration')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Non-migration files — should NOT be scanned for SQL patterns
// ---------------------------------------------------------------------------

describe('non-migration files are not scanned for SQL', () => {
  it('ignores .ts files containing DROP TABLE strings', () => {
    const files = [
      makeFile('src/db.ts', "const query = 'DROP TABLE users';"),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-drop-table')).toBe(false)
  })

  it('ignores README.md with SQL examples', () => {
    const files = [
      makeFile('README.md', '```sql\nDROP TABLE example;\n```'),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-drop-table')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Multiple findings in one file
// ---------------------------------------------------------------------------

describe('multiple findings in one migration file', () => {
  it('captures all distinct issues', () => {
    const sql = [
      'DROP TABLE legacy;',
      'ALTER TABLE users DROP COLUMN old_field;',
      'TRUNCATE temp_cache;',
      'DELETE FROM sessions;',
    ].join('\n')
    const files = [makeFile('migrations/big_change.sql', sql)]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-drop-table')).toBe(true)
    expect(findings.some((f) => f.id === 'db-drop-column')).toBe(true)
    expect(findings.some((f) => f.id === 'db-truncate')).toBe(true)
    expect(findings.some((f) => f.id === 'db-delete-without-where')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('edge cases', () => {
  it('returns empty array for empty file list', () => {
    expect(databaseCheck.run([], POLICY)).toEqual([])
  })

  it('returns empty array for an empty SQL file', () => {
    const files = [makeFile('migrations/empty.sql', '')]
    expect(databaseCheck.run(files, POLICY)).toHaveLength(0)
  })

  it('handles malformed JSON in package.json gracefully', () => {
    const files = [makeFile('package.json', '{invalid json')]
    expect(() => databaseCheck.run(files, POLICY)).not.toThrow()
  })

  // ---------------------------------------------------------------------------
  // FAIL-BEFORE/PASS-AFTER regression (loud-errors fix, folded into
  // 
  // a malformed package.json used to be swallowed with a bare `catch { return }`
  // — db-push-in-scripts checks silently produced zero findings, with no
  // warning distinguishing "clean" from "couldn't check." 
  // every catch block must log.
  // ---------------------------------------------------------------------------
  it('FAIL-BEFORE regression: malformed package.json logs a warning to stderr ' +
     '(not a silent skip)', () => {
    const warnSpy = vi.spyOn(logger, 'warn').mockImplementation(() => {})
    const files = [makeFile('package.json', '{invalid json')]
    databaseCheck.run(files, POLICY)
    expect(warnSpy).toHaveBeenCalledWith(expect.stringMatching(/package\.json.*JSON|JSON.*package\.json/i))
    warnSpy.mockRestore()
  })

  it('FAIL-BEFORE regression: malformed package.json produces a visible, ' +
     'non-blocking informational finding — NOT indistinguishable from "no ' +
     'dangerous scripts found"', () => {
    const files = [makeFile('package.json', '{invalid json')]
    const findings = databaseCheck.run(files, POLICY)
    const parseFailureFinding = findings.find((f) => f.id === 'pkg-json-unparseable-database')
    expect(parseFailureFinding).toBeDefined()
    expect(parseFailureFinding?.blocking).toBe(false)
    expect(parseFailureFinding?.severity).toBe('info')
  })

  it('a VALID package.json with a dangerous script still produces the real finding ' +
     '(the loud-parse-failure fix did not break the happy path)', () => {
    const files = [makeFile('package.json', JSON.stringify({ scripts: { deploy: 'prisma db push' } }))]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-push-in-scripts')).toBe(true)
    expect(findings.some((f) => f.id === 'pkg-json-unparseable-database')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// FAIL-BEFORE/PASS-AFTER regression (free-tier secret gaps, seen on a real
// project): the
// DEFAULT Supabase CLI migration layout `supabase/migrations/*.sql` was not in
// MIGRATION_PATTERNS (database.ts:10-18, pre-fix list was prisma/migrations/,
// drizzle/, migrations/, db/, root .sql — no supabase/migrations/ entry), so a
// real Supabase migration file was never classified as a migration and the
// destructive-SQL checks (DROP TABLE, TRUNCATE, DELETE FROM without WHERE,
// ALTER TABLE DROP) silently never ran against it — same fixture as the
// article: `supabase/migrations/0001_create_orders.sql`.
// ---------------------------------------------------------------------------
describe('Supabase CLI default migration layout (supabase/migrations/) — free-tier secret gaps', () => {
  it('classifies supabase/migrations/*.sql as a migration file and runs destructive checks', () => {
    const files = [
      makeFile(
        'supabase/migrations/0001_create_orders.sql',
        'DROP TABLE orders;\nCREATE TABLE orders (id uuid PRIMARY KEY, user_id uuid NOT NULL);',
      ),
    ]
    const findings = databaseCheck.run(files, POLICY)
    const f = findings.find((x) => x.id === 'db-drop-table')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('critical')
    expect(f!.file).toBe('supabase/migrations/0001_create_orders.sql')
  })

  it('timestamped Supabase CLI migration filenames (supabase migration new output) are also recognized', () => {
    const files = [
      makeFile(
        'supabase/migrations/20260714120000_add_orders_table.sql',
        'TRUNCATE orders;',
      ),
    ]
    const findings = databaseCheck.run(files, POLICY)
    expect(findings.some((f) => f.id === 'db-truncate')).toBe(true)
  })
})
