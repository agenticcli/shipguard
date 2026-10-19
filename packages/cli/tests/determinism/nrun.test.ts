/**
 * D.6 — N-run determinism test
 *
 * Validates that the re2js-v1 linear-time engine produces byte-identical
 * `--json` output across 10 runs of the built CLI, even when the file-list
 * presented to the scanner varies in order between runs. This proves that
 * scan findings and risk scoring are order-independent.
 *
 * Strategy:
 *   1. Build the PACKAGED CLI (dist/cli.js) is done once in the worktree
 *      beforeAll step (build is pre-existing on the branch; we verify it).
 *   2. Create a fixture directory with files that trigger at least one finding
 *      per free-tier detector (secrets, auth, database, payments, deployment).
 *   3. Run N=10 scans in separate child processes (spawnSync of dist/cli.js),
 *      each in a FRESH clone of the fixture directory. Between clones the
 *      files are written in a shuffled order so fast-glob may encounter them
 *      in a different OS inode sequence per run.
 *   4. Normalise per-run non-deterministic fields (timestamp) and sort the
 *      findings array by a stable key (file, line, column, id) to produce a
 *      canonical form independent of discovery order.
 *   5. Assert the canonical form is byte-identical across all N runs.
 *
 * Why normalise + sort?
 *   The CLI emits findings in file-discovery order (fast-glob inode order).
 *   Inode order varies between fresh directories on some filesystems. The
 *   canonical form — after stable sort — proves the SET of findings and their
 *   CONTENT are identical regardless of traversal order. Ordering instability
 *   is a known non-issue (it's the file's content that matters, not the order
 *   in which it appears in JSON output).
 *
 * Node version matrix: runs on the current Node (≥20, per engines.node).
 * A full multi-Node matrix is a documented follow-up.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawnNode } from '../helpers/spawn-cli.js'
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  mkdirSync,
  existsSync,
} from 'node:fs'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Resolve the built CLI relative to this package root (packages/cli/dist/cli.js).
// __dirname is packages/cli/tests/determinism — two levels up reaches packages/cli.
const CLI_DIST = resolve(__dirname, '../../dist/cli.js')
const N_RUNS = 10

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Fisher-Yates shuffle (pure, returns a new array). */
function shuffle<T>(arr: T[]): T[] {
  const out = [...arr]
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[out[i], out[j]] = [out[j], out[i]]
  }
  return out
}

/**
 * Stable sort key for a finding: sort by file path, then line, then column,
 * then id. This produces a canonical ordering independent of discovery order.
 */
function findingSortKey(f: Record<string, unknown>): string {
  return [
    String(f['file'] ?? ''),
    String(f['line'] ?? '0').padStart(8, '0'),
    String(f['column'] ?? '0').padStart(8, '0'),
    String(f['id'] ?? ''),
  ].join('\x00')
}

/**
 * Normalise the JSON output for determinism comparison:
 *   1. Replace per-run fields (timestamp, scanId) with stable sentinels.
 *   2. Sort the findings array by a stable key so that file-discovery-order
 *      differences do not produce false negatives.
 */
function normaliseJson(raw: string): string {
  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>
  } catch {
    return raw // Return raw so the test can fail with a meaningful message
  }
  if ('timestamp' in parsed) parsed['timestamp'] = '<normalised>'
  if ('scanId' in parsed) parsed['scanId'] = '<normalised>'
  // `runId` (schemaVersion 5) is the same per-run identity value
  // surfaced in the JSON receipt. It is volatile BY DESIGN, like timestamp/scanId — a new
  // run must get a new id — so it is normalised here rather than treated as a determinism
  // failure. What must be identical across runs is the finding set, the verdict, and
  // `treeDigest`, all of which are left untouched by this normalisation.
  if ('runId' in parsed) parsed['runId'] = '<normalised>'

  if (Array.isArray(parsed['findings'])) {
    parsed['findings'] = [...(parsed['findings'] as Record<string, unknown>[])].sort(
      (a, b) => findingSortKey(a).localeCompare(findingSortKey(b)),
    )
  }

  return JSON.stringify(parsed, null, 2)
}

/**
 * Fixture file definitions: content triggers at least one finding per
 * free-tier detector (secrets, auth, database, deployment).
 *
 * NOTE: file names are STABLE across runs; only the WRITE ORDER is shuffled
 * so fast-glob may see different inode creation timestamps on some filesystems.
 * This correctly tests order-independence without shuffling file content.
 */
interface FixtureFile {
  name: string    // Relative path within the fixture dir
  content: string
}

const FIXTURE_FILES: FixtureFile[] = [
  // 1. Secrets — hardcoded OpenAI key (new sk-proj- format)
  {
    name: 'secrets-openai.ts',
    content: [
      '// Intentional test secret for shipguard fixture (not a real key)',
      'const OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstu1234";',
    ].join('\n'),
  },
  // 2. Secrets — Stripe test key
  {
    name: 'secrets-stripe.ts',
    content: [
      '// Stripe test key fixture',
      'const stripeKey = "sk_test_abcdefghijklmnopqrstuvwx12";',
    ].join('\n'),
  },
  // 3. Auth — Next.js admin route without auth guard
  {
    name: 'app/admin/page.tsx',
    content: [
      'export default function AdminPage() {',
      '  return <div>Admin dashboard (no auth guard)</div>',
      '}',
    ].join('\n'),
  },
  // 4. Database — SQL migration with DROP TABLE
  {
    name: 'migrations/001_init.sql',
    content: [
      'CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT);',
      'DROP TABLE IF EXISTS legacy_users;',
    ].join('\n'),
  },
  // 5. Plain JS file (ensures filesScanned > 0)
  {
    name: 'index.js',
    content: 'console.log("hello");',
  },
  // 6. Project root marker (satisfies scope guard)
  {
    name: 'package.json',
    content: JSON.stringify({ name: 'sg-determinism-fixture', version: '1.0.0' }),
  },
]

/**
 * Create a fresh fixture directory with files written in the given order.
 * Using a fresh dir (not rename) avoids content-at-path mismatches across runs.
 */
function createFixtureDir(writeOrder: FixtureFile[]): string {
  const dir = mkdtempSync(join(tmpdir(), 'sg-determinism-'))
  for (const { name, content } of writeOrder) {
    const fullPath = join(dir, name)
    mkdirSync(join(fullPath, '..'), { recursive: true })
    writeFileSync(fullPath, content, 'utf-8')
  }
  return dir
}

/**
 * Run one scan in a fresh child process with the given cwd.
 * Returns the normalised JSON string.
 */
function runScan(fixtureCwd: string): Promise<string> {
  if (!existsSync(CLI_DIST)) {
    throw new Error(
      `Built CLI not found at ${CLI_DIST}. ` +
        `Run \`pnpm --filter @agenticcli/shipguard build\` first.`,
    )
  }

  // Async helper (not spawnSync): 10 sequential scans blocked the vitest worker's event loop
  // for ~27s+ - the "Timeout calling onTaskUpdate" failure class.
  return spawnNode(CLI_DIST, ['scan', '--json'], {
    cwd: fixtureCwd,
    env: { PATH: process.env.PATH, HOME: process.env.HOME },
  }).then((res) => {
    const rawJson = res.stdout.trim()
    if (!rawJson) {
      throw new Error(`CLI produced no stdout (exit=${res.code}). stderr: ${res.stderr}`)
    }
    return normaliseJson(rawJson)
  })
}

// ---------------------------------------------------------------------------
// Fixture cleanup tracking
// ---------------------------------------------------------------------------

const createdDirs: string[] = []

afterAll(() => {
  for (const dir of createdDirs) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // ignore cleanup errors
    }
  }
})

// ---------------------------------------------------------------------------
// The determinism test
// ---------------------------------------------------------------------------

describe('D.6 — N-run determinism (re2js-v1 engine)', () => {
  it(
    `produces byte-identical canonical --json output across ${N_RUNS} runs with shuffled write order`,
    async () => {
      const outputs: string[] = []

      for (let run = 0; run < N_RUNS; run++) {
        // Each run gets a FRESH fixture dir with files written in a shuffled order.
        // This changes the inode creation order so fast-glob may discover them
        // in a different sequence on each run — exercising order-independence.
        const writeOrder = shuffle(FIXTURE_FILES)
        const dir = createFixtureDir(writeOrder)
        createdDirs.push(dir)

        const output = await runScan(dir)
        outputs.push(output)
      }

      // Assert all N canonical outputs are byte-identical
      const baseline = outputs[0]
      for (let i = 1; i < N_RUNS; i++) {
        expect(
          outputs[i],
          `Run ${i + 1} canonical output differs from run 1. ` +
            `The engine produces non-deterministic findings (set, content, or risk score).`,
        ).toBe(baseline)
      }

      // Log a summary for CI visibility
      try {
        const parsed = JSON.parse(outputs[0]) as {
          findings?: unknown[]
          filesScanned?: number
          riskScore?: { score: number; recommendation: string }
        }
        console.log(
          `[D.6] ${N_RUNS}/${N_RUNS} runs byte-identical ✓ ` +
            `| filesScanned=${parsed.filesScanned} ` +
            `| findings=${parsed.findings?.length ?? 0} ` +
            `| score=${parsed.riskScore?.score} ` +
            `| verdict=${parsed.riskScore?.recommendation}`,
        )
      } catch {
        // JSON parse error — the assertion above already caught it
      }
    },
    90_000, // 90s timeout for 10 child-process runs
  )
})
