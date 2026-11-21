/**
 * Shared fixtures for the gate tests: real temp git repos, a scan stand-in that reads the
 * extracted commit (so a test proves WHICH tree was scanned), and a GateDeps builder.
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { headLabel, listRefCommits, repoTopLevel, resolveCommit, extractCommit, removeExtraction, uncommittedFiles } from '../../src/core/gate-scan.js'
import type { GateDeps } from '../../src/commands/gate.js'
import type { ScanRun } from '../../src/core/gate-scan.js'

export const SECRET_MARKER = 'PLANTED_SECRET'

const roots: string[] = []

export function cleanup(): void {
  for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true })
}

export function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
}

/** A repo with one commit on `main`. Returns the real path. */
export function mkRepo(files: Record<string, string> = { 'package.json': '{"name":"fx"}', 'src/a.ts': 'export const a = 1\n' }): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'sg-gate-')))
  roots.push(root)
  const dir = join(root, 'main')
  mkdirSync(dir)
  git(dir, 'init', '-q', '-b', 'main')
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(join(dir, name, '..'), { recursive: true })
    writeFileSync(join(dir, name), body)
  }
  git(dir, 'add', '-A')
  git(dir, 'commit', '-q', '-m', 'initial')
  return dir
}

export function commitFile(dir: string, name: string, body: string, message = 'change'): string {
  mkdirSync(join(dir, name, '..'), { recursive: true })
  writeFileSync(join(dir, name), body)
  git(dir, 'add', '-A')
  git(dir, 'commit', '-q', '-m', message)
  return git(dir, 'rev-parse', 'HEAD')
}

/** `git worktree add ../<name> -b <branch>`; returns the real path of the new worktree. */
export function addWorktree(main: string, name: string, branch: string): string {
  const path = join(main, '..', name)
  git(main, 'worktree', 'add', '-q', '-b', branch, path)
  return realpathSync(path)
}

function walk(dir: string, base = dir, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === '.git' || name === '.shipguard') continue
    if (statSync(p).isDirectory()) walk(p, base, out)
    else out.push(p.slice(base.length + 1))
  }
  return out
}

export interface FakeScanOptions {
  /** Line number reported for the planted finding (a test varies it to prove the loop count ignores it). */
  line?: number
  /** Extra top-level keys merged into the JSON. */
  extra?: Record<string, unknown>
  /** Findings that do not block. */
  nonBlocking?: number
  /** Report these directories the scan was run on. */
  seen?: string[]
}

/** A scan stand-in: BLOCKS when any file of the extracted commit holds the marker; records what it saw. */
export function fakeScan(opts: FakeScanOptions = {}): GateDeps['runScan'] {
  return async ({ dir }): Promise<ScanRun> => {
    opts.seen?.push(dir)
    const files = walk(dir)
    const hit = files.find((f) => readFileSync(join(dir, f), 'utf-8').includes(SECRET_MARKER))
    const findings: unknown[] = []
    if (hit) {
      findings.push({
        id: 'generic.secrets.stripe-live-key',
        title: 'A hardcoded Stripe live secret key (sk_live_ prefix) or live restricted key (rk_live_ prefix) was detected in a source file',
        severity: 'critical',
        category: 'secrets',
        evidence: { kind: 'secret', secretType: 'stripe_live_key', length: 32, valueHidden: true },
        file: hit,
        line: opts.line ?? 2,
        blocking: true,
        fix: 'Rotate it first, then read the new one from process.env.STRIPE_SECRET_KEY. More detail follows.',
      })
    }
    for (let i = 0; i < (opts.nonBlocking ?? 0); i++) {
      findings.push({ id: `nit.${i}`, title: 'a nit', severity: 'low', category: 'config', file: 'src/a.ts', line: 1, blocking: false })
    }
    const verdict = hit ? 'DO_NOT_SHIP' : findings.length > 0 ? 'REVIEW_BEFORE_SHIP' : 'SAFE_TO_SHIP'
    const json = {
      recommendation: verdict,
      degraded: false,
      filesScanned: files.length,
      rulesApplied: 36,
      runId: '247f9045-8511-4647-80fd-a4945e28d135',
      findings,
      coverage: { discovered: files.length, scanned: files.length },
      ...opts.extra,
    }
    return { exitCode: hit ? 1 : 0, stdout: JSON.stringify(json), timedOut: false, stderrTail: '' }
  }
}

export interface Captured {
  stdout: string
  stderr: string
}

export function mkDeps(cwd: string, stdin: string, over: Partial<GateDeps> = {}, env: NodeJS.ProcessEnv = {}): { deps: GateDeps; out: Captured } {
  const out: Captured = { stdout: '', stderr: '' }
  const deps: GateDeps = {
    now: () => Date.now(),
    env: { HOME: '/nonexistent-home', ...env },
    cwd,
    readStdin: async () => stdin,
    writeStdout: (t) => void (out.stdout += t),
    writeStderr: (t) => void (out.stderr += t),
    repoTopLevel,
    resolveCommit,
    headLabel,
    uncommittedFiles,
    listRefCommits,
    extractCommit,
    removeExtraction,
    runScan: fakeScan(),
    gapLine: () => null,
    isSafeMode: () => false,
    ...over,
  }
  return { deps, out }
}

export function claudeInput(command: string, cwd: string): string {
  return JSON.stringify({ session_id: 's', cwd, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } })
}
