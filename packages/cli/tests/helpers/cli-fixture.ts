/**
 * Shared helpers for the e2e files that spawn the CLI.
 *
 * `cliPath()` returns env SHIPGUARD_CLI when set (the C0 rehearsal points it at the INSTALLED
 * tarball binary), else the freshly built dist/cli.js. The same test files therefore run against
 * both.
 */
import { execSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnNode, type SpawnResult } from './spawn-cli.js'

const here = dirname(fileURLToPath(import.meta.url))
export const pkgRoot = resolve(here, '../../')

export function cliPath(): string {
  const fromEnv = process.env.SHIPGUARD_CLI
  if (fromEnv) return fromEnv
  const dist = resolve(pkgRoot, 'dist/cli.js')
  if (!existsSync(dist)) throw new Error(`dist/cli.js not found at ${dist}: run the build first`)
  return dist
}

const trees: string[] = []

export type FileMap = Record<string, Buffer | string>

/** Create a temp project. `git: true` makes it a git repo with NO commits (all files are untracked). */
export function mkTree(files: FileMap, opts: { git?: boolean } = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'sg-e2e-'))
  trees.push(dir)
  if (opts.git) {
    execSync('git init -q', { cwd: dir })
    execSync('git config user.email test@example.com', { cwd: dir })
    execSync('git config user.name test', { cwd: dir })
  }
  for (const [name, content] of Object.entries(files)) {
    const full = join(dir, name)
    mkdirSync(dirname(full), { recursive: true })
    writeFileSync(full, content)
  }
  return dir
}

export function cleanupTrees(): void {
  for (const d of trees.splice(0)) {
    try {
      rmSync(d, { recursive: true, force: true })
    } catch {
      /* best-effort temp cleanup */
    }
  }
}

export interface CliRun extends SpawnResult {
  /** Parsed stdout when it is JSON, else undefined. */
  json?: ScanJson
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ScanJson = Record<string, any>

export async function runCli(
  args: string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number } = {},
): Promise<CliRun> {
  const res = await spawnNode(cliPath(), args, {
    cwd: opts.cwd ?? pkgRoot,
    env: { ...process.env, ...(opts.env ?? {}) },
    timeoutMs: opts.timeoutMs,
  })
  let json: ScanJson | undefined
  try {
    json = JSON.parse(res.stdout)
  } catch {
    json = undefined
  }
  return { ...res, json }
}

/** `scan <dir> --json [...extra]` */
export function scanJson(dir: string, extra: string[] = [], opts: { env?: NodeJS.ProcessEnv; timeoutMs?: number } = {}): Promise<CliRun> {
  return runCli(['scan', dir, '--json', ...extra], opts)
}

export const KEY = 'AKIAIOSFODNN7EXAMPLE'
export const ENV_KEY_LINE = `AWS_ACCESS_KEY_ID=${KEY}\n`

export const utf16le = (s: string, bom = false): Buffer =>
  Buffer.concat([bom ? Buffer.from([0xff, 0xfe]) : Buffer.alloc(0), Buffer.from(s, 'utf16le')])
export const utf16be = (s: string, bom = false): Buffer => {
  const b = Buffer.from(s, 'utf16le')
  b.swap16()
  return Buffer.concat([bom ? Buffer.from([0xfe, 0xff]) : Buffer.alloc(0), b])
}

/** Deterministic pseudo-random bytes. */
export function noise(n: number, seed = 12345): Buffer {
  const out = Buffer.alloc(n)
  let s = seed
  for (let i = 0; i < n; i++) {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0
    out[i] = (s >>> 16) & 0xff
  }
  return out
}

/** True when a hardcoded-secret finding names this file. */
export function keyFoundIn(json: ScanJson | undefined, file: string): boolean {
  return Boolean(json?.findings?.some((f: { id: string; file: string }) => f.id === 'hardcoded_secret' && f.file === file))
}

export function degradeCodes(json: ScanJson | undefined): string[] {
  return ((json?.degradedReasons ?? []) as Array<{ code: string }>).map((r) => r.code).sort()
}
