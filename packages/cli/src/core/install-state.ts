/**
 * install-state.ts: `.shipguard/installed.json`, the record of what `shipguard setup` wrote (spec 07).
 *
 * Every managed write is recorded with a content hash, so `shipguard uninstall` (W4b) can tell content
 * ShipGuard wrote (and nobody edited) from user edits, and `shipguard status` and the scan screen can say
 * what is really installed. The record lives in the project, never in ~/.config. Reads are strict: a
 * file of the wrong shape is "no record", never a half-trusted one.
 */
import { createHash } from 'node:crypto'
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { logger } from '../utils/logger.js'
import { GIT_HOOK_NAMES, SHIM_RELATIVE_PATH } from './hook-templates.js'

export const INSTALL_STATE_DIR = '.shipguard'
export const INSTALL_STATE_FILE = '.shipguard/installed.json'
export const INSTALL_STATE_GITIGNORE = '.shipguard/.gitignore'
const MAX_BYTES = 256 * 1024

export type InstallAgent = 'claude' | 'codex' | 'cursor' | 'ci' | 'git'
export const INSTALL_AGENTS: readonly InstallAgent[] = ['claude', 'codex', 'cursor', 'ci', 'git']

/**
 * file: the whole file is ShipGuard's (hash = whole content)
 * block: a marked block inside a file that has other content (hash = the block text)
 * json-hook: one hook entry inside .claude/settings.json (hash = JSON of the hook object)
 */
export type InstallEntryKind = 'file' | 'block' | 'json-hook'

export interface InstallEntry {
  /** Project-relative, forward slashes; for git hooks the folder git runs, relative or absolute. */
  path: string
  kind: InstallEntryKind
  sha256: string
  /** Shim or block version the content carries (hook v2). */
  version?: number
}

export interface InstallState {
  version: 1
  shipguardVersion: string
  /** Newest hook version written (read by the scan screen: below 2 means stale). */
  hookVersion: number
  agents: InstallAgent[]
  entries: InstallEntry[]
  /** Project-relative folders setup created (they did not exist before); uninstall tidies only these. */
  createdDirs?: string[]
}

export function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex')
}

/**
 * Where `setup` writes anything it records. A record is a file in the project that a clone brings along, so an entry for
 * any other path is not ours: it is dropped, never followed. (Git hooks live in a folder git names, so only the file
 * name is checked there.)
 */
const KNOWN_ENTRY_PATHS: readonly string[] = ['.claude/settings.json', SHIM_RELATIVE_PATH, 'CLAUDE.md', 'AGENTS.md', '.github/workflows/shipguard.yml']
const isKnownEntryPath = (path: string, kind: InstallEntryKind): boolean =>
  KNOWN_ENTRY_PATHS.includes(path) || (kind === 'block' && (GIT_HOOK_NAMES as readonly string[]).includes(path.split('/').pop() ?? ''))

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

function parseState(raw: unknown): InstallState | null {
  if (!isRecord(raw) || raw['version'] !== 1) return null
  if (typeof raw['shipguardVersion'] !== 'string' || typeof raw['hookVersion'] !== 'number') return null
  const agents = raw['agents']
  const entries = raw['entries']
  if (!Array.isArray(agents) || !Array.isArray(entries)) return null
  const outAgents = agents.filter((a): a is InstallAgent => INSTALL_AGENTS.includes(a as InstallAgent))
  const outEntries: InstallEntry[] = []
  for (const e of entries) {
    if (!isRecord(e)) return null
    if (typeof e['path'] !== 'string' || typeof e['sha256'] !== 'string') return null
    if (e['kind'] !== 'file' && e['kind'] !== 'block' && e['kind'] !== 'json-hook') return null
    if (!isKnownEntryPath(e['path'], e['kind'])) {
      logger.debug(`install-state: ignoring a record entry for ${JSON.stringify(e['path'])}: not a place setup writes`)
      continue
    }
    outEntries.push({
      path: e['path'],
      kind: e['kind'],
      sha256: e['sha256'],
      ...(typeof e['version'] === 'number' ? { version: e['version'] } : {}),
    })
  }
  const dirs = raw['createdDirs']
  const createdDirs = Array.isArray(dirs) ? dirs.filter((x): x is string => typeof x === 'string' && x !== '' && !x.startsWith('/') && !x.split('/').includes('..')) : undefined
  return { version: 1, shipguardVersion: raw['shipguardVersion'], hookVersion: raw['hookVersion'], agents: outAgents, entries: outEntries, ...(createdDirs ? { createdDirs } : {}) }
}

/** The record, or null when there is none or it is not a valid record (a bad file is logged, never trusted). */
export function readInstallState(dir: string): InstallState | null {
  const file = join(dir, INSTALL_STATE_FILE)
  if (!existsSync(file)) return null
  try {
    if (lstatSync(file).isSymbolicLink()) return null
    const text = readFileSync(file, 'utf-8')
    if (text.length > MAX_BYTES) {
      logger.debug(`install-state: ${INSTALL_STATE_FILE} is too large, ignoring it`)
      return null
    }
    const state = parseState(JSON.parse(text))
    if (!state) logger.debug(`install-state: ${INSTALL_STATE_FILE} has an unknown shape, ignoring it`)
    return state
  } catch (err) {
    logger.debug(`install-state: cannot read ${INSTALL_STATE_FILE}: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}

/** Merge new entries into the old record (same path + kind replaces) and return the next record. */
export function mergeInstallState(
  prev: InstallState | null,
  next: { shipguardVersion: string; agents: readonly InstallAgent[]; entries: readonly InstallEntry[]; hookVersion?: number; createdDirs?: readonly string[] },
): InstallState {
  const entries = [...(prev?.entries ?? [])]
  for (const e of next.entries) {
    const i = entries.findIndex((x) => x.path === e.path && x.kind === e.kind)
    if (i === -1) entries.push(e)
    else entries[i] = e
  }
  const agents = [...new Set([...(prev?.agents ?? []), ...next.agents])]
  return {
    version: 1,
    shipguardVersion: next.shipguardVersion,
    hookVersion: Math.max(prev?.hookVersion ?? 0, next.hookVersion ?? 0),
    agents: INSTALL_AGENTS.filter((a) => agents.includes(a)),
    entries,
    ...(prev?.createdDirs || next.createdDirs ? { createdDirs: [...new Set([...(prev?.createdDirs ?? []), ...(next.createdDirs ?? [])])] } : {}),
  }
}

/** Write the record and `.shipguard/.gitignore` (one line, `*`, so `.shipguard/` stays out of git). */
export function writeInstallState(dir: string, state: InstallState): void {
  mkdirSync(join(dir, INSTALL_STATE_DIR), { recursive: true })
  const ignore = join(dir, INSTALL_STATE_GITIGNORE)
  if (!existsSync(ignore)) writeFileSync(ignore, '*\n', 'utf-8')
  writeFileSync(join(dir, INSTALL_STATE_FILE), JSON.stringify(state, null, 2) + '\n', 'utf-8')
}
