import { dirname, isAbsolute, relative, resolve } from 'node:path'
import { existsSync, lstatSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs'
import { logger } from './logger.js'
import { DEFAULT_POLICY_PATH, DEFAULT_REPORT_DIR } from '@agenticcli/shared'

export function resolveProjectRoot(startDir: string = process.cwd()): string {
  return resolve(startDir)
}

export function resolvePolicyPath(rootDir: string): string {
  return resolve(rootDir, DEFAULT_POLICY_PATH)
}

export function resolveReportDir(rootDir: string): string {
  return resolve(rootDir, DEFAULT_REPORT_DIR)
}

export function fileExists(filePath: string): boolean {
  return existsSync(filePath)
}

/**
 * Why `value` (a path a project's own policy file asked ShipGuard to write) may not be used, or null when it is fine.
 * The policy comes from the scanned repo, which may be somebody else's clone, so a write path must stay inside the project:
 * lexically (no absolute path or `..` out of the root) and for real (no symlink on the way, or as the file itself, that
 * leads out of the root). Nothing is created or written here.
 */
export function pathEscapeReason(root: string, value: unknown): string | null {
  if (typeof value !== 'string' || value.trim().length === 0) return 'it is not a path'
  if (value.includes('\0')) return 'it contains a NUL character'
  let realRoot: string
  try {
    realRoot = realpathSync(root)
  } catch (error) {
    return `the project folder cannot be resolved (${error instanceof Error ? error.message : error})`
  }
  const target = resolve(root, value)
  const lexical = relative(resolve(root), target)
  if (lexical === '' || lexical === '..' || lexical.startsWith('..' + '/') || lexical.startsWith('..\\') || isAbsolute(lexical)) {
    return 'it points outside the project folder'
  }
  // Walk up to the nearest part that exists; its real location must be inside the real root.
  let probe = target
  while (!existsSync(probe)) {
    const up = dirname(probe)
    if (up === probe) return 'it points outside the project folder'
    probe = up
  }
  try {
    // No part of the way below the project folder may be a symbolic link, even one that points back inside.
    const parts = lexical.split(/[\\/]/).filter(Boolean)
    let walk = resolve(root)
    for (const part of parts) {
      walk = resolve(walk, part)
      if (lstatSync(walk, { throwIfNoEntry: false })?.isSymbolicLink()) return walk === target ? 'it is a symbolic link' : 'it goes through a symbolic link'
    }
    const rel = relative(realRoot, realpathSync(probe))
    if (rel === '..' || rel.startsWith('..' + '/') || rel.startsWith('..\\') || isAbsolute(rel)) {
      return 'it goes through a symbolic link that leaves the project folder'
    }
  } catch (error) {
    return `it cannot be checked (${error instanceof Error ? error.message : error})`
  }
  return null
}

const warnedWrites = new Set<string>()

/**
 * True (with one warning per run) when ShipGuard must NOT write `path` (relative to `root`, or inside it) because the way
 * to it is a symbolic link or leaves the project: a cloned repo can commit `.shipguard -> /somewhere`. Nothing is created
 * through it; the scan itself still runs and prints.
 */
export function refuseWrite(root: string, path: string, what: string): boolean {
  const why = pathEscapeReason(root, path)
  if (why === null) return false
  const msg = `Not saving ${what}: ${why}. The scan still runs; nothing is written there.`
  if (!warnedWrites.has(msg)) {
    warnedWrites.add(msg)
    logger.warn(msg)
  }
  return true
}

/**
 * Keep ShipGuard's own folder out of git without touching the user's `.gitignore`: `.shipguard/.gitignore` holding `*`
 * ignores the folder, itself included (the same file `setup` writes). Idempotent; never throws; writes nothing through a
 * symbolic link. Call it wherever ShipGuard is about to put a file in `.shipguard/`.
 */
export function ensureShipguardDirIgnored(root: string): void {
  try {
    if (pathEscapeReason(root, '.shipguard/.gitignore') !== null) return
    const dir = resolve(root, '.shipguard')
    mkdirSync(dir, { recursive: true })
    const ignore = resolve(dir, '.gitignore')
    if (!existsSync(ignore)) writeFileSync(ignore, '*\n', 'utf-8')
  } catch (err) {
    logger.warn(`Could not write .shipguard/.gitignore: ${err instanceof Error ? err.message : err}`)
  }
}
