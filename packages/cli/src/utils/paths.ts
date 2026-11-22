import { dirname, isAbsolute, relative, resolve } from 'node:path'
import { existsSync, lstatSync, realpathSync } from 'node:fs'
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
    if (lstatSync(target, { throwIfNoEntry: false })?.isSymbolicLink()) return 'it is a symbolic link'
    const rel = relative(realRoot, realpathSync(probe))
    if (rel === '..' || rel.startsWith('..' + '/') || rel.startsWith('..\\') || isAbsolute(rel)) {
      return 'it goes through a symbolic link that leaves the project folder'
    }
  } catch (error) {
    return `it cannot be checked (${error instanceof Error ? error.message : error})`
  }
  return null
}
