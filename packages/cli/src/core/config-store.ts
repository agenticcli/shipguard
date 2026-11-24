/**
 * config-store.ts: the small file helpers shared by the plan modules (account cache, offer cache,
 * hint file, nag counters). Everything lives under ~/.config/shipguard (mode 0700 dir, 0600 files), is
 * size-capped before it is parsed, and is NEVER read from the scanned project.
 *
 * Reads refuse symlinks, non-files and group/other-accessible files (like the credentials file).
 * Writes are best-effort and atomic (temp file + rename): a read-only HOME must never break a scan,
 * but a failed write is logged (SHIPGUARD_DEBUG) and reported to the caller, never swallowed silently.
 */
import { lstatSync, readFileSync, readdirSync, renameSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { ensureSecureDir, writeSecureFileSync } from '../utils/secure-fs.js'
import { logger } from '../utils/logger.js'
import { isSafeMode } from './telemetry-config.js'

const isPosix = process.platform !== 'win32'

export type ConfigRead =
  | { state: 'ok'; text: string }
  | { state: 'missing' }
  | { state: 'unsafe'; why: string }

/** Read a config file as text. `maxBytes` is checked BEFORE the file is read. */
export function readConfigText(file: string, maxBytes: number): ConfigRead {
  let st
  try {
    st = lstatSync(file)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { state: 'missing' }
    logger.debug(`config-store: cannot stat ${file}: ${err instanceof Error ? err.message : String(err)}`)
    return { state: 'unsafe', why: 'unreadable' }
  }
  if (!st.isFile()) return { state: 'unsafe', why: 'not a regular file' }
  if (isPosix && (st.mode & 0o077) !== 0) return { state: 'unsafe', why: 'group/other-accessible' }
  if (st.size > maxBytes) return { state: 'unsafe', why: 'too large' }
  try {
    return { state: 'ok', text: readFileSync(file, 'utf8') }
  } catch (err) {
    logger.debug(`config-store: cannot read ${file}: ${err instanceof Error ? err.message : String(err)}`)
    return { state: 'unsafe', why: 'unreadable' }
  }
}

/** Atomic 0600 write into a 0700 directory. Returns false (and logs) when it could not write. */
export function writeConfigText(dir: string, name: string, data: string): boolean {
  // Safe mode: nothing new is written under ~/.config. One guard here covers nag, hint, plan and offer cache.
  if (isSafeMode()) {
    logger.debug(`config-store: safe mode, not writing ${join(dir, name)}`)
    return false
  }
  const tmp = join(dir, `.${name}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`)
  try {
    ensureSecureDir(dir)
    writeSecureFileSync(tmp, data)
    renameSync(tmp, join(dir, name))
    return true
  } catch (err) {
    logger.debug(`config-store: cannot write ${join(dir, name)}: ${err instanceof Error ? err.message : String(err)}`)
    try {
      rmSync(tmp, { force: true })
    } catch (cleanupErr) {
      logger.debug(`config-store: cannot remove ${tmp}: ${cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr)}`)
    }
    return false
  }
}

/** Remove a config file; a missing file is fine. Returns false (and logs) on a real failure. */
export function removeConfigFile(file: string): boolean {
  try {
    rmSync(file, { force: true })
    return true
  } catch (err) {
    logger.debug(`config-store: cannot remove ${file}: ${err instanceof Error ? err.message : String(err)}`)
    return false
  }
}

/** Names in a config directory ([] when it does not exist). */
export function listConfigDir(dir: string): string[] {
  try {
    return readdirSync(dir)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      logger.debug(`config-store: cannot list ${dir}: ${err instanceof Error ? err.message : String(err)}`)
    }
    return []
  }
}
