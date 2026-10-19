// Single place that creates per-user state directories and files for ShipGuard
// (~/.shipguard, ~/.config/shipguard, ...). Why: the release-floor
// lock was opened before ~/.shipguard existed, so the FIRST Pro scan on a fresh
// machine failed with ENOENT. Every writer under the user's home must go through
// these helpers so "parent dir missing" can never recur.
import { chmodSync, mkdirSync, statSync, writeFileSync } from 'node:fs'

/** Directories holding user state: owner-only. */
export const SECURE_DIR_MODE = 0o700
/** Files holding user state or secrets: owner read/write only. */
export const SECURE_FILE_MODE = 0o600

const isPosix = process.platform !== 'win32'

/**
 * `mkdir -p` that also tightens `dir` to 0700. The `mode` option of mkdirSync is masked
 * by the umask and ignored for an existing dir, so we chmod explicitly (POSIX only).
 * Only the leaf is chmod'ed, and only when we own it: pre-existing ancestors (e.g. $HOME)
 * are never touched, and a shared dir owned by someone else (e.g. a caller-supplied path
 * under /tmp) is left alone instead of failing with EPERM.
 */
export function ensureSecureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: SECURE_DIR_MODE })
  if (isPosix && statSync(dir).uid === process.getuid?.()) chmodSync(dir, SECURE_DIR_MODE)
}

/** Write a file with 0600 perms, also tightening a pre-existing file. Parent must exist. */
export function writeSecureFileSync(file: string, data: string | Uint8Array): void {
  writeFileSync(file, data, { mode: SECURE_FILE_MODE })
  if (isPosix) chmodSync(file, SECURE_FILE_MODE)
}
