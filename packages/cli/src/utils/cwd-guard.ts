import { realpathSync } from 'node:fs'

/**
 * Fail loudly when the folder being scanned has been removed or moved under us.
 *
 * Why: Node's recursive mkdir on a RELATIVE path (`.shipguard/reports`) retries forever when the
 * process's working directory no longer exists (ENOENT, climb to the parent, ENOENT, ...), so a scan
 * whose folder vanished spun at ~40% CPU for hours instead of ending. One live check before every
 * relative mkdir turns that loop into an error (exit 3 for the scan itself, never a SAFE verdict).
 *
 * process.cwd() is CACHED by Node and keeps answering after the folder is gone; the native realpath
 * of '.' asks the OS (getcwd) and throws ENOENT.
 */
export function assertCwdAlive(): void {
  try {
    realpathSync.native('.')
  } catch (err: unknown) {
    throw new Error(
      `The folder being scanned no longer exists (removed or moved during the scan): ${err instanceof Error ? err.message : String(err)}`,
    )
  }
}
