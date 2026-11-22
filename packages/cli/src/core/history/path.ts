import { relative, resolve } from 'node:path'
import { ensureShipguardDirIgnored, pathEscapeReason } from '../../utils/paths.js'
import type { Policy } from '@agenticcli/shared'
import { DEFAULT_HISTORY_PATH, HISTORY_PATH_ENV_VAR } from '@agenticcli/shared'

/**
 * Resolve the history store's file path for this scan.
 * Precedence: env var wins over policy file
 * wins over default — the same pattern already used for the API URL elsewhere in the CLI.
 */
export function resolveHistoryPath(cwd: string, policy: Pick<Policy, 'history'>): string {
  const envPath = process.env[HISTORY_PATH_ENV_VAR]
  if (envPath && envPath.trim().length > 0) {
    return resolve(cwd, envPath)
  }
  const policyPath = policy.history?.path
  if (policyPath && policyPath.trim().length > 0) {
    return resolve(cwd, policyPath)
  }
  return resolve(cwd, DEFAULT_HISTORY_PATH)
}

/**
 * Why the history store must not be opened for this project, or null. The env override is the user's own choice and is
 * always allowed; any other location (policy value or the default) must be inside the project with no symbolic link on the
 * way, or a cloned repo could send the history database anywhere (`.shipguard -> /elsewhere`).
 */
export function historyPathRefusal(cwd: string, policy: Pick<Policy, 'history'>): string | null {
  const envPath = process.env[HISTORY_PATH_ENV_VAR]
  if (envPath && envPath.trim().length > 0) return null
  const why = pathEscapeReason(cwd, resolveHistoryPath(cwd, policy))
  return why === null ? null : `the history location is not safe: ${why}`
}

/** Before opening a history file that will live in `.shipguard/`: make sure git ignores that folder (never the user's .gitignore). */
export function ensureHistoryFolderIgnored(cwd: string, policy: Pick<Policy, 'history'>): void {
  const envPath = process.env[HISTORY_PATH_ENV_VAR]
  if (envPath && envPath.trim().length > 0) return
  if (relative(cwd, resolveHistoryPath(cwd, policy)).split(/[\\/]/)[0] === '.shipguard') ensureShipguardDirIgnored(cwd)
}
