import { resolve } from 'node:path'
import type { Policy } from '@agenticcli/shared'
import { DEFAULT_HISTORY_PATH, HISTORY_PATH_ENV_VAR } from '@agenticcli/shared'

/**
 * Resolve the history store's file path for this scan.
 * Precedence (05-OBSERVABILITY-SCHEMA-DESIGN.md §1.2): env var wins over policy file
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
