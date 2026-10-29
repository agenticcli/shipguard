/**
 * Persistent telemetry settings in the user's config dir (~/.config/shipguard), plus the pure
 * helper that reads the project-policy toggle. Kept apart from telemetry.ts so the file-system
 * bits are small, injectable (every function takes the directory) and testable.
 *
 * Files (all optional, all best-effort: a read-only HOME must never break a scan):
 *   telemetry.json            { "enabled": false, ... }  written by `shipguard telemetry enable|disable`.
 *                             Unknown keys are preserved. Also holds `installId`: a random
 *                             v4 UUID (crypto.randomUUID) made lazily on the first non-CI ping; never derived from anything.
 *   telemetry-notice-shown    marker: the one-line "we send an anonymous ping" notice was printed.
 *   telemetry-first-run-sent  marker: the one-off `cli_first_run` event was handled for this install.
 */
import { randomUUID } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import YAML from 'yaml'
import { ensureSecureDir, writeSecureFileSync } from '../utils/secure-fs.js'
import { DEFAULT_POLICY_PATH } from '@agenticcli/shared'
import { logger } from '../utils/logger.js'

const CONFIG_FILE = 'telemetry.json'
const NOTICE_MARKER = 'telemetry-notice-shown'
const FIRST_RUN_MARKER = 'telemetry-first-run-sent'

export function getConfigDir(): string {
  return join(homedir(), '.config', 'shipguard')
}

export function configFilePath(dir: string = getConfigDir()): string {
  return join(dir, CONFIG_FILE)
}

export interface UserTelemetryConfig {
  enabled?: boolean
  installId?: string
  [key: string]: unknown
}

/** Read the user-level settings. Missing or malformed -> {} (malformed is logged under SHIPGUARD_DEBUG). */
export function readUserConfig(dir: string = getConfigDir()): UserTelemetryConfig {
  const file = configFilePath(dir)
  try {
    if (!existsSync(file)) return {}
    const parsed: unknown = JSON.parse(readFileSync(file, 'utf-8'))
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as UserTelemetryConfig) : {}
  } catch (err) {
    logger.debug(`telemetry: ignoring unreadable ${file}: ${err instanceof Error ? err.message : String(err)}`)
    return {}
  }
}

/** True when telemetry.json exists but is not a readable JSON object (corrupt or truncated). Missing file = false. */
export function userConfigUnreadable(dir: string = getConfigDir()): boolean {
  const file = configFilePath(dir)
  try {
    if (!existsSync(file)) return false
    const parsed: unknown = JSON.parse(readFileSync(file, 'utf-8'))
    return !(parsed && typeof parsed === 'object' && !Array.isArray(parsed))
  } catch {
    return true
  }
}

/** RFC 4122 v4, lowercase: the only shape the relay accepts (contracts/cli-telemetry-v2.md section 4). */
export const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

function writeConfig(dir: string, next: UserTelemetryConfig): string {
  const file = configFilePath(dir)
  ensureSecureDir(dir)
  writeSecureFileSync(file, JSON.stringify(next, null, 2) + '\n')
  return file
}

/** The stored install id if present and well-formed, else undefined. Never creates anything. */
export function readInstallId(dir: string = getConfigDir()): string | undefined {
  const id = readUserConfig(dir).installId
  return typeof id === 'string' && UUID_V4.test(id) ? id : undefined
}

/**
 * The install id, created on first use (crypto.randomUUID, stored 0600 next to `enabled`, other keys
 * kept). Returns undefined when it cannot be persisted: better no ping than a fresh id per run,
 * which would inflate the install count. Callers must not call this in CI.
 */
export function getOrCreateInstallId(dir: string = getConfigDir()): string | undefined {
  const existing = readInstallId(dir)
  if (existing) return existing
  try {
    const installId = randomUUID()
    writeConfig(dir, { ...readUserConfig(dir), installId })
    return installId
  } catch (err) {
    logger.debug(`telemetry: could not persist the install id: ${err instanceof Error ? err.message : String(err)}`)
    return undefined
  }
}

/** Forget the install id (a new one is made on the next ping). Other keys are kept. Throws on write failure. */
export function resetInstallId(dir: string = getConfigDir()): { hadId: boolean; oldId?: string } {
  const cfg = readUserConfig(dir)
  const hadId = 'installId' in cfg
  const oldId = readInstallId(dir)
  if (hadId) {
    delete cfg.installId
    writeConfig(dir, cfg)
  }
  return { hadId, oldId }
}

/** Persist enabled=true|false, keeping any other keys. Throws on failure (callers report it). */
export function writeUserEnabled(dir: string, enabled: boolean): string {
  return writeConfig(dir, { ...readUserConfig(dir), enabled })
}

export function noticeShown(dir: string = getConfigDir()): boolean {
  return existsSync(join(dir, NOTICE_MARKER))
}

/** Record that the notice was printed. Best-effort: if it cannot be written the notice just repeats. */
export function markNoticeShown(dir: string = getConfigDir()): void {
  try {
    ensureSecureDir(dir)
    writeSecureFileSync(join(dir, NOTICE_MARKER), '1\n')
  } catch (err) {
    logger.debug(`telemetry: could not persist the notice marker: ${err instanceof Error ? err.message : String(err)}`)
  }
}

export function firstRunHandled(dir: string = getConfigDir()): boolean {
  return existsSync(join(dir, FIRST_RUN_MARKER))
}

/** Record that the first-run event was sent (or skipped for an older install). Returns false if it could not be saved. */
export function markFirstRunHandled(dir: string = getConfigDir()): boolean {
  try {
    ensureSecureDir(dir)
    writeSecureFileSync(join(dir, FIRST_RUN_MARKER), '1\n')
    return true
  } catch (err) {
    logger.debug(`telemetry: could not persist the first-run marker: ${err instanceof Error ? err.message : String(err)}`)
    return false
  }
}

const FALSE_LIKE = new Set(['false', 'off', 'no', '0'])

/** The repo-local config file `scan --pro` auto-generates (core/config-generator.ts writes `telemetry.enabled: true` into it). */
export const GENERATED_CONFIG_FILE = '.shipguard.yml'

/**
 * `telemetry.enabled` from a parsed config object (shipguard.policy.yml or .shipguard.yml).
 * Returns false only for an explicit false-like value (false, "false", "off", "no", 0); true for an
 * explicit true; undefined when absent or unrecognisable. Anything else is never a reason to send.
 */
export function policyTelemetryEnabled(policy: unknown): boolean | undefined {
  if (!policy || typeof policy !== 'object') return undefined
  const t = (policy as { telemetry?: unknown }).telemetry
  if (!t || typeof t !== 'object') return undefined
  const v = (t as { enabled?: unknown }).enabled
  if (v === false || v === 0) return false
  if (typeof v === 'string' && FALSE_LIKE.has(v.trim().toLowerCase())) return false
  if (v === true) return true
  return undefined
}

function readYamlToggle(file: string): boolean | undefined {
  try {
    if (!existsSync(file)) return undefined
    return policyTelemetryEnabled(YAML.parse(readFileSync(file, 'utf-8')))
  } catch (err) {
    logger.debug(`telemetry: ignoring unreadable ${file}: ${err instanceof Error ? err.message : String(err)}`)
    return undefined
  }
}

/**
 * The project-level toggle. Two files can carry `telemetry.enabled`: the already-loaded
 * shipguard.policy.yml (`policy`, or read from `projectDir`) and `.shipguard.yml` (the file that
 * actually contains the toggle today). Any explicit false wins; else any explicit true; else undefined.
 */
export function projectTelemetryEnabled(input: { policy?: unknown; projectDir?: string }): boolean | undefined {
  const values: Array<boolean | undefined> = [policyTelemetryEnabled(input.policy)]
  if (input.projectDir) {
    if (input.policy === undefined) values.push(readYamlToggle(join(input.projectDir, DEFAULT_POLICY_PATH)))
    values.push(readYamlToggle(join(input.projectDir, GENERATED_CONFIG_FILE)))
  }
  if (values.includes(false)) return false
  if (values.includes(true)) return true
  return undefined
}
