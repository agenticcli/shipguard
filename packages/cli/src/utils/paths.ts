import { resolve } from 'node:path'
import { existsSync } from 'node:fs'
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
