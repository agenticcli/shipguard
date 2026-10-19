import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import YAML from 'yaml'
import type { Policy } from '@agenticcli/shared'
import { DEFAULT_POLICY_PATH, DEFAULT_REPORT_DIR } from '@agenticcli/shared'
import {
  DEFAULT_MAX_FILE_SIZE_BYTES,
  DEFAULT_MAX_TOTAL_BYTES,
  DEFAULT_MAX_FILES,
} from '../utils/fs.js'
import { fileExists } from '../utils/paths.js'

const DEFAULT_POLICY: Policy = {
  version: 1,
  project: {
    name: 'my-app',
    framework: 'auto',
    risk_profile: 'standard',
  },
  scan: {
    changed_files_only: true,
    generate_report: true,
  },
  block: [
    'exposed_env',
    'hardcoded_secret',
    'public_admin_route',
    'auth_route_without_guard',
    'payment_webhook_without_signature_check',
    'destructive_migration',
    'unsafe_deployment_config',
  ],
  warn: [
    'missing_tests_for_changed_code',
    'missing_error_handling',
    'risky_dependency_change',
    'missing_rate_limit',
    'missing_input_validation',
  ],
  ignore: {
    paths: [
      'node_modules/**',
      'dist/**',
      'build/**',
      '.next/**',
      'coverage/**',
      // ShipGuard's own report output — never scan the tool's own artifacts
      '.shipguard/**',
    ],
  },
  report: {
    output: '.shipguard/reports/latest.md',
    format: 'markdown',
  },
  limits: {
    maxFileSizeBytes: DEFAULT_MAX_FILE_SIZE_BYTES,
    maxTotalBytes: DEFAULT_MAX_TOTAL_BYTES,
    maxFiles: DEFAULT_MAX_FILES,
  },
}

export async function loadPolicy(dir: string): Promise<Policy> {
  const policyPath = join(dir, DEFAULT_POLICY_PATH)

  if (!fileExists(policyPath)) {
    return DEFAULT_POLICY
  }

  try {
    const content = await readFile(policyPath, 'utf-8')
    const parsed = YAML.parse(content)
    // Deep-merge limits so existing policies without a `limits` block still get defaults
    return {
      ...DEFAULT_POLICY,
      ...parsed,
      limits: { ...DEFAULT_POLICY.limits, ...(parsed.limits ?? {}) },
    }
  } catch (error) {
    throw new Error(`Invalid policy file: ${error instanceof Error ? error.message : error}`)
  }
}

export async function createPolicyFile(dir: string): Promise<boolean> {
  const policyPath = join(dir, DEFAULT_POLICY_PATH)

  if (fileExists(policyPath)) {
    return false
  }

  const yamlContent = YAML.stringify(DEFAULT_POLICY, { indent: 2 })
  await writeFile(policyPath, yamlContent, 'utf-8')
  return true
}

export async function createShipguardDir(dir: string): Promise<void> {
  const reportDir = resolve(dir, DEFAULT_REPORT_DIR)
  await mkdir(reportDir, { recursive: true })
}

export { DEFAULT_POLICY }
