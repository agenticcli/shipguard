import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import YAML from 'yaml'
import type { Policy } from '@agenticcli/shared'
import { DEFAULT_HISTORY_PATH, DEFAULT_POLICY_PATH, DEFAULT_REPORT_DIR } from '@agenticcli/shared'
import {
  DEFAULT_MAX_FILE_SIZE_BYTES,
  DEFAULT_MAX_TOTAL_BYTES,
  DEFAULT_MAX_FILES,
} from '../utils/fs.js'
import { fileExists, pathEscapeReason } from '../utils/paths.js'
import { logger } from '../utils/logger.js'

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

const isMapping = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

/**
 * What is wrong with the SHAPE of a parsed policy file, or null. The scan and the gate read these keys without checking,
 * so a file that parses as YAML but is a list, a number, or has `ignore: nope` must be refused up front with a clear
 * cause (INVALID_POLICY), never reach the scanner and crash there or be silently ignored. An empty file is fine (defaults).
 */
export function policyShapeProblem(parsed: unknown): string | null {
  if (parsed === null || parsed === undefined) return null
  if (!isMapping(parsed)) return 'the file must be a list of "key: value" lines at the top level'
  for (const key of ['project', 'scan', 'limits', 'report', 'history', 'gate', 'ignore'] as const) {
    if (parsed[key] !== undefined && !isMapping(parsed[key])) return `"${key}" must have indented "name: value" lines under it`
  }
  for (const key of ['block', 'warn'] as const) {
    const v = parsed[key]
    if (v !== undefined && !(Array.isArray(v) && v.every((x) => typeof x === 'string'))) return `"${key}" must be a list of names`
  }
  const paths = isMapping(parsed['ignore']) ? parsed['ignore']['paths'] : undefined
  if (paths !== undefined && !(Array.isArray(paths) && paths.every((x) => typeof x === 'string'))) return '"ignore.paths" must be a list of path patterns'
  return null
}

/** Plain-words causes for the YAML parser's error codes (the parser's own sentence is never shown). */
const YAML_CAUSES: Record<string, string> = {
  BAD_INDENT: 'is indented wrongly',
  TAB_AS_INDENT: 'is indented with a tab; use spaces',
  DUPLICATE_KEY: 'repeats a key that is already used above',
  MISSING_CHAR: 'opens a quote, list or block that is never closed',
  BLOCK_AS_IMPLICIT_KEY: 'is missing a colon or an indent',
  MULTILINE_IMPLICIT_KEY: 'has a key that runs over more than one line',
}

/** The line (1-based) of the innermost `[` or `{` opened before `end` and never closed, or null. Quotes and comments are skipped. */
function unclosedOpenerLine(text: string, end: number): { line: number; char: '[' | '{' } | null {
  const stack: Array<{ line: number; char: '[' | '{' }> = []
  let line = 1
  let quote: string | null = null
  for (let i = 0; i < Math.min(end, text.length); i++) {
    const c = text[i]
    if (c === '\n') { line++; quote = null; continue }
    if (quote) { if (c === quote) quote = null; continue }
    if (c === '"' || c === "'") { quote = c; continue }
    if (c === '#' && (i === 0 || /\s/.test(text[i - 1]))) { while (i < text.length && text[i + 1] !== '\n') i++; continue }
    if (c === '[' || c === '{') stack.push({ line, char: c })
    else if (c === ']' || c === '}') stack.pop()
  }
  return stack.length > 0 ? stack[stack.length - 1] : null
}

/**
 * The first YAML error of a policy file in OUR words, with the line it belongs to, or null when the YAML parses.
 * Used by the scan, `schema` and the gate so the same file gets the same message everywhere.
 * An unclosed `[` or `{` is reported at the line that opened it, not at the end of the file where the parser notices.
 */
export function explainPolicyYamlError(text: string): { line: number | null; cause: string } | null {
  const err = YAML.parseDocument(text, { lineCounter: new YAML.LineCounter() }).errors[0]
  if (!err) return null
  const errLine = err.linePos?.[0]?.line ?? null
  const open = /^(Flow sequence|Flow map)/.test(err.message) || err.code === 'MISSING_CHAR' ? unclosedOpenerLine(text, err.pos[0]) : null
  if (open) {
    const [what, close] = open.char === '[' ? ['a list', ']'] : ['a block', '}']
    return { line: open.line, cause: `line ${open.line} starts ${what} with ${open.char} and never closes it with ${close}.` }
  }
  const why = YAML_CAUSES[err.code] ?? 'is not valid YAML'
  return { line: errLine, cause: errLine ? `line ${errLine} ${why}.` : `the file ${why}.` }
}

/** A policy file that cannot be used; `cause` is already in plain words (with its line), `line` is for the error envelope. */
export class PolicyFileError extends Error {
  constructor(readonly cause: string, readonly line: number | null) {
    super(`Invalid policy file: ${cause}`)
  }
}

const warned = new Set<string>()

/**
 * A policy file from a cloned repo must not choose where ShipGuard writes: report.output and history.path stay inside the
 * project. Anything else is refused with one warning per run and the default location is used instead. (The user's own
 * SHIPGUARD_HISTORY_PATH env override is not checked here and stays allowed.)
 */
function containWritePaths(dir: string, policy: Policy): Policy {
  const out: Policy = { ...policy }
  const refuse = (key: string, value: unknown, why: string, fallback: string): void => {
    const msg = `Ignoring ${key} in ${DEFAULT_POLICY_PATH} (${String(value).slice(0, 120)}): ${why}. Using ${fallback} instead.`
    if (!warned.has(msg)) {
      warned.add(msg)
      logger.warn(msg)
    }
  }
  if (policy.report && policy.report.output !== undefined) {
    const why = pathEscapeReason(dir, policy.report.output)
    if (why) {
      refuse('report.output', policy.report.output, why, DEFAULT_POLICY.report.output ?? '')
      out.report = { ...policy.report, output: DEFAULT_POLICY.report.output }
    }
  }
  if (policy.history && policy.history.path !== undefined) {
    const why = pathEscapeReason(dir, policy.history.path)
    if (why) {
      refuse('history.path', policy.history.path, why, DEFAULT_HISTORY_PATH)
      out.history = { ...policy.history, path: undefined }
    }
  }
  return out
}

export async function loadPolicy(dir: string): Promise<Policy> {
  const policyPath = join(dir, DEFAULT_POLICY_PATH)

  if (!fileExists(policyPath)) {
    return DEFAULT_POLICY
  }

  try {
    const content = await readFile(policyPath, 'utf-8')
    const yamlProblem = explainPolicyYamlError(content)
    if (yamlProblem) throw new PolicyFileError(yamlProblem.cause, yamlProblem.line)
    const parsed = YAML.parse(content)
    const shape = policyShapeProblem(parsed)
    if (shape !== null) throw new PolicyFileError(shape, null)
    // Deep-merge limits so existing policies without a `limits` block still get defaults
    return containWritePaths(dir, {
      ...DEFAULT_POLICY,
      ...(parsed ?? {}),
      limits: { ...DEFAULT_POLICY.limits, ...(parsed?.limits ?? {}) },
    })
  } catch (error) {
    if (error instanceof PolicyFileError) throw error
    // A read failure (permission, folder instead of file) or an unexpected bug: say what it was, never swallow it.
    throw new PolicyFileError(error instanceof Error ? error.message : String(error), null)
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
