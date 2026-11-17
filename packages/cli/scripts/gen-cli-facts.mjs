#!/usr/bin/env node
/**
 * gen-cli-facts.mjs — generate dist/cli-facts.json
 *
 * Reads the actual source files of @agenticcli/shipguard and emits a
 * machine-readable facts document into dist/cli-facts.json.
 *
 * Values are DERIVED from the code — nothing is hardcoded here.
 * Run after `pnpm build` so dist/ exists (needed only to determine the output
 * path; gen-cli-facts itself reads from src/ and shared/src/).
 *
 * Usage:
 *   node packages/cli/scripts/gen-cli-facts.mjs
 *
 * Output: packages/cli/dist/cli-facts.json
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const cliDir   = join(__dirname, '..')
const distDir  = join(cliDir, 'dist')
const sharedSrcDir = join(cliDir, '..', 'shared', 'src')

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readSrc(relPath) {
  return readFileSync(join(cliDir, relPath), 'utf-8')
}

function readShared(relPath) {
  return readFileSync(join(sharedSrcDir, relPath), 'utf-8')
}

/**
 * Extract a TypeScript `const NAME = { ... } as const` object's string keys.
 * Works for simple objects like EXIT_CODES / CATEGORIES.
 */
function extractConstObjectKeys(src, constName) {
  // Match: export const NAME = { ... } as const
  // or:    export const NAME = ['a','b','c'] as const
  const re = new RegExp(`export const ${constName}\\s*=\\s*\\{([^}]+)\\}`, 's')
  const m = re.exec(src)
  if (!m) return []
  const body = m[1]
  // Extract identifier keys (SAFE: 0, BLOCKED: 1 etc.)
  const keys = [...body.matchAll(/^\s*([A-Z_][A-Z_0-9]*)(?:\s*:|\s*=)/gm)].map(x => x[1])
  return keys
}

/**
 * Extract values from a TypeScript `export const CATEGORIES = [...] as const` array.
 */
function extractConstArray(src, constName) {
  const re = new RegExp(`export const ${constName}\\s*=\\s*\\[([^\\]]+)\\]`, 's')
  const m = re.exec(src)
  if (!m) return []
  // Extract string literals between quotes
  const items = [...m[1].matchAll(/['"]([^'"]+)['"]/g)].map(x => x[1])
  return items
}

/**
 * Extract the numeric value for a key from an EXIT_CODES object.
 * Returns a Record<string, number>.
 */
function extractExitCodesMap(src) {
  const re = /export const EXIT_CODES\s*=\s*\{([^}]+)\}\s*as const/s
  const m = re.exec(src)
  if (!m) return {}
  const body = m[1]
  const result = {}
  for (const entry of body.matchAll(/([A-Z_]+)\s*:\s*(\d+)/g)) {
    result[entry[1]] = Number(entry[2])
  }
  return result
}

/**
 * Extract the type union members from a `export type DegradeCode = 'A' | 'B' | ...`
 *
 * Stops at the first newline or semicolon — whichever comes first — so that
 * single-line union types without a trailing semicolon are parsed correctly.
 * Multi-line union types (DegradeCode) that span multiple lines end at the first
 * semicolon.
 */
function extractTypeUnionMembers(src, typeName) {
  // Match the part of the type declaration after '='
  // Use a non-greedy match that stops at either a bare newline (single-line types)
  // or a semicolon (multi-line types like DegradeCode).
  const re = new RegExp(`export type ${typeName}\\s*=\\s*([^\n]+(?:\n\\s*\\|[^\n]+)*)`)
  const m = re.exec(src)
  if (!m) return []
  const union = m[1]
  return [...union.matchAll(/['"]([^'"]+)['"]/g)].map(x => x[1])
}

/**
 * Extract the keys of an interface definition.
 * e.g. export interface ScanResult { findings: Finding[]; riskScore: RiskScore; ... }
 */
function extractInterfaceKeys(src, ifaceName) {
  // Match the entire interface body including nested braces by finding the
  // outermost matching brace pair after "interface NAME".
  const startRe = new RegExp(`export interface ${ifaceName}\\s*\\{`)
  const startM = startRe.exec(src)
  if (!startM) return []

  let depth = 0
  let start = -1
  let i = startM.index
  while (i < src.length) {
    if (src[i] === '{') {
      if (depth === 0) start = i
      depth++
    } else if (src[i] === '}') {
      depth--
      if (depth === 0) {
        break
      }
    }
    i++
  }
  if (start === -1 || depth !== 0) return []
  const body = src.slice(start + 1, i)

  // Extract property names: lines like `  propName?: type` or `  propName: type`
  // Skip comment lines and nested interface/type lines.
  const keys = []
  for (const line of body.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue
    // Match: optionalIdentifier?: or mandatoryIdentifier:
    const m = trimmed.match(/^([a-zA-Z_$][a-zA-Z0-9_$]*)\??\s*:/)
    if (m) {
      keys.push(m[1])
    }
  }
  return keys
}

/**
 * Extract CHECK_MODULES member names from scanner.ts.
 * Looks for: const CHECK_MODULES = [secretsCheck, authCheck, ...]
 * Then resolves the `id` of each CheckModule by finding `id: 'xxx'` or `id: "xxx"`.
 * Since the IDs are each module's exported .id field, we read the check file names
 * from the import lines and then find `id: '...'` in each check file.
 */
function extractFreeModuleNames(scannerSrc) {
  // Extract variable names from CHECK_MODULES array
  const re = /const CHECK_MODULES\s*=\s*\[([^\]]+)\]/s
  const m = re.exec(scannerSrc)
  if (!m) return []
  const vars = [...m[1].matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)/g)].map(x => x[1])
  return vars
}

/**
 * Extract free rule IDs from a check module source file.
 *
 * Handles three patterns used across the check files:
 *   1. `id: 'xxx'`           — inline object property (most modules)
 *   2. `const id = 'xxx'`    — local variable pattern (secrets.ts)
 *   3. `makeId('xxx')`       — deployment.ts helper that prepends 'deployment_'
 */
function extractRuleIds(src) {
  const ids = new Set()

  // Pattern 1: id: 'xxx' (object property or assignment)
  for (const m of src.matchAll(/\bid\s*:\s*['"]([a-zA-Z0-9_-]+)['"]/g)) {
    ids.add(m[1])
  }

  // Pattern 2: const id = 'xxx' (local const variable in secrets.ts etc.)
  for (const m of src.matchAll(/\bconst\s+id\s*=\s*['"]([a-zA-Z0-9_-]+)['"]/g)) {
    ids.add(m[1])
  }

  // Pattern 3: makeId('xxx') → deployment_xxx
  for (const m of src.matchAll(/\bmakeId\s*\(\s*['"]([a-zA-Z0-9_-]+)['"]\s*\)/g)) {
    // Skip template-literal forms like makeId(`pkg_node_env_dev_${name}`) — not static
    ids.add(`deployment_${m[1]}`)
  }

  return [...ids]
}

/**
 * Extract the `schemaVersion` field default value from ScanResult or a version
 * constant. Since the codebase doesn't have an explicit SCHEMA_VERSION constant,
 * we derive it from the package.json major.minor.
 */
function deriveSchemaVersion(version) {
  const parts = version.split('.')
  return `${parts[0]}.${parts[1]}`
}

/**
 * Extract node engine requirement from package.json.
 */
function extractNodeEngine(pkg) {
  return pkg.engines?.node ?? '>=20'
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

// 1. Read package.json
const pkgPath = join(cliDir, 'package.json')
const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
const version = pkg.version
const packageName = pkg.name
const nodeEngine = extractNodeEngine(pkg)

// License — DERIVED from package.json's `license` field (the legal source of
// truth), never hardcoded. licenseDisplay is the short UI label the website
// renders in footers (it consumes cli-facts.json as its facts source of truth;
// a missing license field there once let a hardcoded "MIT" label show for an
// ELv2 product).
// Fail LOUD if the field is missing or unmapped: silently emitting no license
// (the pre-fix behavior) is exactly what allowed the drift.
const LICENSE_DISPLAY = {
  'Elastic-2.0': 'ELv2',
}
const license = pkg.license
if (!license) {
  console.error('[gen-cli-facts] ERROR: package.json has no "license" field — refusing to emit facts without it (a missing license let a wrong hardcoded label ship on the public site).')
  process.exit(1)
}
const licenseDisplay = LICENSE_DISPLAY[license]
if (!licenseDisplay) {
  console.error(`[gen-cli-facts] ERROR: no display label mapped for license "${license}" — add it to LICENSE_DISPLAY in this script (never silently fall back).`)
  process.exit(1)
}

// 2. Read shared/src/constants.ts for EXIT_CODES, CATEGORIES
const constantsSrc = readShared('constants.ts')
const exitCodesMap = extractExitCodesMap(constantsSrc)
const categories   = extractConstArray(constantsSrc, 'CATEGORIES')

// 3. Read shared/src/types.ts for ScanResult fields, DegradeCode
const typesSrc = readShared('types.ts')
const jsonSchemaFields = extractInterfaceKeys(typesSrc, 'ScanResult')
const degradeCodes     = extractTypeUnionMembers(typesSrc, 'DegradeCode')

// Get Severity type members
const severities = extractTypeUnionMembers(typesSrc, 'Severity')

// 4. Read scanner.ts for CHECK_MODULES (free module names)
const scannerSrc = readSrc('src/core/scanner.ts')
const checkModuleVarNames = extractFreeModuleNames(scannerSrc)

// Map var names to module IDs by reading each check file
const checksDir = join(cliDir, 'src', 'checks')
const checkFiles = {
  secretsCheck: 'secrets.ts',
  authCheck: 'auth.ts',
  databaseCheck: 'database.ts',
  payments: 'payments.ts',
  deploymentCheck: 'deployment.ts',
}

const freeModules = []
const freeRuleIds = []

for (const varName of checkModuleVarNames) {
  const fileName = checkFiles[varName]
  if (!fileName) continue
  const src = readSrc(`src/checks/${fileName}`)

  // Extract the module id from: id: 'xxx', (the exported CheckModule object)
  // This is typically at the export level: `export const secretsCheck: CheckModule = { id: 'secrets', ...}`
  const moduleIdRe = /export const \w+:\s*CheckModule\s*=\s*\{\s*id:\s*['"]([^'"]+)['"]/
  const mm = moduleIdRe.exec(src)
  if (mm) {
    freeModules.push(mm[1])
  }

  // Collect all rule IDs from findings pushed in this file
  const ids = extractRuleIds(src)
  for (const id of ids) {
    if (!freeRuleIds.includes(id)) freeRuleIds.push(id)
  }
}

// The CheckModule objects themselves carry `id: 'secrets'` / `'auth'` / … and the
// extractor above cannot tell a MODULE id from a RULE id — so the five module names were
// being counted as rules, and `freeRuleCount` read 35 when only 30 rules exist. Subtract
// them explicitly (they are already collected in `freeModules`) rather than leaving a
// count that overstates the product by five.
const legacyRuleIds = freeRuleIds.filter((id) => !freeModules.includes(id))
const legacyRuleCount = legacyRuleIds.length

// 4b. The bundled corpus rules — the governed offline free set that now actually ships
// inside the CLI (packages/cli/rules/free-bundle.json, generated in the platform repo by
// scripts/build-free-bundle.ts from every rule.yaml with bundleEligible:true).
//
// Before 2026-08-04 this file described ONLY the hand-written check modules, so every
// downstream consumer of cli-facts.json — the web site's /shipguard/rules.json, the
// llms-full.txt tier table, the agent-surface gate — reported a free tier that contained
// none of the corpus. Emitting both sets, separately and truthfully, is what lets those
// surfaces stop disagreeing with the product.
const bundlePath = join(cliDir, 'rules', 'free-bundle.json')
let bundle
try {
  bundle = JSON.parse(readFileSync(bundlePath, 'utf-8'))
} catch (err) {
  console.error(
    `[gen-cli-facts] ERROR: could not read ${bundlePath}: ${err.message}\n` +
    '  The offline rule bundle is what the free tier actually applies. Emitting facts ' +
    'without it would republish the exact defect this field exists to close.',
  )
  process.exit(1)
}
const bundledCorpusRuleIds = bundle.rules.map((r) => r.id).sort()
if (bundledCorpusRuleIds.length !== bundle.ruleCount) {
  console.error(
    `[gen-cli-facts] ERROR: free-bundle.json declares ruleCount ${bundle.ruleCount} but ` +
    `carries ${bundledCorpusRuleIds.length} rules — refusing to emit inconsistent facts.`,
  )
  process.exit(1)
}

// 5. Assemble the facts document
const facts = {
  version,
  packageName,
  license,
  licenseDisplay,
  nodeEngine,
  exitCodes: exitCodesMap,
  freeModules,
  // The CLI's own hand-written check rules (kept — they cover ground the corpus does not:
  // git-tracked .env, Dockerfile/compose/vercel/netlify shapes, payment webhooks,
  // destructive SQL, unguarded routes).
  freeRuleIds: legacyRuleIds,
  freeRuleCount: legacyRuleCount,
  // The governed corpus rules bundled into this build and applied on every offline scan.
  bundledCorpusRuleIds,
  bundledCorpusRuleCount: bundledCorpusRuleIds.length,
  corpusVersion: bundle.corpusVersion,
  bundleContentHash: bundle.contentHash,
  // What an anonymous, offline `shipguard scan` actually applies, end to end.
  offlineRuleCount: legacyRuleCount + bundledCorpusRuleIds.length,
  jsonSchemaFields,
  schemaVersion: deriveSchemaVersion(version),
  degradeCodes,
  severities,
  categories,
  installSnippet: 'npx @agenticcli/shipguard scan --changed --strict --json',
  re2Engine: true,
  generatedAt: new Date().toISOString(),
}

// 6. Write to dist/cli-facts.json (create dist/ if needed)
mkdirSync(distDir, { recursive: true })
const outPath = join(distDir, 'cli-facts.json')
writeFileSync(outPath, JSON.stringify(facts, null, 2) + '\n', 'utf-8')

// 7. Verify it round-trips as valid JSON
const parsed = JSON.parse(readFileSync(outPath, 'utf-8'))
if (parsed.version !== version) {
  console.error(`[gen-cli-facts] ERROR: version mismatch in emitted JSON: expected ${version}, got ${parsed.version}`)
  process.exit(1)
}

console.log(`[gen-cli-facts] Written ${outPath}`)
console.log(`  version:       ${facts.version}`)
console.log(`  packageName:   ${facts.packageName}`)
console.log(`  license:       ${facts.license} (display: ${facts.licenseDisplay})`)
console.log(`  nodeEngine:    ${facts.nodeEngine}`)
console.log(`  freeModules:   ${facts.freeModules.join(', ')}`)
console.log(`  freeRuleIds:   ${facts.freeRuleIds.join(', ')}`)
console.log(`  freeRuleCount: ${facts.freeRuleCount}`)
console.log(`  bundledCorpusRuleCount: ${facts.bundledCorpusRuleCount} (corpusVersion ${facts.corpusVersion})`)
console.log(`  offlineRuleCount:       ${facts.offlineRuleCount}`)
console.log(`  schemaVersion: ${facts.schemaVersion}`)
console.log(`  degradeCodes:  ${facts.degradeCodes.join(', ')}`)
console.log(`  severities:    ${facts.severities.join(', ')}`)
console.log(`  categories:    ${facts.categories.join(', ')}`)
console.log(`  re2Engine:     ${facts.re2Engine}`)
console.log(`  generatedAt:   ${facts.generatedAt}`)
