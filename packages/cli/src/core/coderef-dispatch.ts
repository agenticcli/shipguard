/**
 * Coderef rule dispatch — Suricata hybrid model (Phase 1 registry engine).
 *
 * Rules with `implType:"coderef"` carry a `codeRef{ moduleId, exportName,
 * minCliVersion, checksum }` pointer. This module resolves those pointers to
 * the real CheckModule.run implementations that are bundled in the CLI binary.
 *
 * Governance: /rules.md + docs/superpowers/specs/2026-06-08-rule-registry-lifecycle-design.md §3
 */
import type { CheckModule, QualityGateRule, FileInfo, Policy, Finding } from '@agenticcli/shared'

import { secretsCheck } from '../checks/secrets.js'
import { authCheck } from '../checks/auth.js'
import { databaseCheck } from '../checks/database.js'
import { deploymentCheck } from '../checks/deployment.js'
import { payments } from '../checks/payments.js'

// ---------------------------------------------------------------------------
// Local-only types (CLI-side augmentation — not added to @agenticcli/shared
// because the concurrent Convex schema agent owns those fields there; we avoid
// the file-overlap in the rebase). as-any casts below carry WHY comments.
// ---------------------------------------------------------------------------

export interface CodeRef {
  moduleId: string
  exportName: string
  minCliVersion: string
  checksum?: string
}

/** CLI-local augmentation of QualityGateRule with registry Phase-1 fields. */
export interface CoderefRule extends QualityGateRule {
  implType?: 'declarative' | 'coderef'
  codeRef?: CodeRef
}

// ---------------------------------------------------------------------------
// Dispatch table: "moduleId:exportName" → CheckModule
// Keyed by the strings stored in codeRef.moduleId + codeRef.exportName.
// ---------------------------------------------------------------------------

export type DispatchTable = Record<string, CheckModule>

export const DEFAULT_DISPATCH_TABLE: DispatchTable = {
  'secrets:secretsCheck': secretsCheck,
  'auth:authCheck': authCheck,
  'database:databaseCheck': databaseCheck,
  'deployment:deploymentCheck': deploymentCheck,
  'payments:payments': payments,
}

// ---------------------------------------------------------------------------
// Semver compare — minimal int-based compare, no new dependency.
// Returns -1 | 0 | 1 (same contract as localeCompare).
// ---------------------------------------------------------------------------

function parseSemver(v: string): [number, number, number] {
  const [major = 0, minor = 0, patch = 0] = v.split('.').map(Number)
  return [major, minor, patch]
}

/** Returns true if `a` is strictly less than `b`. Equal → false (equal runs). */
export function semverLt(a: string, b: string): boolean {
  const [aMaj, aMin, aPatch] = parseSemver(a)
  const [bMaj, bMin, bPatch] = parseSemver(b)
  if (aMaj !== bMaj) return aMaj < bMaj
  if (aMin !== bMin) return aMin < bMin
  return aPatch < bPatch
}

// ---------------------------------------------------------------------------
// Coderef dispatch result
// ---------------------------------------------------------------------------

export interface CoderefDispatchResult {
  findings: Finding[]
  /** True when ≥1 rule was skipped because minCliVersion > installed version,
   *  or because the rule's moduleId:exportName is not in the dispatch table. */
  degraded: boolean
  /** Human-readable warnings for skip events (non-fatal). */
  warnings: string[]
}

// ---------------------------------------------------------------------------
// Optional checksum manifest type (Phase 2 build-time artifact).
// If absent, checksum verification is skipped gracefully.
// ---------------------------------------------------------------------------

export interface ChecksumManifest {
  [moduleId: string]: string  // moduleId → SHA-256 hex
}

// ---------------------------------------------------------------------------
// runCoderefRules — main dispatch entry point
// ---------------------------------------------------------------------------

/**
 * Dispatch coderef rules to their bundled CheckModule implementations.
 *
 * @param rules       All rules fetched from the registry (mixed implType).
 * @param files       Scanned file list.
 * @param policy      Active policy.
 * @param cliVersion  Installed CLI version (default: read from package.json at
 *                    import time — injectable for tests so we never hit the fs).
 * @param table       Dispatch table (injectable for tests).
 * @param manifest    Optional checksum manifest (injectable; absent → skip check).
 */
export function runCoderefRules(
  rules: QualityGateRule[],
  files: FileInfo[],
  policy: Policy,
  cliVersion: string = CLI_VERSION,
  table: DispatchTable = DEFAULT_DISPATCH_TABLE,
  manifest?: ChecksumManifest,
): CoderefDispatchResult {
  const findings: Finding[] = []
  let degraded = false
  const warnings: string[] = []

  // Cast to the CLI-local augmented type — WHY: QualityGateRule is the shared
  // interface which intentionally does not carry implType/codeRef (those live
  // in the Convex schema and the Sonnet registry agent owns shared type changes).
  const augmented = rules as CoderefRule[]

  const coderefs = augmented.filter(r => r.implType === 'coderef')

  for (const rule of coderefs) {
    const ref = rule.codeRef
    if (!ref) {
      warnings.push(
        `[shipguard] coderef rule ${rule.id} has implType:"coderef" but no codeRef pointer — skipping`,
      )
      continue
    }

    // 1. Version gate: skip if installed CLI is older than rule's minimum
    if (semverLt(cliVersion, ref.minCliVersion)) {
      warnings.push(
        `[shipguard] Skipping coderef rule ${rule.id}: requires CLI ≥${ref.minCliVersion}, installed ${cliVersion}`,
      )
      degraded = true
      continue
    }

    // 2. Checksum guard: if manifest present, verify moduleId checksum.
    //    FAIL CLOSED on mismatch or absent-from-manifest — a tampered or
    //    unrecognized module must NOT run silently (GC.12 / C.10 fix).
    //    Cryptographic signing of the manifest is deferred (Codex E1 scope);
    //    this is integrity/fail-closed only.
    if (manifest) {
      const expected = manifest[ref.moduleId]
      if (expected === undefined) {
        // Module not in manifest → treat as tampered / unrecognized — fail closed.
        warnings.push(
          `[shipguard] CODEREF_CHECKSUM_MISMATCH: rule ${rule.id}: module "${ref.moduleId}" is absent from the checksum manifest — refusing to run (non-safe)`,
        )
        degraded = true
        continue
      }
      if (expected !== ref.checksum) {
        // Checksum mismatch → tampered module — fail closed.
        warnings.push(
          `[shipguard] CODEREF_CHECKSUM_MISMATCH: rule ${rule.id}: checksum mismatch for module "${ref.moduleId}" (expected ${expected}, got ${ref.checksum ?? 'undefined'}) — refusing to run (non-safe)`,
        )
        degraded = true
        continue
      }
    }
    // If no manifest exists, skip the checksum check gracefully (Phase 2 build artifact).

    // 3. Resolve the dispatch key: "moduleId:exportName"
    const dispatchKey = `${ref.moduleId}:${ref.exportName}`
    const mod = table[dispatchKey]

    if (!mod) {
      warnings.push(
        `[shipguard] Unknown coderef "${dispatchKey}" for rule ${rule.id} — skipping (not a crash)`,
      )
      degraded = true
      continue
    }

    // 4. Invoke the CheckModule — findings are already fully-formed (blocking
    //    derived inside each CheckModule.run); concat directly.
    const moduleFindings = mod.run(files, policy)
    findings.push(...moduleFindings)
  }

  return { findings, degraded, warnings }
}

// ---------------------------------------------------------------------------
// CLI_VERSION — read once at module load from package.json.
// The path is relative to the compiled output in dist/core/ → ../../package.json
// In tests (ts-node / vitest via tsx) import.meta.url resolves from src/core/ —
// same two-level parent → packages/cli/package.json either way.
// ---------------------------------------------------------------------------

import { createRequire } from 'node:module'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const _require = createRequire(import.meta.url)
const _pkgPath = join(dirname(fileURLToPath(import.meta.url)), '../../package.json')

let CLI_VERSION: string
try {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WHY: package.json is untyped
  const pkg = _require(_pkgPath) as any
  CLI_VERSION = typeof pkg.version === 'string' ? pkg.version : '0.0.0'
} catch {
  CLI_VERSION = '0.0.0'
}

// ---------------------------------------------------------------------------
// loadChecksumManifest — load dist/checksum-manifest.json at CLI startup.
//
// The manifest is generated at build time by scripts/gen-checksum-manifest.mjs.
// The CLI calls this once at startup and passes the result to runCoderefRules
// so every coderef dispatch is verified against the build-time hash.
//
// Returns undefined if the manifest file does not exist (pre-build or test
// environment — checksum check is skipped gracefully in that case).
//
// Path resolution: from dist/core/coderef-dispatch.js → ../../checksum-manifest.json
// (same two-level parent as package.json, landing in dist/).
// In tests (tsx from src/core/) the path resolves to src/../../checksum-manifest.json
// = packages/cli/checksum-manifest.json which will not exist → returns undefined
// (tests inject manifest directly — correct behavior).
// ---------------------------------------------------------------------------

const _manifestPath = join(dirname(fileURLToPath(import.meta.url)), '../../checksum-manifest.json')

/**
 * Load the build-time checksum manifest from dist/checksum-manifest.json.
 *
 * Returns the parsed manifest, or undefined if the file does not exist
 * (pre-build environments or test injection scenarios — caller skips check).
 *
 * Logs a warning (never throws) on parse errors so a corrupt manifest does
 * not crash the CLI — the caller should treat undefined as "no manifest"
 * and decide whether to degrade (a future hardening option).
 */
export function loadChecksumManifest(): ChecksumManifest | undefined {
  if (!existsSync(_manifestPath)) {
    return undefined
  }
  try {
    const raw = readFileSync(_manifestPath, 'utf-8')
    const parsed = JSON.parse(raw) as unknown
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      console.warn('[shipguard] checksum-manifest.json is not a valid object — skipping checksum verification')
      return undefined
    }
    return parsed as ChecksumManifest
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.warn(`[shipguard] Failed to load checksum-manifest.json: ${msg} — skipping checksum verification`)
    return undefined
  }
}
