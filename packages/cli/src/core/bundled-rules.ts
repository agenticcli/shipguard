// Offline free rule bundle — the governed corpus rules that ship INSIDE the CLI.
//
// WHY THIS FILE EXISTS
// ====================
// The platform repo's `rules.md` §9 row 1 promises an anonymous, logged-out user
// "Bundled offline-free rules only (bundleEligible: true)". Until 2026-08-04 the CLI
// shipped no corpus rule at all: its free tier came entirely from the hand-written
// check modules in src/checks/**, whose flat rule IDs (`hardcoded_secret`,
// `exposed_env`, …) had ZERO overlap with the corpus's namespaced IDs
// (`generic.secrets.openai-api-key`, …). Two rule systems, one governed and unshipped,
// one shipped and ungoverned, and nothing anywhere compared them.
//
// This module loads the bundle the platform repo now generates
// (`scripts/build-free-bundle.ts` → `rule-corpus/free-bundle.json`, vendored here as
// `packages/cli/rules/free-bundle.json`) and hands it to the SAME declarative matcher
// engine the Pro path already uses (`runProRules`, re2js-v1). No second engine, no
// network call, no auth — the bundle is data, compiled into the published artifact.
//
// THE BUNDLE IS STATICALLY IMPORTED, ON PURPOSE
// =============================================
// `import bundleJson from '../../rules/free-bundle.json'` means esbuild/tsup inlines
// the rules into `dist/cli.js` at build time. A runtime `readFileSync` of a path
// relative to `import.meta.url` is the alternative, and it is the mechanism that has
// already failed silently once in this codebase (see coderef-dispatch.ts's manifest
// path comment, which resolves to a non-existent file under tsx and returns undefined).
// A missing bundle would mean every offline scan applies zero corpus rules and reports
// clean — the exact "green that measured nothing" failure this work exists to remove.
// A static import cannot be missing at runtime: if it is absent, the BUILD fails.
//
// The same file is ALSO listed in package.json `files`, so the published tarball
// carries a human-readable, greppable copy that CI diffs against the platform repo's
// `rule-corpus/INVENTORY.json` (`tests/bundle/free-bundle-tarball.test.ts`). Both come
// from one file in one build, so they cannot drift from each other.

import type { QualityGateRule } from '@agenticcli/shared'
import { validateBundleCompile } from './pro-scanner.js'
import bundleJson from '../../rules/free-bundle.json' with { type: 'json' }

/**
 * Bundle schema version this CLI knows how to read. Must match the
 * `FREE_BUNDLE_SCHEMA_VERSION` the platform repo's generator stamps.
 *
 * A mismatch throws rather than best-effort parsing an unknown layout: silently
 * running a bundle you do not understand is how you end up applying a subset of the
 * rules while telling the user you applied all of them.
 */
export const SUPPORTED_FREE_BUNDLE_SCHEMA_VERSION = 1

export interface FreeBundleMeta {
  /** Corpus version the bundle was compiled from (rule-corpus/corpusVersion.json). */
  corpusVersion: number
  /** SHA-256 over the canonical rules array — the drift fingerprint. */
  contentHash: string
  /** Number of corpus rules in the bundle. */
  ruleCount: number
}

interface RawBundle {
  schemaVersion: number
  corpusVersion: number
  corpusHash: string
  ruleCount: number
  contentHash: string
  rules: unknown[]
}

const raw = bundleJson as unknown as RawBundle

/**
 * Thrown when the vendored bundle cannot be trusted. Never swallowed: a scan that
 * cannot load its own rule set has not "passed", it has not run.
 */
export class FreeBundleError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FreeBundleError'
  }
}

let validated = false

function validateOnce(): void {
  if (validated) return

  if (raw.schemaVersion !== SUPPORTED_FREE_BUNDLE_SCHEMA_VERSION) {
    throw new FreeBundleError(
      `Bundled rule set declares schemaVersion ${raw.schemaVersion}, but this CLI reads ` +
        `${SUPPORTED_FREE_BUNDLE_SCHEMA_VERSION}. Refusing to run a bundle whose layout this build does not ` +
        `understand — a partially-parsed rule set would silently under-scan.`,
    )
  }

  if (!Array.isArray(raw.rules) || raw.rules.length === 0) {
    throw new FreeBundleError(
      'Bundled rule set is empty. An offline scan with zero corpus rules would report clean ' +
        'while applying nothing — failing loud instead.',
    )
  }

  if (raw.rules.length !== raw.ruleCount) {
    throw new FreeBundleError(
      `Bundled rule set declares ruleCount ${raw.ruleCount} but carries ${raw.rules.length} rules — ` +
        'the bundle is inconsistent with its own header.',
    )
  }

  // Atomic compile check, once per process (memoised by `validated`).
  //
  // WHY THIS IS NOT LEFT TO runProRules: that function reacts to a compile failure by logging
  // and returning `[]`. On the pro path a caller turns that into a `degraded` scan; on THIS
  // path an empty result is indistinguishable from "the code was clean", so a bundle that
  // failed to compile would hand the user a confident all-clear over zero corpus rules — the
  // exact silent-nothing failure this bundle exists to remove. Fail here instead, loudly.
  const compile = validateBundleCompile(raw.rules as QualityGateRule[])
  if (!compile.ok) {
    throw new FreeBundleError(
      `Bundled rule set failed to compile: ${compile.reason}. Refusing to run — a scan that ` +
        'silently applied zero corpus rules would report clean while checking nothing.',
    )
  }

  validated = true
}

/**
 * The bundled corpus rules, in the shape `runProRules` consumes.
 *
 * Pure and side-effect free (the JSON is already in memory — this is a cast + a
 * consistency check, not I/O). Safe to call per scan.
 */
export function loadBundledRules(): QualityGateRule[] {
  validateOnce()
  // The generator emits exactly the QualityGateRule field set the engine reads
  // (id/framework/category/tier/severity/confidence/action/matcher/explanation/
  // recommendation/fix/cwe/aiCodeTarget). It is validated shape-wise by the platform
  // repo's own gate (scripts/build-free-bundle.test.ts) before it is ever vendored here.
  return raw.rules as QualityGateRule[]
}

/** Provenance for `--json` output, `shipguard status`, and the facts file. */
export function bundledRulesMeta(): FreeBundleMeta {
  validateOnce()
  return {
    corpusVersion: raw.corpusVersion,
    contentHash: raw.contentHash,
    ruleCount: raw.ruleCount,
  }
}

/** Sorted rule IDs — used by the tarball verification test and by cli-facts. */
export function bundledRuleIds(): string[] {
  return loadBundledRules()
    .map((r) => r.id)
    .sort()
}
