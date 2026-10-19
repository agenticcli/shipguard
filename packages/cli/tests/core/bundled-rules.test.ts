/**
 * bundled-rules.test.ts — the offline free rule bundle is real, loadable, and complete.
 *
 * WHAT THIS GUARDS
 * ================
 * Until 2026-08-04 the CLI shipped ZERO rules from the governed corpus. The platform
 * product promised anonymous users "Bundled offline-free rules only
 * (bundleEligible: true)" and the CLI's free tier was instead 30 hand-written checks whose
 * IDs had no overlap with the corpus at all. Nothing failed, because nothing checked.
 *
 * These tests make the bundle's presence and integrity a hard, fast assertion: if the
 * vendored bundle goes missing, empties out, or changes shape, the suite goes red long
 * before anything is packed or published.
 */

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { RE2JS } from 're2js'
import { validateBundleCompile } from '../../src/core/pro-scanner.js'
import type { QualityGateRule } from '@agenticcli/shared'
import {
  loadBundledRules,
  bundledRulesMeta,
  bundledRuleIds,
  SUPPORTED_FREE_BUNDLE_SCHEMA_VERSION,
} from '../../src/core/bundled-rules.js'

const CLI_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const BUNDLE_PATH = join(CLI_DIR, 'rules', 'free-bundle.json')

describe('bundled rule set — it exists and it is not empty', () => {
  it('loads a non-empty set of corpus rules', () => {
    const rules = loadBundledRules()
    expect(rules.length).toBeGreaterThan(0)
  })

  it('reports provenance the user can check: corpus version + content hash', () => {
    const meta = bundledRulesMeta()
    expect(meta.corpusVersion).toBeGreaterThan(0)
    expect(meta.contentHash).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(meta.ruleCount).toBe(loadBundledRules().length)
  })

  it('agrees with the vendored file on disk (the copy that goes in the tarball)', () => {
    const onDisk = JSON.parse(readFileSync(BUNDLE_PATH, 'utf-8')) as {
      schemaVersion: number
      ruleCount: number
      contentHash: string
      rules: Array<{ id: string }>
    }
    expect(onDisk.schemaVersion).toBe(SUPPORTED_FREE_BUNDLE_SCHEMA_VERSION)
    expect(onDisk.contentHash).toBe(bundledRulesMeta().contentHash)
    expect(onDisk.rules.map((r) => r.id).sort()).toEqual(bundledRuleIds())
  })
})

describe('bundled rule set — every rule can actually run', () => {
  const rules = loadBundledRules()

  it('carries only free/local tier rules — never a paid rule', () => {
    for (const r of rules) {
      expect(['free', 'local'], `${r.id} tier`).toContain(r.tier)
    }
  })

  it('carries only matcher types the engine implements', () => {
    for (const r of rules) {
      expect(['pattern', 'file-presence', 'file-relationship']).toContain(r.matcher.type)
    }
  })

  it('every pattern compiles under re2js — the engine that will execute it', () => {
    for (const r of rules) {
      const flags = r.matcher.flags ?? ''
      const bits =
        (flags.includes('i') ? RE2JS.CASE_INSENSITIVE : 0) |
        (flags.includes('m') ? RE2JS.MULTILINE : 0) |
        (flags.includes('s') ? RE2JS.DOTALL : 0)
      for (const p of [...r.matcher.patterns, ...r.matcher.antiPatterns]) {
        expect(() => RE2JS.compile(p, bits), `${r.id}: ${p}`).not.toThrow()
      }
    }
  })

  it('carries the human text the report prints — no rule renders as a blank finding', () => {
    for (const r of rules) {
      expect(r.explanation.trim().length, `${r.id} explanation`).toBeGreaterThan(10)
      expect(r.recommendation.trim().length, `${r.id} recommendation`).toBeGreaterThan(10)
      expect(r.id).toMatch(/^[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+$/)
    }
  })

  it('emits only categories the CLI --json schema declares', () => {
    const categories = [
      'secrets', 'auth', 'payments', 'database', 'deployment',
      'injection', 'supply-chain', 'crypto', 'config',
    ]
    for (const r of rules) {
      expect(categories, `${r.id} category`).toContain(r.category)
    }
  })
})

describe('bundled rule set — the FX-11 gap is closed', () => {
  it('includes the debug-endpoint env-dump rule the benchmark found missing', () => {
    // content-pipeline/benchmarks/RESULTS.md recorded a debug endpoint returning the whole
    // process.env as missed by all four scanners, ShipGuard included.
    expect(bundledRuleIds()).toContain('generic.config.debug-endpoint-env-dump')
  })
})

describe('bundled rule set — a bundle that cannot compile fails loud, never quiet', () => {
  it('the real bundle passes the atomic compile check loadBundledRules() enforces', () => {
    expect(validateBundleCompile(loadBundledRules())).toEqual({ ok: true })
  })

  it('a bundle with an uncompilable pattern is rejected, not silently skipped', () => {
    // WHY THIS MATTERS: runProRules reacts to a compile failure by logging and returning [].
    // On the pro path a caller turns that into a `degraded` scan. On the offline path an empty
    // result is indistinguishable from "the code was clean" — so without an explicit check, a
    // broken bundle would hand the user a confident all-clear over zero corpus rules. That is
    // the exact silent-nothing failure this whole bundle exists to remove.
    const broken = [
      {
        ...loadBundledRules()[0],
        id: 'generic.test.broken-pattern',
        matcher: {
          type: 'pattern',
          fileGlob: '**/*.ts',
          patterns: ['(?<=lookbehind-is-not-RE2-compatible)'],
          antiPatterns: [],
          flags: '',
        },
      },
    ] as unknown as QualityGateRule[]
    const result = validateBundleCompile(broken)
    expect(result.ok).toBe(false)
  })
})
