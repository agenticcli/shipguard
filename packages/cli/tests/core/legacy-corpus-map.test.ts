/**
 * legacy-corpus-map.test.ts — reconciling the hand-written checks with the governed corpus.
 *
 * The rule: every legacy check is RETAINED; where a legacy check
 * and a corpus rule fire on the SAME line, the corpus finding wins. The two properties that
 * make this safe are the ones worth testing, because both are ways this could quietly break:
 *
 *   1. Dedup can never REMOVE a detection — it only fires when both already matched.
 *   2. Dedup can never LOWER a severity — a `critical` must not silently become a `high`,
 *      because severity feeds the risk score and therefore the ship / do-not-ship verdict.
 */

import { describe, it, expect } from 'vitest'
import type { Finding } from '@agenticcli/shared'
import {
  dedupeLegacyAgainstCorpus,
  LEGACY_TO_CORPUS,
  LEGACY_RETAINED_NO_CORPUS_EQUIVALENT,
} from '../../src/core/legacy-corpus-map.js'
import { bundledRuleIds } from '../../src/core/bundled-rules.js'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

function f(partial: Partial<Finding> & Pick<Finding, 'id' | 'file' | 'severity'>): Finding {
  return {
    title: 't',
    category: 'secrets',
    confidence: 'HIGH',
    explanation: 'e',
    recommendation: 'r',
    blocking: true,
    ...partial,
  } as Finding
}

describe('dedupe — the corpus wins on a same-line duplicate', () => {
  it('drops the legacy finding when a mapped corpus rule reports the same line', () => {
    const legacy = [f({ id: 'hardcoded_secret', file: 'src/a.js', line: 8, severity: 'high' })]
    const corpus = [f({ id: 'generic.secrets.aws-access-key', file: 'src/a.js', line: 8, severity: 'high' })]
    const r = dedupeLegacyAgainstCorpus(legacy, corpus)
    expect(r.findings).toHaveLength(0)
    expect(r.notes).toEqual([
      { legacyId: 'hardcoded_secret', corpusId: 'generic.secrets.aws-access-key', file: 'src/a.js', line: 8 },
    ])
  })

  it('keeps the legacy finding when the corpus rule fired on a DIFFERENT line', () => {
    const legacy = [f({ id: 'hardcoded_secret', file: 'src/a.js', line: 8, severity: 'high' })]
    const corpus = [f({ id: 'generic.secrets.aws-access-key', file: 'src/a.js', line: 40, severity: 'high' })]
    expect(dedupeLegacyAgainstCorpus(legacy, corpus).findings).toHaveLength(1)
  })

  it('keeps the legacy finding when the corpus rule fired in a DIFFERENT file', () => {
    const legacy = [f({ id: 'hardcoded_secret', file: 'src/a.js', line: 8, severity: 'high' })]
    const corpus = [f({ id: 'generic.secrets.aws-access-key', file: 'src/b.js', line: 8, severity: 'high' })]
    expect(dedupeLegacyAgainstCorpus(legacy, corpus).findings).toHaveLength(1)
  })

  it('keeps a legacy finding that has NO line — we cannot prove it is the same code', () => {
    const legacy = [f({ id: 'hardcoded_secret', file: 'src/a.js', severity: 'high' })]
    const corpus = [f({ id: 'generic.secrets.aws-access-key', file: 'src/a.js', line: 8, severity: 'high' })]
    expect(dedupeLegacyAgainstCorpus(legacy, corpus).findings).toHaveLength(1)
  })

  it('keeps an UNMAPPED legacy finding even on an identical line', () => {
    const legacy = [f({ id: 'exposed_env', file: 'src/a.js', line: 8, severity: 'high' })]
    const corpus = [f({ id: 'generic.secrets.aws-access-key', file: 'src/a.js', line: 8, severity: 'high' })]
    expect(dedupeLegacyAgainstCorpus(legacy, corpus).findings).toHaveLength(1)
  })

  it('never drops a corpus finding — corpus findings are not this function s input to filter', () => {
    const corpus = [f({ id: 'generic.secrets.aws-access-key', file: 'src/a.js', line: 8, severity: 'high' })]
    const r = dedupeLegacyAgainstCorpus([], corpus)
    expect(r.findings).toEqual([])
    expect(r.notes).toEqual([])
  })
})

describe('dedupe — suppression state survives in both directions', () => {
  it('never drops a SUPPRESSED legacy finding — that is user-acknowledged state', () => {
    // applySuppressions deliberately RETAINS suppressed findings (counted and recorded, only
    // marked non-blocking). Deleting one here would erase the record that the user
    // acknowledged this line, and would break `// shipguard-ignore: hardcoded_secret`.
    const legacy = [
      f({ id: 'hardcoded_secret', file: 'a.js', line: 1, severity: 'high', suppressed: true, blocking: false }),
    ]
    const corpus = [f({ id: 'generic.secrets.aws-access-key', file: 'a.js', line: 1, severity: 'high' })]
    const r = dedupeLegacyAgainstCorpus(legacy, corpus)
    expect(r.findings).toHaveLength(1)
    expect(r.findings[0].suppressed).toBe(true)
    expect(r.notes).toHaveLength(0)
  })

  it('an ACTIVE legacy finding is dropped (with a note) when its corpus twin is SUPPRESSED - the user can only see/suppress the corpus id', () => {
    const legacy = [f({ id: 'hardcoded_secret', file: 'a.js', line: 1, severity: 'high' })]
    const corpus = [
      f({ id: 'generic.secrets.aws-access-key', file: 'a.js', line: 1, severity: 'high', suppressed: true, blocking: false }),
    ]
    const r = dedupeLegacyAgainstCorpus(legacy, corpus)
    expect(r.findings).toHaveLength(0)
    expect(r.notes[0].supersededBySuppressedTwin).toBe(true)
    expect(r.corpusFindings).toHaveLength(1)
  })

  it('a corpus finding suppressed by the rule antiPattern (NOT the user) does not retire an ACTIVE legacy finding', () => {
    // Legacy checks have no antiPattern exemptions; dropping them here would silently lose a detection.
    const legacy = [f({ id: 'hardcoded_secret', file: 'a.js', line: 1, severity: 'high' })]
    const corpus = [
      f({ id: 'generic.secrets.aws-access-key', file: 'a.js', line: 1, severity: 'high', suppressed: true, blocking: false }),
    ]
    const r = dedupeLegacyAgainstCorpus(legacy, corpus, () => false)
    expect(r.findings).toHaveLength(1)
    expect(r.findings[0].blocking).toBe(true)
    expect(r.notes).toHaveLength(0)
  })

  it('an ACTIVE corpus twin keeps winning even if another mapped corpus id on the line is suppressed', () => {
    const legacy = [f({ id: 'hardcoded_secret', file: 'a.js', line: 1, severity: 'high' })]
    const corpus = [
      f({ id: 'generic.secrets.aws-access-key', file: 'a.js', line: 1, severity: 'high', suppressed: true, blocking: false }),
      f({ id: 'generic.secrets.openai-api-key', file: 'a.js', line: 1, severity: 'high' }),
    ]
    const r = dedupeLegacyAgainstCorpus(legacy, corpus)
    expect(r.findings).toHaveLength(0)
    expect(r.notes[0].corpusId).toBe('generic.secrets.openai-api-key')
    expect(r.notes[0].supersededBySuppressedTwin).toBeUndefined()
  })

  it('drops a SUPPRESSED legacy duplicate when the corpus twin is ALSO suppressed (no double count)', () => {
    const legacy = [f({ id: 'hardcoded_secret', file: 'a.js', line: 1, severity: 'high', suppressed: true, blocking: false })]
    const corpus = [
      f({ id: 'generic.secrets.aws-access-key', file: 'a.js', line: 1, severity: 'high', suppressed: true, blocking: false }),
    ]
    const r = dedupeLegacyAgainstCorpus(legacy, corpus)
    expect(r.findings).toHaveLength(0)
    expect(r.corpusFindings).toHaveLength(1)
  })

  it('still dedupes when BOTH are active', () => {
    const legacy = [f({ id: 'hardcoded_secret', file: 'a.js', line: 1, severity: 'high' })]
    const corpus = [f({ id: 'generic.secrets.aws-access-key', file: 'a.js', line: 1, severity: 'high' })]
    expect(dedupeLegacyAgainstCorpus(legacy, corpus).findings).toHaveLength(0)
  })
})

describe('dedupe — it can never soften a report', () => {
  it('folds into ONE finding at the HIGHER severity when the legacy check rates the defect higher', () => {
    // Real case: a PEM private key is `critical` to the legacy secrets check and `high` in the corpus.
    // Keeping both reported one secret twice (80 points); dropping legacy silently would lower severity.
    const legacy = [f({ id: 'hardcoded_secret', file: 'src/pay.js', line: 5, severity: 'critical' })]
    const corpus = [f({ id: 'generic.secrets.private-key-pem', file: 'src/pay.js', line: 5, severity: 'high' })]
    const r = dedupeLegacyAgainstCorpus(legacy, corpus)
    expect(r.findings).toHaveLength(0)
    expect(r.corpusFindings).toHaveLength(1)
    expect(r.corpusFindings[0].severity).toBe('critical')
    expect(r.corpusFindings[0].explanation).toContain('Severity raised from high to critical')
    expect(corpus[0].severity).toBe('high') // input not mutated
    expect(r.notes[0].severityRaised).toBe(true)
    expect(r.severityDisagreements).toEqual([
      {
        legacyId: 'hardcoded_secret',
        corpusId: 'generic.secrets.private-key-pem',
        file: 'src/pay.js',
        line: 5,
        legacySeverity: 'critical',
        corpusSeverity: 'high',
      },
    ])
  })

  it('drops the legacy finding when the corpus rates it HIGHER (no severity is lost)', () => {
    const legacy = [f({ id: 'deployment_config_debug_mode', file: 'cfg.js', line: 3, severity: 'medium' })]
    const corpus = [f({ id: 'generic.config.debug-mode-enabled', file: 'cfg.js', line: 3, severity: 'high' })]
    const r = dedupeLegacyAgainstCorpus(legacy, corpus)
    expect(r.findings).toHaveLength(0)
    expect(r.severityDisagreements).toHaveLength(0)
  })

  it('the highest severity present before dedup is still present after, always', () => {
    const legacy = [
      f({ id: 'hardcoded_secret', file: 'a.js', line: 1, severity: 'critical' }),
      f({ id: 'deployment_cors_wildcard', file: 'a.js', line: 2, severity: 'high' }),
      f({ id: 'deployment_config_debug_mode', file: 'a.js', line: 3, severity: 'medium' }),
    ]
    const corpus = [
      f({ id: 'generic.secrets.stripe-live-key', file: 'a.js', line: 1, severity: 'high' }),
      f({ id: 'generic.cors.wildcard-origin', file: 'a.js', line: 2, severity: 'medium' }),
      f({ id: 'generic.config.debug-mode-enabled', file: 'a.js', line: 3, severity: 'high' }),
    ]
    const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
    const before = Math.max(...[...legacy, ...corpus].map((x) => rank[x.severity]))
    const r = dedupeLegacyAgainstCorpus(legacy, corpus)
    const after = Math.max(...[...r.findings, ...r.corpusFindings].map((x) => rank[x.severity]))
    expect(after).toBe(before)
  })
})

describe('dedupe — it can never soften BLOCK behaviour either', () => {
  it('promotes the surviving corpus finding to blocking when the dropped legacy one blocked', () => {
    const legacy = [f({ id: 'deployment_config_cors_wildcard_origin', file: 'a.ts', line: 3, severity: 'high', blocking: true })]
    const corpus = [f({ id: 'generic.cors.wildcard-origin', file: 'a.ts', line: 3, severity: 'high', blocking: false })]
    const r = dedupeLegacyAgainstCorpus(legacy, corpus)
    expect(r.findings).toHaveLength(0)
    expect(r.corpusFindings).toHaveLength(1)
    expect(r.corpusFindings[0].blocking).toBe(true)
    expect(r.corpusFindings[0].severity).toBe('high')
    // the promotion is visible in the finding text itself (no schema change)
    expect(r.corpusFindings[0].explanation).toContain('BLOCKING because the equivalent built-in check (deployment_config_cors_wildcard_origin)')
    expect(r.notes[0].blockingPromoted).toBe(true)
    // input is not mutated
    expect(corpus[0].blocking).toBe(false)
  })

  it('does not promote when the legacy finding was non-blocking, or the corpus one already blocks', () => {
    const c = () => [f({ id: 'generic.cors.wildcard-origin', file: 'a.ts', line: 3, severity: 'high', blocking: false })]
    const l = (blocking: boolean) => [f({ id: 'deployment_config_cors_wildcard_origin', file: 'a.ts', line: 3, severity: 'high', blocking })]
    expect(dedupeLegacyAgainstCorpus(l(false), c()).corpusFindings[0].blocking).toBe(false)
    const both = dedupeLegacyAgainstCorpus(l(true), [{ ...c()[0], blocking: true }])
    expect(both.notes[0].blockingPromoted).toBeUndefined()
  })
})

describe('the reconciliation is complete — no legacy rule is left unclassified', () => {
  // cli-facts.json's freeRuleIds is derived from the check-module SOURCE by
  // gen-cli-facts.mjs, so this compares the map against the real rule set rather than
  // against a second hand-written list that could drift with it.
  const factsPath = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'cli-facts.json')
  const legacyIds = (
    JSON.parse(readFileSync(factsPath, 'utf-8')) as { freeRuleIds: string[] }
  ).freeRuleIds

  it('every legacy rule is either mapped to a corpus rule or explicitly retained', () => {
    const classified = new Set([
      ...Object.keys(LEGACY_TO_CORPUS),
      ...LEGACY_RETAINED_NO_CORPUS_EQUIVALENT,
    ])
    const unclassified = legacyIds.filter((id) => !classified.has(id))
    expect(unclassified, 'add these to LEGACY_TO_CORPUS or LEGACY_RETAINED_NO_CORPUS_EQUIVALENT').toEqual([])
  })

  it('the map never points at a corpus rule that is not actually bundled', () => {
    const bundled = new Set(bundledRuleIds())
    for (const [legacyId, corpusIds] of Object.entries(LEGACY_TO_CORPUS)) {
      for (const cid of corpusIds) {
        expect(bundled.has(cid), `${legacyId} -> ${cid} is not in the bundle`).toBe(true)
      }
    }
  })

  it('a rule is never both mapped and listed as having no equivalent', () => {
    for (const id of LEGACY_RETAINED_NO_CORPUS_EQUIVALENT) {
      expect(LEGACY_TO_CORPUS[id], `${id} is in both lists`).toBeUndefined()
    }
  })
})
