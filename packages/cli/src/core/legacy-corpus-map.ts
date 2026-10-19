// Reconciliation between the CLI's hand-written check modules and the governed corpus.
//
// THE SITUATION THIS RESOLVES
// ===========================
// Until 2026-08-04 the CLI's free tier was 30 hand-written rules in src/checks/**, and
// the platform repo's governed corpus had 29 rules flagged `bundleEligible: true` that
// shipped nowhere. Now both run. Most of them cover different ground, but a few describe
// the SAME defect under two different IDs, and reporting one line of code twice — once as
// `hardcoded_secret`, once as `generic.secrets.openai-api-key` — is noise that makes the
// tool look broken.
//
// THE DECISION
// ===========================
//  1. Every legacy check is RETAINED. Deleting hand-written checks to "let the corpus win"
//     would be a straight detection regression: the corpus has no rule for a git-tracked
//     `.env`, for Dockerfile/compose/vercel/netlify config shapes, for Stripe webhook
//     signature verification, for destructive SQL in migrations, or for unguarded routes.
//     Those are 26 of the 30 legacy rules.
//  2. Where a legacy rule and a corpus rule fire on the SAME LINE of the SAME FILE, the
//     CORPUS finding wins and the legacy duplicate is dropped. The corpus rule is the
//     governed one: it is versioned, changelogged, ReDoS-proven by Gate B, fixture-certified
//     by Gate C, and it carries CWE/OWASP references the legacy check does not.
//  3. Dedup is CONSERVATIVE by construction. It only ever fires when BOTH rules already
//     matched the same line, so it can never remove a detection — if the corpus pattern is
//     narrower and misses, the legacy finding survives untouched. There is no case where
//     this function turns a reported issue into an unreported one.
//
// WHAT IS NOT DECIDED HERE
// ========================
// No legacy rule CONTRADICTS a corpus rule (one saying "safe" where the other says
// "unsafe") — every pair below is the same verdict under two names. If such a
// contradiction is ever found, it is a product decision, not a merge
// conflict to resolve in code: keep both findings and flag it.

import type { Finding } from '@agenticcli/shared'

/**
 * legacy rule id -> the corpus rule ids that describe the same defect.
 *
 * Derived by reading both sides, not guessed. Every entry is justified in the comment
 * above it, because an unexplained suppression is indistinguishable from a bug.
 */
export const LEGACY_TO_CORPUS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  // The legacy secrets check is one catch-all id covering ~15 provider patterns. The corpus
  // splits the same ground into one rule per provider, each with its own CWE + fix text. Same
  // line, same secret, better finding.
  hardcoded_secret: [
    'generic.secrets.anthropic-api-key',
    'generic.secrets.aws-access-key',
    'generic.secrets.azure-storage-key',
    'generic.secrets.db-connection-string',
    'generic.secrets.gcp-service-account-key',
    'generic.secrets.github-token',
    'generic.secrets.huggingface-token',
    'generic.secrets.openai-api-key',
    'generic.secrets.private-key-pem',
    'generic.secrets.slack-token',
    'generic.secrets.stripe-live-key',
  ],
  // Next.js headers() wildcard CORS — the corpus rule covers the same
  // `Access-Control-Allow-Origin: *` shape across every framework.
  deployment_cors_wildcard: ['generic.cors.wildcard-origin'],
  // `origin: '*'` in a cors() middleware config — same defect, same line.
  deployment_config_cors_wildcard_origin: ['generic.cors.wildcard-origin'],
  // `debug: true` in a config file.
  deployment_config_debug_mode: ['generic.config.debug-mode-enabled'],
})

/**
 * Legacy rule ids with NO corpus equivalent — retained, and recorded so the retention is a
 * documented decision rather than an oversight. Kept as data (not a comment) so a test can
 * assert that every legacy id is either mapped or explicitly listed here, and a newly-added
 * legacy rule that is neither will fail that test instead of slipping through unclassified.
 */
export const LEGACY_RETAINED_NO_CORPUS_EQUIVALENT: readonly string[] = Object.freeze([
  // secrets
  'exposed_env', // a .env file tracked by git — a repo-state fact no content regex can see
  // auth (the corpus has no route-authorization rules at all)
  'public_admin_route',
  'auth_route_without_guard',
  // database
  'db-drop-table',
  'db-drop-column',
  'db-truncate',
  'db-delete-without-where',
  'db-alter-drop',
  'db-push-in-scripts',
  'db-schema-without-migration',
  'pkg-json-unparseable-database',
  // payments
  'payment_webhook_without_signature_check',
  'missing_idempotency',
  'missing_error_handling',
  // deployment / IaC config shapes
  'deployment_source_maps_exposed',
  'deployment_missing_x_frame_options',
  'deployment_missing_x_content_type',
  'deployment_docker_root_user',
  'deployment_docker_unpinned_image',
  'deployment_compose_unpinned_image',
  'deployment_vercel_broad_rewrite',
  'deployment_vercel_missing_headers',
  'deployment_netlify_missing_headers',
  'deployment_missing_env_example',
  'deployment_env_undocumented_keys',
  'pkg-json-unparseable-deployment',
])

/**
 * Severity ordering, used ONLY to guarantee dedup can never soften a report.
 * Mirrors SEVERITY_ORDER in core/render.ts.
 */
const SEVERITY_RANK: Readonly<Record<string, number>> = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
})

/** A dropped duplicate, surfaced so the suppression is visible rather than silent. */
export interface DedupNote {
  legacyId: string
  corpusId: string
  file: string
  line: number
  /**
   * True when the legacy finding was ACTIVE and was dropped because its same-line corpus twin is
   * suppressed (the user acknowledged that line via the corpus id).
   */
  supersededBySuppressedTwin?: boolean
  /**
   * True when the dropped legacy finding was BLOCKING and the surviving corpus finding was not,
   * so the survivor was promoted to blocking (see guarantee 4 below). Never silent.
   */
  blockingPromoted?: boolean
  /** True when the surviving corpus finding was raised to the legacy finding's higher severity. */
  severityRaised?: boolean
}

/**
 * A duplicate that was KEPT because the legacy check rates the same defect MORE severely
 * than the corpus rule does. Surfaced so the disagreement becomes a visible governance
 * question instead of a silent downgrade.
 */
export interface SeverityDisagreement extends DedupNote {
  legacySeverity: string
  corpusSeverity: string
}

export interface DedupResult {
  findings: Finding[]
  /**
   * The corpus findings to report - the input list, with any survivor of a dedup promoted to
   * `blocking: true` when the legacy finding it superseded was blocking. New array; the input
   * findings are not mutated.
   */
  corpusFindings: Finding[]
  notes: DedupNote[]
  /** Same-line pairs where the legacy severity was strictly higher - folded at the higher severity, surfaced here. */
  severityDisagreements: SeverityDisagreement[]
}

/**
 * Drop legacy findings that a mapped corpus finding already reports on the same line.
 *
 * Pure: (legacyFindings, corpusFindings) -> findings. No I/O, no mutation of inputs.
 *
 * TWO GUARANTEES, both deliberate:
 *
 *  1. A legacy finding with no `line` is NEVER dropped. Without a line we cannot prove the
 *     two findings are about the same code, and dropping on a guess would lose a detection.
 *
 *  2. Suppression state is never lost, and never double-counted. A SUPPRESSED legacy finding is
 *     kept (applySuppressions RETAINS suppressed findings - counted and recorded, only marked
 *     non-blocking) UNLESS its same-line corpus twin is also suppressed: that is one
 *     acknowledged defect reported twice, and keeping both would double its weight in the
 *     risk score. A legacy finding is never dropped in favour of an ACTIVE-vs-SUPPRESSED
 *     swap that hides a live finding: an ACTIVE legacy finding is dropped for a SUPPRESSED
 *     corpus twin only because the user can only see (and so can only suppress) the corpus id;
 *     leaving the hidden legacy twin behind would resurrect the line as blocking. That drop
 *     carries a note (`supersededBySuppressedTwin`), never silent.
 *
 *     Note the honest consequence that remains: `// shipguard-ignore: hardcoded_secret` does
 *     not silence `generic.secrets.aws-access-key` on the same line. Suppression is per rule
 *     id by design, and this is what happens whenever a scanner gains rules.
 *
 *  3. A legacy finding is NEVER folded into a LESS severe corpus finding without raising it. "The
 *     corpus wins" is the right default — it is the governed, versioned, gate-certified
 *     rule — but silently replacing a `critical` with a `high` would quietly soften a
 *     report, and severity feeds the risk score and therefore the ship / do-not-ship
 *     verdict. This guarantee is what caught the two real disagreements the corpus used
 *     to carry (a hardcoded live Stripe key: legacy `critical` vs corpus `high`; a
 *     wildcard CORS origin: legacy `high` vs corpus `medium`) instead of silently
 *     softening either report. RESOLVED: the corpus rules were upgraded to match
 *     `generic.secrets.stripe-live-key` -> critical (v5), `generic.cors.wildcard-origin`
 *     -> high (v4) — so both pairs now agree and this branch only still matters as a
 *     structural guarantee against a FUTURE re-divergence, not because one exists today.
 *     Severity canon is a governance decision for the corpus owner, never
 *     something this dedup function should settle by silently picking the lower number.
 *
 *  4. Dedup never softens BLOCK/WARN behaviour either. Severity is not the whole story: the
 *     legacy CORS checks are `blocking: true` while the corpus rule is `action: warn`. The
 *     resolution changed only the corpus SEVERITY label, not whether the finding
 *     gates a ship, so dropping a blocking legacy finding in favour of a non-blocking corpus
 *     twin would turn `scan --strict` exit 1 into 0. When the dropped legacy finding blocks,
 *     the surviving corpus finding is promoted to `blocking: true` (`blocking = legacy ||
 *     corpus`; severity is already the higher, since equal/lower legacy is the only way to
 *     reach the drop) and the promotion is recorded on the DedupNote.
 */
export function dedupeLegacyAgainstCorpus(
  legacyFindings: Finding[],
  corpusFindings: Finding[],
  /**
   * Was this SUPPRESSED corpus finding suppressed by the USER (a `shipguard-ignore` comment) as
   * opposed to by the rule's own antiPattern exemption (`suppressed: true` too, e.g. an
   * `EXAMPLE` placeholder)? Only a user acknowledgement may retire the legacy twin: the legacy
   * checks have no such exemptions, so an antiPattern-suppressed corpus finding must NOT hide a
   * legacy detection. Defaults to "any suppressed corpus finding" for callers without file text.
   */
  isUserSuppressed: (corpusFinding: Finding) => boolean = (cf) => cf.suppressed === true,
): DedupResult {
  // (file, line) -> corpus findings reported there, by rule id
  const corpusIndex = new Map<string, Map<string, Finding>>()
  for (const f of corpusFindings) {
    if (f.line === undefined) continue
    const key = `${f.file} ${f.line}`
    let byId = corpusIndex.get(key)
    if (!byId) {
      byId = new Map<string, Finding>()
      corpusIndex.set(key, byId)
    }
    byId.set(f.id, f)
  }

  const promoted = new Map<Finding, { legacyId: string; blocking: boolean; severity?: string }>()
  const notes: DedupNote[] = []
  const severityDisagreements: SeverityDisagreement[] = []
  const kept: Finding[] = []

  for (const f of legacyFindings) {
    const mapped = LEGACY_TO_CORPUS[f.id]
    if (!mapped || f.line === undefined) {
      kept.push(f)
      continue
    }
    const atSameLine = corpusIndex.get(`${f.file} ${f.line}`)
    const twinIds = atSameLine ? mapped.filter((id) => atSameLine.has(id)) : []
    const activeTwin = twinIds.find((id) => !atSameLine!.get(id)!.suppressed)
    const suppressedTwin = twinIds.find((id) => {
      const cf = atSameLine!.get(id)!
      return cf.suppressed === true && isUserSuppressed(cf)
    })

    // Guarantee 2a — a suppressed legacy finding is user-acknowledged state; it is kept, EXCEPT
    // when the same-line corpus twin is ALSO suppressed: then the pair is one acknowledged defect
    // reported twice, and keeping both double-counts it in the risk score (2 x high = 60 =
    // DO_NOT_SHIP), so a fully-suppressed line would still fail `--strict`. The suppressed corpus
    // finding stays as the record of the acknowledgement.
    if (f.suppressed) {
      if (suppressedTwin !== undefined && activeTwin === undefined) {
        notes.push({ legacyId: f.id, corpusId: suppressedTwin, file: f.file, line: f.line })
      } else {
        kept.push(f)
      }
      continue
    }

    // Guarantee 2b — a suppressed corpus finding cannot make an ACTIVE legacy finding vanish
    // silently, but neither may it leave the legacy twin behind as a second, un-acknowledged copy.
    // The user only ever SEES the corpus id (the legacy twin is deduped away in the normal case),
    // so suppressing it is how they acknowledge the line; the hidden legacy twin must not reappear
    // as a blocking finding. It is dropped with a note (suppressedTwin), never silently.
    if (activeTwin === undefined) {
      if (suppressedTwin !== undefined) {
        notes.push({
          legacyId: f.id,
          corpusId: suppressedTwin,
          file: f.file,
          line: f.line,
          supersededBySuppressedTwin: true,
        })
      } else {
        kept.push(f)
      }
      continue
    }
    const winnerId = activeTwin

    const corpusFinding = atSameLine!.get(winnerId)!
    const legacyRank = SEVERITY_RANK[f.severity] ?? 0
    const corpusRank = SEVERITY_RANK[corpusFinding.severity] ?? 0

    // Legacy rates the SAME defect more severely. It used to be kept alongside the corpus finding, but
    // that reports ONE secret twice and double-counts it in the risk score (critical + high = 80 for
    // one PEM key). Fold instead: the corpus finding survives at the HIGHER severity (never softened),
    // the legacy duplicate is dropped, and the disagreement stays a visible governance warning
    // (severityDisagreements) plus a note in the finding text.
    const severityRaised = legacyRank > corpusRank
    if (severityRaised) {
      severityDisagreements.push({
        legacyId: f.id,
        corpusId: winnerId,
        file: f.file,
        line: f.line,
        legacySeverity: f.severity,
        corpusSeverity: corpusFinding.severity,
      })
    }
    const blockingPromoted = f.blocking === true && corpusFinding.blocking !== true
    if (severityRaised || blockingPromoted) {
      const prev = promoted.get(corpusFinding)
      const nextSeverity =
        severityRaised && (!prev?.severity || (SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[prev.severity] ?? 0))
          ? f.severity
          : prev?.severity
      promoted.set(corpusFinding, {
        legacyId: prev?.legacyId ?? f.id,
        blocking: blockingPromoted || prev?.blocking === true,
        severity: nextSeverity,
      })
    }
    notes.push({
      legacyId: f.id,
      corpusId: winnerId,
      file: f.file,
      line: f.line,
      ...(blockingPromoted ? { blockingPromoted: true } : {}),
      ...(severityRaised ? { severityRaised: true } : {}),
    })
  }

  const outCorpus = corpusFindings.map((cf) => {
    const p = promoted.get(cf)
    if (p === undefined) return cf
    const notesText: string[] = []
    if (p.severity) {
      notesText.push(
        `Severity raised from ${cf.severity} to ${p.severity} because the equivalent built-in check ` +
          `(${p.legacyId}) rates this defect ${p.severity}.`,
      )
    }
    if (p.blocking) {
      notesText.push(
        `Reported as BLOCKING because the equivalent built-in check (${p.legacyId}) blocks on this line; ` +
          `this rule's own action is warn.`,
      )
    }
    return {
      ...cf,
      ...(p.severity ? { severity: p.severity as Finding['severity'] } : {}),
      ...(p.blocking ? { blocking: true } : {}),
      explanation: `${cf.explanation}\n[shipguard] ${notesText.join(' ')}`,
    }
  })
  return { findings: kept, corpusFindings: outCorpus, notes, severityDisagreements }
}
