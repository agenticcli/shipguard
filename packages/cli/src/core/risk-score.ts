import type { Finding, RiskScore } from '@agenticcli/shared'
import { SEVERITY_WEIGHTS } from '@agenticcli/shared'
import { computeVerdict } from './verdict.js'

/**
 * DESIGN DECISION: suppressed findings do NOT count toward the risk score, the
 * severity counts, or the verdict - matching suppression.ts ("cannot fail a gate"). A suppressed
 * finding (a `shipguard-ignore` comment OR a rule's own antiPattern exemption) is still REPORTED
 * in `findings[]` (with `suppressed: true`) and still counted in `totalFindings`; the number of
 * suppressed findings is therefore `totalFindings - (critical+high+medium+low+info counts)`.
 * No new --json field is needed.
 */
export function computeRiskScore(findings: Finding[]): RiskScore {
  let rawScore = 0
  let criticalCount = 0
  let highCount = 0
  let mediumCount = 0
  let lowCount = 0
  let infoCount = 0
  let blockingCount = 0

  for (const finding of findings) {
    if (finding.suppressed === true) continue
    rawScore += SEVERITY_WEIGHTS[finding.severity] ?? 0

    switch (finding.severity) {
      case 'critical': criticalCount++; break
      case 'high':     highCount++;     break
      case 'medium':   mediumCount++;   break
      case 'low':      lowCount++;      break
      case 'info':     infoCount++;     break
    }

    if (finding.blocking) blockingCount++
  }

  const score = Math.min(100, rawScore)

  // Score-only verdict. The thresholds live in computeVerdict() and nowhere else
  // : this call knows
  // nothing about degradation because a RiskScore is a pure function of findings.
  // The degradation-aware, fail-closed verdict is stamped later by applyVerdict(),
  // which overwrites this field as a deliberate MIRROR of the top-level
  // `recommendation` — see core/verdict.ts.
  const recommendation: RiskScore['recommendation'] = computeVerdict({
    riskScore: { score },
    degraded: false,
  })

  return {
    score,
    recommendation,
    totalFindings: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount,
    blockingCount,
  }
}
