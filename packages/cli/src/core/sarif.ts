import { createHash } from 'node:crypto'
import type { Finding, ScanResult } from '@agenticcli/shared'

// SARIF 2.1.0 — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// Emitted by `shipguard scan --sarif` for GitHub Code Scanning interop.

const SARIF_SCHEMA = 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json'
const SARIF_VERSION = '2.1.0'

type SarifLevel = 'error' | 'warning' | 'note' | 'none'

const SEVERITY_TO_LEVEL: Record<Finding['severity'], SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
}

const SEVERITY_TO_SCORE: Record<Finding['severity'], number> = {
  critical: 9.0,
  high: 7.0,
  medium: 5.0,
  low: 3.0,
  info: 1.0,
}

/**
 * Build a stable SHA-256 fingerprint for a finding.
 * Keyed on id + file + line so duplicate suppressions are deterministic across runs.
 */
function fingerprint(finding: Finding): string {
  const line = finding.line ?? 1
  return createHash('sha256')
    .update(`${finding.id}:${finding.file}:${line}`)
    .digest('hex')
}

/**
 * Build SARIF tool.driver.rules[] by deduplicating findings by `id`.
 * First occurrence of each id wins for rule metadata (title, explanation, fix, cwe).
 */
function buildRules(findings: Finding[]): object[] {
  const seen = new Map<string, Finding>()
  for (const f of findings) {
    if (!seen.has(f.id)) {
      seen.set(f.id, f)
    }
  }

  return Array.from(seen.values()).map((f) => {
    const tags: string[] = [...(f.cwe ?? [])]

    return {
      id: f.id,
      shortDescription: { text: f.title },
      fullDescription: { text: f.explanation },
      ...(f.fix ? { help: { text: f.fix } } : {}),
      properties: {
        tags,
        'security-severity': SEVERITY_TO_SCORE[f.severity],
      },
    }
  })
}

/**
 * Build SARIF results[] — one entry per finding.
 */
function buildResults(findings: Finding[]): object[] {
  return findings.map((f) => {
    const startLine = f.line ?? 1
    return {
      ruleId: f.id,
      level: SEVERITY_TO_LEVEL[f.severity],
      message: { text: f.explanation },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: { startLine },
          },
        },
      ],
      partialFingerprints: {
        primary: fingerprint(f),
      },
    }
  })
}

export interface SarifRule {
  id: string
  shortDescription: { text: string }
  fullDescription: { text: string }
  help?: { text: string }
  properties: { tags: string[]; 'security-severity': number }
}

export interface SarifResultEntry {
  ruleId: string
  level: SarifLevel
  message: { text: string }
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string }
      region: { startLine: number }
    }
  }>
  partialFingerprints: { primary: string }
}

export interface SarifLog {
  $schema: string
  version: string
  runs: Array<{
    tool: { driver: { name: string; rules: SarifRule[] } }
    results: SarifResultEntry[]
  }>
}

/**
 * Convert a ScanResult to a SARIF 2.1.0 log object.
 * The caller is responsible for JSON serialization and stdout output.
 */
export function toSarif(result: ScanResult): SarifLog {
  const { findings } = result

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'shipguard',
            rules: buildRules(findings) as SarifRule[],
          },
        },
        results: buildResults(findings) as SarifResultEntry[],
      },
    ],
  }
}
