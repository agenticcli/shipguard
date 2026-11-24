import { Command } from 'commander'
import { resolve } from 'node:path'
import { loadPolicy } from '../core/policy.js'
import { resolveHistoryPath, resolveRepoIdentity, HistoryStore } from '../core/history/index.js'
import { openHistoryStore } from '../core/history/store.js'
import { logger } from '../utils/logger.js'
import { VERDICT_WORDS } from '../core/verdict.js'
import type { Recommendation } from '@agenticcli/shared'

declare const __SHIPGUARD_VERSION__: string | undefined
const CLI_VERSION =
  typeof __SHIPGUARD_VERSION__ !== 'undefined' ? __SHIPGUARD_VERSION__ : (process.env.npm_package_version ?? '0.0.0-dev')

type HistoryRow = ReturnType<HistoryStore['listRecentScans']>[number]

/** Shorten a long target with a middle `...` (terminal only; `history --json` has the full value). */
function shortenMiddle(text: string, max: number): string {
  if (text.length <= max || max < 8) return text
  const keep = max - 3
  const head = Math.ceil(keep / 2)
  return `${text.slice(0, head)}...${text.slice(text.length - (keep - head))}`
}

/**
 * The history table: same names and order as the screen, identical piped; newest first.
 * Rows written before schema 4 show `-` for the facts they never kept.
 */
export function renderHistoryTable(scans: readonly HistoryRow[], columns?: number): string {
  const dash = '-'
  const rulesW = Math.max(10, 'RULES'.length, ...scans.map((s) => (s.rulesLabel ?? dash).length))
  const fixed = 8 + 2 + 16 + 2 + 18 + 2 + 8 + 2 + 8 + 2 + 10 + 2 + rulesW + 2
  const lines: string[] = []
  lines.push(
    ['RUN'.padEnd(8), 'WHEN (UTC)'.padEnd(16), 'VERDICT'.padEnd(18), 'BLOCKING'.padStart(8), 'FINDINGS'.padStart(8), 'INCOMPLETE'.padEnd(10), 'RULES'.padEnd(rulesW), 'TARGET'].join('  '),
  )
  for (const s of scans) {
    const when = new Date(s.timestamp).toISOString().slice(0, 16).replace('T', ' ')
    const verdict = s.recommendation ? (VERDICT_WORDS[s.recommendation as Recommendation] ?? s.recommendation) : 'UNKNOWN'
    let target = s.target ?? dash
    if (columns != null) target = shortenMiddle(target, Math.max(10, Math.min(100, Math.max(60, columns)) - fixed))
    lines.push(
      [
        s.scanId.replace(/[^A-Za-z0-9]/g, '').slice(0, 8).padEnd(8),
        when.padEnd(16),
        verdict.padEnd(18),
        String(s.blockingCount).padStart(8),
        String(s.findingCount).padStart(8),
        (s.incomplete === null ? dash : s.incomplete ? 'yes' : 'no').padEnd(10),
        (s.rulesLabel ?? dash).padEnd(rulesW),
        target,
      ].join('  '),
    )
  }
  return lines.join('\n')
}

/**
 * `shipguard history` — read-only view of the local audit-trail store (DIY-first: "the schema is the product's documented on-disk
 * FORMAT ... a user or their own agent is free to `sqlite3 .shipguard/history.db` and write
 * their own queries" — this command is a convenience view, not the only way in).
 * Informational only — never gates, never changes any exit code.
 */
export function historyCommand(): Command {
  return new Command('history')
    .description('Show recent local scan history for this repo (read-only; --json for machine output)')
    .argument('[path]', 'Path to project root (defaults to current directory)')
    .option('--json', 'Output as JSON')
    .option('--limit <n>', 'Number of recent scans to show', (v: string) => Number.parseInt(v, 10) || 10, 10)
    .action(async (scanPath: string | undefined, opts) => {
      const cwd = scanPath ? resolve(scanPath) : process.cwd()
      const machineOutput = Boolean(opts.json)
      const limit: number = opts.limit

      let policy
      try {
        policy = await loadPolicy(cwd)
      } catch (error) {
        logger.error(`Config error: ${error instanceof Error ? error.message : error}`)
        return
      }

      const identity = resolveRepoIdentity(cwd)
      const historyPath = resolveHistoryPath(cwd, policy)
      const openResult = await openHistoryStore(cwd, policy, CLI_VERSION)

      if (!openResult.ok) {
        if (machineOutput) {
          console.log(JSON.stringify({ version: 1, available: false, status: openResult.status, reason: openResult.reason }))
        } else {
          logger.warn(`History unavailable (${openResult.status}): ${openResult.reason}`)
          logger.info(
            openResult.reason.startsWith('node:sqlite is not available')
              ? 'No history to show: history cannot be recorded on this Node.js runtime, so every scan here skips it.'
              : 'No history to show. History is recorded automatically on the next successful scan.',
          )
        }
        return
      }

      const store = openResult.store
      try {
        const scans = store.listRecentScans(identity.repoId, limit)

        if (machineOutput) {
          console.log(
            JSON.stringify({
              version: 1,
              available: true,
              historyPath,
              repoId: identity.repoId,
              repoIdKind: identity.repoIdKind,
              // Old keys keep their meaning; the field-vocabulary names are added beside them.
              scans: scans.map((s) => ({
                ...s,
                runId: s.scanId,
                when: new Date(s.timestamp).toISOString(),
                verdict: s.recommendation,
                findings: s.findingCount,
                files: s.filesScanned,
                rules: s.rulesLabel,
              })),
            }, null, 2),
          )
          return
        }

        if (scans.length === 0) {
          logger.info(`No scan history yet for this repo at ${historyPath}. Run \`shipguard scan\` to start recording.`)
          return
        }

        console.log(renderHistoryTable(scans, process.stdout.isTTY ? (process.stdout.columns ?? 100) : undefined))
      } finally {
        store.close()
      }
    })
}
