import { Command } from 'commander'
import { resolve } from 'node:path'
import { loadPolicy } from '../core/policy.js'
import { resolveHistoryPath, resolveRepoIdentity, HistoryStore } from '../core/history/index.js'
import { logger } from '../utils/logger.js'

declare const __SHIPGUARD_VERSION__: string | undefined
const CLI_VERSION =
  typeof __SHIPGUARD_VERSION__ !== 'undefined' ? __SHIPGUARD_VERSION__ : (process.env.npm_package_version ?? '0.0.0-dev')

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
      const openResult = await HistoryStore.open(historyPath, CLI_VERSION)

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
              scans,
            }, null, 2),
          )
          return
        }

        if (scans.length === 0) {
          logger.info(`No scan history yet for this repo at ${historyPath}. Run \`shipguard scan\` to start recording.`)
          return
        }

        logger.info(`Recent scans for this repo (${historyPath}):`)
        console.log('')
        for (const s of scans) {
          const ts = new Date(s.timestamp).toISOString()
          console.log(
            `  ${ts}  ${(s.recommendation ?? 'UNKNOWN').padEnd(18)}  blocking:${s.blockingCount}  state:${s.stateStatus}  scope:${s.scopeFingerprint}  corpus:${s.corpusVersion}  (${s.scanId})`,
          )
        }
        console.log('')
        logger.info('Full schema is documented and DIY-queryable: `sqlite3 ' + historyPath + '`.')
      } finally {
        store.close()
      }
    })
}
