import { Command } from 'commander'
import { CLI_VERSION } from '../core/telemetry.js'
import { decideRecommendation, planJson, receiptNote, statusLines, usageNote } from '../core/plan-lines.js'
import { DEFAULT_API_URL, generalRuleCount, getPlanEnv, lastScanHere, planEnvelope, readPlanFresh } from '../core/plan-client.js'
import { gateHealthLines, gateHealthWarnings, healthWarningLine } from '../core/gate-state.js'
import { logger } from '../utils/logger.js'

/**
 * `shipguard status` (spec 05): sign-in, plan and usage exactly as the server reports them, from ONE fresh signed read
 * (never the cache first); a verified cached copy is shown only when the live read failed. It says nothing about which
 * rules the next scan will use: the server decides that during the scan. No plan fact lives here.
 */
export function statusCommand(): Command {
  return new Command('status')
    .description('Sign-in, plan and usage, as the server reports them')
    .option('--json', 'Machine-readable output (the same envelope as upgrade --json)')
    .option('--api-url <url>', 'API server URL', DEFAULT_API_URL)
    .action(async (opts: { json?: boolean; apiUrl: string }) => {
      const env = getPlanEnv({ projectDir: process.cwd() })
      const fresh = await readPlanFresh(opts.apiUrl, env)
      const lastScan = await lastScanHere(process.cwd())
      const general = generalRuleCount()

      if (opts.json) {
        const recommendation = decideRecommendation({
          plan: fresh.plan, signedIn: fresh.signIn === 'signed-in', accountStatus: fresh.accountStatus, detected: [], rulesApplied: general,
          scanComplete: true, blocking: false, fallbackActive: false, ci: false, hookOrGate: false, safeMode: false, muted: false, recentlyShown: false,
        })
        const plan = planJson({
          plan: fresh.plan, recommendation,
          usageNote: usageNote(fresh.plan, { quietContext: false, jsonDue: true }),
          receiptNote: receiptNote({ receipt: null, plan: fresh.plan, quietContext: false, jsonDue: false }),
        })
        console.log(JSON.stringify(planEnvelope(CLI_VERSION, plan, {
          signedIn: fresh.signIn === 'signed-in',
          warnings: gateHealthWarnings(process.cwd()).map((w) => ({ code: w.code, message: w.message, command: w.command })),
          lastScan: lastScan ? { runId: lastScan.runId, corpus: lastScan.corpus, applied: lastScan.applied, at: lastScan.at } : null,
        }), null, 2))
        return
      }

      const lines = statusLines({
        auth: fresh.signIn,
        expiredAt: fresh.expiresAt !== undefined ? new Date(fresh.expiresAt).toISOString() : null,
        plan: fresh.plan,
        generalCount: general,
        lastScan,
        ...(lastScan ? { scanCommand: lastScan.scanCommand } : {}),
      })
      for (const line of lines) console.log(line)
      // Gate health (spec 07): what is installed here, when the gate last ran, how strong it is; the warnings go to stderr.
      for (const line of gateHealthLines(process.cwd())) console.log(line)
      for (const w of gateHealthWarnings(process.cwd())) process.stderr.write(`${healthWarningLine(w)}\n`)
      if (fresh.retryAfterSeconds !== undefined && fresh.failure !== null) {
        logger.info(`The service asked for a wait before the next try (${fresh.retryAfterSeconds} s).`)
      }
    })
}
