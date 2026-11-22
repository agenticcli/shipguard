import { Command } from 'commander'
import { CLI_VERSION } from '../core/telemetry.js'
import { loadCredentials } from '../core/auth.js'
import {
  planJson, receiptNote, upgradeLines, upgradePath, upgradeRecommendation, usageNote, type UpgradeInput,
} from '../core/plan-lines.js'
import {
  DEFAULT_API_URL, detectedStacks, generalRuleCount, getPlanEnv, lastScanHere, loadNagFor, nagCtx, planEnvelope, readPlanFresh,
} from '../core/plan-client.js'
import { fetchPublicOffer, normalizeStacks, readOffer } from '../core/offer-cache.js'
import { isMuted, setMuted } from '../core/nag.js'
import { unavailableBlock } from '../core/plan.js'
import type { AccountStatus, PlanBlock } from '../core/plan-types.js'
import { openUrl } from '../utils/open-url.js'
import { logger } from '../utils/logger.js'

/**
 * `shipguard upgrade` (spec 05): what a plan would add for THIS repo, as checks that did not run, then the steps to
 * start it. Read-only except ~/.config/shipguard. It prints and exits 0: a missing or unverified plan block is not an
 * error. Every number, name and sentence about a plan comes from the verified server block; the CLI has none of its own.
 * `--dry-run` prints the request without sending it; `--mute` / `--unmute` silence or restore promotion on the scan screen.
 */
export function upgradeCommand(): Command {
  return new Command('upgrade')
    .description('What a plan would add for this repo and how to start it')
    .option('--json', 'Machine-readable output (the same envelope as status --json, plus path)')
    .option('--open', 'Open the checkout link in a browser')
    .option('--dry-run', 'Show the request that would be sent, without sending it')
    .option('--mute', 'Stop the Free-to-Pro lines on the scan screen')
    .option('--unmute', 'Show the Free-to-Pro lines again')
    .option('--api-url <url>', 'API server URL', DEFAULT_API_URL)
    .action(async (opts: { json?: boolean; open?: boolean; dryRun?: boolean; mute?: boolean; unmute?: boolean; apiUrl: string }) => {
      const cwd = process.cwd()
      const env = getPlanEnv({ projectDir: cwd })

      if (opts.mute || opts.unmute) {
        const wrote = setMuted(nagCtx(env), Boolean(opts.mute))
        if (!wrote) {
          logger.warn('Nothing was saved (safe mode, API-key mode or an unwritable ~/.config/shipguard). For one session set SHIPGUARD_NO_PROMO=1.')
        } else {
          console.log(opts.mute ? 'Promotion is muted: the scan screen no longer shows Free-to-Pro lines. Restore: shipguard upgrade --unmute' : 'Promotion is on again.')
        }
        return
      }

      const detected = detectedStacks(cwd)
      const stackNames = normalizeStacks(detected.map((d) => d.key))

      if (opts.dryRun) {
        // The one request this command would make, named in full: nothing is sent.
        if (env.apiKeyMode || loadCredentials() !== null) {
          console.log(`Would read your account and plan: GET ${opts.apiUrl}/api/user/me with your sign-in, the CLI version and a random nonce (no code, no paths, no file names).`)
        } else {
          console.log(`Would ask the rulebook service for the public offer: GET ${opts.apiUrl}/api/cli/v1/offer${stackNames.length > 0 ? `?stacks=${stackNames.join(',')}` : ''}`)
          console.log(`Asked for: ${stackNames.length > 0 ? stackNames.join(', ') : 'nothing stack-specific'} (framework names only, no code, no paths, no sign-in).`)
        }
        console.log('Nothing was sent.')
        return
      }

      // One fresh read: the account document when signed in; the public offer for these framework names when not.
      let plan: PlanBlock
      let signedIn = false
      let accountStatus: AccountStatus | null = null
      const fresh = await readPlanFresh(opts.apiUrl, env)
      if (fresh.signIn === 'signed-in') {
        signedIn = true
        plan = fresh.plan
        accountStatus = fresh.accountStatus
      } else {
        const fetched = await fetchPublicOffer({
          configDir: env.configDir, now: env.now, stacks: stackNames.length > 0 ? stackNames : null, safeMode: env.safeMode, apiUrl: opts.apiUrl,
        })
        if (fetched.ok) {
          plan = fetched.block
        } else {
          const cached = await readOffer({ configDir: env.configDir, now: env.now, safeMode: env.safeMode }, stackNames)
          plan = cached.block.status === 'cached' ? cached.block : unavailableBlock(fetched.reason)
        }
      }

      const last = await lastScanHere(cwd)
      const input: UpgradeInput = { plan, signedIn, accountStatus, detected, generalCount: generalRuleCount(), hasHistory: last !== null, ...(last ? { scanCommand: last.scanCommand } : {}) }

      if (opts.json) {
        const planOut = planJson({
          plan,
          recommendation: upgradeRecommendation(input),
          usageNote: usageNote(plan, { quietContext: false, jsonDue: true }),
          receiptNote: receiptNote({ receipt: null, plan, quietContext: false, jsonDue: false }),
        })
        console.log(JSON.stringify(planEnvelope(CLI_VERSION, planOut, { path: upgradePath(input) }), null, 2))
      } else {
        for (const line of upgradeLines(input)) console.log(line)
        if (isMuted(loadNagFor(env))) console.log('(Free-to-Pro lines on the scan screen are muted: shipguard upgrade --unmute)')
      }

      if (opts.open) {
        if (plan.link) openUrl(plan.link, opts.apiUrl, (err) => logger.warn(`Could not open a browser (${err.message}). Open the link above manually.`))
        else logger.info('There is no checkout link to open right now.')
      }
    })
}
