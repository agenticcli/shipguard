import { Command } from 'commander'
import { EXIT_CODES } from '@agenticcli/shared'
import { logger } from '../utils/logger.js'
import {
  decideTelemetry,
  detectCi,
  getProvenance,
  resolveEndpoint,
  type TelemetryDecision,
} from '../core/telemetry.js'
import { configFilePath, getConfigDir, noticeShown, readInstallId, resetInstallId, writeUserEnabled } from '../core/telemetry-config.js'

const DOCS = 'https://agenticcli.dev/docs#telemetry'

const SOURCE_TEXT: Record<TelemetryDecision['source'], string> = {
  'env:SHIPGUARD_TELEMETRY': 'SHIPGUARD_TELEMETRY=0 is set in the environment',
  'env:DO_NOT_TRACK': 'DO_NOT_TRACK=1 is set in the environment',
  'user-config': 'turned off with `shipguard telemetry disable`',
  'project-policy': '`telemetry.enabled: false` in shipguard.policy.yml or .shipguard.yml',
  default: 'default (on)',
}


/**
 * `shipguard telemetry status|enable|disable` — the pseudonymous usage ping (what it sends: see
 * src/core/telemetry.ts). `reset` forgets the local install id.
 */
export function telemetryCommand(): Command {
  const cmd = new Command('telemetry').description(
    'Show or change the pseudonymous usage ping (status, enable, disable, reset)',
  )

  cmd
    .command('status')
    .description('Show whether usage pings are on, why, and where they would go')
    .option('--json', 'Machine-readable output')
    .action(async (o: { json?: boolean }) => {
      const decision = decideTelemetry({ projectDir: process.cwd() })
      const provenance = getProvenance()
      const endpoint = resolveEndpoint()
      const installId = readInstallId() ?? null
      const info = {
        version: 2,
        enabled: decision.enabled,
        source: decision.source,
        provenance,
        endpoint,
        noticeShown: noticeShown(),
        installIdPresent: installId !== null,
        installId,
        ci: detectCi(),
        configFile: configFilePath(),
        optOut: ['SHIPGUARD_TELEMETRY=0', 'DO_NOT_TRACK=1', 'shipguard telemetry disable'],
      }
      if (o.json) {
        console.log(JSON.stringify(info, null, 2))
        return
      }
      console.log(`Usage pings: ${decision.enabled ? 'ON' : 'OFF'} (${SOURCE_TEXT[decision.source]})`)
      console.log(
        `Build:       ${provenance}` +
          (provenance === 'dev' ? ' (a dev build never pings production; only a loopback SHIPGUARD_TELEMETRY_URL)' : ''),
      )
      console.log(`Endpoint:    ${endpoint ?? 'none'}`)
      console.log(
        `Install id:  ${installId ?? 'none yet'}` +
          (installId ? '' : ' (a random id is made on the first ping outside CI)') +
          (detectCi() ? ' (CI detected: no install id is created or sent)' : ''),
      )
      console.log(`Sends:       after each scan: CLI version, verdict, duration bucket, CI flag, build type, install id (null in CI). Plus one first-run and one login event (no verdict). Never code, paths, repo names or your account.`)
      console.log(`Turn off:    SHIPGUARD_TELEMETRY=0 | DO_NOT_TRACK=1 | shipguard telemetry disable`)
      console.log(`Inspect:     SHIPGUARD_TELEMETRY_DEBUG=1 shipguard scan   (prints the exact payload, sends nothing)`)
      console.log(`Details:     ${DOCS}`)
    })

  for (const [name, enabled] of [['enable', true], ['disable', false]] as const) {
    cmd
      .command(name)
      .description(enabled ? 'Turn usage pings on for this user' : 'Turn usage pings off for this user')
      .action(() => {
        try {
          const file = writeUserEnabled(getConfigDir(), enabled)
          console.log(`Usage pings ${enabled ? 'enabled' : 'disabled'} for this user (${file}).`)
        } catch (err) {
          logger.error(`Could not save the setting: ${err instanceof Error ? err.message : String(err)}`)
          process.exitCode = EXIT_CODES.RUNTIME_ERROR
          return
        }
        // Say so when something stronger still wins, so the command never looks like it did nothing.
        const decision = decideTelemetry({ projectDir: process.cwd() })
        if (enabled && !decision.enabled) {
          logger.warn(`Pings stay OFF: ${SOURCE_TEXT[decision.source]}.`)
        }
      })
  }

  cmd
    .command('reset')
    .description('Forget the local install id (a new random one is made on the next ping)')
    .action(() => {
      try {
        const { hadId, oldId } = resetInstallId(getConfigDir())
        console.log(hadId ? 'Install id deleted. A new random one is made on the next ping.' : 'No install id was stored. Nothing to reset.')
        if (oldId) console.log(`Old install id: ${oldId}`)
        console.log(
          'Pings already sent stay on the server under the old id. Past events can be deleted on request' +
            (oldId ? ': quote the old install id above.' : '.') +
            ` Retention and deletion: ${DOCS}`,
        )
      } catch (err) {
        logger.error(`Could not reset the install id: ${err instanceof Error ? err.message : String(err)}`)
        process.exitCode = EXIT_CODES.RUNTIME_ERROR
      }
    })

  // Nested commands do not inherit exitOverride(): without it a typo would exit 1, not the CLI's 2.
  for (const sub of cmd.commands) sub.exitOverride()
  return cmd
}
