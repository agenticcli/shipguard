import { Command } from 'commander'
import { createPolicyFile, createShipguardDir } from '../core/policy.js'
import { logger } from '../utils/logger.js'

export function initCommand(): Command {
  return new Command('init')
    .description('Initialize ShipGuard in your project')
    .action(async () => {
      try {
        const policyCreated = await createPolicyFile(process.cwd())
        await createShipguardDir(process.cwd())
        if (policyCreated) {
          logger.success('ShipGuard initialized')
          logger.info('Created shipguard.policy.yml')
          logger.info('Run: shipguard scan')
        } else {
          logger.warn('shipguard.policy.yml already exists, skipping')
          logger.info('Run: shipguard scan')
        }
      } catch (error) {
        logger.error(`Init failed: ${error instanceof Error ? error.message : error}`)
        process.exit(3)
      }
    })
}
