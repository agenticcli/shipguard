import { Command } from 'commander'
import { clearCredentials } from '../core/auth.js'
import { logger } from '../utils/logger.js'

export function logoutCommand(): Command {
  return new Command('logout')
    .description('Remove stored credentials')
    .action(async () => {
      clearCredentials()
      logger.info('Logged out.')
    })
}
