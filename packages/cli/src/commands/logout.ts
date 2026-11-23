import { Command } from 'commander'
import { clearCredentials } from '../core/auth.js'
import { forgetAccountState, getPlanEnv } from '../core/plan-client.js'
import { logger } from '../utils/logger.js'

export function logoutCommand(): Command {
  return new Command('logout')
    .description('Remove stored credentials')
    .action(async () => {
      clearCredentials()
      // The account cache and the hint belong to the account that just signed out.
      forgetAccountState(getPlanEnv())
      logger.info('Logged out.')
    })
}
