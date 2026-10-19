import { Command } from 'commander'
import { loadCredentials, isTokenExpired } from '../core/auth.js'
import { logger } from '../utils/logger.js'
import { assertTrustedApiUrl } from '../utils/trust.js'

export function statusCommand(): Command {
  return new Command('status')
    .description('Show authentication and account status')
    .action(async () => {
      const creds = loadCredentials()
      if (!creds) {
        logger.info('Not authenticated. Run `shipguard login` to get started.')
        return
      }

      const expired = isTokenExpired(creds)
      logger.info(`API: ${creds.apiUrl}`)
      logger.info(`Token: ${expired ? 'expired' : 'valid'} (expires ${new Date(creds.expiresAt).toISOString()})`)

      if (!expired) {
        try {
          assertTrustedApiUrl(creds.apiUrl)
          const res = await fetch(`${creds.apiUrl}/api/user/me`, {
            headers: { 'Authorization': `Bearer ${creds.accessToken}` },
          })
          if (res.ok) {
            const { email, plan, credits } = await res.json()
            logger.info(`Email: ${email}`)
            logger.info(`Plan: ${plan}`)
            logger.info(`Credits: ${credits}`)
          } else {
            logger.warn('Could not fetch account details (server returned non-OK)')
          }
        } catch {
          logger.warn('Could not fetch account details')
        }
      } else {
        logger.warn('Token is expired. Run `shipguard login` to re-authenticate.')
      }
    })
}
