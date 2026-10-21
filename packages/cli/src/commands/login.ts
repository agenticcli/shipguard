import { Command } from 'commander'
import { saveCredentials } from '../core/auth.js'
import { logger } from '../utils/logger.js'
import { openUrl, parseOpenableUrl } from '../utils/open-url.js'
import { assertTrustedApiUrl } from '../utils/trust.js'

const DEFAULT_API_URL = 'https://agenticcli.dev'

export function loginCommand(): Command {
  return new Command('login')
    .description('Authenticate with ShipGuard for pro features')
    .option('--api-url <url>', 'API server URL', DEFAULT_API_URL)
    .action(async (opts) => {
      const apiUrl = opts.apiUrl
      assertTrustedApiUrl(apiUrl)
      const res = await fetch(`${apiUrl}/api/auth/device`, { method: 'POST' })
      if (!res.ok) { logger.error('Failed to start auth'); process.exit(2) }
      const { device_code, user_code, verification_uri, expires_in, interval } = await res.json()

      // verification_uri is server-supplied: never trust it. Show only a validated, normalised
      // URL, and open it without a shell (see utils/open-url.ts).
      const safeUrl = parseOpenableUrl(verification_uri, apiUrl)
      if (safeUrl) {
        logger.info(`\nVisit: ${safeUrl.href}`)
      } else {
        logger.warn('\nThe server sent a verification URL that is not a safe link to the ShipGuard server, so it was not opened or shown.')
        logger.info(`Open ${apiUrl}/auth/device in your browser yourself.`)
      }
      logger.info(`Enter code: ${String(user_code).replace(/[^\x20-\x7E]/g, '')}\n`)

      if (safeUrl) {
        openUrl(safeUrl.href, apiUrl, (err) => logger.warn(`Could not open a browser (${err.message}). Open the link above manually.`))
      }

      const deadline = Date.now() + expires_in * 1000
      const pollMs = (interval ?? 5) * 1000

      while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, pollMs))
        const tokenRes = await fetch(`${apiUrl}/api/auth/device/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ device_code, grant_type: 'urn:ietf:params:oauth:grant-type:device_code' }),
        })
        const tokenBody = await tokenRes.json()
        if (tokenRes.ok) {
          const { access_token, refresh_token, expires_in: ttl } = tokenBody
          await saveCredentials({
            accessToken: access_token,
            refreshToken: refresh_token,
            expiresAt: Date.now() + ttl * 1000,
            apiUrl,
          })
          logger.success('Authenticated successfully!')
          return
        }
        const { error } = tokenBody
        if (error === 'authorization_pending') continue
        if (error === 'slow_down') { await new Promise(r => setTimeout(r, 5000)); continue }
        logger.error(`Auth failed: ${error}`); process.exit(2)
      }
      logger.error('Auth timed out'); process.exit(2)
    })
}
