import { Command } from 'commander'
import { saveCredentials } from '../core/auth.js'
import { logger } from '../utils/logger.js'
import { openUrl, parseOpenableUrl } from '../utils/open-url.js'
import { assertTrustedApiUrl } from '../utils/trust.js'
import { CLI_VERSION, sendLifecycleEvent } from '../core/telemetry.js'
import { buildErrorEnvelope } from '../core/outcome.js'
import type { ErrorCode } from '../core/outcome.js'
import { emitError } from '../utils/exit.js'
import { forgetAccountState, getPlanEnv, lastScanHere, planEnvelope, readPlanFresh } from '../core/plan-client.js'
import type { FreshPlan } from '../core/plan-client.js'
import { decideRecommendation, planJson, receiptNote, usageNote } from '../core/plan-lines.js'
import { hasPaidPlan } from '../core/plan.js'

const DEFAULT_API_URL = 'https://agenticcli.dev'
/** The server's poll `interval` is clamped: never a busy loop, never a wait longer than a minute. */
const POLL_MIN_SECONDS = 5
const POLL_MAX_SECONDS = 60
const CREDENTIALS_NOTE = 'Credentials saved in ~/.config/shipguard/ (readable only by you).'

type Poll =
  | { kind: 'approved'; body: { access_token: string; refresh_token: string; expires_in: number } }
  | { kind: 'pending' }
  | { kind: 'slow' }
  | { kind: 'expired' }
  | { kind: 'failed'; why: string }

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

/** One poll of the device-code token endpoint. A network or service problem is `failed`, never a timeout. */
async function pollOnce(apiUrl: string, deviceCode: string): Promise<Poll> {
  let res: Response
  try {
    res = await fetch(`${apiUrl}/api/auth/device/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_code: deviceCode, grant_type: 'urn:ietf:params:oauth:grant-type:device_code' }),
    })
  } catch (err) {
    return { kind: 'failed', why: err instanceof Error ? err.message : String(err) }
  }
  let body: Record<string, unknown>
  try {
    body = (await res.json()) as Record<string, unknown>
  } catch (err) {
    return { kind: 'failed', why: `the account service sent an unreadable answer (${err instanceof Error ? err.message : String(err)})` }
  }
  if (res.ok) {
    const { access_token, refresh_token, expires_in } = body
    if (typeof access_token === 'string' && typeof refresh_token === 'string' && typeof expires_in === 'number') {
      return { kind: 'approved', body: { access_token, refresh_token, expires_in } }
    }
    return { kind: 'failed', why: 'the account service approved the sign-in but sent no usable token' }
  }
  const error = body.error
  if (error === 'authorization_pending') return { kind: 'pending' }
  if (error === 'slow_down') return { kind: 'slow' }
  if (error === 'expired_token') return { kind: 'expired' }
  return { kind: 'failed', why: typeof error === 'string' ? `the account service answered "${error}"` : `the account service answered HTTP ${res.status}` }
}

function fail(code: ErrorCode, message: string, opts: { json: boolean; cause?: string; fix?: string }): void {
  emitError(buildErrorEnvelope({
    code, message, cliVersion: CLI_VERSION,
    ...(opts.cause ? { cause: opts.cause } : {}),
    ...(opts.fix ? { fix: opts.fix } : {}),
  }), { machine: opts.json })
}

/** What the account service said about the plan after sign-in: the success lines. */
function successLines(fresh: FreshPlan, scanCommand: string): string[] {
  const p = fresh.plan
  const head = '✓ Signed in.'
  if (p.reason === 'PLAN_UNVERIFIED') return [`${head} Plan details could not be verified, so none are shown. ${CREDENTIALS_NOTE}`, 'Next: shipguard scan']
  if (p.status === 'unavailable' || p.server === null) return [`${head} Plan details are not available right now. ${CREDENTIALS_NOTE}`, 'Next: shipguard scan']
  const status = p.server.account?.status ?? null
  if (hasPaidPlan(status)) {
    const name = p.server.label
    return [`${head} ${name ? `Plan: ${name}.` : 'This account has an active plan.'} ${CREDENTIALS_NOTE}`, 'Next: shipguard scan']
  }
  if (status === 'none' || status === 'lapsed') {
    const text = p.server.account?.text
    const start = p.link
      ? `Next: start checkout ${p.link} (on the page, sign in with the same account${text ? `; ${text}` : ''})   then: ${scanCommand}`
      : 'Next: shipguard scan'
    return [`${head} ${status === 'lapsed' ? 'Your plan is no longer active.' : 'No active plan on this account yet.'} ${CREDENTIALS_NOTE}`, start]
  }
  if (status === 'pending') return [`${head} Payment not confirmed yet. ${CREDENTIALS_NOTE}`, 'Next: check again in a minute: shipguard status']
  return [`${head} ${CREDENTIALS_NOTE}`, 'Next: shipguard scan']
}

export function loginCommand(): Command {
  return new Command('login')
    .description('Sign in to run rulebook scans with the full current rulebook')
    .option('--api-url <url>', 'API server URL', DEFAULT_API_URL)
    .option('--json', 'Machine-readable output (errors as the error envelope; success as the status envelope)')
    .action(async (opts: { apiUrl: string; json?: boolean }) => {
      const apiUrl = opts.apiUrl
      const json = Boolean(opts.json)
      try {
        assertTrustedApiUrl(apiUrl)
      } catch (err) {
        return fail('LOGIN_START_FAILED', `could not start sign-in (${err instanceof Error ? err.message : String(err)}).`, { json })
      }

      let started: { device_code: string; user_code: string; verification_uri: string; expires_in: number; interval?: number }
      try {
        const res = await fetch(`${apiUrl}/api/auth/device`, { method: 'POST' })
        if (!res.ok) return fail('LOGIN_START_FAILED', `could not start sign-in (the account service answered HTTP ${res.status}).`, { json })
        started = (await res.json()) as typeof started
      } catch (err) {
        return fail('LOGIN_START_FAILED', `could not start sign-in (${err instanceof Error ? err.message : String(err)}).`, { json })
      }
      const { device_code, user_code, verification_uri } = started
      const expiresIn = typeof started.expires_in === 'number' && started.expires_in > 0 ? started.expires_in : 600
      const deadline = Date.now() + expiresIn * 1000
      let pollMs = Math.min(POLL_MAX_SECONDS, Math.max(POLL_MIN_SECONDS, started.interval ?? POLL_MIN_SECONDS)) * 1000

      // verification_uri is server-supplied: never trust it. Show only a validated, normalised URL, and open it
      // without a shell (see utils/open-url.ts).
      const safeUrl = parseOpenableUrl(verification_uri, apiUrl)
      const expiresAtUtc = new Date(deadline).toISOString().slice(11, 16)
      if (safeUrl) {
        logger.info(`Open this page and approve the sign-in:  ${safeUrl.href}`)
      } else {
        logger.warn('The server sent a verification URL that is not a safe link to the ShipGuard server, so it was not opened or shown.')
        logger.info(`Open ${apiUrl}/auth/device in your browser yourself.`)
      }
      logger.info(`Code: ${String(user_code).replace(/[^\x20-\x7E]/g, '')}  (expires in ${Math.round(expiresIn / 60)} min, at ${expiresAtUtc} UTC)`)
      logger.info('Waiting for approval in the browser...')
      if (safeUrl) {
        openUrl(safeUrl.href, apiUrl, (err) => logger.warn(`Could not open a browser (${err.message}). Open the link above manually.`))
      }

      // The timeout is decided only when the deadline has passed AND one final poll saw no approval (a poll that
      // lands just before the deadline must never be reported as a timeout). A poll error is LOGIN_CONFIRM_FAILED.
      let lastNote = Date.now()
      // Ctrl-C while waiting is LOGIN_CANCELLED (exit 130), not a crash and not a timeout. Removed again on every way out.
      let onSigint: () => void = () => {}
      const cancelled = new Promise<true>((resolve) => { onSigint = () => resolve(true); process.once('SIGINT', onSigint) })
      const cancel = (): void => {
        fail('LOGIN_CANCELLED', 'sign-in stopped.', { json, fix: 'sign in again when you are ready.' })
        // The poll timer is still pending: leave promptly once the message is out (unref: never keeps the process alive).
        setTimeout(() => process.exit(130), 200).unref()
      }
      try {
      for (;;) {
        if (await Promise.race([sleep(Math.min(pollMs, Math.max(deadline - Date.now(), 0))).then(() => false), cancelled])) return cancel()
        const polled = await Promise.race([pollOnce(apiUrl, device_code), cancelled])
        if (polled === true) return cancel()
        const r = polled
        if (r.kind === 'approved') {
          const env = getPlanEnv()
          forgetAccountState(env) // nothing cached about a previous account may linger
          await saveCredentials({
            accessToken: r.body.access_token,
            refreshToken: r.body.refresh_token,
            expiresAt: Date.now() + r.body.expires_in * 1000,
            apiUrl,
          })
          // Success is printed only after the token is stored AND checked with the account service (a fresh plan read).
          const fresh = await readPlanFresh(apiUrl, env)
          if (fresh.authRejected) {
            return fail('LOGIN_CONFIRM_FAILED', 'the browser approval was received but ShipGuard could not confirm it with the account service.', {
              json, cause: 'the account service did not accept the new sign-in. Your approval is not lost.',
            })
          }
          if (json) {
            const recommendation = decideRecommendation({
              plan: fresh.plan, signedIn: true, accountStatus: fresh.accountStatus, detected: [], rulesApplied: 0,
              scanComplete: true, blocking: false, fallbackActive: false, ci: false, hookOrGate: false, safeMode: false, muted: false, recentlyShown: false,
            })
            const plan = planJson({
              plan: fresh.plan, recommendation,
              usageNote: usageNote(fresh.plan, { quietContext: false, jsonDue: true }),
              receiptNote: receiptNote({ receipt: null, plan: fresh.plan, quietContext: false, jsonDue: false }),
            })
            console.log(JSON.stringify(planEnvelope(CLI_VERSION, plan, { signedIn: true }), null, 2))
          } else {
            const lines = successLines(fresh, (await lastScanHere(process.cwd()))?.scanCommand ?? 'shipguard scan')
            logger.success(lines[0].replace(/^✓ /, ''))
            for (const line of lines.slice(1)) console.error(line)
          }
          // Fire-and-forget lifecycle ping; bounded, never rejects, honours every opt-out.
          await sendLifecycleEvent('cli_login', { cliVersion: CLI_VERSION }, { projectDir: process.cwd() })
          return
        }
        if (r.kind === 'expired') {
          return fail('LOGIN_EXPIRED', 'the sign-in code expired before it was approved (10 min).', { json, fix: 'start a new sign-in and approve it within 10 minutes.' })
        }
        if (r.kind === 'failed') {
          return fail('LOGIN_CONFIRM_FAILED', 'the browser approval was received but ShipGuard could not confirm it with the account service.', {
            json, cause: `${r.why}. Your approval is not lost.`,
          })
        }
        if (r.kind === 'slow') pollMs = Math.min(POLL_MAX_SECONDS * 1000, pollMs + 5000)
        if (Date.now() >= deadline) {
          return fail('LOGIN_EXPIRED', 'the sign-in code expired before it was approved (10 min).', { json, fix: 'start a new sign-in and approve it within 10 minutes.' })
        }
        // A piped run prints a line every 30 s; a terminal keeps the single waiting line.
        if (Date.now() - lastNote >= 30_000) {
          lastNote = Date.now()
          logger.info(`Still waiting (${Math.max(0, Math.round((deadline - Date.now()) / 60000))} min left). Wrong browser? Open the link above yourself.`)
        }
      }
      } finally {
        process.removeListener('SIGINT', onSigint)
      }
    })
}
