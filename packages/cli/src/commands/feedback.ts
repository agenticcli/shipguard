import { Command } from 'commander';
import { getAuthToken, loadCredentials } from '../core/auth.js';
import { logger } from '../utils/logger.js';
import { assertTrustedApiUrl } from '../utils/trust.js';

const ISSUES_URL = 'https://github.com/agenticcli/shipguard/issues';

/**
 * `shipguard feedback` makes NO network call. It used to POST free text to `{apiUrl}/api/feedback`,
 * a route that does not exist on prod (404), behind a login round-trip. Feedback now goes through
 * the repo's public issue tracker, so the user sees exactly where it goes.
 * The optional [text] argument is accepted (old invocations keep working) and deliberately never
 * sent, stored or echoed.
 */
export function feedbackCommand(): Command {
  return new Command('feedback')
    .description('Tell us what you think: prints where to send feedback (no network call)')
    .argument('[text]', 'Ignored. Feedback is not sent from the CLI; open an issue instead')
    .action(() => {
      logger.info(`Feedback and bug reports go to GitHub issues: ${ISSUES_URL}`);
      logger.info('The CLI does not send your feedback anywhere itself.');
    });
}

export function rateCommand(): Command {
  return new Command('rate')
    .description('Rate a finding from your last scan')
    .argument('<findingNumber>', 'Finding number from scan output')
    .argument('<rating>', 'Rating: "helpful" or "not-helpful"')
    .action(async (findingNumber: string, rating: string) => {
      const num = parseInt(findingNumber, 10);
      if (isNaN(num) || num < 1) {
        logger.error('Finding number must be a positive integer.');
        return;
      }

      const ratingValue = rating === 'helpful' ? 1 : rating === 'not-helpful' ? -1 : null;
      if (ratingValue === null) {
        logger.error('Rating must be "helpful" or "not-helpful".');
        return;
      }

      let token: string;
      try {
        // getAuthToken now exchanges a raw SHIPGUARD_API_KEY for an
        // access token and THROWS a distinct error on exchange failure — never a
        // silent null.
        const t = await getAuthToken();
        if (!t) {
          logger.error('Not authenticated. Run `shipguard login` first.');
          return;
        }
        token = t;
      } catch (err) {
        logger.error(`Authentication failed: ${err instanceof Error ? err.message : String(err)}`);
        return;
      }

      const creds = loadCredentials();
      if (!creds) {
        logger.error('No credentials found. Run `shipguard login` first.');
        return;
      }

      try {
        assertTrustedApiUrl(creds.apiUrl);
        const res = await fetch(`${creds.apiUrl}/api/feedback`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            findingIndex: num - 1,
            rating: ratingValue,
          }),
        });

        if (!res.ok) {
          logger.error(`Rating submission failed: ${res.statusText}`);
          return;
        }

        logger.success(`Finding #${num} rated as ${rating}`);
      } catch (err) {
        logger.error(`Failed to send rating: ${err instanceof Error ? err.message : String(err)}`);
      }
    });
}
