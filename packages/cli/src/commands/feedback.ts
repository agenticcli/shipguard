import { Command } from 'commander';
import { logger } from '../utils/logger.js';

const ISSUES_URL = 'https://github.com/agenticcli/shipguard/issues';

/**
 * `shipguard feedback` makes NO network call. It used to POST free text to `{apiUrl}/api/feedback`,
 * a route that does not exist on prod (404), behind a login round-trip. Feedback now goes through
 * the repo's public issue tracker, so the user sees exactly where it goes.
 * The optional [text] argument is accepted (old invocations keep working) and deliberately never
 * sent, stored or echoed.
 * `shipguard rate` is the same: it used to POST a rating to the same missing route and now only
 * prints where to send feedback. The arguments are accepted and never sent, stored or echoed.
 */
function printWhereToSend(): void {
  logger.info(`Feedback and bug reports go to GitHub issues: ${ISSUES_URL}`);
  logger.info('The CLI does not send your feedback anywhere itself.');
}

export function feedbackCommand(): Command {
  return new Command('feedback')
    .description('Tell us what you think: prints where to send feedback (no network call)')
    .argument('[text]', 'Ignored. Feedback is not sent from the CLI; open an issue instead')
    .action(printWhereToSend);
}

export function rateCommand(): Command {
  return new Command('rate')
    .description('Rate a finding: prints where to send feedback (no network call)')
    .argument('[findingNumber]', 'Ignored. Ratings are not sent from the CLI')
    .argument('[rating]', 'Ignored. Ratings are not sent from the CLI')
    .action(printWhereToSend);
}
