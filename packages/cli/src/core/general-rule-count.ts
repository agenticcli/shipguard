import { bundledRulesMeta } from './bundled-rules.js'
import { logger } from '../utils/logger.js'

/**
 * The number of bundled general rules, counted at run time (never typed in text). If the bundle cannot
 * be read the number is left out of the text (the line then says "general rules") and one warning is
 * logged: the scan itself would already have failed loudly on a broken bundle.
 */
export function generalRuleCountOrNull(): number | null {
  try {
    return bundledRulesMeta().ruleCount
  } catch (err) {
    logger.warn(`Could not count the bundled general rules (${err instanceof Error ? err.message : String(err)}); the count is left out of the output.`)
    return null
  }
}

