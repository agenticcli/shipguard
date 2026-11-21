/**
 * screen-plan-lines.ts: the Free-to-Pro lines of the scan screen (spec 05), built from ONE verified plan block.
 *
 * HARD RULE: no plan fact lives here. Every number, plan name, area and the offer wording comes from
 * the server block (`PlanServerBlock`, W1a verifies it before it gets here). The words around a server
 * value are the CLI's own. With no data the lines say less, never more.
 *
 * Who decides WHETHER a line may show: the caller passes the facts (account, counters, channel); this
 * module applies the one rule set from spec 05 / 02 "Moments and bounds" and returns the lines.
 */

import type { AccountStatus, PlanServerBlock } from './plan-types.js'
import { stackDisplayName, realStacks } from './fix-guidance.js'

export interface PlanLineContext {
  /** Verified server block (account document or public offer), or null when none is available. */
  server: PlanServerBlock | null
  /** `PLAN_UNVERIFIED` etc. A failed verification shows no line at all. */
  planReason: string | null
  signedIn: boolean
  /** LAST verified account status; null = never verified. Kept after the document expired. */
  accountStatus: AccountStatus | null
  /** Detected framework names (lowercase). */
  stacks: readonly string[]
  /** The scan was complete (nothing unscanned). */
  complete: boolean
  blockingCount: number
  /** A plain general-rules run (the rulebook was not what ran). */
  plainGeneralRun: boolean
  /** The screen counter has not shown any Free-to-Pro line for this repo in the last 7 days. */
  counterAllowed: boolean
  muted: boolean
  quiet: boolean
  ci: boolean
  safeMode: boolean
  /** Interactive terminal (stdout is a TTY). */
  terminal: boolean
  /** 'gate' = a hook or gate pass: only the gap line's first line, never anything else. */
  surface: 'screen' | 'gate'
}

export type PlanLineKind = 'gap' | 'pointer' | 'coverage'

export interface PlanLines {
  kind: PlanLineKind | null
  lines: string[]
}

const NONE: PlanLines = { kind: null, lines: [] }

function stackText(stacks: readonly string[]): string {
  return stacks.map(stackDisplayName).join(' + ')
}

/** Account is signed out, or signed in with a last verified status of none or lapsed. */
function accountMayBePitched(ctx: PlanLineContext): boolean {
  if (!ctx.signedIn) return true
  return ctx.accountStatus === 'none' || ctx.accountStatus === 'lapsed'
}

export function planLines(ctx: PlanLineContext): PlanLines {
  if (ctx.muted || ctx.quiet || ctx.ci || ctx.safeMode || !ctx.counterAllowed) return NONE
  if (!accountMayBePitched(ctx)) return NONE
  if (ctx.planReason === 'PLAN_UNVERIFIED') return NONE
  if (!ctx.complete) return NONE
  const stacks = realStacks(ctx.stacks)
  if (stacks.length === 0) return NONE

  const proAdds = ctx.server?.proAdds ?? null
  const proStacks = (proAdds?.stacks ?? []).map((s) => s.toLowerCase())
  const covers = proAdds !== null && (proStacks.length === 0 || stacks.some((s) => proStacks.includes(s)))

  // Blocking scan: only the one coverage line, terminal only, never the gate.
  if (ctx.blockingCount > 0) {
    if (ctx.surface !== 'screen' || !ctx.terminal || !ctx.plainGeneralRun) return NONE
    return { kind: 'coverage', lines: [`Checks for ${stackText(stacks)} that did not run here: shipguard upgrade`] }
  }

  if (!ctx.plainGeneralRun) return NONE

  if (covers && proAdds) {
    const shownStacks = proStacks.length > 0 ? stacks.filter((s) => proStacks.includes(s)) : stacks
    const plan = proAdds.planName && proAdds.planName.length > 0 ? proAdds.planName : 'The full rulebook'
    const areas = proAdds.areas ?? []
    const first = areas.slice(0, 3)
    const areasText = first.join(', ') + (areas.length > 3 ? ', and more' : '')
    const s1 = areas.length > 0 ? `Not run here (checks, not problems found): ${areasText}. ` : ''
    const adds = proAdds.rules !== null && proAdds.rules !== undefined
      ? `${plan} adds ${proAdds.rules} rules for ${stackText(shownStacks)}`
      : `${plan} adds more rules for ${stackText(shownStacks)}`
    const tail = areas.length > 0 || (proAdds.rules !== null && proAdds.rules !== undefined)
      ? '; the general-rule results above stay as they are.'
      : '.'
    const lines = [`${s1}${adds}${tail}`]
    if (ctx.surface === 'screen') {
      const offer = ctx.server?.offer?.text
      lines.push(offer && offer.length > 0 ? `${offer}   Details: shipguard upgrade` : 'Details: shipguard upgrade')
    }
    return { kind: 'gap', lines }
  }

  // Pointer: no usable server data, number-free, names only what this scan detected. Screen only, same bounds as the gap line.
  if (ctx.surface !== 'screen') return NONE
  return {
    kind: 'pointer',
    lines: [
      `See what the full rulebook would add for ${stackText(stacks)} here (checks that did not run; no login, no code sent): shipguard upgrade`,
    ],
  }
}
