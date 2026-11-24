/** rules-ran.ts: the `Rules ran:` line and fallback sentences (spec 05). Pure; imports nothing heavy. */

/** What rules ran in this scan (the `Rules ran:` line and the fallback sentence under the header). */
export type RulesRan =
  | { kind: 'general' }
  | { kind: 'rulebook'; label?: string | null; count: number }
  | { kind: 'partial'; count: number }
  | { kind: 'fallback'; code: 'RULEBOOK_WITHHELD' | 'RULEBOOK_UNREACHABLE' | 'PLAN_INACTIVE'; serverText?: string | null }

export function generalRulesText(n: number | null): string {
  return n === null ? 'general rules' : `${n} general rules`
}

/** The `Rules ran:` line (spec 05) and, for a fallback, the sentence that goes under the header. */
export function rulesRanLines(r: RulesRan | undefined, generalRuleCount: number | null, terminal = true): { runSentence: string | null; line: string } {
  const n = generalRulesText(generalRuleCount)
  if (!r || r.kind === 'general') return { runSentence: null, line: `Rules ran: ${n} (Free).` }
  if (r.kind === 'rulebook') {
    const who = r.label && r.label.length > 0 ? `${r.label} rulebook` : 'full rulebook'
    return { runSentence: null, line: `Rules ran: ${who}, ${r.count} rules.` }
  }
  if (r.kind === 'partial') {
    return {
      runSentence: 'Only part of the rulebook was provided; the verdict covers the rules that ran.',
      line: `Rules ran: ${r.count} rules (part of the rulebook).`,
    }
  }
  const line = `Rules ran: ${n} (full rulebook not used).`
  if (r.code === 'RULEBOOK_UNREACHABLE') {
    return {
      runSentence: 'Rulebook could not be reached. This scan ran general rules only; it is not a full rulebook scan. Retry when you are online.',
      line,
    }
  }
  if (r.code === 'PLAN_INACTIVE') {
    // Terminal only; hooks, the gate, CI and --quiet print just the Rules ran line.
    return {
      runSentence: terminal
        ? `${r.serverText && r.serverText.length > 0 ? r.serverText : 'Your plan is no longer active.'} This scan ran general rules only; the verdict covers those rules only.`
        : null,
      line,
    }
  }
  return {
    runSentence: `${r.serverText && r.serverText.length > 0 ? r.serverText : 'The rulebook was not provided for this scan.'} This scan ran general rules only; the verdict covers those rules only.`,
    line,
  }
}

