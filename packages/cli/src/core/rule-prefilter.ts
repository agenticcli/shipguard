// Cheap "can this rule possibly match this file?" check that runs BEFORE the regex engine.
//
// WHY: re2js is linear-time but slow in absolute terms (about 90% of scan CPU). Most rules can only
// match a file that contains some fixed text (`createCipheriv`, `Access-Control-Allow-Origin`, ...).
// A plain `includes` on that text is orders of magnitude cheaper than running the regex over the file.
//
// THE ONE RULE: a rule is skipped only when it PROVABLY cannot match. Everything here is built so
// that "unsure" means "do not skip":
//   - the pattern is read by a small parser that understands only the plain RE2 constructs below; any
//     construct it does not fully understand (inline flags, \p{..}, \x.., \Q..\E, back-references,
//     odd braces, ...) makes the whole pattern "no prefilter" (the rule always runs);
//   - only text that every match MUST contain is kept ("required runs"); anything optional,
//     repeated, inside an alternation or a class is dropped, which only weakens the filter;
//   - a rule with several patterns is filtered only if EVERY pattern has a required run;
//   - with the `i` flag only plain ASCII runs are kept, and the content is folded the way RE2's
//     simple case folding folds it (lowercase, plus U+017F long s -> s; U+212A Kelvin already
//     lowercases to k). Folding may over-keep a file; it can never drop one that matches.
//
// This file is outside the frozen matcher-contract adapter on purpose: the adapter's hash is bound
// into published Pro bundles, so it must stay byte-identical.

/**
 * What every match of one top-level alternative must contain: ALL `runs` occur in the content, and
 * from each `ors` set AT LEAST ONE member occurs (e.g. `(?:exec|execSync)` gives {exec, execSync}).
 */
export type PrefilterBranch = {
  readonly runs: ReadonlyArray<string>
  readonly ors: ReadonlyArray<ReadonlyArray<string>>
}

/** The content may match only if it satisfies at least one branch. */
export type RulePrefilter = {
  readonly alts: ReadonlyArray<PrefilterBranch>
  /** True when the runs are lowercase ASCII and are searched in folded content. */
  readonly folded: boolean
}

class Unsure extends Error {}

const MAX_RUNS_PER_BRANCH = 2
const MAX_ORS_PER_BRANCH = 3
const MAX_OR_MEMBERS = 12

type Quant = { min: number; present: boolean }
type Branch = { runs: string[]; ors: string[][] }

const longest = (runs: string[]): string | undefined => runs.reduce<string | undefined>((a, b) => (a === undefined || b.length > a.length ? b : a), undefined)

/** Parse a quantifier right after an atom. Returns `present:false` when there is none. */
function parseQuant(src: string, pos: number): { q: Quant; pos: number } {
  const c = src[pos]
  let q: Quant = { min: 1, present: false }
  if (c === '*' || c === '?') {
    q = { min: 0, present: true }
    pos++
  } else if (c === '+') {
    q = { min: 1, present: true }
    pos++
  } else if (c === '{') {
    let j = pos + 1
    let digits = ''
    while (j < src.length && src[j] >= '0' && src[j] <= '9') digits += src[j++]
    if (digits === '') throw new Unsure()
    if (src[j] === ',') {
      j++
      while (j < src.length && src[j] >= '0' && src[j] <= '9') j++
    }
    if (src[j] !== '}') throw new Unsure()
    q = { min: Number(digits), present: true }
    pos = j + 1
  } else {
    return { q, pos }
  }
  if (src[pos] === '?') pos++ // lazy marker
  const n = src[pos]
  if (n === '*' || n === '+' || n === '?' || n === '{') throw new Unsure() // stacked quantifiers
  return { q, pos }
}

/** Skip a character class starting at `[`; returns the index after the closing `]`. */
function skipClass(src: string, start: number): number {
  let i = start + 1
  if (src[i] === '^') i++
  if (src[i] === ']') i++ // a leading ] is a literal
  while (i < src.length) {
    const c = src[i]
    if (c === '\\') {
      const n = src[i + 1]
      if (n === undefined || n === 'Q' || n === 'E') throw new Unsure()
      i += 2
      if ((n === 'p' || n === 'P' || n === 'x') && src[i] === '{') {
        const close = src.indexOf('}', i)
        if (close < 0) throw new Unsure()
        i = close + 1
      }
    } else if (c === '[' && src[i + 1] === ':') {
      const close = src.indexOf(':]', i + 2)
      if (close < 0) throw new Unsure()
      i = close + 2
    } else if (c === ']') {
      return i + 1
    } else {
      i++
    }
  }
  throw new Unsure()
}

const ESCAPE_LITERAL: Record<string, string> = { n: '\n', t: '\t', r: '\r', f: '\f', v: '\v' }

/**
 * Parse alternatives until the end of input or a `)`. Returns, per top-level branch, the runs of text
 * every match of that branch must contain. A branch with no run is returned as an empty list.
 */
function parseBranches(src: string, start: number, inGroup: boolean): { branches: Branch[]; pos: number } {
  const branches: Branch[] = []
  let runs: string[] = []
  let ors: string[][] = []
  let cur = ''
  const flush = (): void => {
    if (cur !== '') runs.push(cur)
    cur = ''
  }
  let pos = start
  while (pos < src.length) {
    const ch = src[pos]
    if (ch === '|') {
      flush()
      branches.push({ runs, ors })
      runs = []
      ors = []
      pos++
      continue
    }
    if (ch === ')') {
      if (!inGroup) throw new Unsure()
      break
    }
    if (ch === '(') {
      let p = pos + 1
      if (src[p] === '?') {
        if (src[p + 1] === ':') p += 2
        else if (src[p + 1] === 'P' && src[p + 2] === '<') p = nameEnd(src, p + 3)
        else if (src[p + 1] === '<' && src[p + 2] !== '=' && src[p + 2] !== '!') p = nameEnd(src, p + 2)
        else throw new Unsure() // inline flags, lookaround, comments: not understood
      }
      const inner = parseBranches(src, p, true)
      if (src[inner.pos] !== ')') throw new Unsure()
      const after = parseQuant(src, inner.pos + 1)
      flush()
      // A group counts only when it must occur at least once.
      if (after.q.min >= 1) {
        if (inner.branches.length === 1) {
          runs.push(...inner.branches[0].runs)
          ors.push(...inner.branches[0].ors)
        } else {
          // Alternation: one member of the set must occur, provided EVERY branch has a run to offer.
          const members = inner.branches.map((b) => longest(b.runs))
          if (members.every((m) => m !== undefined) && members.length <= MAX_OR_MEMBERS) {
            ors.push([...new Set(members as string[])])
          }
        }
      }
      pos = after.pos
      continue
    }
    if (ch === '*' || ch === '+' || ch === '?' || ch === '{' || ch === '}' || ch === ']') throw new Unsure()
    if (ch === '^' || ch === '$') {
      flush()
      pos++
      continue
    }
    if (ch === '.') {
      pos = parseQuant(src, pos + 1).pos
      flush()
      continue
    }
    if (ch === '[') {
      pos = parseQuant(src, skipClass(src, pos)).pos
      flush()
      continue
    }
    let literal: string | undefined
    let next: number
    if (ch === '\\') {
      const e = src[pos + 1]
      if (e === undefined) throw new Unsure()
      next = pos + 2
      if ('dDwWsS'.includes(e)) {
        pos = parseQuant(src, next).pos
        flush()
        continue
      }
      if ('bBAz'.includes(e)) {
        flush()
        pos = next
        continue
      }
      if (e in ESCAPE_LITERAL) literal = ESCAPE_LITERAL[e]
      else if (e.charCodeAt(0) < 128 && !/[A-Za-z0-9]/.test(e)) literal = e
      else throw new Unsure()
    } else {
      // A literal code point; keep a surrogate pair together so a quantifier covers both halves.
      const cp = src.codePointAt(pos) as number
      literal = String.fromCodePoint(cp)
      next = pos + literal.length
    }
    const after = parseQuant(src, next)
    if (after.q.min >= 1) cur += literal
    if (after.q.present || after.q.min < 1) flush()
    pos = after.pos
  }
  flush()
  branches.push({ runs, ors })
  return { branches, pos }
}

function nameEnd(src: string, from: number): number {
  const close = src.indexOf('>', from)
  if (close < 0) throw new Unsure()
  return close + 1
}

/** The branches of one pattern; undefined when any branch has nothing usable to require. */
function patternAlts(pattern: string, caseInsensitive: boolean): PrefilterBranch[] | undefined {
  let parsed: { branches: Branch[]; pos: number }
  try {
    parsed = parseBranches(pattern, 0, false)
  } catch (err) {
    if (err instanceof Unsure) return undefined
    throw err
  }
  if (parsed.pos !== pattern.length) return undefined
  const isAscii = (r: string): boolean => [...r].every((c) => c.charCodeAt(0) < 128)
  const out: PrefilterBranch[] = []
  for (const b of parsed.branches) {
    let runs = b.runs
    let ors = b.ors
    if (caseInsensitive) {
      // Only ASCII text is searched in folded content. A run that is not ASCII is dropped; so is a whole
      // or-set that has such a member (dropping one member would wrongly narrow the set). Both only
      // weaken the filter.
      runs = runs.filter(isAscii).map((r) => r.toLowerCase())
      ors = ors.filter((set) => set.every(isAscii)).map((set) => set.map((r) => r.toLowerCase()))
    }
    if (runs.length === 0 && ors.length === 0) return undefined
    // Longest runs are the most selective; a couple are plenty.
    out.push({
      runs: [...new Set(runs)].sort((x, y) => y.length - x.length).slice(0, MAX_RUNS_PER_BRANCH),
      ors: ors.slice(0, MAX_ORS_PER_BRANCH),
    })
  }
  return out
}

/**
 * Build the prefilter for a `pattern` rule: its patterns (any of them may produce a finding) and its
 * flag string. `undefined` means "no prefilter, always run the rule".
 */
export function buildPrefilter(patterns: readonly string[], flags: string): RulePrefilter | undefined {
  if (!Array.isArray(patterns) || patterns.length === 0) return undefined
  if (!patterns.every((p) => typeof p === 'string')) return undefined
  // parseFlags allows only i, m, s; refuse to reason about anything else.
  if (!/^[ims]*$/.test(flags)) return undefined
  const ci = flags.includes('i')
  const alts: PrefilterBranch[] = []
  for (const p of patterns) {
    const a = patternAlts(p, ci)
    if (a === undefined) return undefined
    alts.push(...a)
  }
  return { alts, folded: ci }
}

/** Fold content for a case-insensitive prefilter (see the header comment). */
export function foldContent(content: string): string {
  return content.toLowerCase().replaceAll('\u017f', 's')
}

/**
 * One file's text plus memoised "does it contain X" answers. Many rules ask about the same short
 * text (`(`, `req.`, `=`), so each distinct question scans the file once, not once per rule. The
 * folded copy is built only if a case-insensitive rule asks, and dies with the probe.
 */
export class FileProbe {
  private readonly raw = new Map<string, boolean>()
  private readonly fold = new Map<string, boolean>()
  private foldedText: string | undefined

  constructor(private readonly content: string) {}

  has(needle: string, folded: boolean): boolean {
    const memo = folded ? this.fold : this.raw
    let found = memo.get(needle)
    if (found === undefined) {
      const hay = folded ? (this.foldedText ??= foldContent(this.content)) : this.content
      found = hay.includes(needle)
      memo.set(needle, found)
    }
    return found
  }
}

/** True when the rule might match the file behind `probe`. */
export function mayMatch(pf: RulePrefilter, probe: FileProbe): boolean {
  for (const b of pf.alts) {
    if (b.runs.every((r) => probe.has(r, pf.folded)) && b.ors.every((set) => set.some((r) => probe.has(r, pf.folded)))) return true
  }
  return false
}

/** Test hook: lets a test run the same scan with the prefilter off to prove the findings are equal. */
export const prefilterControl = { enabled: true }
