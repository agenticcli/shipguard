import { describe, expect, it } from 'vitest'
import { RE2JS } from 're2js'
import { buildPrefilter, foldContent, mayMatch, type RulePrefilter } from '../../src/core/rule-prefilter.js'

const pf = (patterns: string[], flags = ''): RulePrefilter | undefined => buildPrefilter(patterns, flags)
const passes = (f: RulePrefilter, content: string): boolean => mayMatch(f, content, foldContent(content))

describe('buildPrefilter: what is required', () => {
  it('keeps the text every match must contain', () => {
    expect(pf(['createCipheriv\\s*\\(\\s*[\'"]des[\'"]'])!.alts).toEqual([{ runs: ['createCipheriv', 'des'], ors: [] }])
    expect(pf(['Access-Control-Allow-Origin[^\\n]{0,40}req'])!.alts[0].runs).toEqual(['Access-Control-Allow-Origin', 'req'])
  })

  it('drops optional and repeated parts but keeps one required copy', () => {
    // "ab?c": b is optional so "abc" is NOT required; a and c are.
    expect(pf(['xab?cy'])!.alts[0].runs.sort()).toEqual(['cy', 'xa'].sort())
    // "ab+c": at least one b, but "abbc" has no "abc"
    expect(pf(['xab+cy'])!.alts[0].runs.sort()).toEqual(['cy', 'xab'].sort())
    // "(?:abc)*" is optional, "(?:abc)+" is required
    expect(pf(['(?:abc)*zzz'])!.alts[0].runs).toEqual(['zzz'])
    expect(pf(['(?:abc)+z'])!.alts[0].runs.sort()).toEqual(['abc', 'z'].sort())
    expect(pf(['a{0}bcd'])!.alts[0].runs).toEqual(['bcd'])
  })

  it('treats alternation of groups as an or-set and top-level alternation as separate branches', () => {
    expect(pf(['(?:exec|execSync)\\s*\\('])!.alts).toEqual([{ runs: ['('], ors: [['exec', 'execSync']] }])
    expect(pf(['(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}'])!.alts).toEqual([{ runs: [], ors: [['A3T', 'AKIA', 'ASIA']] }])
    expect(pf(['foo|barbaz'])!.alts).toEqual([
      { runs: ['foo'], ors: [] },
      { runs: ['barbaz'], ors: [] },
    ])
  })

  it('a rule is filtered only when EVERY pattern and EVERY branch has something to require', () => {
    expect(pf(['foo', '[A-Z]{20}'])).toBeUndefined()
    expect(pf(['foo|[a-z]+'])).toBeUndefined()
    expect(pf(['(?:a|b)*zzz', '\\d+'])).toBeUndefined()
    expect(pf(['foo|'])).toBeUndefined()
    expect(pf([])).toBeUndefined()
  })

  it('refuses anything it does not fully understand', () => {
    for (const p of [
      '(?i)abc', '(?i:abc)def', '(?s:.)abc', '(?=abc)abc', '(?<!x)abc', '(?#c)abc',
      '\\p{L}abc', '\\pLabc', '\\x41abc', '\\x{41}abc', '\\Qa.b\\Eabc', '\\1abc', '\\Zabc', '\\Cabc',
      'abc{', 'abc{x}', 'abc{,3}', 'a}bc', 'a]bc', '{abc', '*abc', 'abc**', 'abc+*', 'ab(c', 'ab)c', 'a[bc',
      '\\é',
    ]) {
      expect(pf([p]), p).toBeUndefined()
    }
  })

  it('unknown flags disable the filter', () => {
    expect(pf(['abc'], 'g')).toBeUndefined()
    expect(pf(['abc'], 'x')).toBeUndefined()
    expect(pf(['abc'], 'ims')).toBeDefined()
  })

  it('reads escapes, classes and named groups', () => {
    expect(pf(['foo\\.bar\\(\\)'])!.alts[0].runs).toEqual(['foo.bar()'])
    expect(pf(['a\\_b\\-c\\ d'])!.alts[0].runs).toEqual(['a_b-c d'])
    expect(pf(['x[^\\]a]yz[]q]end'])!.alts[0].runs.sort()).toEqual(['end', 'yz'].sort())
    expect(pf(['x[[:alpha:]]ymn'])!.alts[0].runs.sort()).toEqual(['x', 'ymn'].sort())
    expect(pf(['(?P<n>foo)bar'])!.alts[0].runs.sort()).toEqual(['bar', 'foo'].sort())
    expect(pf(['(?<n>foo)bar'])!.alts[0].runs.sort()).toEqual(['bar', 'foo'].sort())
    expect(pf(['\\bword\\b'])!.alts[0].runs).toEqual(['word'])
    expect(pf(['tab\\there'])!.alts[0].runs).toEqual(['tab\there'])
  })

  it('keeps a surrogate pair together under a quantifier', () => {
    const f = pf(['x😀+yy'])!
    expect(f.alts[0].runs.sort()).toEqual(['x😀', 'yy'].sort())
  })
})

describe('case-insensitive prefilter', () => {
  it('searches lowercase ASCII in folded content', () => {
    const f = pf(['Next_Public_Secret'], 'i')!
    expect(f.folded).toBe(true)
    expect(f.alts[0].runs).toEqual(['next_public_secret'])
    expect(passes(f, 'x NEXT_PUBLIC_SECRET y')).toBe(true)
    expect(passes(f, 'nothing here')).toBe(false)
  })

  it('folds the two non-ASCII characters RE2 folds to ASCII (long s, Kelvin sign)', () => {
    // the premise: RE2 really folds these two to ASCII
    expect(RE2JS.compile('select', RE2JS.CASE_INSENSITIVE).matcher('ſelect').find()).toBe(true)
    expect(RE2JS.compile('key', RE2JS.CASE_INSENSITIVE).matcher('Key').find()).toBe(true)
    expect(passes(pf(['select'], 'i')!, 'ſelect * from t')).toBe(true)
    expect(passes(pf(['key'], 'i')!, 'KEY')).toBe(true)
  })

  it('drops non-ASCII runs and or-sets with a non-ASCII member under i', () => {
    expect(pf(['café'], 'i')).toBeUndefined() // nothing ASCII left to require
    expect(pf(['(?:abc|éé)zzz'], 'i')!.alts).toEqual([{ runs: ['zzz'], ors: [] }])
    // without i the same pattern keeps the exact text
    expect(pf(['café'])!.alts[0].runs).toEqual(['café'])
  })
})

describe('mayMatch', () => {
  it('requires every run and one member of each or-set', () => {
    const f = pf(['(?:exec|execSync)\\s*\\(\\s*[a-z]+\\s*\\+'])!
    expect(passes(f, 'execSync(cmd +')).toBe(true)
    expect(passes(f, 'exec(cmd +')).toBe(true)
    expect(passes(f, 'run(cmd +')).toBe(false)
    expect(passes(f, 'exec cmd +')).toBe(false) // no "("
  })

  it('any branch may satisfy a rule with several patterns', () => {
    const f = pf(['alpha\\d', 'beta\\d'])!
    expect(passes(f, 'xx beta1')).toBe(true)
    expect(passes(f, 'xx gamma1')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Differential soundness: random regexes + random and generated-matching strings. Whenever RE2 finds
// a match, the prefilter MUST let the file through. (The reverse need not hold.)
// ---------------------------------------------------------------------------

function rng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const ALPHA = ['a', 'b', 'c', 'A', 'B', 'k', 's', 'K', 'S', '-', '_', ' ', '(', 'x', '1']
const UNI = ['ſ', 'K', 'é', 'É']

interface Node {
  src: string
  sample: (r: () => number, ci: boolean) => string
}

function genNode(r: () => number, depth: number): Node {
  const pick = <T,>(xs: T[]): T => xs[Math.floor(r() * xs.length)]
  const kind = r()
  let base: Node
  if (kind < 0.4) {
    const c = pick(ALPHA)
    const src = /[A-Za-z0-9_\- ]/.test(c) ? c : '\\' + c
    base = { src, sample: (rr, ci) => (ci && rr() < 0.5 ? (rr() < 0.5 ? c.toUpperCase() : c.toLowerCase()) : c) }
  } else if (kind < 0.47) {
    const c = pick(UNI)
    base = { src: c, sample: (rr, ci) => (ci && rr() < 0.5 ? (c === 'ſ' ? 's' : c === 'K' ? 'k' : c.toLowerCase()) : c) }
  } else if (kind < 0.57) {
    const members = [pick(ALPHA), pick(ALPHA), pick(ALPHA)].filter((c) => /[A-Za-z0-9_ ]/.test(c))
    const set = members.length ? members : ['a']
    base = { src: `[${set.join('')}]`, sample: (rr) => pick(set) }
  } else if (kind < 0.62) {
    base = { src: '.', sample: (rr) => pick(ALPHA) }
  } else if (kind < 0.67) {
    base = { src: '\\d', sample: () => '1' }
  } else if (kind < 0.7) {
    base = { src: '\\b', sample: () => '' }
  } else if (kind < 0.9 && depth < 3) {
    const nAlt = 1 + Math.floor(r() * 3)
    const alts = Array.from({ length: nAlt }, () => genSeq(r, depth + 1))
    const named = r() < 0.2 ? '?:' : ''
    base = { src: `(${named}${alts.map((a) => a.src).join('|')})`, sample: (rr, ci) => pick(alts).sample(rr, ci) }
  } else {
    const c = pick(['a', 'b', 'c'])
    base = { src: c, sample: () => c }
  }
  const q = r()
  if (base.src === '\\b') return base
  if (q < 0.15) return { src: base.src + '*', sample: (rr, ci) => (rr() < 0.5 ? '' : base.sample(rr, ci).repeat(1 + Math.floor(rr() * 2))) }
  if (q < 0.3) return { src: base.src + '+', sample: (rr, ci) => Array.from({ length: 1 + Math.floor(rr() * 3) }, () => base.sample(rr, ci)).join('') }
  if (q < 0.42) return { src: base.src + '?', sample: (rr, ci) => (rr() < 0.5 ? '' : base.sample(rr, ci)) }
  if (q < 0.5) return { src: base.src + '{2,3}', sample: (rr, ci) => base.sample(rr, ci) + base.sample(rr, ci) }
  return base
}

function genSeq(r: () => number, depth: number): Node {
  const n = 1 + Math.floor(r() * 5)
  const nodes = Array.from({ length: n }, () => genNode(r, depth))
  return { src: nodes.map((x) => x.src).join(''), sample: (rr, ci) => nodes.map((x) => x.sample(rr, ci)).join('') }
}

describe('differential soundness against re2js', () => {
  it('never filters out a string that re2js matches (3000 random patterns, i and plain)', () => {
    const r = rng(20261117)
    let filtered = 0
    let checkedMatches = 0
    for (let i = 0; i < 3000; i++) {
      const top = r() < 0.3 ? [genSeq(r, 0), genSeq(r, 0)] : [genSeq(r, 0)]
      const pattern = top.map((t) => t.src).join('|')
      const ci = r() < 0.5
      let compiled: RE2JS
      try {
        compiled = RE2JS.compile(pattern, ci ? RE2JS.CASE_INSENSITIVE : 0)
      } catch {
        continue // the generator can emit something RE2 rejects; skip it
      }
      const f = buildPrefilter([pattern], ci ? 'i' : '')
      if (f !== undefined) filtered++
      const samples: string[] = []
      for (let k = 0; k < 6; k++) {
        const pre = Array.from({ length: Math.floor(r() * 4) }, () => ALPHA[Math.floor(r() * ALPHA.length)]).join('')
        const suf = Array.from({ length: Math.floor(r() * 4) }, () => ALPHA[Math.floor(r() * ALPHA.length)]).join('')
        const t = top[Math.floor(r() * top.length)]
        samples.push(pre + t.sample(r, ci) + suf)
      }
      for (let k = 0; k < 6; k++) {
        samples.push(Array.from({ length: Math.floor(r() * 12) }, () => (r() < 0.1 ? UNI[Math.floor(r() * UNI.length)] : ALPHA[Math.floor(r() * ALPHA.length)])).join(''))
      }
      for (const s of samples) {
        if (!compiled.matcher(s).find()) continue
        checkedMatches++
        if (f !== undefined) {
          expect(mayMatch(f, s, foldContent(s)), `pattern ${JSON.stringify(pattern)} flags ${ci ? 'i' : ''} matched ${JSON.stringify(s)} but the prefilter dropped it: ${JSON.stringify(f)}`).toBe(true)
        }
      }
    }
    // The run must be meaningful: many patterns got a filter and many strings really matched.
    expect(filtered).toBeGreaterThan(1000)
    expect(checkedMatches).toBeGreaterThan(5000)
  })
})
