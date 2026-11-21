/**
 * W2a acceptance tests: golden scan screens (spec 01) built from pure inputs.
 * Clean pass, blocked (A1), incomplete scan (A3d), quiet, narrow terminal, plan lines, no promotion
 * where it must not appear, line budget, banned words and plan-fact grep on rendered output.
 */
import { describe, it, expect } from 'vitest'
import { renderScanScreen, renderQuietLine, SCREEN_MAX_LINES } from '../../src/core/render.js'
import { a1Findings, a3dResult, finding, result } from './_fixtures.js'

const N = 36 // any number: the screen prints whatever count it is given (run-time N)

const base = { elapsedMs: 200, strict: false, generalRuleCount: N }

describe('A1: three planted blockers', () => {
  const out = renderScanScreen({
    ...base,
    result: result(a1Findings()),
    reportPath: '.shipguard/reports/latest.md',
    stacks: ['nextjs', 'supabase'],
    next: { agent: null, gate: 'none', suggestionShownRecently: false },
  })
  const lines = out.split('\n')

  it('line 1 is the verdict line, line 2 the exit sentence', () => {
    expect(lines[0]).toBe(`DO NOT SHIP · 3 blocking of 5 findings · 16 files, ${N} general rules, 0.2s`)
    expect(lines[1]).toBe('This scan finished (exit 0). Add --strict to exit 1 on DO NOT SHIP.')
  })

  it('Fix first lists the blockers in order, secrets first, two lines each, stack-specific fixes', () => {
    expect(out).toContain('Fix first (3 blocking):')
    expect(lines[4]).toBe(' 1. CRITICAL lib/stripe.ts:2  live Stripe secret key in source (value hidden)')
    expect(lines[5]).toMatch(/^ {4}fix: rotate the key in Stripe first/)
    expect(out).toContain('fix: build the event with stripe.webhooks.constructEvent(await req.text(), sig, secret); return 400 if it throws')
    expect(out).toContain('fix: call supabase.auth.getUser() and return 401 if there is no user')
  })

  it('Also found has the low-confidence items with their "not a vulnerability if" line', () => {
    expect(out).toContain('Also found (2 low, may be false positives, check by hand):')
    expect(out).toContain('not a vulnerability if: a shared wrapper (for example withErrorHandler) already catches errors for this route')
  })

  it('closing lines: Report, Next, Rules ran, in that order; no upgrade line (blocking present)', () => {
    const tail = lines.slice(-3)
    expect(tail[0]).toBe('Report: .shipguard/reports/latest.md   (all fixes; agents: shipguard scan --json)')
    expect(tail[1]).toBe('Next: fix the 3 above, then: shipguard scan --strict')
    expect(tail[2]).toBe(`Rules ran: ${N} general rules (Free).`)
  })

  it('has no box art, no emoji, no legend, no tips, no confidence tags', () => {
    expect(out).not.toMatch(/[╭╮╰╯│├┤─█🛑⛔🐛✅⚠ℹ]/u)
    expect(out).not.toMatch(/What now|Confidence legend|Learn more|shipguard feedback|shipguard rate/)
    expect(out).not.toMatch(/\[(moderate|low false|higher false)/)
  })

  it('fits the 25-line budget', () => {
    expect(lines.length).toBeLessThanOrEqual(SCREEN_MAX_LINES)
  })
})

describe('--strict on a blocked scan', () => {
  it('ends with the one Exit 1 line and omits the exit-0 sentence', () => {
    const out = renderScanScreen({ ...base, strict: true, exitCode: 1, result: result(a1Findings()) })
    const lines = out.split('\n')
    expect(lines[1]).toBe('')
    expect(lines[lines.length - 1]).toBe('Exit 1: --strict stops on DO NOT SHIP. Fix the items above or use shipguard ignore with a reason.')
  })
})

describe('clean pass (A3)', () => {
  const clean = (next: Parameters<typeof renderScanScreen>[0]['next']) =>
    renderScanScreen({ ...base, result: result([], { filesScanned: 10 }), reportPath: '.shipguard/reports/latest.md', next, stacks: ['generic'] })

  it('says SAFE TO SHIP and always states the limit of "safe"', () => {
    const out = clean({ agent: 'claude', gate: 'none', suggestionShownRecently: false })
    const lines = out.split('\n')
    expect(lines[0]).toBe(`SAFE TO SHIP · 0 findings · 10 files, ${N} general rules, 0.2s`)
    expect(lines[1]).toBe('"Safe" here means no rule matched. It is not a security audit.')
  })

  it('Next: from agent and install state (the five cases of spec 01)', () => {
    expect(clean({ agent: 'claude', gate: 'none', suggestionShownRecently: false })).toContain(
      'Next: shipguard setup --agent claude   (Claude Code detected, no gate installed yet; the gate blocks git push when ShipGuard finds a blocker)',
    )
    expect(clean({ agent: 'claude', gate: 'none', suggestionShownRecently: true })).toContain(
      'Next: no gate is installed. Re-check after changes: shipguard scan --strict',
    )
    expect(clean({ agent: 'claude', gate: 'current', gateLabel: 'Claude project hook v2', suggestionShownRecently: false })).toContain(
      'Next: nothing to fix. The gate is on (Claude project hook v2). Re-check after changes: shipguard scan --strict',
    )
    expect(clean({ agent: 'claude', gate: 'stale', suggestionShownRecently: false })).toContain('Next: shipguard setup --agent claude   (updates your older hook)')
    expect(clean({ agent: null, gate: 'none', suggestionShownRecently: false })).toContain('Next: shipguard setup   (detects your agent and previews the changes)')
  })

  it('never says the gate is on when the suggestion was only hidden', () => {
    expect(clean({ agent: 'claude', gate: 'none', suggestionShownRecently: true })).not.toContain('The gate is on')
  })

  it('stack not recognised: a Stack: line sits right before Rules ran', () => {
    const out = renderScanScreen({ ...base, result: result([]), stacks: ['generic'], manifest: 'package.json' })
    const lines = out.split('\n')
    expect(lines[lines.length - 2]).toBe('Stack: project found, framework not recognised (package.json). Stack-specific checks may not have applied.')
    expect(lines[lines.length - 1]).toMatch(/^Rules ran:/)
  })
})

describe('review only (no blockers)', () => {
  it('REVIEW BEFORE SHIP with Next: pointing at the report', () => {
    const out = renderScanScreen({
      ...base,
      result: result([finding({ id: 'x', title: 'Some nit', severity: 'medium', category: 'config', blocking: false, confidence: 'HIGH', file: 'a.ts', line: 3 })]),
      reportPath: '.shipguard/reports/latest.md',
    })
    expect(out.split('\n')[0]).toBe(`REVIEW BEFORE SHIP · 1 finding, 0 blocking · 16 files, ${N} general rules, 0.2s`)
    expect(out).toContain('Next: review the 1 finding in .shipguard/reports/latest.md (nothing blocks a push), then: shipguard scan --strict')
  })
})

describe('incomplete scan (A3d)', () => {
  const { result: r, notScanned } = a3dResult()
  const out = renderScanScreen({ ...base, result: r, notScanned, reportPath: '.shipguard/reports/latest.md' })
  const lines = out.split('\n')

  it('verdict never says clean; names the coverage stop', () => {
    expect(lines[0]).toBe('DO NOT SHIP · cannot clear this repo: 2 of 12 files were not scanned · 0 findings in the 10 that were')
    expect(lines[1]).toBe('Not scanned means not checked. This is a stop because of coverage, not because of a finding.')
    expect(out).not.toMatch(/clean scan|No findings detected|SAFE TO SHIP/)
  })

  it('names both files with reason and fix, aligned, never cut mid-word', () => {
    expect(out).toContain('Not scanned (2):')
    expect(out).toContain(' - data-dump.txt  too large (700 KB, limit 512 KB)')
    expect(out).toContain(' - mystery.dat    binary data with unknown format (NUL bytes)')
    expect(out).toContain('shipguard ignore mystery.dat --reason "<why: what this file is>"')
    expect(out).toContain('(ask the user first, or give a reason you checked')
    expect(out).not.toContain('...')
    expect(lines[lines.length - 2]).toBe('Next: fix or exclude the 2 files, then: shipguard scan --strict')
  })
})

describe('--quiet: one line', () => {
  it('blocked scan: fixed key order, yes/no booleans, run id of 8 characters', () => {
    const line = renderQuietLine({ result: result(a1Findings()), reportPath: '.shipguard/reports/latest.md' })
    expect(line).toBe('shipguard: verdict=DO_NOT_SHIP blocking=3 findings=5 incomplete=no agentAction=fix_and_rerun run=247f9045 report=.shipguard/reports/latest.md')
    expect(line).not.toContain('\n')
    expect(line).not.toMatch(/score=|Exit 1/)
  })

  it('incomplete scan: notScanned and fallback appear only when set', () => {
    const { result: r } = a3dResult()
    expect(renderQuietLine({ result: r, notScanned: 2, reportPath: '.shipguard/reports/latest.md' })).toBe(
      'shipguard: verdict=DO_NOT_SHIP blocking=0 findings=0 incomplete=yes notScanned=2 agentAction=ask_human run=247f9045 report=.shipguard/reports/latest.md',
    )
    expect(renderQuietLine({ result: result([]), fallbackCode: 'RULEBOOK_WITHHELD' })).toContain('incomplete=no fallback=RULEBOOK_WITHHELD agentAction=proceed')
  })
})

describe('width rule', () => {
  const input = { ...base, result: result(a1Findings()), stacks: ['nextjs', 'supabase'] }

  it('piped: no wrapping and no "..." anywhere; every record one physical line', () => {
    const out = renderScanScreen(input)
    expect(out).not.toContain('...')
    expect(Math.max(...out.split('\n').map((l) => l.length))).toBeGreaterThan(100)
  })

  it('narrow terminal (60 columns): prose wraps at word boundaries, paths and file:line stay whole', () => {
    const out = renderScanScreen({ ...input, columns: 60 })
    for (const l of out.split('\n')) expect(l.length).toBeLessThanOrEqual(60 + 30) // a glued call may overshoot, never a path
    expect(out).toContain('app/api/webhooks/stripe/route.ts:2')
    expect(out).toContain('lib/stripe.ts:2')
    expect(out).toMatch(/\n {8}\S/) // hanging indent
  })
})

describe('line budget', () => {
  it('stays at 25 lines or fewer even with many findings and many unscanned files', () => {
    const many = Array.from({ length: 12 }, (_, i) =>
      finding({ id: `auth_route_without_guard`, file: `app/api/r${i}/route.ts`, line: 1, severity: 'high', category: 'auth', title: 'x' }),
    )
    const low = Array.from({ length: 8 }, (_, i) =>
      finding({ id: 'missing_error_handling', file: `app/p${i}/route.ts`, line: 2, severity: 'low', category: 'payments', blocking: false, confidence: 'LOW', title: 'y' }),
    )
    const { notScanned } = a3dResult()
    const out = renderScanScreen({ ...base, result: result([...many, ...low]), notScanned, stacks: ['nextjs'] })
    expect(out.split('\n').length).toBeLessThanOrEqual(SCREEN_MAX_LINES)
    expect(out).toMatch(/\+\d+ more/)
  })
})

describe('rendered text is free of banned words and plan facts', () => {
  it('no banned words, price, count of scans, credits or trial length on any screen', () => {
    const { result: r3d, notScanned } = a3dResult()
    const screens = [
      renderScanScreen({ ...base, result: result(a1Findings()) }),
      renderScanScreen({ ...base, result: result([]) }),
      renderScanScreen({ ...base, result: r3d, notScanned }),
      renderScanScreen({ ...base, result: result([]), rulesRan: { kind: 'fallback', code: 'RULEBOOK_UNREACHABLE' } }),
    ].join('\n')
    expect(screens).not.toMatch(/release gate|\bcloud\b|our servers/i)
    expect(screens).not.toMatch(/\$\d|\bcredits?\b|per month|a month|\d+[- ]day|\bscans a\b/i)
  })
})

describe('Rules ran line and fallback sentences (spec 05)', () => {
  it('rulebook ran', () => {
    const out = renderScanScreen({ ...base, result: result([]), rulesRan: { kind: 'rulebook', label: 'Pro', count: 77 } })
    expect(out.split('\n').pop()).toBe('Rules ran: Pro rulebook, 77 rules.')
    expect(renderScanScreen({ ...base, result: result([]), rulesRan: { kind: 'rulebook', count: 77 } })).toContain('Rules ran: full rulebook, 77 rules.')
  })

  it('unreachable rulebook: says what ran, directly under the header', () => {
    const out = renderScanScreen({ ...base, result: result([]), rulesRan: { kind: 'fallback', code: 'RULEBOOK_UNREACHABLE' } })
    const lines = out.split('\n')
    expect(lines[2]).toBe('Rulebook could not be reached. This scan ran general rules only; it is not a full rulebook scan. Retry when you are online.')
    expect(lines[lines.length - 1]).toBe(`Rules ran: ${N} general rules (full rulebook not used).`)
  })

  it('withheld by the server: the server text is printed verbatim, the CLI adds only the run sentence', () => {
    const out = renderScanScreen({ ...base, result: result([]), rulesRan: { kind: 'fallback', code: 'RULEBOOK_WITHHELD', serverText: 'Scan allowance used up. Resets 2026-12-01.' } })
    expect(out).toContain('Scan allowance used up. Resets 2026-12-01. This scan ran general rules only; the verdict covers those rules only.')
  })

  it('partial rulebook', () => {
    const out = renderScanScreen({ ...base, result: result([]), rulesRan: { kind: 'partial', count: 20 } })
    expect(out).toContain('Only part of the rulebook was provided; the verdict covers the rules that ran.')
    expect(out.split('\n').pop()).toBe('Rules ran: 20 rules (part of the rulebook).')
  })
})

describe('fix loop and test values', () => {
  it('shows "since the last run" and the repeat line directly above Next:', () => {
    const out = renderScanScreen({
      ...base,
      result: result(a1Findings()),
      fixLoop: { fixed: 1, added: 0, repeatLine: 'Same blocking result. Re-read the Verify step of this finding in the report (.shipguard/reports/latest.md), then fix and re-run.' },
    })
    const lines = out.split('\n')
    expect(out).toContain('Fix first (3 blocking; since the last run: 1 fixed, 0 new):')
    const nextIdx = lines.findIndex((l) => l.startsWith('Next:'))
    expect(lines[nextIdx - 1]).toMatch(/^Same blocking result\./)
  })

  it('"ignored N test values" line', () => {
    const out = renderScanScreen({ ...base, result: result([]), ignoredTestValues: 3 })
    expect(out).toContain('Ignored 3 test values (placeholder and sample values; listed in the report).')
  })

  it('a finding that came from the rulebook ends with the server plan name, else [rulebook rule]', () => {
    const f = finding({ blocking: true }) as ReturnType<typeof finding> & { origin: string }
    f.origin = 'rulebook'
    expect(renderScanScreen({ ...base, result: result([f]), planLabel: 'Pro' })).toContain('(value hidden) [Pro rule]')
    expect(renderScanScreen({ ...base, result: result([f]) })).toContain('(value hidden) [rulebook rule]')
  })
})

describe('secrets are never printed on the screen', () => {
  it('no evidence text and no character of the value; the W5 label seam adds type and length', () => {
    const f = finding({ evidence: 'sk_live_51Habc***' })
    const plain = renderScanScreen({ ...base, result: result([f]) })
    expect(plain).not.toContain('sk_live_51')
    expect(plain).toContain('(value hidden)')
    const masked = renderScanScreen({ ...base, result: result([f]), secretLabel: () => '32 chars, value hidden' })
    expect(masked).toContain('live Stripe secret key in source (32 chars, value hidden)')
  })
})
