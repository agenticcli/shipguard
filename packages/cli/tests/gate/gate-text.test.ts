/**
 * Gate text builders and the scan JSON reader: pure functions, both JSON shapes (0.12 schema "6",
 * 0.13 schema "7"), the machine line, the sample texts from spec 03.
 */
import { describe, expect, it } from 'vitest'
import { parseScanJson, scanErrorCode } from '../../src/core/gate-scan.js'
import {
  firstSentence,
  machineLine,
  orderBlocking,
  rerunCommand,
  repeatString,
  shellQuote,
  type GateFinding,
} from '../../src/core/gate-text.js'

describe('machine line', () => {
  it('fixed key order; run is none without one; rerun is last and one JSON string', () => {
    expect(machineLine({ code: 'SAFE_TO_SHIP', agentAction: 'proceed', run: '4f2a91cc' })).toBe('shipguard-gate: code=SAFE_TO_SHIP agentAction=proceed run=4f2a91cc')
    expect(machineLine({ code: 'GATE_NOT_STARTED', agentAction: 'fix_and_rerun', run: null })).toBe('shipguard-gate: code=GATE_NOT_STARTED agentAction=fix_and_rerun run=none')
    const line = machineLine({ code: 'BLOCKING_FINDINGS', agentAction: 'fix_and_rerun', run: '247f9045', rerun: `shipguard scan 'my "app"' --strict` })
    expect(line).toBe('shipguard-gate: code=BLOCKING_FINDINGS agentAction=fix_and_rerun run=247f9045 rerun="shipguard scan \'my \\"app\\"\' --strict"')
    // Parse as documented: drop the prefix, read three tokens up to ` rerun=`, JSON-decode the rest.
    const body = line.slice('shipguard-gate: '.length)
    const cut = body.indexOf(' rerun=')
    expect(body.slice(0, cut).split(' ').map((t) => t.split('=')[0])).toEqual(['code', 'agentAction', 'run'])
    expect(JSON.parse(body.slice(cut + ' rerun='.length))).toBe(`shipguard scan 'my "app"' --strict`)
  })

  it('backslashes and control characters are escaped, so the line stays one line', () => {
    const line = machineLine({ code: 'X', agentAction: 'stop', run: null, rerun: 'a\\b\nc\td' })
    expect(line.split('\n')).toHaveLength(1)
    expect(JSON.parse(line.slice(line.indexOf(' rerun=') + 7))).toBe('a\\b\nc\td')
  })
})

describe('re-run command (one builder)', () => {
  it('bare form at the cwd, a quoted target otherwise', () => {
    expect(rerunCommand(null)).toBe('shipguard scan --strict')
    expect(rerunCommand('../wt')).toBe('shipguard scan ../wt --strict')
    expect(rerunCommand('./apps/my web')).toBe(`shipguard scan './apps/my web' --strict`)
    expect(shellQuote("it's")).toBe(`'it'\\''s'`)
  })
})

describe('repeat strings (spec 04, defined once)', () => {
  it('none on a first sighting; the two second-run forms; the stop string at the third run', () => {
    expect(repeatString(0, false, null)).toBeNull()
    expect(repeatString(1, true, null)).toBe('Same blocking result on the same commit. If you changed a file, commit it, then push.')
    expect(repeatString(1, false, '.shipguard/reports/latest.md')).toBe(
      'Same blocking result. Re-read the Verify step of this finding in the report (.shipguard/reports/latest.md), then fix and re-run.',
    )
    expect(repeatString(2, false, null)).toBe('Repeated blocking result. Stop and ask the user; do not ignore or bypass it (shipguard ignore, --no-verify) on your own.')
    expect(repeatString(5, true, null)).toContain('Stop and ask the user')
  })
})

describe('order of the findings shown (spec 04)', () => {
  const f = (id: string, severity: string, category: string | null, file = 'a.ts'): GateFinding => ({
    id, title: id, severity, file, line: 1, blocking: true, fix: null, category, occurrence: id,
  })
  it('exposed secrets first, then critical and high, payments and auth before the rest', () => {
    const ordered = orderBlocking([f('cfg', 'high', 'config'), f('auth', 'high', 'auth'), f('secret', 'critical', 'secrets'), f('pay', 'critical', 'payments')])
    expect(ordered.map((x) => x.id)).toEqual(['secret', 'pay', 'auth', 'cfg'])
  })
  it('first sentence of a long fix', () => {
    expect(firstSentence('Rotate it first. Then read it from env.')).toBe('Rotate it first.')
    expect(firstSentence('  one   two  ')).toBe('one two')
  })
})

describe('reading the scan JSON', () => {
  const v6 = {
    recommendation: 'DO_NOT_SHIP', degraded: false, filesScanned: 16, rulesApplied: 36,
    runId: '247f9045-8511-4647-80fd-a4945e28d135',
    findings: [
      { id: 'auth_route_without_guard', title: 'Unprotected API route handler', severity: 'high', category: 'auth', file: 'app/api/admin/users/route.ts', line: 1, blocking: true, recommendation: 'Add a check at the top. Return a 401.' },
      { id: 'generic.secrets.stripe-live-key', severity: 'critical', category: 'secrets', file: 'lib/stripe.ts', line: 2, blocking: true, fix: 'Replace with process.env.STRIPE_SECRET_KEY. Rotate the key.', suppressed: false },
      { id: 'quiet', severity: 'low', file: 'b.ts', blocking: true, suppressed: true },
    ],
    coverage: { discovered: 16, scanned: 16 },
  }

  it('schema 6: verdict, findings, one-sentence fixes, run id, suppressed findings never block', () => {
    const p = parseScanJson(JSON.stringify(v6), 1.5)!
    expect(p.summary.verdict).toBe('DO_NOT_SHIP')
    expect(p.summary.runId).toBe('247f9045')
    expect(p.summary.filesScanned).toBe(16)
    expect(p.summary.rulesApplied).toBe(36)
    expect(p.summary.findings.map((x) => [x.id, x.blocking, x.fix])).toEqual([
      ['auth_route_without_guard', true, 'Add a check at the top.'],
      ['generic.secrets.stripe-live-key', true, 'Replace with process.env.STRIPE_SECRET_KEY.'],
      ['quiet', false, null],
    ])
    expect(p.suppressed).toEqual([{ id: 'quiet', file: 'b.ts' }])
    expect(p.summary.findings[0].occurrence).toMatch(/^[0-9a-f]{12}$/)
    expect(p.summary.seconds).toBe(1.5)
  })

  it('schema 7: verdict.value, the occurrence key as sent, fix.summary, rules.fallback, plan usage state', () => {
    const v7 = {
      schemaVersion: '7', runId: '4f2a91cc-0000', elapsedMs: 249,
      verdict: { value: 'SAFE_TO_SHIP', complete: true },
      rules: { corpus: 'general', applied: 36, fallback: { code: 'RULEBOOK_PARTIAL' }, receipt: null },
      plan: { server: { usage: { state: 'warn' } } },
      findings: [{ id: 'r', severity: 'low', file: 'f.ts', line: 3, blocking: false, occurrence: '9c41e07ab3d2', fix: { summary: 'Do the thing. Then more.' } }],
      coverage: { discovered: 4, scanned: 4 },
      report: { markdown: '.shipguard/reports/latest.md' },
    }
    const p = parseScanJson(JSON.stringify(v7), 9)!
    expect(p.summary.seconds).toBeCloseTo(0.249)
    expect(p.summary.corpus).toBe('general')
    expect(p.summary.fallbackCode).toBe('RULEBOOK_PARTIAL')
    expect(p.usageState).toBe('warn')
    expect(p.summary.findings[0]).toMatchObject({ occurrence: '9c41e07ab3d2', fix: 'Do the thing.' })
    expect(p.summary.degraded).toBe(false)
  })

  it('incomplete scans: files named per code from either shape; counts:false skips do not degrade', () => {
    const v6 = parseScanJson(JSON.stringify({
      recommendation: 'DO_NOT_SHIP', degraded: true, filesScanned: 10, findings: [],
      coverage: { discovered: 12, scanned: 10, files: { tooLarge: ['data-dump.txt'], unknownBinary: ['mystery.dat'] } },
      degradedReasons: [{ code: 'FILE_TOO_LARGE' }, { code: 'UNSCANNED_UNKNOWN_BINARY' }, { code: 'OUTPUT_TRUNCATED', detail: 'stopped at the limit' }],
    }), 1)!
    expect(v6.summary.notScanned.map((n) => [n.file, n.code])).toEqual([
      ['data-dump.txt', 'FILE_TOO_LARGE'], ['mystery.dat', 'UNSCANNED_UNKNOWN_BINARY'], [null, 'OUTPUT_TRUNCATED'],
    ])
    const v7 = parseScanJson(JSON.stringify({
      verdict: { value: 'DO_NOT_SHIP', complete: false }, findings: [],
      coverage: { discovered: 12, scanned: 10, notScanned: [{ file: 'big.txt', code: 'FILE_TOO_LARGE', bytes: 716800 }, { file: 'logo.png', code: 'BINARY', counts: false }] },
      degradedReasons: [{ code: 'FILE_TOO_LARGE', files: ['big.txt'] }],
    }), 1)!
    expect(v7.summary.degraded).toBe(true)
    expect(v7.summary.notScanned).toEqual([{ file: 'big.txt', code: 'FILE_TOO_LARGE', reason: 'too large (700 KB)' }])
  })

  it('anything that is not a scan result is null (the gate fails closed on it)', () => {
    for (const bad of ['', 'not json', '[]', '{}', '{"recommendation":"MAYBE"}', '{"error":"x","code":"NOT_A_PROJECT"}']) {
      expect(parseScanJson(bad, 1), bad).toBeNull()
    }
  })

  it('error codes from a failed scan, both shapes', () => {
    expect(scanErrorCode('{"error":"x","code":"NOT_A_PROJECT"}')).toBe('NOT_A_PROJECT')
    expect(scanErrorCode('{"ok":false,"error":{"code":"INTERNAL_ERROR"}}')).toBe('INTERNAL_ERROR')
    expect(scanErrorCode('nope')).toBeNull()
  })
})
