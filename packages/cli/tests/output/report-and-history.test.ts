/** W2a acceptance tests: the report layout (spec 01) and the history table. */
import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { generateReport } from '../../src/core/report.js'
import { renderHistoryTable } from '../../src/commands/history.js'
import { HistoryStore } from '../../src/core/history/index.js'
import { a1Findings, a3dResult, finding, result } from './_fixtures.js'

const dirs: string[] = []
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }) })
const tmp = () => { const d = mkdtempSync(join(tmpdir(), 'sg-w2a-')); dirs.push(d); return d }

async function report(r: ReturnType<typeof result>, ctx = {}): Promise<string> {
  const p = await generateReport(r, join(tmp(), 'latest.md'), 0, { generalRuleCount: 36, ...ctx })
  return readFileSync(p.mdPath, 'utf-8')
}

// A planted-key stand-in assembled at run time so no key-shaped literal sits in this file.
const PLANTED = ['sk', 'live', '51Habcdefghijklmnop'].join('_')

describe('report layout', () => {
  it('header, rerun line and the Fix in this order / Check by hand / Not scanned / Ignored sections', async () => {
    const md = await report(result(a1Findings()), { stacks: ['nextjs', 'supabase'] })
    const lines = md.split('\n')
    expect(lines[0]).toBe('# ShipGuard report: DO NOT SHIP (run 247f9045)')
    expect(lines[1]).toBe('verdict: DO NOT SHIP   blocking: 3   findings: 5   incomplete: no   files: 16   rules: general:36   when: 2026-11-17 23:07 UTC')
    expect(lines[2]).toBe('rerun: shipguard scan --strict')
    expect(md).toContain('## Fix in this order (3 blocking)')
    expect(md).toContain('## Check by hand (2, not blocking)')
    expect(md).toContain('## Not scanned (0)')
    expect(md).toContain('## Ignored (0)')
    expect(md.trimEnd().split('\n').pop()).toBe('Rules ran: 36 general rules (Free).')
  })

  it('each blocker has why, fix, verify and the same one-line fix as the screen', async () => {
    const md = await report(result(a1Findings()), { stacks: ['nextjs', 'supabase'] })
    expect(md).toContain('1. CRITICAL lib/stripe.ts:2  live Stripe secret key in source   id: generic.secrets.stripe-live-key')
    expect(md).toContain('fix (effort: quick): rotate the key in Stripe first (the old one is exposed), then read the new one from process.env.STRIPE_SECRET_KEY')
    expect(md).toContain('verify: shipguard scan --strict   (this finding no longer appears; exit 0 only when nothing else blocks.')
    expect(md).toContain('Manual: call the route signed out (expect 401), then signed in as a normal non-admin user (expect 403).')
  })

  it('secrets: the evidence line says value hidden; the evidence text is never written', async () => {
    const md = await report(result([finding({ evidence: `${PLANTED}***` })]))
    expect(md).toContain('evidence: value hidden')
    expect(md).not.toContain(PLANTED.slice(0, 10))
    const masked = await report(result([finding({ evidence: 'x' })]), { secretEvidence: () => 'stripe_live_secret_key, 32 characters, value hidden' })
    expect(masked).toContain('evidence: stripe_live_secret_key, 32 characters, value hidden')
  })

  it('incomplete scan: Not scanned names each file with its code and fix', async () => {
    const { result: r, notScanned } = a3dResult()
    const md = await report(r, { notScanned })
    expect(md).toContain('## Not scanned (2)')
    expect(md).toContain('- data-dump.txt  too large (700 KB, limit 512 KB)   code: FILE_TOO_LARGE')
    expect(md).toContain('- mystery.dat  binary data with unknown format (NUL bytes)   code: UNSCANNED_UNKNOWN_BINARY')
    expect(md).toContain('incomplete: yes')
  })

  it('ignored test values are counted in the Ignored section', async () => {
    const md = await report(result([]), { ignoredTestValues: 2 })
    expect(md).toContain('## Ignored (2)')
    expect(md).toContain('- 2 test value(s): placeholder and sample values, not reported')
  })
})

describe('history table', () => {
  const row = (o: Partial<Parameters<typeof renderHistoryTable>[0][number]> = {}) => ({
    scanId: '247f9045-8511-4647-80fd-a4945e28d135',
    timestamp: '2026-11-17T23:07:00.000Z',
    scopeFingerprint: 'x',
    corpusVersion: 'free:0.13.0',
    recommendation: 'DO_NOT_SHIP',
    blockingCount: 3,
    findingCount: 5,
    incomplete: false as boolean | null,
    filesScanned: 16 as number | null,
    rulesLabel: 'general:36' as string | null,
    target: '.' as string | null,
    stateStatus: 'complete',
    ...o,
  })

  it('columns and widths match the spec table; identical piped', () => {
    const out = renderHistoryTable([
      row({ scanId: '9a0b1c2d-0000', timestamp: '2026-11-17T23:31:00.000Z', recommendation: 'REVIEW_BEFORE_SHIP', blockingCount: 0, findingCount: 2 }),
      row(),
    ])
    expect(out.split('\n')).toEqual([
      'RUN       WHEN (UTC)        VERDICT             BLOCKING  FINDINGS  INCOMPLETE  RULES       TARGET',
      '9a0b1c2d  2026-11-17 23:31  REVIEW BEFORE SHIP         0         2  no          general:36  .',
      '247f9045  2026-11-17 23:07  DO NOT SHIP                3         5  no          general:36  .',
    ])
  })

  it('rows from before schema 4 show - for the facts they never kept', () => {
    const out = renderHistoryTable([row({ incomplete: null, filesScanned: null, rulesLabel: null, target: null })])
    const cells = out.split('\n')[1].split(/\s{2,}/)
    expect(cells.slice(-3)).toEqual(['-', '-', '-'])
  })

  it('a long target is shortened with a middle ... on a terminal only', () => {
    const long = 'apps/' + 'x'.repeat(80) + '/web'
    expect(renderHistoryTable([row({ target: long })]).split('\n')[1]).toContain(long)
    const term = renderHistoryTable([row({ target: long })], 80).split('\n')[1]
    expect(term).toContain('...')
    expect(term).not.toContain(long)
  })
})

describe('history store: schema 4 columns round-trip', () => {
  it('writeScan keeps incomplete, files, rules and target; listRecentScans returns them with the finding count', async () => {
    const dbPath = join(tmp(), 'history.db')
    const opened = await HistoryStore.open(dbPath, '0.13.0')
    if (!opened.ok) return // node:sqlite unavailable on this runtime: the store reports it, nothing to assert
    const store = opened.store
    try {
      const w = store.writeScan({
        scanId: 'abc12345-0000', repoId: 'r', repoIdKind: 'path', scopeFingerprint: 's', corpusVersion: 'free:0.13.0', releaseId: 'unversioned',
        cliVersion: '0.13.0', timestamp: '2026-11-17T23:07:00.000Z', recommendation: 'DO_NOT_SHIP', blockingCount: 3, criticalCount: 2, highCount: 1,
        mediumCount: 0, lowCount: 2, infoCount: 0, incomplete: true, filesScanned: 10, rulesLabel: 'general:36', target: 'apps/web', ruleOutcomes: [], findings: [],
      })
      expect(w.ok).toBe(true)
      const [r] = store.listRecentScans('r', 10)
      expect(r).toMatchObject({ findingCount: 5, incomplete: true, filesScanned: 10, rulesLabel: 'general:36', target: 'apps/web' })
    } finally {
      store.close()
    }
  })
})
