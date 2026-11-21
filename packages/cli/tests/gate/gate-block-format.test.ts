/**
 * QA fix 6 (QA-CLI-0130 FAIL 6): the gate block lists a finding in the SAME form as the scan screen (spec 03, spec 06
 * "one representation, every channel"): the current guidance wording, a secret shown as `(N chars, value hidden)`,
 * the current fix text. FAIL-BEFORE: the block printed the rule's long title ("A hardcoded Stripe live secret key
 * (sk_live_ prefix) ... was detected in…"), the old fix text, and no length.
 */
import { spawnSync } from 'node:child_process'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { runGate, type GateDeps } from '../../src/commands/gate.js'
import { runScanChild } from '../../src/core/gate-scan.js'
import { buildVariant } from '../helpers/recorded-cli.js'
import { claudeInput, cleanup, commitFile, mkDeps, mkRepo } from './gate-fixtures.js'

vi.setConfig({ testTimeout: 90_000 })

let distCli = ''
beforeAll(() => {
  distCli = buildVariant('dev', 'gate-block-format')
}, 240_000)
afterEach(cleanup)

// Split so this file does not itself hold a live-looking key.
const KEY = `sk_live_${'abcdefghijklmnopqrstuvwx1234567'}`
const realScan: GateDeps['runScan'] = ({ dir, budgetMs, host, top, sha }) => runScanChild({ cliEntry: distCli, dir, budgetMs, host, top, sha })

describe('gate block = the scan screen, finding for finding', () => {
  it('a planted live key: type wording, length, current fix; same two lines as `shipguard scan`', async () => {
    const main = mkRepo()
    commitFile(main, 'lib/stripe.ts', `export const k = "${KEY}"\n`)
    const { deps, out } = mkDeps(main, claudeInput('git push origin main', main), { runScan: realScan })
    expect(await runGate({ host: 'claude' }, deps)).toBe(2)
    const t = out.stderr
    const length = String(KEY.length)
    expect(t).toContain(`live Stripe secret key in source (${length} chars, value hidden)`)
    expect(t).toContain('fix: rotate the key in Stripe first (the old one is exposed), then read the new one from process.env.STRIPE_SECRET_KEY')
    expect(t).not.toContain('sk_live_ prefix')
    expect(t).not.toContain('Replace with `process.env.STRIPE_SECRET_KEY` and add it')
    expect(t).not.toContain(KEY)

    // The scan screen on the same tree gives the same finding line and fix line.
    const screen = spawnSync(process.execPath, [distCli, 'scan', '--strict'], {
      cwd: main,
      encoding: 'utf-8',
      env: { PATH: process.env.PATH, HOME: main, SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1', CI: '1' },
    }).stdout
    const pick = (text: string): string[] => text.split('\n').filter((l) => /CRITICAL +lib\/stripe\.ts:1 {2}|^ {4}fix: rotate the key/.test(l))
    expect(pick(screen)).toHaveLength(2)
    expect(pick(t)).toEqual(pick(screen))
  })
})
