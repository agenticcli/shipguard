/**
 * Exit-code notice: exit 0 is "the scan finished", never "safe".
 *
 * FAIL-BEFORE (0.11.0): a blocked project scanned without --strict exited 0 and printed no line
 * saying what that 0 means; the JSON had no `exitMeaning`; `scan --help` listed the codes only as
 * a long verdict-neutral paragraph with no "Exit codes" heading at the top level of the help.
 *
 * PASS-AFTER: human output ends with the notice when blocking findings exist and --strict is off;
 * --json carries `exitMeaning` (same sentence); the exit-code contract itself is unchanged.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, mkTree, runCli } from '../helpers/cli-fixture.js'
import { EXIT_NOTICE } from '../../src/commands/scan.js'

vi.setConfig({ testTimeout: 30_000 })
afterEach(cleanupTrees)

const BLOCKED = {
  'package.json': '{"name":"fixture"}',
  'config.js': "const k = 'AKIAIOSFODNN7EXAMPLE'\nconst s = 'sk_live_51H8xQwEXAMPLEKEYabcdefghijklmnop'\n",
}
const CLEAN = { 'package.json': '{"name":"fixture"}', 'ok.js': 'const ok = 1\n' }

// eslint-disable-next-line no-control-regex
const stripAnsi = (s: string): string => s.replace(/\x1b\[[0-9;]*m/g, '')
const lastLine = (s: string): string => stripAnsi(s).trimEnd().split('\n').pop() ?? ''

describe('exit-code notice', () => {
  it('the sentence is the agreed one', () => {
    expect(EXIT_NOTICE).toBe('exit 0 = scan finished, not safe. Add --strict to fail on blocking findings.')
  })

  it('human output without --strict says on line 2 that the scan finished with exit 0 (exit stays 0)', async () => {
    const r = await runCli(['scan', mkTree(BLOCKED)])
    expect(r.code).toBe(0)
    expect(stripAnsi(r.stdout).split('\n')[1]).toBe('This scan finished (exit 0). Add --strict to exit 1 on DO NOT SHIP.')
    expect(lastLine(r.stdout)).toMatch(/^Rules ran: /) // nothing about exit codes after line 2
  })

  it('human output with --strict has no notice (the exit code says it) and exits 1', async () => {
    const r = await runCli(['scan', mkTree(BLOCKED), '--strict'])
    expect(r.code).toBe(1)
    expect(stripAnsi(r.stdout)).not.toContain(EXIT_NOTICE)
    expect(lastLine(r.stdout)).toMatch(/^Exit 1: --strict stops on DO NOT SHIP\./)
  })

  it('a clean scan prints no notice', async () => {
    const r = await runCli(['scan', mkTree(CLEAN)])
    expect(r.code).toBe(0)
    expect(stripAnsi(r.stdout)).not.toContain(EXIT_NOTICE)
  })

  it('--json carries exitMeaning and stays one JSON document', async () => {
    const r = await runCli(['scan', mkTree(BLOCKED), '--json'])
    expect(r.code).toBe(0)
    expect(r.json?.exitMeaning).toBe(EXIT_NOTICE)
    expect(r.stdout).not.toContain('Add --strict to fail on blocking findings.\n\n')
  })

  it('--json --strict on a blocked project: exit 1 and exitMeaning says blocked', async () => {
    const r = await runCli(['scan', mkTree(BLOCKED), '--json', '--strict'])
    expect(r.code).toBe(1)
    expect(r.json?.exitMeaning).toMatch(/^exit 1 = blocked/)
  })

  it('--json on a clean project: exitMeaning is present and does not claim "not safe"', async () => {
    const r = await runCli(['scan', mkTree(CLEAN), '--json'])
    expect(r.code).toBe(0)
    expect(typeof r.json?.exitMeaning).toBe('string')
    expect(r.json?.exitMeaning).not.toContain('not safe')
  })

  it('--quiet is still one line', async () => {
    const r = await runCli(['scan', mkTree(BLOCKED), '--quiet'])
    expect(stripAnsi(r.stdout).trim().split('\n')).toHaveLength(1)
  })
})

describe('--help lists the exit codes', () => {
  it('scan --help has an "Exit codes" section naming 0, 1, 2 and 3', async () => {
    const r = await runCli(['scan', '--help'])
    expect(r.code).toBe(0)
    expect(r.stdout).toMatch(/Exit codes/)
    expect(r.stdout).toMatch(/0\s+Scan completed/)
    expect(r.stdout).toMatch(/1\s+Blocked/)
    expect(r.stdout).toMatch(/2\s+Config error/)
    expect(r.stdout).toMatch(/3\s+Runtime error/)
  })

  it('top-level --help has the short exit-code section', async () => {
    const r = await runCli(['--help'])
    expect(r.code).toBe(0)
    expect(r.stdout).toMatch(/Exit codes/)
    expect(r.stdout).toContain('0  scan completed')
    expect(r.stdout).toContain('1  blocked only with --strict')
    expect(r.stdout).toContain('2  config error')
    expect(r.stdout).toContain('3  runtime error')
  })
})
