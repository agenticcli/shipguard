// 0.12 refused `telemetry status` when run offline (`--offline`). The flag is gone in 0.13 and the telemetry
// commands are local-only: they must succeed with an unreachable endpoint and make no request at all.
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { buildVariant, makeRecordedCli, type RecordedCli } from '../helpers/recorded-cli.js'

vi.setConfig({ testTimeout: 60_000, hookTimeout: 120_000 })

describe('telemetry commands work with no network', () => {
  let cli: RecordedCli
  const ENV = { SHIPGUARD_TELEMETRY_URL: 'http://127.0.0.1:1', DO_NOT_TRACK: '0' }
  beforeAll(() => {
    cli = makeRecordedCli(buildVariant('published', 'tele-offline'), { freshInstall: true })
  })
  afterAll(() => cli?.cleanup())

  for (const sub of ['status', 'disable', 'enable', 'reset']) {
    it(`telemetry ${sub}: exit 0, no request`, async () => {
      const r = await cli.run(['telemetry', sub], { env: ENV })
      expect(r.code).toBe(0)
      expect(r.attempts).toEqual([])
    })
  }

  it('the removed --offline flag is a clean usage error, not a refusal of the command', async () => {
    const r = await cli.run(['telemetry', 'status', '--offline'], { env: ENV })
    expect(r.code).toBe(2)
    expect(r.stderr).toContain('UNKNOWN_OPTION')
  })
})
