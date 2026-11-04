/** The built CLI, real process: cli_first_run is sent once on the first command of a fresh install. */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { buildVariant, makeRecordedCli, type RecordedCli } from '../helpers/recorded-cli.js'

vi.setConfig({ testTimeout: 60_000, hookTimeout: 120_000 })

const SINK = 'http://127.0.0.1:1/cli-telemetry'
const ON = { SHIPGUARD_TELEMETRY: '1', DO_NOT_TRACK: '0', SHIPGUARD_TELEMETRY_URL: SINK }
let devPath: string
beforeAll(() => {
  devPath = buildVariant('dev', 'first-run')
})
const bodies = (r: { attempts: Array<{ body: string }> }) => r.attempts.map((a) => JSON.parse(a.body))

describe('cli_first_run (built CLI)', () => {
  it('fires once on the first command of any kind, never again', async () => {
    const cli: RecordedCli = makeRecordedCli(devPath, { freshInstall: true })
    try {
      const first = await cli.run(['status'], { env: ON })
      const events = bodies(first).map((b) => b.event)
      expect(events).toEqual(['cli_first_run'])
      const second = await cli.run(['status'], { env: ON })
      expect(second.attempts).toEqual([])
      const scan = await cli.run(['scan', cli.project, '--json'], { env: ON })
      expect(bodies(scan).map((b) => b.schema)).toEqual([2])
    } finally {
      cli.cleanup()
    }
  })
  it('opt-out sends nothing, even on the first command', async () => {
    const cli = makeRecordedCli(devPath, { freshInstall: true })
    try {
      const r = await cli.run(['status'], { env: { ...ON, DO_NOT_TRACK: '1' } })
      expect(r.attempts).toEqual([])
    } finally {
      cli.cleanup()
    }
  })
  it('does not send in CI', async () => {
    const cli = makeRecordedCli(devPath, { freshInstall: true })
    try {
      const r = await cli.run(['status'], { env: { ...ON, CI: 'true' } })
      expect(r.attempts).toEqual([])
    } finally {
      cli.cleanup()
    }
  })
})
