/**
 * C1 regression: a dev build / source checkout must never ping production.
 *
 * Fail-before: src/core/telemetry.ts defaulted the endpoint to the prod Convex site in EVERY build,
 * so `pnpm build && node dist/cli.js scan` from a checkout (and every developer/agent run of a local
 * build) counted as real usage. Pass-after: the prod endpoint exists only in a build made with
 * SHIPGUARD_PUBLISHED_BUILD=1 (`pnpm build:publish`); a dev build sends only to a loopback URL.
 *
 * Nothing here can reach the network: see tests/helpers/recorded-cli.ts (fetch is replaced by a
 * recorder in every CLI run). The canary (published build) proves the recorder sees a real send.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { buildVariant, makeRecordedCli, type RecordedCli } from '../helpers/recorded-cli.js'
import {
  IS_PUBLISHED_BUILD,
  PROD_TELEMETRY_ENDPOINT,
  getProvenance,
  isLoopbackUrl,
  resolveEndpoint,
} from '../../src/core/telemetry.js'

vi.setConfig({ testTimeout: 60_000, hookTimeout: 120_000 })

const PROD = 'https://cheery-toucan-348.convex.site/cli-telemetry'
const ON = { SHIPGUARD_TELEMETRY: '1', DO_NOT_TRACK: '0' }

describe('resolveEndpoint (unit)', () => {
  it('this (vitest, unbundled) build is a dev build', () => {
    expect(IS_PUBLISHED_BUILD).toBe(false)
    expect(getProvenance()).toBe('dev')
    expect(getProvenance(true)).toBe('published')
  })

  it('dev build: no endpoint by default, never prod, never a remote override', () => {
    expect(resolveEndpoint(false, {})).toBeNull()
    expect(resolveEndpoint(false, { SHIPGUARD_TELEMETRY_URL: PROD })).toBeNull()
    expect(resolveEndpoint(false, { SHIPGUARD_TELEMETRY_URL: 'https://example.com/x' })).toBeNull()
    expect(resolveEndpoint(false, { SHIPGUARD_TELEMETRY_URL: 'not a url' })).toBeNull()
  })

  it('dev build: loopback override is honoured (local capture servers)', () => {
    for (const u of ['http://127.0.0.1:4000/t', 'http://localhost:4000/t', 'http://[::1]:4000/t']) {
      expect(isLoopbackUrl(u)).toBe(true)
      expect(resolveEndpoint(false, { SHIPGUARD_TELEMETRY_URL: u })).toBe(u)
    }
    // look-alike hosts are not loopback
    expect(isLoopbackUrl('http://127.0.0.1.evil.com/t')).toBe(false)
    expect(isLoopbackUrl('http://localhost.evil.com/t')).toBe(false)
  })

  it('published build: prod by default, override honoured', () => {
    expect(resolveEndpoint(true, {})).toBe(PROD_TELEMETRY_ENDPOINT)
    expect(PROD_TELEMETRY_ENDPOINT).toBe(PROD)
    expect(resolveEndpoint(true, { SHIPGUARD_TELEMETRY_URL: 'https://sink.example/t' })).toBe('https://sink.example/t')
    expect(resolveEndpoint(true, { SHIPGUARD_TELEMETRY_URL: '' })).toBe(PROD_TELEMETRY_ENDPOINT)
  })
})

describe('built CLI provenance (e2e, nothing leaves the machine)', () => {
  let devCli: RecordedCli
  let pubCli: RecordedCli

  beforeAll(() => {
    devCli = makeRecordedCli(buildVariant('dev', 'c1'))
    pubCli = makeRecordedCli(buildVariant('published', 'c1'))
  })
  afterAll(() => {
    devCli?.cleanup()
    pubCli?.cleanup()
  })

  it('canary: a PUBLISHED build with telemetry on attempts the production relay (recorder sees it)', async () => {
    const r = await pubCli.run(['scan', pubCli.project, '--json', '--quiet'], { env: ON })
    expect(r.attempts.map((a) => a.url)).toEqual([PROD, PROD]) // cli_first_run + the scan ping
  })

  it('DEV build with telemetry on and no URL attempts nothing (was: pinged prod)', async () => {
    const r = await devCli.run(['scan', devCli.project, '--json', '--quiet'], { env: ON })
    expect(r.attempts, `dev build attempted: ${r.attempts.map((a) => a.url)}`).toEqual([])
  })

  it('DEV build pointed at the production URL explicitly still attempts nothing', async () => {
    const r = await devCli.run(['scan', devCli.project, '--json', '--quiet'], {
      env: { ...ON, SHIPGUARD_TELEMETRY_URL: PROD },
    })
    expect(r.attempts).toEqual([])
  })

  it('DEV build pointed at a remote non-prod URL attempts nothing', async () => {
    const r = await devCli.run(['scan', devCli.project, '--json', '--quiet'], {
      env: { ...ON, SHIPGUARD_TELEMETRY_URL: 'https://sink.example.com/t' },
    })
    expect(r.attempts).toEqual([])
  })

  it('DEV build pointed at loopback DOES send (local capture server workflow)', async () => {
    const r = await devCli.run(['scan', devCli.project, '--json', '--quiet'], {
      env: { ...ON, SHIPGUARD_TELEMETRY_URL: 'http://127.0.0.1:1/cli-telemetry' },
    })
    expect(r.attempts.map((a) => a.url)).toEqual(['http://127.0.0.1:1/cli-telemetry', 'http://127.0.0.1:1/cli-telemetry']) // cli_first_run + the scan ping
  })
})
