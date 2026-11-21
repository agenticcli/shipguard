/**
 * Run ping schema 5 (v4 + gateKind): coding-agent label, interactive flag, output kind,
 * the agenticcli.dev endpoint, and the `telemetry` on/off state. fetch is always stubbed: nothing here
 * can send a real ping.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  AGENT_MARKERS,
  NOTICE_TEXT,
  OTHER_AGENT_MARKERS,
  PROD_TELEMETRY_ENDPOINT,
  TELEMETRY_AGENTS,
  TELEMETRY_OUTPUTS,
  buildPayload,
  detectAgent,
  resolveEndpoint,
  sendTelemetry,
  telemetryState,
  validatePayload,
  type TelemetryPayload,
} from '../../src/core/telemetry.js'

const GOOD: TelemetryPayload = {
  schema: 5,
  eventId: '3f2b6c1e-8a4d-4e0b-9c77-5d1f0a2b3c4d',
  installId: '7b1e4f52-0c3a-4d8e-a1b6-92f3c5d7e801',
  cliVersion: '0.12.0',
  provenance: 'published',
  verdict: 'safe',
  durationBucket: 'lt1s',
  ci: false,
  agent: 'none',
  interactive: true,
  output: 'human',
  gateKind: 'none',
}

describe('detectAgent (env markers, presence only)', () => {
  const matrix: Array<[string, NodeJS.ProcessEnv, string]> = [
    ['claude_code via CLAUDECODE', { CLAUDECODE: '1' }, 'claude_code'],
    ['claude_code via CLAUDE_CODE_ENTRYPOINT', { CLAUDE_CODE_ENTRYPOINT: 'cli' }, 'claude_code'],
    ['codex via CODEX_SANDBOX', { CODEX_SANDBOX: 'seatbelt' }, 'codex'],
    ['codex via CODEX_SANDBOX_NETWORK_DISABLED', { CODEX_SANDBOX_NETWORK_DISABLED: '1' }, 'codex'],
    ['cursor via CURSOR_AGENT', { CURSOR_AGENT: '1' }, 'cursor'],
    ['gemini_cli via GEMINI_CLI', { GEMINI_CLI: '1' }, 'gemini_cli'],
    ['copilot via COPILOT_CLI', { COPILOT_CLI: '1' }, 'copilot'],
    ['copilot via COPILOT_AGENT_RUNNER_TYPE', { COPILOT_AGENT_RUNNER_TYPE: 'x' }, 'copilot'],
    ['opencode via OPENCODE', { OPENCODE: '1' }, 'opencode'],
    ['unknown agent AI_AGENT', { AI_AGENT: 'some-new-agent' }, 'other_agent'],
    ['unknown agent AGENT', { AGENT: 'amp' }, 'other_agent'],
    ['unknown agent GOOSE_TERMINAL', { GOOSE_TERMINAL: '1' }, 'other_agent'],
    ['no markers', {}, 'none'],
    ['unrelated env only', { PATH: '/bin', HOME: '/home/x', CI: 'true' }, 'none'],
    ['empty marker value is not a marker', { CLAUDECODE: '', AI_AGENT: '' }, 'none'],
    ['a specific agent beats the generic marker', { AI_AGENT: 'claude-code_2', CLAUDECODE: '1' }, 'claude_code'],
    ['CURSOR_TRACE_ID (set for humans too) is not a marker', { CURSOR_TRACE_ID: 'abc' }, 'none'],
    ['CODEX_HOME (user config) is not a marker', { CODEX_HOME: '/x' }, 'none'],
  ]
  it.each(matrix)('%s', (_name, env, want) => {
    expect(detectAgent(env)).toBe(want)
  })

  it('every marker row maps to a contract enum value, and every enum value is reachable', () => {
    const labels = new Set<string>([...AGENT_MARKERS.map(([a]) => a), 'other_agent', 'none'])
    expect([...labels].sort()).toEqual([...TELEMETRY_AGENTS].sort())
    expect(OTHER_AGENT_MARKERS.length).toBeGreaterThan(0)
  })

  it('the enums are exactly the contract values', () => {
    expect([...TELEMETRY_AGENTS]).toEqual(['claude_code', 'codex', 'cursor', 'gemini_cli', 'copilot', 'opencode', 'other_agent', 'none'])
    expect([...TELEMETRY_OUTPUTS]).toEqual(['json', 'human', 'sarif'])
  })
})

describe('schema 5 payload', () => {
  it('has exactly the 12 contract keys (+ optional traffic) and nothing else', () => {
    const leaky = { ...GOOD, agentValue: 'claude-code_2-1-322', cwd: '/home/x' } as unknown as TelemetryPayload
    expect(Object.keys(buildPayload(leaky)).sort()).toEqual(
      ['agent', 'ci', 'cliVersion', 'durationBucket', 'eventId', 'gateKind', 'installId', 'interactive', 'output', 'provenance', 'schema', 'verdict'],
    )
    expect(validatePayload(GOOD)).toBe(true)
    expect(validatePayload({ ...GOOD, traffic: 'test' })).toBe(true)
    expect(validatePayload({ ...GOOD, extra: 1 })).toBe(false)
  })

  it.each(['agent', 'interactive', 'output', 'gateKind'])('missing %s is rejected', (k) => {
    const copy: Record<string, unknown> = { ...GOOD }
    delete copy[k]
    expect(validatePayload(copy)).toBe(false)
  })

  it('validates every enum value and rejects unknown ones', () => {
    for (const agent of TELEMETRY_AGENTS) expect(validatePayload({ ...GOOD, agent })).toBe(true)
    for (const output of TELEMETRY_OUTPUTS) expect(validatePayload({ ...GOOD, output })).toBe(true)
    for (const bad of ['Claude_Code', 'claude', 'cursor ', '', 'cloud', null, 1, undefined]) {
      expect(validatePayload({ ...GOOD, agent: bad })).toBe(false)
    }
    for (const bad of ['JSON', 'text', 'quiet', '', null, 0]) expect(validatePayload({ ...GOOD, output: bad })).toBe(false)
    expect(validatePayload({ ...GOOD, interactive: 'true' })).toBe(false)
    expect(validatePayload({ ...GOOD, interactive: 1 })).toBe(false)
  })

  it('schema 2 and 3 are not a valid run ping any more', () => {
    expect(validatePayload({ ...GOOD, schema: 2 })).toBe(false)
    expect(validatePayload({ ...GOOD, schema: 3 })).toBe(false)
  })
})

describe('endpoint', () => {
  it('is the agenticcli.dev relay route, and a published build uses it by default', () => {
    expect(PROD_TELEMETRY_ENDPOINT).toBe('https://agenticcli.dev/api/cli-telemetry')
    expect(resolveEndpoint(true, {})).toBe('https://agenticcli.dev/api/cli-telemetry')
  })
  it('never names the old Convex host', () => {
    expect(PROD_TELEMETRY_ENDPOINT).not.toContain('convex')
  })
})

describe('sendTelemetry sends schema 5 with the detected agent', () => {
  let dir: string
  let fetchMock: ReturnType<typeof vi.fn>
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sg-tel-v4-'))
    fetchMock = vi.fn().mockResolvedValue({ ok: true })
    vi.stubGlobal('fetch', fetchMock)
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })
  const input = { cliVersion: '0.12.0', verdict: 'safe' as const, durationMs: 10, output: 'sarif' as const }
  const body = () => JSON.parse((fetchMock.mock.calls[0] as [string, { body: string }])[1].body)

  it('posts to the new endpoint with agent, interactive and output; never the marker value', async () => {
    await sendTelemetry(input, {
      published: true,
      env: { CURSOR_AGENT: '1', AI_AGENT: 'secret-looking-value-123' },
      configDir: dir,
      interactive: true,
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0]).toBe('https://agenticcli.dev/api/cli-telemetry')
    expect(body()).toMatchObject({ schema: 5, agent: 'cursor', interactive: true, output: 'sarif' })
    expect(JSON.stringify(body())).not.toContain('secret-looking-value-123')
  })

  it('no agent env -> "none"; unknown agent env -> "other_agent"', async () => {
    await sendTelemetry(input, { published: true, env: {}, configDir: dir, interactive: false })
    expect(body()).toMatchObject({ agent: 'none', interactive: false })
    fetchMock.mockClear()
    await sendTelemetry(input, { published: true, env: { AI_AGENT: 'brand-new' }, configDir: dir, interactive: false })
    expect(body()).toMatchObject({ agent: 'other_agent' })
  })

  it('interactive defaults to whether stdout is a terminal', async () => {
    const was = process.stdout.isTTY
    try {
      Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true })
      await sendTelemetry(input, { published: true, env: {}, configDir: dir })
      expect(body().interactive).toBe(true)
      fetchMock.mockClear()
      Object.defineProperty(process.stdout, 'isTTY', { value: undefined, configurable: true })
      await sendTelemetry(input, { published: true, env: {}, configDir: dir })
      expect(body().interactive).toBe(false)
    } finally {
      Object.defineProperty(process.stdout, 'isTTY', { value: was, configurable: true })
    }
  })

  it('a failing endpoint is ignored: no throw, no retry, no fallback host', async () => {
    fetchMock.mockRejectedValue(new Error('down'))
    await expect(sendTelemetry(input, { published: true, env: {}, configDir: dir })).resolves.toBeUndefined()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('telemetryState (the JSON `telemetry` field)', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sg-tel-state-'))
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })
  it('on by default', () => {
    expect(telemetryState({ env: {}, configDir: dir })).toBe('on')
  })
  it.each([
    ['SHIPGUARD_TELEMETRY=0', { SHIPGUARD_TELEMETRY: '0' }],
    ['DO_NOT_TRACK=1', { DO_NOT_TRACK: '1' }],
  ])('off with %s', (_n, env) => {
    expect(telemetryState({ env, configDir: dir })).toBe('off')
  })
  it('off when the project policy opts out', () => {
    expect(telemetryState({ env: {}, configDir: dir, policy: { telemetry: { enabled: false } } })).toBe('off')
  })
})

describe('first-run notice line', () => {
  it('says usage pings: on, how to turn them off, the new fields, and no "cloud"', () => {
    expect(NOTICE_TEXT.split('\n')).toHaveLength(1)
    expect(NOTICE_TEXT).toContain('usage pings on:')
    expect(NOTICE_TEXT).toContain('Off: shipguard telemetry disable')
    for (const s of ['verdict', 'terminal', 'which agent or gate ran it', 'never code, paths or your account']) expect(NOTICE_TEXT).toContain(s)
    expect(NOTICE_TEXT.toLowerCase()).not.toContain('cloud')
  })
})
