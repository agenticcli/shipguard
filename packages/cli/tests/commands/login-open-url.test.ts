import { describe, it, expect, vi, beforeEach } from 'vitest'

// Regression: `shipguard login` used to pass the server-supplied verification_uri to
// child_process.exec() inside double quotes, so `$(...)`, backticks, `"` and `;` were run by
// /bin/sh. The URI must reach the OS opener as ONE argv element, never through a shell.
const exec = vi.fn()
const execSync = vi.fn()
const spawnCalls: Array<{ cmd: string; args: readonly string[]; opts: Record<string, unknown> }> = []
const execFileCalls: Array<{ cmd: string; args: readonly string[]; opts: Record<string, unknown> }> = []

vi.mock('node:child_process', () => {
  const fakeChild = () => ({ on: vi.fn(), unref: vi.fn() })
  return {
    exec: (...a: unknown[]) => exec(...a),
    execSync: (...a: unknown[]) => execSync(...a),
    spawn: (cmd: string, args: readonly string[], opts: Record<string, unknown>) => {
      spawnCalls.push({ cmd, args, opts: opts ?? {} })
      return fakeChild()
    },
    execFile: (cmd: string, args: readonly string[], opts: Record<string, unknown>, cb?: () => void) => {
      execFileCalls.push({ cmd, args, opts: (typeof opts === 'object' ? opts : {}) ?? {} })
      if (typeof opts === 'function') (opts as () => void)()
      else if (cb) cb()
      return fakeChild()
    },
  }
})
vi.mock('../../src/core/auth.js', () => ({ saveCredentials: vi.fn(), clearCredentials: vi.fn() }))

const { loginCommand } = await import('../../src/commands/login.js')

function mockDeviceFlow(verification_uri: string) {
  global.fetch = vi.fn()
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({ device_code: 'dc', user_code: 'ABCD-1234', verification_uri, expires_in: 300, interval: 0.01 }),
    })
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({ access_token: 't', refresh_token: 'r', expires_in: 900 }),
    }) as unknown as typeof fetch
}

const launches = () => [...spawnCalls, ...execFileCalls]

describe('login: opening the verification URI', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    spawnCalls.length = 0
    execFileCalls.length = 0
  })

  it.each([
    ['command substitution', 'https://agenticcli.dev/$(touch${IFS}/tmp/pwned)'],
    ['backticks', 'https://agenticcli.dev/`touch${IFS}/tmp/pwned`'],
    ['quote break-out + semicolon', 'https://agenticcli.dev/";touch${IFS}/tmp/pwned;"'],
  ])('never runs a shell for a URI with %s', async (_n, uri) => {
    mockDeviceFlow(uri)
    await loginCommand().parseAsync(['node', 'login'])
    expect(exec).not.toHaveBeenCalled()
    expect(execSync).not.toHaveBeenCalled()
    for (const l of launches()) {
      expect(l.opts.shell).toBeFalsy()
      // the URI is a single argv element, never concatenated into a command string
      expect(l.args.filter((a) => a.includes('touch'))).toHaveLength(1)
      expect(l.cmd).not.toMatch(/touch|\$\(|;/)
    }
    expect(launches().length).toBeGreaterThan(0)
  })

  it.each([
    'file:///etc/passwd',
    'javascript:alert(1)',
    'ftp://x.example/a',
    'http://evil.example/activate', // plaintext to a non-loopback host
    'https://evil.example/activate', // https, but not the API host
    'not a url; touch /tmp/pwned',
    '--help',
    'https://agenticcli.dev/$(touch /tmp/pwned)', // whitespace in the URI
  ])('refuses to open %s but still prints the code and completes login', async (uri) => {
    mockDeviceFlow(uri)
    await loginCommand().parseAsync(['node', 'login'])
    expect(exec).not.toHaveBeenCalled()
    expect(launches()).toHaveLength(0)
  })

  it.each(['https://agenticcli.dev/activate', 'http://localhost:3000/activate', 'http://127.0.0.1:3000/activate'])(
    'opens allowed URI %s',
    async (uri) => {
      mockDeviceFlow(uri)
      await loginCommand().parseAsync(['node', 'login'])
      const l = launches()
      expect(l).toHaveLength(1)
      expect(l[0].args.join(' ')).toContain(new URL(uri).href)
    },
  )
})
