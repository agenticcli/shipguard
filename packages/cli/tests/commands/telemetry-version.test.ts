/**
 * Telemetry cliVersion single-source regression.
 *
 * Symptom: commands/scan.ts hardcoded `cliVersion: '0.1.2'` in the telemetry
 * payload, independent of package.json (which had moved to 0.2.0). Every
 * telemetry row therefore mislabeled the CLI version — the same single-source
 * drift class as the --version literal, just in the
 * telemetry call-site instead of the program.version() call.
 *
 * Fix: source the telemetry cliVersion from the injected __SHIPGUARD_VERSION__
 * (the same build-time single source already used by cli.ts), so it always
 * equals package.json.
 *
 * DISCIPLINE: behavioral — spawn the BUILT binary, point its telemetry
 * endpoint at a throwaway local HTTP server, capture the POST body, and assert
 * the payload cliVersion === package.json version. A source-guard backs it up
 * so the literal can never silently return.
 */
import { spawnSync, execSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { createServer, type Server } from 'node:http'
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'

// Real-process e2e file: every test spawns the built CLI (each spawn ~0.3-1s idle, several x
// under load). Vitest's 5s default is below the cost of a 3-4 spawn test on a shared box, so
// state the budget explicitly (same 30s as the per-spawn kill timeout), file-scoped - not global.
vi.setConfig({ testTimeout: 30_000 })

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')
const cliSource = readFileSync(resolve(pkgRoot, 'src/commands/scan.ts'), 'utf-8')
const pkgVersion = JSON.parse(
  readFileSync(resolve(pkgRoot, 'package.json'), 'utf-8'),
).version as string

const tempDirs: string[] = []
function mkProjectFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-telemetry-version-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(join(dir, 'app.js'), 'const x = 1\n', 'utf-8')
  return dir
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
})

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 120_000)

/** Spin a one-shot HTTP server that captures the first POST body, returns it. */
function captureTelemetry(args: string[]): Promise<{ body: Record<string, unknown> | null }> {
  return new Promise((resolvePromise) => {
    let captured: Record<string, unknown> | null = null
    const server: Server = createServer((req, res) => {
      let data = ''
      req.on('data', (c) => (data += c))
      req.on('end', () => {
        try {
          captured = JSON.parse(data)
        } catch {
          captured = null
        }
        res.statusCode = 200
        res.end('ok')
      })
    })
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      const fixture = mkProjectFixture()
      // Run the scan with telemetry pointed at our local capture server.
      spawnSync('node', [distCli, 'scan', fixture, ...args], {
        cwd: pkgRoot,
        encoding: 'utf-8',
        timeout: 30_000,
        env: {
          ...process.env,
          SHIPGUARD_TELEMETRY_URL: `http://127.0.0.1:${port}/cli-telemetry`,
          // Ensure opt-out env from the harness does not suppress the ping.
          SHIPGUARD_TELEMETRY: '1',
          DO_NOT_TRACK: '0',
        },
      })
      // Telemetry is fire-and-forget with a 1s timeout; give it a moment.
      setTimeout(() => {
        server.close(() => resolvePromise({ body: captured }))
      }, 1500)
    })
  })
}

describe('telemetry cliVersion is sourced from package.json ', () => {
  it('the telemetry POST body cliVersion equals package.json version', async () => {
    const { body } = await captureTelemetry(['--quiet'])
    expect(body).not.toBeNull()
    expect(body!.cliVersion).toBe(pkgVersion)
    // Guard against the exact stale literal that caused the drift.
    expect(body!.cliVersion).not.toBe('0.1.2')
  }, 20_000)

  it('source guard: scan.ts does NOT hardcode a semver in the telemetry cliVersion', () => {
    // The exact regression pattern: cliVersion: '1.2.3' literal in source.
    const hardcoded = /cliVersion:\s*['"][0-9]+\.[0-9]+\.[0-9]+['"]/
    expect(
      hardcoded.test(cliSource),
      'REGRESSION: scan.ts hardcodes a semver literal for telemetry cliVersion. ' +
        'Use the injected __SHIPGUARD_VERSION__ single source. Incident 148d6876.',
    ).toBe(false)
  })

  it('source guard: scan.ts references __SHIPGUARD_VERSION__ for the telemetry version', () => {
    expect(
      cliSource,
      'scan.ts must source the telemetry cliVersion from __SHIPGUARD_VERSION__ (build-time single source).',
    ).toContain('__SHIPGUARD_VERSION__')
  })
})
