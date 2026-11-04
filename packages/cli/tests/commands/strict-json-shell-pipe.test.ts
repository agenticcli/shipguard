/**
 * QA (2026-11-02, qa-final on ed3a6ae9): BUG 2 through a REAL shell pipe.
 *
 * B12/B13 hold the socket pair a spawned child gets (about 200 KB of buffer). A CI job runs
 * `shipguard scan --json --strict | jq ...` through a bash pipe (64 KiB on Linux). This test runs
 * exactly that shape: the CLI writes about 580 KB of JSON into a bash pipe whose reader sleeps 5 s
 * before it reads anything. The old code called process.exit(1) with most of the document still
 * queued, so the reader got a cut, unparseable document. The fixed code only sets the exit code, so
 * the reader gets the whole document and the CLI still exits 1 (PIPESTATUS[0]).
 *
 * Fail-before: run with utils/exit.ts setExitCode mutated to call process.exit (QA mutation M10a).
 */
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { cleanupTrees, cliPath, pkgRoot, scanJson } from '../helpers/cli-fixture.js'
import { mkBigFindingsTree } from '../helpers/pipe-fixture.js'

vi.setConfig({ testTimeout: 90_000 })
const outDirs: string[] = []
afterAll(() => {
  cleanupTrees()
  for (const d of outDirs) rmSync(d, { recursive: true, force: true })
})

function runThroughSlowShellPipe(args: string[]): Promise<{ cliCode: number; out: Buffer; stderr: string }> {
  const outDir = mkdtempSync(join(tmpdir(), 'sg-shellpipe-'))
  outDirs.push(outDir)
  const outFile = join(outDir, 'stdout.json')
  return new Promise((resolveRun, reject) => {
    // The reader sleeps before reading: the CLI must wait for it (pipe back-pressure), never drop data.
    const script = '"$NODE" "$0" "$@" | { sleep 5; cat > "$OUT_FILE"; }; echo "CLI_EXIT=${PIPESTATUS[0]}" >&2'
    const child = spawn('bash', ['-c', script, cliPath(), ...args], {
      cwd: pkgRoot,
      env: { ...process.env, NODE: process.execPath, OUT_FILE: outFile },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let err = ''
    child.stderr.setEncoding('utf-8').on('data', (d: string) => { err += d })
    child.stdout.resume()
    const killer = setTimeout(() => child.kill('SIGKILL'), 60_000)
    child.on('error', reject)
    child.on('close', () => {
      clearTimeout(killer)
      const m = err.match(/CLI_EXIT=(\d+)/)
      resolveRun({ cliCode: m ? Number(m[1]) : -1, out: readFileSync(outFile), stderr: err })
    })
  })
}

describe.skipIf(process.platform === 'win32')('QA: strict JSON through a slow bash pipe (64 KiB pipe buffer)', () => {
  it('--json --strict: the reader gets the whole document and the CLI exits 1', async () => {
    const dir = mkBigFindingsTree(120)
    const expected = (await scanJson(dir)).json!.findings.length
    expect(expected).toBeGreaterThan(100)

    const run = await runThroughSlowShellPipe(['scan', dir, '--json', '--strict'])
    expect(run.out.length, run.stderr.slice(0, 300)).toBeGreaterThan(4 * 65_536)
    const parsed = JSON.parse(run.out.toString('utf-8'))
    expect(parsed.findings.length).toBe(expected)
    expect(parsed.schemaVersion).toBe('6')
    expect(run.cliCode).toBe(1)
  })

  it('--sarif --strict: the reader gets the whole SARIF document and the CLI exits 1', async () => {
    const dir = mkBigFindingsTree(120)
    const run = await runThroughSlowShellPipe(['scan', dir, '--sarif', '--strict'])
    expect(run.out.length, run.stderr.slice(0, 300)).toBeGreaterThan(65_536)
    const sarif = JSON.parse(run.out.toString('utf-8'))
    expect(sarif.runs[0].results.length).toBeGreaterThan(100)
    expect(run.cliCode).toBe(1)
  })
})
