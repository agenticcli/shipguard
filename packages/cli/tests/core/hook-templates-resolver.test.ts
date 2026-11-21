/**
 * Hook templates must resolve the SCOPED package, never the unrelated unscoped npm `shipguard`
 *, and must never block a push without saying how to fix it.
 *
 * Behavioral: the generated shell is run with a restricted PATH and stub binaries.
 */
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { CLAUDE_HOOK_COMMAND, NPX_SPEC, gitHookScript } from '../../src/core/hook-templates.js'

const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))

/** A work dir plus a bin dir holding only the stubs asked for (plus sh basics via symlink-free PATH). */
function sandbox(stubs: { npx?: string; shipguard?: string; local?: string }) {
  const root = mkdtempSync(join(tmpdir(), 'sg-hook-resolver-'))
  roots.push(root)
  const bin = join(root, 'bin')
  const work = join(root, 'work')
  mkdirSync(bin)
  mkdirSync(join(work, 'node_modules', '.bin'), { recursive: true })
  const put = (path: string, body: string) => { writeFileSync(path, `#!/bin/sh\n${body}\n`); chmodSync(path, 0o755) }
  if (stubs.npx) put(join(bin, 'npx'), stubs.npx)
  if (stubs.shipguard) put(join(bin, 'shipguard'), stubs.shipguard)
  if (stubs.local) put(join(work, 'node_modules', '.bin', 'shipguard'), stubs.local)
  const log = join(root, 'calls.log')
  return { root, bin, work, log }
}

const run = (sb: ReturnType<typeof sandbox>, script: string, input = '') =>
  // PATH = stubs + the system dirs that hold sh/cat only; the dev box wrapper dir is not on it.
  spawnSync('/bin/sh', ['-c', script], {
    cwd: sb.work, input, encoding: 'utf-8',
    env: { PATH: `${sb.bin}:/usr/bin:/bin`, HOME: sb.root },
  })

describe('hook templates: scoped package + resolver', () => {
  it('never mentions the unscoped package or --no-install shipguard', () => {
    for (const t of [gitHookScript('pre-push'), CLAUDE_HOOK_COMMAND]) {
      expect(t).not.toMatch(/npx --no-install shipguard/)
      expect(t).not.toMatch(/npx (--yes )?shipguard\b/)
      expect(t).toContain('@agenticcli/shipguard@0')
    }
  })

  it('pinned major equals this package major', () => {
    const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf-8')) as { version: string }
    expect(NPX_SPEC).toBe(`@agenticcli/shipguard@${pkg.version.split('.')[0]}`)
  })

  it('git hook, nothing installed, npx works: runs npx --yes <scoped>@<major>, never bare shipguard', () => {
    const sb = sandbox({ npx: 'exit 0' })
    writeFileSync(join(sb.bin, 'npx'), `#!/bin/sh\necho "$@" >> ${sb.log}\nexit 0\n`)
    const r = run(sb, gitHookScript('pre-push'))
    expect(r.status).toBe(0)
    const calls = readFileSync(sb.log, 'utf-8')
    expect(calls).toContain(`--yes ${NPX_SPEC} scan --json --strict`)
    expect(calls).not.toMatch(/--no-install/)
  })

  it('git hook: local node_modules/.bin wins over PATH and npx', () => {
    const sb = sandbox({ local: 'echo local >> LOG; exit 0', shipguard: 'echo path >> LOG; exit 0', npx: 'echo npx >> LOG; exit 0' })
    writeFileSync(join(sb.work, 'node_modules', '.bin', 'shipguard'), `#!/bin/sh\necho local >> ${sb.log}\nexit 0\n`)
    const r = run(sb, gitHookScript('pre-push'))
    expect(r.status).toBe(0)
    expect(readFileSync(sb.log, 'utf-8').trim()).toBe('local')
  })

  it('git hook: a real block (exit 1 from the gate) still blocks and prints the output', () => {
    const sb = sandbox({ shipguard: 'echo FINDINGS; exit 1' })
    const r = run(sb, gitHookScript('pre-push'))
    expect(r.status).toBe(1)
    expect(r.stderr).toMatch(/blocked this: the security scan did not pass/)
    expect(r.stderr).toContain('FINDINGS')
  })

  it('git hook: neither shipguard nor a working npx: blocks WITH the fix, says nothing was scanned', () => {
    const none = sandbox({})
    const failingNpx = sandbox({ npx: 'exit 1' })
    for (const sb of [none, failingNpx]) {
      const r = run(sb, gitHookScript('pre-push'))
      expect(r.status).toBe(1)
      expect(r.stderr).toMatch(/did NOT run and nothing was scanned/)
      expect(r.stderr).toContain('npm i -D @agenticcli/shipguard')
      expect(r.stderr).toContain('npm i -g @agenticcli/shipguard')
    }
  })

  it('claude hook: gates git push, resolves via scoped npx, never bare shipguard', () => {
    const sb = sandbox({})
    writeFileSync(join(sb.bin, 'npx'), `#!/bin/sh\necho "$@" >> ${sb.log}\nexit 0\n`)
    chmodSync(join(sb.bin, 'npx'), 0o755)
    const r = run(sb, CLAUDE_HOOK_COMMAND, '{"command":"git push origin main"}')
    expect(r.status).toBe(0)
    expect(readFileSync(sb.log, 'utf-8')).toContain(`--yes ${NPX_SPEC} scan --json --strict`)
  })

  it('claude hook: nothing installed: exit 2 (blocks) with the fix message', () => {
    const sb = sandbox({})
    const r = run(sb, CLAUDE_HOOK_COMMAND, '{"command":"git push"}')
    expect(r.status).toBe(2)
    expect(r.stderr).toMatch(/did NOT run and nothing was scanned/)
    expect(r.stderr).toContain('npm i -D @agenticcli/shipguard')
  })

  it('claude hook: unrelated commands pass without resolving anything', () => {
    const sb = sandbox({})
    const r = run(sb, CLAUDE_HOOK_COMMAND, '{"command":"ls -la"}')
    expect(r.status).toBe(0)
    expect(r.stderr).toBe('')
  })
})
