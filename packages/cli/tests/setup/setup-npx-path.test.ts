/**
 * A-10 (2026-11-22 e2e): `npx -p <pkg> shipguard setup` puts a temporary `shipguard` on PATH. Setup took it for a PATH
 * install ("found on PATH ... a push does not need the network") and planned no exact pin; once npx exited, every push
 * fell back to the npx network download. A runner's temp folder is never an install: the plan adds the exact-pinned
 * devDependency instead.
 */
import { execFileSync, spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { findShipguardOnPath } from '../../src/commands/setup.js'

vi.setConfig({ testTimeout: 60_000 })

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')
beforeAll(() => {
  if (!existsSync(distCli)) execFileSync('npx', ['tsup'], { cwd: pkgRoot, stdio: 'inherit' })
}, 240_000)

const roots: string[] = []
afterAll(() => roots.forEach((d) => rmSync(d, { recursive: true, force: true })))
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'sg-npxpath-'))
  roots.push(d)
  return d
}
const stub = (dir: string): string => {
  mkdirSync(dir, { recursive: true })
  const f = join(dir, 'shipguard')
  writeFileSync(f, '#!/bin/sh\necho 0.13.0\n')
  chmodSync(f, 0o755)
  return f
}

describe('findShipguardOnPath', () => {
  it('skips the temporary folders of npx, pnpm dlx, yarn dlx and bunx, and finds a real install after them', () => {
    const root = tmp()
    const temps = ['/home/u/.npm/_npx/ab12cd/node_modules/.bin', '/home/u/.cache/pnpm/dlx/x/node_modules/.bin', '/tmp/dlx-1234/node_modules/.bin', '/tmp/xfs-abcd/dlx/.bin', '/tmp/bunx-1000-shipguard/node_modules/.bin'].map((d) => join(root, d))
    temps.forEach(stub)
    expect(findShipguardOnPath({ PATH: temps.join(':') })).toBeNull()
    const real = stub(join(root, 'usr', 'local', 'bin'))
    expect(findShipguardOnPath({ PATH: [...temps, join(root, 'usr', 'local', 'bin')].join(':') })).toBe(real)
    expect(findShipguardOnPath({ PATH: '' })).toBeNull()
  })
})

describe('setup run the way npx runs it', () => {
  it('a shipguard only in the npx temp folder is not "found on PATH": the plan pins the exact version as a devDependency', () => {
    const root = tmp()
    stub(join(root, '.npm', '_npx', 'ab12cd', 'node_modules', '.bin'))
    const project = join(root, 'proj')
    mkdirSync(project)
    execFileSync('git', ['init', '-q'], { cwd: project })
    writeFileSync(join(project, 'package.json'), '{"name":"p","version":"1.0.0"}\n')
    const r = spawnSync(process.execPath, [distCli, 'setup', '--agent', 'claude', '--dry-run'], {
      cwd: project,
      encoding: 'utf-8',
      env: { ...process.env, HOME: root, SHIPGUARD_TELEMETRY: 'off', DO_NOT_TRACK: '1', PATH: `${join(root, '.npm', '_npx', 'ab12cd', 'node_modules', '.bin')}:${dirname(process.execPath)}:/usr/bin:/bin` },
    })
    const out = `${r.stdout}${r.stderr}`
    expect(out).not.toContain('found on PATH')
    expect(out).not.toContain('a push does not need the network')
    expect(out).toMatch(/not installed in this project[\s\S]*exact-pinned devDependency/)
    expect(out).toContain('This will change 7 files')
  })
})
