/**
 * Release gate G3 must fail on a bundle with a real runtime import of a workspace package
 * (@agenticcli/*), and must NOT fail on the plain string '@agenticcli/shipguard@0' (the npx spec).
 * Guard: scripts/check-bundle-imports.mjs, called by scripts/release-gate.sh.
 */
import { describe, it, expect } from 'vitest'
import { spawnSync } from 'node:child_process'
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const GUARD = path.join(here, '..', '..', 'scripts', 'check-bundle-imports.mjs')

function runOn(content: string) {
  const dir = mkdtempSync(path.join(tmpdir(), 'sg-g3-'))
  try {
    const f = path.join(dir, 'cli.js')
    writeFileSync(f, content)
    return spawnSync(process.execPath, [GUARD, f], { encoding: 'utf-8' })
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

describe('G3 bundle-import guard', () => {
  it.each([
    ['require double', `var s = require("@agenticcli/shared");`],
    ['require single', `var s = require('@agenticcli/shared');`],
    ['esbuild __require', `var s = __require("@agenticcli/shared");`],
    ['from double', `import { x } from "@agenticcli/shared";`],
    ['from single', `import { x } from '@agenticcli/shared';`],
    ['dynamic import', `const m = await import("@agenticcli/shared");`],
    ['bare import', `import "@agenticcli/shared";`],
  ])('FAILS on a real import (%s)', (_n, src) => {
    const r = runOn(src)
    expect(r.status).toBe(1)
    expect(r.stderr).toMatch(/@agenticcli\/shared/)
  })

  it('PASSES on the string literal only (npx spec, help text)', () => {
    const r = runOn(
      `const NPX_SPEC = '@agenticcli/shipguard@0'; console.log("run: npx @agenticcli/shipguard scan"); const a = "@agenticcli/shipguard";`,
    )
    expect(r.status).toBe(0)
  })

  it('FAILS when the bundle file is missing', () => {
    expect(spawnSync(process.execPath, [GUARD, '/nonexistent/cli.js'], { encoding: 'utf-8' }).status).toBe(1)
  })
})
