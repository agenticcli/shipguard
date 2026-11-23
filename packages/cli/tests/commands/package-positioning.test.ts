/**
 * npm page positioning: the README opening line (the npm package page shows packages/cli/README.md) leads
 * with the one line "The security scanner your coding agent runs before every commit"; the npm description
 * leads with "Open source CLI" (licence switch, owner decision 2026-11-23); the package stays findable under
 * the category word "security scanner".
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const pkg = JSON.parse(readFileSync(resolve(pkgRoot, 'package.json'), 'utf8'))
const readme = readFileSync(resolve(pkgRoot, 'README.md'), 'utf8')
const ONE_LINE = 'The security scanner your coding agent runs before every commit.'

describe('npm package positioning', () => {
  // Owner decision 2026-11-23 (licence switch, Apache-2.0): the npm description leads with "Open source CLI"
  // (plan option 1), not the ICP one line. The README still opens with the ICP one line.
  it('description says open source CLI, stays short enough for npm search', () => {
    expect(pkg.description.startsWith('Open source CLI that scans AI-written code')).toBe(true)
    expect(pkg.description.length).toBeLessThanOrEqual(250)
  })

  it('description names what it checks and the agents it is for', () => {
    for (const w of ['secrets', 'auth', 'webhook', 'deploy', 'claude code', 'codex', 'cursor']) {
      expect(pkg.description.toLowerCase(), w).toContain(w)
    }
  })

  it('README opens with the same one line', () => {
    const firstContent = readme.split('\n').filter(l => l.trim() !== '' && !l.startsWith('#'))[0]
    expect(firstContent).toContain(ONE_LINE)
  })

  it('keywords include the category word', () => {
    expect(pkg.keywords).toContain('security-scanner')
    expect(pkg.keywords).toContain('open-source')
  })

  it('description makes no claim the product does not back (no "100%", no "SAST", no auto-fix)', () => {
    expect(pkg.description).not.toMatch(/100\s*%|sast|auto-?fix|cve tracker/i)
  })
})
