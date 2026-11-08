/**
 * npm page positioning (ICP.md, agenticcli repo, section 2): the npm description and the README
 * opening line (the npm package page shows packages/cli/README.md) both lead with the one line
 * "The security scanner your coding agent runs before every commit", and the package stays
 * findable under the category word "security scanner".
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
  it('description starts with the ICP one line and stays short enough for npm search', () => {
    expect(pkg.description.startsWith(ONE_LINE)).toBe(true)
    expect(pkg.description.length).toBeLessThanOrEqual(250)
  })

  it('description names what it checks and that it runs locally', () => {
    for (const w of ['secrets', 'routes', 'migrations', 'webhooks', 'deploy', 'locally']) {
      expect(pkg.description.toLowerCase(), w).toContain(w)
    }
  })

  it('README opens with the same one line', () => {
    const firstContent = readme.split('\n').filter(l => l.trim() !== '' && !l.startsWith('#'))[0]
    expect(firstContent).toContain(ONE_LINE)
  })

  it('keywords include the category word', () => {
    expect(pkg.keywords).toContain('security-scanner')
  })

  it('description makes no claim the product does not back (no "100%", no "SAST", no auto-fix)', () => {
    expect(pkg.description).not.toMatch(/100\s*%|sast|auto-?fix|cve tracker/i)
  })
})
