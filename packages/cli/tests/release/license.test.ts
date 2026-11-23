/**
 * Licence switch (ELv2 -> Apache-2.0, owner decision 2026-11-23): the licence text is the canonical Apache-2.0 text
 * (byte-checked by SHA-256 against https://www.apache.org/licenses/LICENSE-2.0.txt), NOTICE travels in the package,
 * every package.json says Apache-2.0, and no shipped text still names the old licence.
 */
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const CLI = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const ROOT = resolve(CLI, '../..')
const read = (p: string): string => readFileSync(p, 'utf8')
const APACHE_2_0_SHA256 = 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'
const sha = (p: string): string => createHash('sha256').update(readFileSync(p)).digest('hex')

describe('Apache-2.0 licence switch', () => {
  it('LICENSE (repo root and package) is the unchanged canonical Apache-2.0 text', () => {
    expect(sha(resolve(ROOT, 'LICENSE'))).toBe(APACHE_2_0_SHA256)
    expect(sha(resolve(CLI, 'LICENSE'))).toBe(APACHE_2_0_SHA256)
  })

  it('NOTICE names AgenticCLI as copyright holder, no third-party credit, same in root and package', () => {
    const n = read(resolve(ROOT, 'NOTICE'))
    expect(n).toContain('Copyright 2026 AgenticCLI')
    expect(n).not.toMatch(/gitleaks/i)
    expect(read(resolve(CLI, 'NOTICE'))).toBe(n)
  })

  it('the three package.json files say Apache-2.0', () => {
    for (const p of ['packages/cli', 'packages/shared', 'packages/matcher-contract']) {
      expect(JSON.parse(read(resolve(ROOT, p, 'package.json'))).license, p).toBe('Apache-2.0')
    }
  })

  it('the npm package ships LICENSE and NOTICE', () => {
    const files: string[] = JSON.parse(read(resolve(CLI, 'package.json'))).files
    expect(files).toContain('LICENSE')
    expect(files).toContain('NOTICE')
  })

  it('CITATION.cff says Apache-2.0', () => {
    expect(read(resolve(ROOT, 'CITATION.cff'))).toMatch(/^license: Apache-2\.0$/m)
  })

  it('TRADEMARKS.md exists and names both marks', () => {
    expect(existsSync(resolve(ROOT, 'TRADEMARKS.md'))).toBe(true)
    const t = read(resolve(ROOT, 'TRADEMARKS.md'))
    expect(t).toContain('ShipGuard')
    expect(t).toContain('AgenticCLI')
  })

  it('CONTRIBUTING has the sign-off text and the Pro-rules rule', () => {
    const c = read(resolve(ROOT, 'CONTRIBUTING.md'))
    expect(c).toContain('Developer Certificate of Origin')
    expect(c).toContain('Pro rules never enter this repo')
  })

  it('no shipped text still names the old licence (history in the CHANGELOG and frozen fixtures excepted)', () => {
    const files = [
      'README.md', 'CONTRIBUTING.md', 'CITATION.cff', 'docs/faq.md', 'docs/privacy.md',
      'packages/cli/README.md', 'packages/cli/docs/llms.txt', 'packages/cli/package.json',
      'packages/shared/package.json', 'packages/matcher-contract/package.json',
      'packages/matcher-contract/src/adapters/re2js-v1.ts', 'packages/cli/scripts/gen-cli-facts.mjs',
    ]
    for (const f of files) expect(read(resolve(ROOT, f)), f).not.toMatch(/elastic|elv2|source[- ]available/i)
  })
})
