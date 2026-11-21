/**
 * network-calls-listed.test.ts - REBUILD.md promises a list of every network call with file names.
 * Any source file that calls fetch( must be named in that table, so a new call cannot ship unlisted.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const SRC = join(CLI_DIR, 'src')
const doc = readFileSync(join(CLI_DIR, '..', '..', 'REBUILD.md'), 'utf-8')

const walk = (d: string): string[] =>
  readdirSync(d).flatMap((n) => {
    const p = join(d, n)
    return statSync(p).isDirectory() ? walk(p) : p.endsWith('.ts') ? [p] : []
  })

describe('REBUILD.md network-call list', () => {
  it('names every source file that calls fetch( or a node http client', () => {
    const callers = walk(SRC).filter((f) => /(^|[^.\w])fetch\(|https?\.request\(|net\.connect\(/.test(
      readFileSync(f, 'utf-8').split('\n').filter((l) => !/^\s*(\*|\/\/)/.test(l)).join('\n')))
    expect(callers.length).toBeGreaterThan(5)
    for (const f of callers) {
      const rel = relative(CLI_DIR, f)
      expect(doc, `${rel} makes a network call but is not listed in REBUILD.md`).toContain('`' + rel + '`')
    }
  })
})
