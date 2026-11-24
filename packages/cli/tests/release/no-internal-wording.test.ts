// The source is public (and the package ships source maps), so comments must read for outside readers:
// no references to internal specs, build streams, work-package codes, review rounds or owner decisions.
// Fail-before / pass-after for the 0.13.1 wording cleanup.
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const SRC = join(__dirname, '..', '..', 'src')
const walk = (d: string): string[] =>
  readdirSync(d).flatMap((n) => {
    const p = join(d, n)
    return statSync(p).isDirectory() ? walk(p) : p.endsWith('.ts') ? [p] : []
  })

const INTERNAL = [
  /\bspec \d{2}\b/i,
  /OUTPUT-SPEC/,
  /owner decision/i,
  /judge R\d/i,
  /\bplan A\d\b/,
  /\bW\d[a-z]?\b(?! ?[=:(),])/,
  /\bP0 STUB\b/,
  /plan section \d/i,
  /\bdesign \d\.\d\b/,
  /for every stream|their own streams|every stream uses/,
]

describe('public source comments carry no internal wording', () => {
  it('no comment line in src/ matches an internal-process pattern', () => {
    const hits: string[] = []
    for (const file of walk(SRC)) {
      readFileSync(file, 'utf-8').split('\n').forEach((line, i) => {
        if (!/^\s*(\/\/|\/\*|\*)/.test(line)) return
        for (const re of INTERNAL) if (re.test(line)) hits.push(`${file.slice(SRC.length + 1)}:${i + 1}: ${line.trim().slice(0, 100)}`)
      })
    }
    expect(hits).toEqual([])
  })
})
