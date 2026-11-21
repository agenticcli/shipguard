import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'

// Copy guard: user-visible ShipGuard copy must not use banned words (regex only, no network).
const CLI = resolve(__dirname, '..', '..')
const ROOT = resolve(CLI, '..', '..')

const BANNED: Array<[string, RegExp]> = [
  ['release gate', /\brelease[ -]gate\b/i],
  ['cloud scan', /\bcloud[ -]scans?\b/i],
  ['on our servers', /\bon our servers\b/i],
  ['secure-ship', /\bsecure-ship\b/i],
  ['harness', /\bharness\b/i],
  ['vibe', /\bvibe\b/i],
  ['free forever', /\bfree forever\b/i],
  ['AI-powered', /\bAI-powered\b/i],
  ['open source', /\bopen[- ]source\b/i],
  ['quality gate', /\bquality gate\b/i],
]
// A line may say ShipGuard is not an OSI-approved open source license.
const ALLOW: Record<string, RegExp> = { 'open source': /not an OSI-approved/i }

/** Return only the string literals of a TS file (comments dropped). */
export function stringLiterals(src: string): string[] {
  const out: string[] = []
  let i = 0
  while (i < src.length) {
    const c = src[i]
    if (c === '/' && src[i + 1] === '/') { while (i < src.length && src[i] !== '\n') i++; continue }
    if (c === '/' && src[i + 1] === '*') { const e = src.indexOf('*/', i + 2); i = e < 0 ? src.length : e + 2; continue }
    if (c === "'" || c === '"' || c === '`') {
      let j = i + 1
      let buf = ''
      while (j < src.length && src[j] !== c) {
        if (src[j] === '\\') { buf += src[j + 1] ?? ''; j += 2; continue }
        if (c !== '`' && src[j] === '\n') break
        buf += src[j]; j++
      }
      out.push(buf)
      i = j + 1
      continue
    }
    i++
  }
  return out
}

function hits(label: string, text: string): string[] {
  const found: string[] = []
  for (const line of text.split('\n')) {
    for (const [name, re] of BANNED) {
      if (re.test(line) && !(ALLOW[name]?.test(line))) found.push(`${label}: "${name}" in: ${line.trim().slice(0, 100)}`)
    }
  }
  return found
}

const docFiles = (dir: string, ext: string) =>
  readdirSync(dir).filter((f) => f.endsWith(ext)).map((f) => join(dir, f))

describe('copy: banned words', () => {
  const textFiles = [
    join(ROOT, 'README.md'),
    join(CLI, 'README.md'),
    ...docFiles(join(ROOT, 'docs'), '.md'),
    join(ROOT, 'CITATION.cff'),
  ]
  for (const f of textFiles) {
    it(`no banned words in ${f.replace(ROOT + '/', '')}`, () => {
      expect(hits(f, readFileSync(f, 'utf8'))).toEqual([])
    })
  }

  it('no banned words in package.json description and keywords', () => {
    const pkg = JSON.parse(readFileSync(join(CLI, 'package.json'), 'utf8'))
    const text = [pkg.description, ...pkg.keywords].join('\n')
    expect(hits('package.json', text)).toEqual([])
  })

  const srcFiles = [
    join(CLI, 'src/cli.ts'),
    ...docFiles(join(CLI, 'src/commands'), '.ts'),
    join(CLI, 'src/core/render.ts'),
    join(CLI, 'src/core/hook-templates.ts'),
  ]
  for (const f of srcFiles) {
    it(`no banned words in strings of ${f.replace(ROOT + '/', '')}`, () => {
      const text = stringLiterals(readFileSync(f, 'utf8')).join('\n')
      expect(hits(f, text)).toEqual([])
    })
  }
})
