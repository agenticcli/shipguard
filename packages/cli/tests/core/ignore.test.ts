/**
 * B18 (unit): the one shared ignore helper. `classifyIgnored` must agree with fast-glob's own
 * `ignore` handling (which is what the full scan uses), so the `--changed` filter and the full
 * scan can never drift apart again.
 */
import { describe, it, expect, afterAll } from 'vitest'
import fg from 'fast-glob'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { buildIgnoreRules, buildIgnorePatterns, classifyIgnored } from '../../src/core/ignore.js'

const FILES = [
  'a.log',
  'sub/b.log',
  'docs/a/b.js',
  'docs/x.md',
  'secrets/k.env',
  'node_modules/p/i.js',
  'sub/node_modules/p/j.js',
  '.hidden/x.js',
  '.env',
  'vendor/v.js',
  'sub/vendor/w.js',
  'pnpm-lock.yaml',
  'sub/pnpm-lock.yaml',
  'src/app.min.js',
  'x.min.js',
  'src/index.ts',
  'logo.png',
  'dist/out.js',
  'tmp/t.js',
]

const root = mkdtempSync(join(tmpdir(), 'sg-ignore-'))
for (const f of FILES) {
  mkdirSync(dirname(join(root, f)), { recursive: true })
  writeFileSync(join(root, f), 'x\n')
}
afterAll(() => rmSync(root, { recursive: true, force: true }))

const policy = (paths: string[]) => ({ ignore: { paths }, report: {}, history: {} }) as never

async function viaFastGlob(patterns: string[]): Promise<string[]> {
  return (await fg(['**/*'], { cwd: root, ignore: patterns, dot: true, onlyFiles: true })).sort()
}
function viaHelper(rules: ReturnType<typeof buildIgnoreRules>): string[] {
  return FILES.filter((f) => classifyIgnored(f, rules) === null).sort()
}

describe('classifyIgnored agrees with fast-glob', () => {
  const corpus: Array<[string, string[]]> = [
    ['defaults only', []],
    ['bare folder name: docs', ['docs']],
    ['trailing slash: secrets/', ['secrets/']],
    ['docs/**', ['docs/**']],
    ['nested glob: **/*.log', ['**/*.log']],
    ['exact nested file', ['sub/b.log']],
    ['dot folder', ['.hidden']],
    ['dot folder glob', ['.hidden/**']],
    ['one file', ['.env']],
  ]
  for (const [name, user] of corpus) {
    it(name, async () => {
      const p = policy(user)
      const expected = await viaFastGlob(buildIgnorePatterns(p))
      expect(viaHelper(buildIgnoreRules(p))).toEqual(expected)
    })
  }

  it('a parent-folder row: pattern "docs" ignores docs/a/b.js', () => {
    expect(classifyIgnored('docs/a/b.js', buildIgnoreRules(policy(['docs'])))).toEqual({ pattern: 'docs', by: 'user' })
  })

  it('root-only default: *.log ignores a root log but not a nested one', () => {
    const rules = buildIgnoreRules(policy([]))
    expect(classifyIgnored('a.log', rules)).toEqual({ pattern: '*.log', by: 'default' })
    expect(classifyIgnored('sub/b.log', rules)).toBeNull()
  })

  it('media extensions are no longer ignored by default (they are classified by content)', () => {
    expect(classifyIgnored('logo.png', buildIgnoreRules(policy([])))).toBeNull()
  })

  it('reports who ignored it: default vs user', () => {
    const rules = buildIgnoreRules(policy(['secrets/**']))
    expect(classifyIgnored('node_modules/p/i.js', rules)?.by).toBe('default')
    expect(classifyIgnored('secrets/k.env', rules)?.by).toBe('user')
  })

  it('--changed behaviour change is explicit: x.min.js, debug.log, vendor/x.js are default-ignored', () => {
    const rules = buildIgnoreRules(policy([]))
    for (const f of ['x.min.js', 'debug.log', 'vendor/x.js', 'tmp/a.js', 'out/a.js']) {
      expect(classifyIgnored(f, rules)?.by).toBe('default')
    }
  })
})
