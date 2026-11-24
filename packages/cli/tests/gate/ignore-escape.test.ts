/**
 * Regression: policy `report.output` and `history.path` are literal paths, never globs.
 * A repo's own shipguard.policy.yml with `report.output: "+(*a)"` made picomatch backtrack
 * exponentially (a 29-character file name took about 20 s). Fail-before: the unescaped pattern
 * `+(*a)` below is what selfArtifactIgnorePatterns() used to return.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import fg from 'fast-glob'
import { afterAll, describe, expect, it } from 'vitest'
import type { Policy } from '@agenticcli/shared'
import { buildIgnoreRules, classifyIgnored, selfArtifactIgnorePatterns } from '../../src/core/ignore.js'

const dirs: string[] = []
afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })))

const NAME = 'a'.repeat(29) + 'b'
const policy = (report: string, history?: string): Policy =>
  ({ report: { output: report, format: 'markdown' }, ...(history ? { history: { path: history } } : {}), ignore: { paths: [] } }) as unknown as Policy

describe('policy paths are escaped before they become ignore patterns', () => {
  it('glob characters in report.output and history.path are escaped; the runs folder keeps its real **', () => {
    const patterns = selfArtifactIgnorePatterns(policy('+(*a)', 'h[1]/db'))
    expect(patterns).toContain('\\+\\(\\*a\\)')
    expect(patterns).toContain('h\\[1\\]/db')
    expect(patterns).not.toContain('+(*a)')
    expect(patterns.some((p) => p.endsWith('/runs/**') || p === 'runs/**')).toBe(true)
    expect(selfArtifactIgnorePatterns(policy('.shipguard/reports/latest.md'))).toContain('.shipguard/reports/latest.md')
  })

  it('matching a hostile pattern against a long file name is fast (minimatch path)', () => {
    const t0 = Date.now()
    const rules = buildIgnoreRules(policy('+(*a)'))
    expect(classifyIgnored(NAME, rules)).toBeNull()
    expect(Date.now() - t0).toBeLessThan(2_000)
  })

  it('and fast through fast-glob with the same ignore list (the real scan path)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sg-esc-'))
    dirs.push(dir)
    mkdirSync(join(dir, 'src'))
    writeFileSync(join(dir, NAME), 'x')
    writeFileSync(join(dir, 'src', 'ok.ts'), 'x')
    const t0 = Date.now()
    const files = await fg('**/*', { cwd: dir, dot: true, ignore: buildIgnoreRules(policy('+(*a)')).map((r) => r.pattern) })
    expect(Date.now() - t0).toBeLessThan(2_000)
    expect(files.sort()).toEqual([NAME, 'src/ok.ts'].sort())
  })

  it('the literal report file itself is still ignored when its name has glob characters', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sg-esc-'))
    dirs.push(dir)
    writeFileSync(join(dir, '+(x).md'), 'x')
    writeFileSync(join(dir, 'keep.ts'), 'x')
    const files = await fg('**/*', { cwd: dir, dot: true, ignore: buildIgnoreRules(policy('+(x).md')).map((r) => r.pattern) })
    expect(files).toEqual(['keep.ts'])
  })
})
