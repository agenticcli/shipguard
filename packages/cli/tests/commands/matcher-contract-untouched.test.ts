/**
 * B9 (guard): this branch must not touch packages/matcher-contract (plan A9). Skipped outside a
 * checkout that has origin/main.
 */
import { execFileSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..')

function git(args: string[]): string | null {
  try {
    return execFileSync('git', args, { cwd: repoRoot, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] })
  } catch {
    return null
  }
}

describe('matcher-contract is untouched', () => {
  const base = git(['merge-base', 'origin/main', 'HEAD'])
  it.skipIf(base === null)('git diff against the merge base with origin/main is empty for packages/matcher-contract', () => {
    const diff = git(['diff', '--name-only', base!.trim(), 'HEAD', '--', 'packages/matcher-contract'])
    expect(diff).toBe('')
  })
})
