import { describe, it, expect, afterEach } from 'vitest'
import { resolve } from 'node:path'
import { resolveHistoryPath } from '../../../src/core/history/path.js'
import { HISTORY_PATH_ENV_VAR } from '@agenticcli/shared'

const ORIGINAL_ENV = process.env[HISTORY_PATH_ENV_VAR]

afterEach(() => {
  if (ORIGINAL_ENV === undefined) delete process.env[HISTORY_PATH_ENV_VAR]
  else process.env[HISTORY_PATH_ENV_VAR] = ORIGINAL_ENV
})

describe('resolveHistoryPath — precedence (§1.2: env > policy > default)', () => {
  it('defaults to .shipguard/history.db when nothing is set', () => {
    delete process.env[HISTORY_PATH_ENV_VAR]
    const result = resolveHistoryPath('/repo', {})
    expect(result).toBe(resolve('/repo', '.shipguard/history.db'))
  })

  it('policy.history.path overrides the default', () => {
    delete process.env[HISTORY_PATH_ENV_VAR]
    const result = resolveHistoryPath('/repo', { history: { path: 'custom/history.db' } })
    expect(result).toBe(resolve('/repo', 'custom/history.db'))
  })

  it('the env var overrides the policy path', () => {
    process.env[HISTORY_PATH_ENV_VAR] = '/tmp/env-history.db'
    const result = resolveHistoryPath('/repo', { history: { path: 'custom/history.db' } })
    expect(result).toBe(resolve('/repo', '/tmp/env-history.db'))
  })

  it('an empty-string policy path is ignored (falls through to default)', () => {
    delete process.env[HISTORY_PATH_ENV_VAR]
    const result = resolveHistoryPath('/repo', { history: { path: '   ' } })
    expect(result).toBe(resolve('/repo', '.shipguard/history.db'))
  })
})
