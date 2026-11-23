import { describe, expect, it } from 'vitest'
import { detectCi } from '../../src/core/telemetry.js'

describe('test setup removes CI signals (sg#53 red CI regression)', () => {
  it('process.env is not CI even when the runner sets CI=true / GITHUB_ACTIONS=true', () => {
    expect(detectCi(process.env)).toBe(false)
    expect(process.env.CI).toBeUndefined()
    expect(process.env.GITHUB_ACTIONS).toBeUndefined()
  })
})
