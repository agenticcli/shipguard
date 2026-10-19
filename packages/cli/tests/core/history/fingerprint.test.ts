import { describe, it, expect } from 'vitest'
import { computeScopeFingerprint } from '../../../src/core/history/fingerprint.js'

describe('computeScopeFingerprint (§2.2)', () => {
  const base = { changedOnly: false, categories: [], ignorePaths: [], proApplied: false }

  it('is deterministic for identical inputs', () => {
    const a = computeScopeFingerprint({ ...base })
    const b = computeScopeFingerprint({ ...base })
    expect(a).toBe(b)
  })

  it('is a 16-char lowercase hex string', () => {
    const fp = computeScopeFingerprint({ ...base })
    expect(fp).toMatch(/^[0-9a-f]{16}$/)
  })

  it('category ORDER does not matter — normalized before hashing', () => {
    const a = computeScopeFingerprint({ ...base, categories: ['secrets', 'auth'] })
    const b = computeScopeFingerprint({ ...base, categories: ['auth', 'secrets'] })
    expect(a).toBe(b)
  })

  it('category CASE does not matter — normalized before hashing', () => {
    const a = computeScopeFingerprint({ ...base, categories: ['Secrets'] })
    const b = computeScopeFingerprint({ ...base, categories: ['secrets'] })
    expect(a).toBe(b)
  })

  it('changed-files-only vs full-repo mode produces DIFFERENT fingerprints', () => {
    const full = computeScopeFingerprint({ ...base, changedOnly: false })
    const changed = computeScopeFingerprint({ ...base, changedOnly: true })
    expect(full).not.toBe(changed)
  })

  it('a category filter produces a DIFFERENT fingerprint than no filter', () => {
    const none = computeScopeFingerprint({ ...base })
    const filtered = computeScopeFingerprint({ ...base, categories: ['secrets'] })
    expect(none).not.toBe(filtered)
  })

  it('different ignore-paths produce a DIFFERENT fingerprint', () => {
    const a = computeScopeFingerprint({ ...base, ignorePaths: ['dist/**'] })
    const b = computeScopeFingerprint({ ...base, ignorePaths: ['dist/**', 'build/**'] })
    expect(a).not.toBe(b)
  })

  it('pro vs free (proApplied) produces a DIFFERENT fingerprint — a pro scan is never compared to a free one', () => {
    const free = computeScopeFingerprint({ ...base, proApplied: false })
    const pro = computeScopeFingerprint({ ...base, proApplied: true })
    expect(free).not.toBe(pro)
  })

  it('ignore-path ORDER does not matter — normalized before hashing', () => {
    const a = computeScopeFingerprint({ ...base, ignorePaths: ['a/**', 'b/**'] })
    const b = computeScopeFingerprint({ ...base, ignorePaths: ['b/**', 'a/**'] })
    expect(a).toBe(b)
  })
})
