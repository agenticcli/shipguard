// computeMatcherRuntimeId algorithm
// Failing tests first, then minimal impl, then commit.

import { describe, it, expect } from 'vitest'
import { computeMatcherRuntimeId } from '../runtime-id.js'
import { makeNativeEngineMeta, makeRe2jsEngineMeta, RE2JS_VERSION } from '../engine-meta.js'

// ---------------------------------------------------------------------------
// Determinism: same input → same output
// ---------------------------------------------------------------------------

describe('computeMatcherRuntimeId — determinism', () => {
  it('is deterministic for fixed input (native)', () => {
    const input = {
      contractVersion: '0.1.0',
      adapterImplHash: 'abc123',
      engineMeta: makeNativeEngineMeta('v20.11.0'),
      buildLock: 'deadbeef',
    }
    const a = computeMatcherRuntimeId(input)
    const b = computeMatcherRuntimeId(input)
    expect(a).toBe(b)
  })

  it('is deterministic for fixed input (re2js)', () => {
    const input = {
      contractVersion: '0.1.0',
      adapterImplHash: 'abc123',
      engineMeta: makeRe2jsEngineMeta(),
      buildLock: 'deadbeef',
    }
    const a = computeMatcherRuntimeId(input)
    const b = computeMatcherRuntimeId(input)
    expect(a).toBe(b)
  })
})

// ---------------------------------------------------------------------------
// Output format: SHA-256 hex string (64 lowercase hex chars)
// ---------------------------------------------------------------------------

describe('computeMatcherRuntimeId — output format', () => {
  it('returns a 64-character lowercase hex string', () => {
    const result = computeMatcherRuntimeId({
      contractVersion: '0.1.0',
      adapterImplHash: 'abc123def456',
      engineMeta: makeNativeEngineMeta('v20.11.0'),
      buildLock: 'lockfile-hash',
    })
    expect(typeof result).toBe('string')
    expect(result).toHaveLength(64)
    expect(result).toMatch(/^[0-9a-f]{64}$/)
  })

  it('never returns uppercase hex', () => {
    const result = computeMatcherRuntimeId({
      contractVersion: '0.1.0',
      adapterImplHash: 'aaa',
      engineMeta: makeRe2jsEngineMeta(),
      buildLock: 'bbb',
    })
    expect(result).not.toMatch(/[A-F]/)
  })
})

// ---------------------------------------------------------------------------
// Sensitivity: any change in input → different output
// ---------------------------------------------------------------------------

describe('computeMatcherRuntimeId — input sensitivity', () => {
  const baseInput = {
    contractVersion: '0.1.0',
    adapterImplHash: 'adapter-hash-v1',
    engineMeta: makeNativeEngineMeta('v20.11.0'),
    buildLock: 'pnpm-lock-hash',
  }
  const base = computeMatcherRuntimeId(baseInput)

  it('changes when contractVersion changes', () => {
    const r = computeMatcherRuntimeId({ ...baseInput, contractVersion: '0.2.0' })
    expect(r).not.toBe(base)
  })

  it('changes when adapterImplHash changes', () => {
    const r = computeMatcherRuntimeId({ ...baseInput, adapterImplHash: 'adapter-hash-v2' })
    expect(r).not.toBe(base)
  })

  it('changes when engineMeta version changes (different node version)', () => {
    const r = computeMatcherRuntimeId({
      ...baseInput,
      engineMeta: makeNativeEngineMeta('v22.4.0'),
    })
    expect(r).not.toBe(base)
  })

  it('changes when engine changes from native to re2js', () => {
    const r = computeMatcherRuntimeId({
      ...baseInput,
      engineMeta: makeRe2jsEngineMeta(),
    })
    expect(r).not.toBe(base)
  })

  it('changes when LOOKBEHINDS changes', () => {
    const withLookbehinds = computeMatcherRuntimeId({
      ...baseInput,
      engineMeta: makeRe2jsEngineMeta(true),
    })
    const withoutLookbehinds = computeMatcherRuntimeId({
      ...baseInput,
      engineMeta: makeRe2jsEngineMeta(false),
    })
    expect(withLookbehinds).not.toBe(withoutLookbehinds)
  })

  it('changes when buildLock changes', () => {
    const r = computeMatcherRuntimeId({ ...baseInput, buildLock: 'different-lock-hash' })
    expect(r).not.toBe(base)
  })
})

// ---------------------------------------------------------------------------
// No frozen values in this module (algorithm only)
// ---------------------------------------------------------------------------

describe('computeMatcherRuntimeId — no frozen values', () => {
  it('does not export NATIVE_V1_RUNTIME_ID (frozen in B.1)', async () => {
    // The algorithm module must NOT export a pre-frozen value — that would
    // couple it to a specific adapter impl hash / build lock, which are Phase B inputs.
    const mod = await import('../runtime-id.js')
    expect('NATIVE_V1_RUNTIME_ID' in mod).toBe(false)
  })

  it('does not export RE2JS_V1_RUNTIME_ID (frozen in D.1)', async () => {
    const mod = await import('../runtime-id.js')
    expect('RE2JS_V1_RUNTIME_ID' in mod).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Stable across equivalent input objects (key-order invariant via canonicalJson)
// ---------------------------------------------------------------------------

describe('computeMatcherRuntimeId — key-order invariant', () => {
  it('produces the same result regardless of input field insertion order', () => {
    // Both inputs have the same logical content, just different field order.
    // canonicalJson (RFC 8785) sorts keys → same preimage → same hash.
    const inputA = {
      contractVersion: '0.1.0',
      adapterImplHash: 'h1',
      engineMeta: makeNativeEngineMeta('v20.0.0'),
      buildLock: 'l1',
    }
    // Same content, different JS object key order (simulated by spreading)
    const inputB = {
      buildLock: 'l1',
      engineMeta: makeNativeEngineMeta('v20.0.0'),
      adapterImplHash: 'h1',
      contractVersion: '0.1.0',
    }
    expect(computeMatcherRuntimeId(inputA)).toBe(computeMatcherRuntimeId(inputB))
  })
})

// ---------------------------------------------------------------------------
// re2js version pin in the runtimeId
// ---------------------------------------------------------------------------

describe('computeMatcherRuntimeId — re2js version is pinned', () => {
  it('the re2js engineMeta version is always RE2JS_VERSION (2.8.3)', () => {
    const meta = makeRe2jsEngineMeta()
    expect(meta.version).toBe(RE2JS_VERSION)
    // If this test fails, it means makeRe2jsEngineMeta is not using the pin
    expect(meta.version).toBe('2.8.3')
  })
})
