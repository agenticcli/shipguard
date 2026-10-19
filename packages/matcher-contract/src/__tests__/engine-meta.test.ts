// EngineMeta, RE2JS_VERSION, SUPPORTED_NODE_VERSIONS, LOOKBEHINDS default

import { describe, it, expect } from 'vitest'
import {
  RE2JS_VERSION,
  SUPPORTED_NODE_VERSIONS,
  type EngineMeta,
  makeNativeEngineMeta,
  makeRe2jsEngineMeta,
} from '../engine-meta.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

describe('RE2JS_VERSION constant', () => {
  it('is the exact pinned version 2.8.3', () => {
    expect(RE2JS_VERSION).toBe('2.8.3')
  })

  it('is a string', () => {
    expect(typeof RE2JS_VERSION).toBe('string')
  })
})

describe('SUPPORTED_NODE_VERSIONS', () => {
  it('is a non-empty array of strings', () => {
    expect(Array.isArray(SUPPORTED_NODE_VERSIONS)).toBe(true)
    expect(SUPPORTED_NODE_VERSIONS.length).toBeGreaterThan(0)
    for (const v of SUPPORTED_NODE_VERSIONS) {
      expect(typeof v).toBe('string')
    }
  })

  it('contains node 20 (CLI engines >=20, tsup target node20)', () => {
    expect(SUPPORTED_NODE_VERSIONS).toContain('20')
  })

  it('contains node 22 (agenticcli CI node version)', () => {
    expect(SUPPORTED_NODE_VERSIONS).toContain('22')
  })

  it('does NOT use an open-ended >=N notation', () => {
    // Must be an explicit list, not a semver range
    for (const v of SUPPORTED_NODE_VERSIONS) {
      expect(v).not.toMatch(/>=/)
      expect(v).not.toMatch(/\^/)
      expect(v).not.toMatch(/~/)
    }
  })
})

// ---------------------------------------------------------------------------
// EngineMeta type shape
// ---------------------------------------------------------------------------

describe('EngineMeta type — native engine', () => {
  it('makeNativeEngineMeta produces a valid EngineMeta with engine="native"', () => {
    const meta: EngineMeta = makeNativeEngineMeta('v20.11.0')
    expect(meta.engine).toBe('native')
    expect(typeof meta.version).toBe('string')
    expect(meta.version).toBe('v20.11.0')
    expect(typeof meta.options).toBe('object')
    expect(meta.options).not.toBeNull()
    expect(typeof meta.options.LOOKBEHINDS).toBe('boolean')
    expect(meta.options.LOOKBEHINDS).toBe(false)
  })

  it('native EngineMeta has engine options separate from author flags', () => {
    // Engine options must NOT contain flag fields (i, m, s) — they are SEPARATE
    const meta = makeNativeEngineMeta('v22.0.0')
    expect('i' in meta.options).toBe(false)
    expect('m' in meta.options).toBe(false)
    expect('s' in meta.options).toBe(false)
  })
})

describe('EngineMeta type — re2js engine', () => {
  it('makeRe2jsEngineMeta produces a valid EngineMeta with engine="re2js"', () => {
    const meta: EngineMeta = makeRe2jsEngineMeta()
    expect(meta.engine).toBe('re2js')
    expect(meta.version).toBe(RE2JS_VERSION) // pinned to 2.8.3
    expect(typeof meta.options).toBe('object')
    expect(meta.options).not.toBeNull()
  })

  it('LOOKBEHINDS defaults to false for v1 (I3 — off by default)', () => {
    const meta = makeRe2jsEngineMeta()
    expect(meta.options.LOOKBEHINDS).toBe(false)
  })

  it('re2js EngineMeta version is exactly RE2JS_VERSION', () => {
    const meta = makeRe2jsEngineMeta()
    expect(meta.version).toBe('2.8.3')
  })
})

describe('EngineMeta serialization — stable and deterministic', () => {
  it('two identical native EngineMeta produce the same JSON', () => {
    const a = makeNativeEngineMeta('v20.11.0')
    const b = makeNativeEngineMeta('v20.11.0')
    expect(JSON.stringify(a)).toBe(JSON.stringify(b))
  })

  it('two identical re2js EngineMeta produce the same JSON', () => {
    const a = makeRe2jsEngineMeta()
    const b = makeRe2jsEngineMeta()
    expect(JSON.stringify(a)).toBe(JSON.stringify(b))
  })

  it('native and re2js EngineMeta produce different JSON (different engines)', () => {
    const a = makeNativeEngineMeta('v20.11.0')
    const b = makeRe2jsEngineMeta()
    expect(JSON.stringify(a)).not.toBe(JSON.stringify(b))
  })

  it('different node versions produce different native EngineMeta JSON', () => {
    const a = makeNativeEngineMeta('v20.11.0')
    const b = makeNativeEngineMeta('v22.4.0')
    expect(JSON.stringify(a)).not.toBe(JSON.stringify(b))
  })
})
