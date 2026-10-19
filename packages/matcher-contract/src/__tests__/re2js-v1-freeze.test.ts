// Regression test — RE2JS_V1_ADAPTER_IMPL_HASH and RE2JS_V1_RUNTIME_ID
//
// Validates that the two frozen constants in re2js-v1.ts match the current
// source file's content and the correct runtimeId derivation.
//
// ## Self-referential hash problem and solution
//
// re2js-v1.ts contains its own SHA-256 as a constant.  Computing SHA-256 of a
// file that contains its own hash is circular: changing the constant changes
// the file, which changes the hash, which changes the constant…
//
// Solution: compute a STABLE "functional content hash" by blanking BOTH
// constant-value lines before hashing.  The test does exactly what the
// bootstrap script did:
//
//   1. Read src/adapters/re2js-v1.ts as raw bytes.
//   2. Replace the RE2JS_V1_ADAPTER_IMPL_HASH value line with 64 zeros.
//   3. Replace the RE2JS_V1_RUNTIME_ID value line with 64 zeros.
//   4. SHA-256(blanked bytes) must equal RE2JS_V1_ADAPTER_IMPL_HASH.
//
// Any structural change to re2js-v1.ts (new logic, renamed imports, comment
// edits, etc.) will shift this hash and cause this test to FAIL — signalling
// that the developer must re-run the freeze bootstrap and update both constants.

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { computeMatcherRuntimeId } from '../runtime-id.js'
import { makeRe2jsEngineMeta } from '../engine-meta.js'
import {
  RE2JS_V1_ADAPTER_IMPL_HASH,
  RE2JS_V1_RUNTIME_ID,
} from '../adapters/re2js-v1.js'

// ---------------------------------------------------------------------------
// Path to the source file under test
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url)
const __dir = dirname(__filename)

// The test lives in  src/__tests__/re2js-v1-freeze.test.ts.
// The adapter lives in src/adapters/re2js-v1.ts.
// __dir = src/__tests__/ ; adapter is at src/adapters/re2js-v1.ts
const RE2JS_V1_SRC = resolve(__dir, '../adapters/re2js-v1.ts')

// ---------------------------------------------------------------------------
// Helper: blank both frozen-constant value lines and return the result buffer
// ---------------------------------------------------------------------------

function blankedSourceBytes(): Buffer {
  const raw = readFileSync(RE2JS_V1_SRC)

  // Blank RE2JS_V1_ADAPTER_IMPL_HASH value line:
  //   '6e5c75edb4e62dd2241877e48d65bc21a67ce6ff77ccda9840d67f2e8252770d' as const
  // Replace any 64-hex-char value on the line immediately after the export const declaration.
  let blanked = raw.toString('utf8')

  // Pattern matches the VALUE line of RE2JS_V1_ADAPTER_IMPL_HASH (indented with 2 spaces)
  blanked = blanked.replace(
    /(export const RE2JS_V1_ADAPTER_IMPL_HASH =\s*\n\s*')[0-9a-f]{64}'/,
    "$1" + '0'.repeat(64) + "'"
  )

  // Pattern matches the VALUE line of RE2JS_V1_RUNTIME_ID (indented with 2 spaces)
  blanked = blanked.replace(
    /(export const RE2JS_V1_RUNTIME_ID =\s*\n\s*')[0-9a-f]{64}'/,
    "$1" + '0'.repeat(64) + "'"
  )

  return Buffer.from(blanked, 'utf8')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RE2JS_V1_ADAPTER_IMPL_HASH — freeze regression', () => {
  it('matches SHA-256 of the current re2js-v1.ts with both constant-value lines blanked', () => {
    const blanked = blankedSourceBytes()
    const actualHash = createHash('sha256').update(blanked).digest('hex')

    // If this fails, the source file changed without updating the constant.
    // Run: python3 scripts/freeze-re2js-v1.py (or equivalent bootstrap) to
    // compute new values and update RE2JS_V1_ADAPTER_IMPL_HASH + RE2JS_V1_RUNTIME_ID.
    expect(actualHash).toBe(RE2JS_V1_ADAPTER_IMPL_HASH)
  })

  it('blanking is idempotent — blanking twice gives the same bytes as blanking once', () => {
    // Ensures the regex does not produce false-positives by matching inside
    // comments or other non-value locations.
    const once = blankedSourceBytes().toString('utf8')
    // Re-blank the already-blanked string
    let twice = once.replace(
      /(export const RE2JS_V1_ADAPTER_IMPL_HASH =\s*\n\s*')[0-9a-f]{64}'/,
      "$1" + '0'.repeat(64) + "'"
    )
    twice = twice.replace(
      /(export const RE2JS_V1_RUNTIME_ID =\s*\n\s*')[0-9a-f]{64}'/,
      "$1" + '0'.repeat(64) + "'"
    )
    expect(twice).toBe(once)
  })
})

describe('RE2JS_V1_RUNTIME_ID — derivation regression', () => {
  it('matches computeMatcherRuntimeId with freeze inputs from the 0.5.0 build', () => {
    // Freeze inputs (matcher spec §9.1) documented in re2js-v1.ts:
    //   contractVersion: '0.5.0'
    //   adapterImplHash: RE2JS_V1_ADAPTER_IMPL_HASH (the stable blanked-file hash)
    //   engineMeta:      re2js@2.8.3, LOOKBEHINDS:false
    //   buildLock:       're2js-v1-build-2026-06-25-v0.5.0'
    const derived = computeMatcherRuntimeId({
      contractVersion: '0.5.0',
      adapterImplHash: RE2JS_V1_ADAPTER_IMPL_HASH,
      engineMeta: makeRe2jsEngineMeta(false),
      buildLock: 're2js-v1-build-2026-06-25-v0.5.0',
    })

    // If this fails, either:
    //  (a) RE2JS_V1_ADAPTER_IMPL_HASH was updated but RE2JS_V1_RUNTIME_ID was not
    //  (b) The freeze inputs in the doc-comment no longer match the constant
    expect(derived).toBe(RE2JS_V1_RUNTIME_ID)
  })

  it('a different adapterImplHash produces a different runtimeId (tamper sensitivity)', () => {
    const tampered = computeMatcherRuntimeId({
      contractVersion: '0.5.0',
      adapterImplHash: 'a'.repeat(64), // wrong hash
      engineMeta: makeRe2jsEngineMeta(false),
      buildLock: 're2js-v1-build-2026-06-25-v0.5.0',
    })
    expect(tampered).not.toBe(RE2JS_V1_RUNTIME_ID)
  })

  it('a different contractVersion produces a different runtimeId', () => {
    const oldContract = computeMatcherRuntimeId({
      contractVersion: '0.4.1', // old version
      adapterImplHash: RE2JS_V1_ADAPTER_IMPL_HASH,
      engineMeta: makeRe2jsEngineMeta(false),
      buildLock: 're2js-v1-build-2026-06-25-v0.5.0',
    })
    expect(oldContract).not.toBe(RE2JS_V1_RUNTIME_ID)
  })
})
