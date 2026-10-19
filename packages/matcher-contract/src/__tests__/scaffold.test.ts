// Package scaffold verification tests.
// These are smoke tests asserting the package resolves and exports compile correctly.

import { describe, it, expect } from 'vitest'
import * as contract from '../index.js'

describe('A.1 — package scaffold', () => {
  it('exports are resolvable (package resolves at all)', () => {
    // If the import above succeeded, the package resolves.
    expect(contract).toBeDefined()
  })

  it('exports matcher types (from matcher.ts)', () => {
    // TypeScript compilation verifies this at build time;
    // this runtime check confirms the JS module is wired up.
    // parseFlags is a runtime export from flags.ts; its presence confirms the barrel works.
    expect(typeof contract.parseFlags).toBe('function')
  })
})
