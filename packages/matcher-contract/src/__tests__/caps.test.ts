// TDD: Task A.7 — CapsProfile + CapTracker
// Failing tests first, then minimal impl, then commit.

import { describe, it, expect } from 'vitest'
import {
  DEFAULT_CAPS,
  CapTracker,
  type CapsProfile,
} from '../caps.js'

describe('CapsProfile — DEFAULT_CAPS', () => {
  it('has all required cap fields as positive numbers', () => {
    const c: CapsProfile = DEFAULT_CAPS
    expect(typeof c.maxFiles).toBe('number')
    expect(typeof c.maxTotalBytes).toBe('number')
    expect(typeof c.maxRules).toBe('number')
    expect(typeof c.maxPatternsPerRule).toBe('number')
    expect(typeof c.maxTotalPatternBytes).toBe('number')
    expect(typeof c.maxFindings).toBe('number')
    expect(c.maxFiles).toBeGreaterThan(0)
    expect(c.maxTotalBytes).toBeGreaterThan(0)
    expect(c.maxRules).toBeGreaterThan(0)
    expect(c.maxPatternsPerRule).toBeGreaterThan(0)
    expect(c.maxTotalPatternBytes).toBeGreaterThan(0)
    expect(c.maxFindings).toBeGreaterThan(0)
  })
})

describe('CapTracker — under caps → complete', () => {
  it('returns no cap hit when nothing is counted', () => {
    const t = new CapTracker(DEFAULT_CAPS)
    const hit = t.capHit()
    expect(hit).toBeNull()
  })

  it('returns no cap hit when counts are exactly at cap limits', () => {
    const caps: CapsProfile = {
      maxFiles: 2,
      maxTotalBytes: 100,
      maxRules: 3,
      maxPatternsPerRule: 2,
      maxTotalPatternBytes: 50,
      maxFindings: 5,
    }
    const t = new CapTracker(caps)
    t.addFile(50)
    t.addFile(50)
    t.addRule(2, 25)
    t.addRule(1, 25)
    t.addFindings(5)
    expect(t.capHit()).toBeNull()
  })
})

describe('CapTracker — exceeding maxFiles → INCOMPLETE', () => {
  it('cap hit when files exceed maxFiles', () => {
    const caps: CapsProfile = {
      ...DEFAULT_CAPS,
      maxFiles: 2,
    }
    const t = new CapTracker(caps)
    t.addFile(1)
    t.addFile(1)
    expect(t.capHit()).toBeNull()
    t.addFile(1) // now at 3, over cap
    const hit = t.capHit()
    expect(hit).not.toBeNull()
    expect(hit?.reason).toBe('cap-exceeded')
    expect(hit?.detail).toMatch(/maxFiles/)
    expect(hit?.incomplete).toBe(true)
  })
})

describe('CapTracker — exceeding maxTotalBytes → INCOMPLETE', () => {
  it('cap hit when total bytes exceed maxTotalBytes', () => {
    const caps: CapsProfile = { ...DEFAULT_CAPS, maxTotalBytes: 100 }
    const t = new CapTracker(caps)
    t.addFile(60)
    expect(t.capHit()).toBeNull()
    t.addFile(50) // total = 110 > 100
    const hit = t.capHit()
    expect(hit).not.toBeNull()
    expect(hit?.reason).toBe('cap-exceeded')
    expect(hit?.detail).toMatch(/maxTotalBytes/)
    expect(hit?.incomplete).toBe(true)
  })
})

describe('CapTracker — exceeding maxRules → INCOMPLETE', () => {
  it('cap hit when rules exceed maxRules', () => {
    const caps: CapsProfile = { ...DEFAULT_CAPS, maxRules: 2 }
    const t = new CapTracker(caps)
    t.addRule(1, 10)
    t.addRule(1, 10)
    expect(t.capHit()).toBeNull()
    t.addRule(1, 10) // now 3 rules
    const hit = t.capHit()
    expect(hit).not.toBeNull()
    expect(hit?.detail).toMatch(/maxRules/)
  })
})

describe('CapTracker — exceeding maxPatternsPerRule → INCOMPLETE', () => {
  it('cap hit when patterns per rule exceed maxPatternsPerRule', () => {
    const caps: CapsProfile = { ...DEFAULT_CAPS, maxPatternsPerRule: 2 }
    const t = new CapTracker(caps)
    // 3 patterns in one rule
    t.addRule(3, 10)
    const hit = t.capHit()
    expect(hit).not.toBeNull()
    expect(hit?.detail).toMatch(/maxPatternsPerRule/)
  })
})

describe('CapTracker — exceeding maxTotalPatternBytes → INCOMPLETE', () => {
  it('cap hit when total pattern bytes exceed maxTotalPatternBytes', () => {
    const caps: CapsProfile = { ...DEFAULT_CAPS, maxTotalPatternBytes: 50 }
    const t = new CapTracker(caps)
    t.addRule(1, 30)
    expect(t.capHit()).toBeNull()
    t.addRule(1, 30) // total = 60 > 50
    const hit = t.capHit()
    expect(hit).not.toBeNull()
    expect(hit?.detail).toMatch(/maxTotalPatternBytes/)
  })
})

describe('CapTracker — exceeding maxFindings → INCOMPLETE', () => {
  it('cap hit when findings exceed maxFindings', () => {
    const caps: CapsProfile = { ...DEFAULT_CAPS, maxFindings: 3 }
    const t = new CapTracker(caps)
    t.addFindings(3)
    expect(t.capHit()).toBeNull()
    t.addFindings(1) // now 4 > 3
    const hit = t.capHit()
    expect(hit).not.toBeNull()
    expect(hit?.detail).toMatch(/maxFindings/)
  })
})

describe('CapTracker — cap hit maps to non-safe exit signal', () => {
  it('incomplete=true signals non-safe (never clean truncation)', () => {
    const caps: CapsProfile = { ...DEFAULT_CAPS, maxFindings: 1 }
    const t = new CapTracker(caps)
    t.addFindings(2)
    const hit = t.capHit()
    expect(hit?.incomplete).toBe(true)
    // reason must be the canonical degraded reason
    expect(hit?.reason).toBe('cap-exceeded')
  })
})
