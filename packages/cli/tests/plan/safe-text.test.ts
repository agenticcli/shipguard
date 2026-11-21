import { describe, expect, it } from 'vitest'
import { safeServerList, safeServerText, TEXT_CAPS } from '../../src/core/safe-text.js'

describe('safeServerText', () => {
  it('passes plain text through', () => {
    expect(safeServerText('Cancelled. Stays active until the end.', 200)).toBe('Cancelled. Stays active until the end.')
  })
  it('strips ANSI colour, cursor and OSC link escape sequences completely', () => {
    expect(safeServerText('a\u001b[31mred\u001b[0m b', 50)).toBe('a red b')
    expect(safeServerText('x\u001b]8;;https://evil.example\u0007link\u001b]8;;\u0007y', 50)).not.toMatch(/[\u001b\u0007]|evil/)
    expect(safeServerText('a\u001b[2J\u001b[Hb', 50)).toBe('a b')
    expect(safeServerText('a\u009b31mb', 50)).toBe('a b')
  })
  it('strips control, bidi, zero-width and tag characters', () => {
    expect(safeServerText('a\u0000b\u0007c\u007fd\u0085e', 50)).toBe('a b c d e')
    expect(safeServerText('pay‮evil‬ ok​z⁦y⁩', 50)).not.toMatch(/[‪-‮​⁦-⁩]/)
    expect(safeServerText('t\u{e0041}\u{e007f}x', 50)).toBe('t x')
  })
  it('removes URLs: the server never sends a link', () => {
    const out = safeServerText('Visit https://evil.example/pay?x=1 or javascript://x now', 100)
    expect(out).not.toMatch(/https?:|javascript:|evil/)
    expect(out).toBe('Visit or now')
  })
  it('collapses whitespace and returns null for nothing printable or for non-strings', () => {
    expect(safeServerText('  a \n\t b  ', 20)).toBe('a b')
    expect(safeServerText('\u001b[31m​', 20)).toBeNull()
    for (const v of [null, undefined, 5, {}, ['a']]) expect(safeServerText(v, 20)).toBeNull()
  })
  it('caps length with an ellipsis and never exceeds the cap', () => {
    const out = safeServerText('x'.repeat(500), TEXT_CAPS.offer)!
    expect(out.length).toBe(TEXT_CAPS.offer)
    expect(out.endsWith('...')).toBe(true)
  })
  it('survives very large hostile input quickly', () => {
    const t0 = Date.now()
    const out = safeServerText('\u001b['.repeat(200000) + 'ok', 50)
    expect(Date.now() - t0).toBeLessThan(1000)
    expect(out === null || out.length <= 50).toBe(true)
  })
})

describe('safeServerList', () => {
  it('keeps strings only, caps each at 40 and the list at 8', () => {
    const list = safeServerList(['a', 5, 'b'.repeat(80), ...Array.from({ length: 20 }, (_, i) => `n${i}`)])
    expect(list.length).toBe(TEXT_CAPS.items)
    expect(list[1].length).toBe(TEXT_CAPS.item)
    expect(list).not.toContain(5 as unknown as string)
  })
  it('returns [] for a non-array', () => {
    expect(safeServerList('x')).toEqual([])
    expect(safeServerList(null)).toEqual([])
  })
})
