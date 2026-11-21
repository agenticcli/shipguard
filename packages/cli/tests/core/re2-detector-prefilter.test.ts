import { afterEach, describe, expect, it } from 'vitest'
import { compileDetectorRegex } from '../../src/core/re2-detector-engine.js'
import { prefilterControl } from '../../src/core/rule-prefilter.js'

afterEach(() => {
  prefilterControl.enabled = true
})

const CASES: Array<[string, string]> = [
  ["['\"]?(sk_live_[a-zA-Z0-9]{24,})['\"]?", 'im'],
  ["['\"]?(AKIA[0-9A-Z]{16})['\"]?", 'm'],
  ['(?:sk|rk)_live_[a-zA-Z0-9]{20,64}', ''],
  ['NEXT_PUBLIC_(SECRET|TOKEN)', 'i'],
  ['process\\.env\\.[A-Z_]+', ''],
  ['=\\s*[\'"]', ''],
  ['^\\s*(\\/\\/|#)', 'm'],
]

const INPUTS = [
  '',
  'const a = 1',
  "const k = 'sk_live_" + 'a'.repeat(30) + "'",
  "const K = 'SK_LIVE_" + 'A'.repeat(30) + "'",
  "x = 'AKIA" + 'A'.repeat(16) + "'",
  'next_public_token=1\nNEXT_PUBLIC_SECRET=2',
  'NEXT_PUBLIC_\u212aEY and next_public_\u017fecret',
  'const x = process.env.FOO_BAR',
  '// comment\n# other\ncode',
  "a = 'b'",
]

describe('detector regex prefilter changes nothing observable', () => {
  for (const [source, flags] of CASES) {
    it(`${source} /${flags}`, () => {
      const re = compileDetectorRegex(source, flags)
      for (const input of INPUTS) {
        prefilterControl.enabled = true
        const on = [re.test(input), re.exec(input), re.matchAll(input), re.replaceFirst(input, '#'), re.replace(input, '#')]
        prefilterControl.enabled = false
        const off = [re.test(input), re.exec(input), re.matchAll(input), re.replaceFirst(input, '#'), re.replace(input, '#')]
        expect(on, JSON.stringify(input)).toEqual(off)
      }
    })
  }
})
