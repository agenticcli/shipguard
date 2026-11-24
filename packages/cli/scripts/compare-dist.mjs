#!/usr/bin/env node
/**
 * compare-dist — are two dist/ folders the same build?
 * Usage: node scripts/compare-dist.mjs <dist-A> <dist-B>
 * Compares SHA-256 of every *.js, *.js.map and checksum-manifest.json (a function of the .js files).
 * cli-facts.json is skipped on purpose: it carries a generatedAt timestamp.
 * Exit 0 = identical file set and bytes; 1 = any difference (each one is printed).
 */
import { createHash } from 'node:crypto'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const [a, b] = process.argv.slice(2)
if (!a || !b) { console.error('usage: compare-dist.mjs <dist-A> <dist-B>'); process.exit(2) }

const hashes = (dir) => {
  const out = {}
  for (const f of readdirSync(dir).sort()) {
    if (f.endsWith('.js') || f.endsWith('.js.map') || f === 'checksum-manifest.json') {
      out[f] = createHash('sha256').update(readFileSync(join(dir, f))).digest('hex')
    }
  }
  return out
}
const ha = hashes(a)
const hb = hashes(b)
const names = [...new Set([...Object.keys(ha), ...Object.keys(hb)])].sort()
let bad = 0
for (const n of names) {
  const state = !ha[n] ? 'ONLY-IN-B' : !hb[n] ? 'ONLY-IN-A' : ha[n] === hb[n] ? 'same' : 'DIFFERENT'
  if (state !== 'same') bad++
  console.log(`${state.padEnd(10)} ${(ha[n] ?? hb[n]).slice(0, 16)}  ${n}`)
}
if (names.length === 0) { console.error('[compare-dist] no files to compare'); process.exit(1) }
console.log(bad === 0 ? `[compare-dist] MATCH: ${names.length} files identical` : `[compare-dist] MISMATCH: ${bad} of ${names.length} files differ`)
process.exit(bad === 0 ? 0 : 1)
