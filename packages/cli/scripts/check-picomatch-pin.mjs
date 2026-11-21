#!/usr/bin/env node
// check-picomatch-pin.mjs - release gate G11 (plan W0): picomatch is pinned to exact versions.
//   - root package.json pnpm.overrides pins picomatch@^2 and picomatch@^4 to exact versions;
//   - pnpm-lock.yaml resolves ONLY those versions (no other picomatch can slip in);
//   - the packed package.json (what ships) carries the same exact pins in `overrides`.
// Usage: node scripts/check-picomatch-pin.mjs [--packed <package.json inside the tarball>]
// Exit 0 pass, 1 pin broken, 2 could not read.
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const EXACT = /^\d+\.\d+\.\d+$/

/** Returns a list of problems (empty = pinned). */
export function checkPin({ rootPkg, lockText, cliPkg }) {
  const problems = []
  const pins = rootPkg?.pnpm?.overrides ?? {}
  const keys = Object.keys(pins).filter((k) => k.startsWith('picomatch'))
  if (keys.length === 0) problems.push('root package.json pnpm.overrides has no picomatch pin')
  for (const k of keys) if (!EXACT.test(pins[k])) problems.push(`pnpm override ${k} is "${pins[k]}", not an exact version`)
  const pinned = new Set(keys.map((k) => pins[k]))
  const resolved = new Set([...lockText.matchAll(/^ {2}picomatch@(\d\S*?):/gm)].map((m) => m[1].replace(/['"]/g, '')))
  if (resolved.size === 0) problems.push('pnpm-lock.yaml resolves no picomatch (unexpected)')
  for (const v of resolved) if (!pinned.has(v)) problems.push(`pnpm-lock.yaml resolves picomatch ${v}, which is not a pinned version (${[...pinned].join(', ')})`)
  const shipped = cliPkg?.overrides ?? {}
  for (const k of keys) {
    if (shipped[k] !== pins[k]) problems.push(`packed package.json overrides["${k}"] is ${JSON.stringify(shipped[k])}, expected "${pins[k]}"`)
  }
  return problems
}

function main() {
  const here = dirname(fileURLToPath(import.meta.url))
  const root = resolve(here, '..', '..', '..')
  const args = process.argv.slice(2)
  const packed = args.includes('--packed') ? args[args.indexOf('--packed') + 1] : resolve(root, 'packages', 'cli', 'package.json')
  let input
  try {
    input = {
      rootPkg: JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf-8')),
      lockText: readFileSync(resolve(root, 'pnpm-lock.yaml'), 'utf-8'),
      cliPkg: JSON.parse(readFileSync(packed, 'utf-8')),
    }
  } catch (err) {
    console.error(`FAIL [picomatch-pin] cannot read inputs: ${err.message}`)
    process.exit(2)
  }
  const problems = checkPin(input)
  if (problems.length) {
    for (const p of problems) console.error(`FAIL [picomatch-pin] ${p}`)
    process.exit(1)
  }
  console.log('PASS [picomatch-pin] picomatch pinned to exact versions in overrides, lockfile and the packed package.json')
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
