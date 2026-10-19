#!/usr/bin/env node
// check-keyring-placeholders.mjs — publish guard.
//
// Fails (exit 1) when any given file still contains an unfilled key placeholder
// ("SHIPGUARD_KEYRING_PLACEHOLDER-<kid>") — i.e. the ra-k2-2026 / cf-k2-2026 / k3-2026 public keys were
// never filled in. A CLI built that way cannot verify any Pro release.
// The three public keys live in ONE file, packages/cli/src/core/keyring-ceremony-output.ts.
//
// Usage: node scripts/check-keyring-placeholders.mjs [file-or-dir ...]   (default: dist/)
// A directory is scanned recursively for .js/.mjs/.cjs/.json files (tsup splits the bundle into chunks).
// Called by tsup onSuccess when SHIPGUARD_PUBLISHED_BUILD=1, and by scripts/release-gate.sh.
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const PLACEHOLDER_RE = /SHIPGUARD_KEYRING_PLACEHOLDER-[A-Za-z0-9-]+/g

export function findPlaceholders(text) {
  return [...new Set(text.match(PLACEHOLDER_RE) ?? [])]
}

function expand(p) {
  let st
  try { st = statSync(p) } catch { return [p] } // unreadable → reported by the read below
  if (!st.isDirectory()) return [p]
  return readdirSync(p).flatMap(name => {
    const child = path.join(p, name)
    if (statSync(child).isDirectory()) return expand(child)
    return /\.(m?js|cjs|json)$/.test(name) ? [child] : []
  })
}

function main() {
  const here = path.dirname(fileURLToPath(import.meta.url))
  const args = process.argv.slice(2)
  if (args.length === 0) args.push(path.join(here, '..', 'dist'))
  const files = args.flatMap(expand)
  if (files.length === 0) {
    console.error(`FAIL [keyring-placeholders] no files to check under: ${args.join(', ')}`)
    process.exit(1)
  }
  let bad = false
  for (const f of files) {
    let text
    try {
      text = readFileSync(f, 'utf-8')
    } catch (err) {
      console.error(`FAIL [keyring-placeholders] cannot read ${f}: ${err.message}`)
      bad = true
      continue
    }
    const hits = findPlaceholders(text)
    if (hits.length) {
      console.error(
        `FAIL [keyring-placeholders] ${f} still contains unfilled key-ceremony placeholders: ${hits.join(', ')}.\n` +
        '  The three PUBLIC keys belong in packages/cli/src/core/keyring-ceremony-output.ts. Do not paste keys anywhere else.',
      )
      bad = true
    }
  }
  if (bad) process.exit(1)
  console.log(`PASS [keyring-placeholders] no unfilled key-ceremony placeholders in ${files.length} file(s)`)
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
