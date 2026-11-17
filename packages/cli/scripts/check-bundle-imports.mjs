#!/usr/bin/env node
// check-bundle-imports.mjs — release gate G3 helper.
//
// Fails (exit 1) when a built bundle still imports a workspace package at runtime
// (@agenticcli/*), i.e. bundling is broken and the published CLI would crash on install.
// Only real imports count: require("@agenticcli/x"), from "@agenticcli/x", import("@agenticcli/x"),
// and bare import "@agenticcli/x". A plain string such as '@agenticcli/shipguard@0' (the npx spec)
// is not an import and passes.
//
// Usage: node scripts/check-bundle-imports.mjs <file> [file ...]   (default: dist/cli.js)
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const Q = `["'\`]`
const IMPORT_RE = new RegExp(
  `(?:require\\(\\s*|import\\(\\s*|\\bfrom\\s*|^\\s*import\\s*)${Q}@agenticcli/[^"'\`]*${Q}`,
  'gm',
)

export function findWorkspaceImports(text) {
  return [...new Set(text.match(IMPORT_RE) ?? [])].map(s => s.trim())
}

function main() {
  const here = path.dirname(fileURLToPath(import.meta.url))
  const files = process.argv.slice(2)
  if (files.length === 0) files.push(path.join(here, '..', 'dist', 'cli.js'))
  let bad = false
  for (const f of files) {
    let text
    try {
      text = readFileSync(f, 'utf-8')
    } catch (err) {
      console.error(`FAIL [bundle-imports] cannot read ${f}: ${err.message}`)
      bad = true
      continue
    }
    const hits = findWorkspaceImports(text)
    if (hits.length > 0) {
      console.error(`FAIL [bundle-imports] ${f}: runtime import of workspace package: ${hits.join(' | ')}`)
      bad = true
    }
  }
  process.exit(bad ? 1 : 0)
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
