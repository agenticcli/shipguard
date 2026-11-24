#!/usr/bin/env node
/**
 * gen-checksum-manifest — build-time coderef integrity artifact
 *
 * Runs AFTER tsup so dist/ files exist. Finds every bundled coderef module
 * file in dist/, computes SHA-256 of each, and writes dist/checksum-manifest.json.
 *
 * The manifest is consumed by the CLI at runtime to verify each dispatched
 * coderef module against its build-time hash (fail-closed on mismatch).
 *
 * Format: { [moduleId]: "sha256hex" }
 * moduleId matches the keys used in DEFAULT_DISPATCH_TABLE (e.g. "secrets",
 * "auth", "database", "deployment", "payments").
 *
 * Cryptographic SIGNING of this manifest is deferred (not yet implemented).
 * This is integrity/fail-closed only.
 *
 * Zero new runtime dependencies — uses Node built-ins only.
 */

import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const distDir = join(__dirname, '..', 'dist')

// The coderef moduleIds known to the dispatch table (DEFAULT_DISPATCH_TABLE).
// These map to the bundled check module source files. After tsup bundles
// src/cli.ts (which transitively imports all checks/*), the check module code
// ends up inlined into the main cli.js bundle. Since tsup produces a single
// entrypoint bundle (entry: ['src/cli.ts']), all coderef module code is inside
// dist/cli.js (and any chunk files tsup produces).
//
// Strategy: hash the entire dist/ bundle output (cli.js + any chunks).
// The manifest maps each moduleId to the SHA-256 of the COMBINED bundle bytes
// (same hash for all — reflects that all modules are in the same bundle).
// This gives a tamper-detectable signal: if any dist file changes, all hashes
// change and the manifest is stale.
//
// This is sufficient for fail-closed semantics: a tampered CLI
// binary produces a different combined hash → manifest mismatch → non-safe.
//
// Future: if coderef modules are split into separate chunk files, update this
// script to hash each chunk individually and map moduleId → its chunk hash.

const CODEREF_MODULE_IDS = ['secrets', 'auth', 'database', 'deployment', 'payments']

function sha256File(filePath) {
  const content = readFileSync(filePath)
  return createHash('sha256').update(content).digest('hex')
}

function sha256Combined(filePaths) {
  const hash = createHash('sha256')
  for (const p of filePaths) {
    hash.update(readFileSync(p))
  }
  return hash.digest('hex')
}

if (!existsSync(distDir)) {
  console.error(`[gen-checksum-manifest] ERROR: dist/ directory not found at ${distDir}`)
  console.error('  Run tsup first: pnpm --filter @agenticcli/shipguard build')
  process.exit(1)
}

// Collect all .js files in dist/ (cli.js + any chunk files tsup produces).
const distFiles = readdirSync(distDir)
  .filter(f => f.endsWith('.js'))
  .sort()  // deterministic order for hash stability
  .map(f => join(distDir, f))

if (distFiles.length === 0) {
  console.error(`[gen-checksum-manifest] ERROR: no .js files found in ${distDir}`)
  process.exit(1)
}

// Compute the combined hash of the entire bundle.
// All coderef modules share this hash (they're all bundled together in cli.js).
const combinedHash = sha256Combined(distFiles)

// Build the manifest: every coderef moduleId → combined bundle hash.
/** @type {Record<string, string>} */
const manifest = {}
for (const moduleId of CODEREF_MODULE_IDS) {
  manifest[moduleId] = combinedHash
}

const manifestPath = join(distDir, 'checksum-manifest.json')
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf-8')

console.log(`[gen-checksum-manifest] Written ${manifestPath}`)
console.log(`  Bundle files hashed: ${distFiles.map(f => f.split('/').pop()).join(', ')}`)
console.log(`  Combined SHA-256: ${combinedHash.slice(0, 16)}…`)
console.log(`  Module IDs: ${CODEREF_MODULE_IDS.join(', ')}`)
