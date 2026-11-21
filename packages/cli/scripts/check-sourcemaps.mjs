#!/usr/bin/env node
/**
 * check-sourcemaps — every dist/*.js has a dist/*.js.map whose sources are real repo files.
 * Usage: node scripts/check-sourcemaps.mjs <dist-dir>
 * Fails (exit 1) when: a .js has no map, a .js lacks its //# sourceMappingURL line, a map lists a
 * source under node_modules or with an absolute path, or an embedded source differs from the file
 * on disk (maps are resolved against the dist dir, so ../src/x.ts is packages/cli/src/x.ts).
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'

const dist = resolve(process.argv[2] ?? 'dist')
const errors = []
const jsFiles = readdirSync(dist).filter((f) => f.endsWith('.js'))
if (jsFiles.length === 0) errors.push(`no .js files in ${dist}`)
let sourceCount = 0
for (const js of jsFiles) {
  const text = readFileSync(join(dist, js), 'utf-8')
  if (!text.trimEnd().endsWith(`//# sourceMappingURL=${js}.map`)) errors.push(`${js}: missing sourceMappingURL line`)
  const mapPath = join(dist, `${js}.map`)
  if (!existsSync(mapPath)) { errors.push(`${js}: no ${js}.map`); continue }
  let map
  try { map = JSON.parse(readFileSync(mapPath, 'utf-8')) } catch (e) { errors.push(`${js}.map: not JSON (${e.message})`); continue }
  const sources = map.sources ?? []
  const contents = map.sourcesContent ?? []
  sources.forEach((s, i) => {
    sourceCount++
    if (isAbsolute(s) || s.includes('node_modules')) { errors.push(`${js}.map: bad source path ${s}`); return }
    const onDisk = resolve(dist, s)
    if (!existsSync(onDisk)) { errors.push(`${js}.map: source not in repo: ${s}`); return }
    if (contents[i] != null && contents[i] !== readFileSync(onDisk, 'utf-8')) errors.push(`${js}.map: embedded source differs from file: ${s}`)
  })
}
if (errors.length) {
  for (const e of errors) console.error(`[check-sourcemaps] ${e}`)
  process.exit(1)
}
console.log(`[check-sourcemaps] ${jsFiles.length} bundles, ${sourceCount} mapped sources, all resolve`)
