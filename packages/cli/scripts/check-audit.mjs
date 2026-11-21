#!/usr/bin/env node
// check-audit.mjs - release gate G10 (plan W0): `npm audit` of the PRODUCTION dependency tree a user gets
// from the packed CLI. Fails on any high or critical advisory not allowed in docs/security/audit-allow.txt.
//
//   node scripts/check-audit.mjs [--input npm-audit.json] [--allow file] [--today YYYY-MM-DD]
//
// Allowlist lines: `GHSA-xxxx-xxxx-xxxx | reason | YYYY-MM-DD` (expiry). An entry with no reason or an
// expired/invalid date is IGNORED with a warning (so it cannot silently allow anything). `#` starts a comment.
// Exit 0 = pass, 1 = blocking advisories, 3 = audit unavailable (no network, registry error): the gate
// treats that as a failure on a real release and as a skip on a dry run. Never "pass" on a failed audit.
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export function parseAllowlist(text, today) {
  const allowed = new Map()
  const warnings = []
  text.split('\n').forEach((raw, i) => {
    const line = raw.trim()
    if (!line || line.startsWith('#')) return
    const [id, reason, expiry] = line.split('|').map((s) => s.trim())
    if (!/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i.test(id ?? '')) return warnings.push(`allowlist line ${i + 1}: not a GHSA id, ignored`)
    if (!reason) return warnings.push(`allowlist ${id}: no reason, ignored`)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(expiry ?? '')) return warnings.push(`allowlist ${id}: no valid expiry date, ignored`)
    if (expiry < today) return warnings.push(`allowlist ${id}: expired ${expiry}, ignored`)
    allowed.set(id.toLowerCase(), { reason, expiry })
  })
  return { allowed, warnings }
}

/**
 * audit = parsed `npm audit --json` output (npm 7+: { vulnerabilities: { <name>: { via: [...] } } }).
 * Every `via` entry that is an object is an advisory (strings only name another package). Returns
 * { blocking: [{id, severity, module}], allowed: [...] } for high and critical advisories.
 */
export function evaluateAudit(audit, allowed) {
  const vulns = audit && typeof audit.vulnerabilities === 'object' && audit.vulnerabilities ? Object.entries(audit.vulnerabilities) : null
  if (!vulns) throw new Error('audit output has no "vulnerabilities" object')
  const blocking = []
  const allowedHits = []
  const seen = new Set()
  for (const [name, v] of vulns) {
    for (const via of Array.isArray(v?.via) ? v.via : []) {
      if (!via || typeof via !== 'object') continue
      if (via.severity !== 'high' && via.severity !== 'critical') continue
      const ghsa = (String(via.url ?? '').match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i) ?? [''])[0].toLowerCase()
      const id = ghsa || `advisory-${via.source ?? name}`
      const key = `${id}|${via.name ?? name}`
      if (seen.has(key)) continue
      seen.add(key)
      const row = { id, severity: via.severity, module: via.name ?? name }
      if (ghsa && allowed.has(ghsa)) allowedHits.push(row)
      else blocking.push(row)
    }
  }
  return { blocking, allowed: allowedHits }
}

/**
 * Audit what a USER gets: pack the CLI, resolve it in a scratch project with npm (lockfile only, no scripts),
 * then `npm audit --omit=dev --json`. (`pnpm audit` 9.x answered an empty result for a known advisory, so it
 * is not trusted for this gate.) Returns the raw JSON text, or null when npm could not resolve or audit.
 */
function runNpmAudit(cliDir) {
  const work = mkdtempSync(join(tmpdir(), 'sg-audit-'))
  try {
    const pack = spawnSync('npm', ['pack', '--ignore-scripts', '--silent', '--pack-destination', work], { cwd: cliDir, encoding: 'utf-8' })
    if (pack.status !== 0) return { raw: null, why: `npm pack failed: ${(pack.stderr || '').trim().split('\n')[0]}` }
    const tgz = join(work, pack.stdout.trim().split('\n').pop())
    const proj = join(work, 'probe')
    mkdirSync(proj)
    writeFileSync(join(proj, 'package.json'), JSON.stringify({ name: 'audit-probe', version: '1.0.0', private: true }))
    const inst = spawnSync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', tgz], { cwd: proj, encoding: 'utf-8' })
    if (inst.status !== 0) return { raw: null, why: `npm install failed: ${(inst.stderr || '').trim().split('\n')[0]}` }
    const aud = spawnSync('npm', ['audit', '--omit=dev', '--json'], { cwd: proj, encoding: 'utf-8', maxBuffer: 32 * 1024 * 1024 })
    // npm audit exits 1 when it finds vulnerabilities; the JSON on stdout is what counts.
    return { raw: aud.stdout, why: (aud.stderr || '').trim().split('\n')[0] || 'no output' }
  } finally {
    rmSync(work, { recursive: true, force: true })
  }
}

function main() {
  const here = dirname(fileURLToPath(import.meta.url))
  const root = resolve(here, '..', '..', '..')
  const args = process.argv.slice(2)
  const opt = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined)
  const allowFile = resolve(opt('--allow') ?? resolve(root, 'docs', 'security', 'audit-allow.txt'))
  const today = opt('--today') ?? new Date().toISOString().slice(0, 10)

  let raw
  const input = opt('--input')
  if (input) raw = readFileSync(input, 'utf-8')
  else {
    const r = runNpmAudit(resolve(here, '..'))
    raw = r.raw
    if (!raw || !raw.trim().startsWith('{')) {
      console.error(`UNAVAILABLE [audit] npm audit gave no JSON (${r.why})`)
      process.exit(3)
    }
  }
  let audit
  try {
    audit = JSON.parse(raw)
  } catch (err) {
    console.error(`UNAVAILABLE [audit] output is not JSON: ${err.message}`)
    process.exit(3)
  }
  if (audit.error) {
    console.error(`UNAVAILABLE [audit] registry error: ${audit.error.code ?? ''} ${audit.error.summary ?? audit.error.message ?? ''}`.trim())
    process.exit(3)
  }
  const { allowed, warnings } = existsSync(allowFile) ? parseAllowlist(readFileSync(allowFile, 'utf-8'), today) : { allowed: new Map(), warnings: [`no allowlist at ${allowFile}`] }
  for (const w of warnings) console.error(`warn [audit] ${w}`)
  let res
  try {
    res = evaluateAudit(audit, allowed)
  } catch (err) {
    console.error(`UNAVAILABLE [audit] ${err.message}`)
    process.exit(3)
  }
  for (const a of res.allowed) console.log(`allowed [audit] ${a.id} (${a.severity}, ${a.module}): ${allowed.get(a.id).reason} (until ${allowed.get(a.id).expiry})`)
  if (res.blocking.length) {
    for (const b of res.blocking) console.error(`FAIL [audit] ${b.id} ${b.severity} in ${b.module}`)
    process.exit(1)
  }
  console.log(`PASS [audit] no unlisted high or critical advisory in production dependencies (${res.allowed.length} allowed)`)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
