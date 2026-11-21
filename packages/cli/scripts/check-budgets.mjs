#!/usr/bin/env node
// check-budgets.mjs - release gate G9 (plan W0): size, speed and network budgets for the built CLI.
// Every budget breach is a gate failure. The pure part (BUDGETS, evaluateBudgets) is unit-tested with
// fake measurements in tests/release/budgets.test.ts; measure() runs the real built package.
//
//   node scripts/check-budgets.mjs [--json] [--pro-scan-seconds N] [--require-pro]
//
// Pro scan speed needs a signed-in account and a real rulebook, so it is measured by the dev run (W11)
// and handed in with --pro-scan-seconds (or RELEASE_GATE_PRO_SCAN_SECONDS); without it that line is
// reported as SKIP on a dry run; with --require-pro (a real release) a missing number FAILS.
// NOT measured here (covered by tests in the stream that builds the behaviour): "signed-out Free scan:
// at most 1 public fetch per 7 days" (W1a fake-clock test) and "signed-in Free hook with a hint = 0
// server calls" (W1a). This gate measures the zero-fetch modes (CI, quiet, safe mode, DO_NOT_TRACK).
//
// Exit 0 = all budgets met, 1 = a budget breached, 2 = could not measure.
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const KIB = 1024
const MIB = 1024 * 1024

export const BUDGETS = {
  tarballBytes: 800 * KIB,
  unpackedBytes: 3 * MIB,
  installBytes: 7 * MIB,
  directDeps: 7,
  versionMs: 250,
  freeScanSeconds: 8,
  proScanSeconds: 10,
  rssMb: 300,
  // public fetches in modes that must make none
  zeroFetchModes: 0,
}

// The runtime dependencies as of 0.13 (jose dropped). A new name here must be a deliberate edit of this
// list in a reviewed change: "no new runtime dependency".
export const BASELINE_DEPS = ['@noble/hashes', 'chalk', 'commander', 'fast-glob', 'minimatch', 're2js', 'yaml']

/**
 * m = { tarballBytes, unpackedBytes, installBytes, dependencies: string[], versionMs, freeScanSeconds,
 *       proScanSeconds?: number, rssMb, fetches: { [mode]: number } }
 * Returns [{ id, ok, skipped?, detail }]. A missing measurement is a failure (never a silent pass),
 * except proScanSeconds, which is skipped on a dry run and a failure when requirePro is set (a real release).
 */
export function evaluateBudgets(m, budgets = BUDGETS, baselineDeps = BASELINE_DEPS, { requirePro = false } = {}) {
  const out = []
  const num = (v) => typeof v === 'number' && Number.isFinite(v)
  const max = (id, v, limit, unit) => {
    if (!num(v)) return out.push({ id, ok: false, detail: `not measured` })
    out.push({ id, ok: v <= limit, detail: `${round(v)} ${unit} (budget <= ${limit} ${unit})` })
  }
  max('tarball', m.tarballBytes, budgets.tarballBytes, 'bytes')
  max('unpacked', m.unpackedBytes, budgets.unpackedBytes, 'bytes')
  max('install', m.installBytes, budgets.installBytes, 'bytes')
  const deps = Array.isArray(m.dependencies) ? m.dependencies : null
  if (!deps) out.push({ id: 'direct-deps', ok: false, detail: 'not measured' })
  else {
    const added = deps.filter((d) => !baselineDeps.includes(d))
    out.push({ id: 'direct-deps', ok: deps.length <= budgets.directDeps, detail: `${deps.length} (budget <= ${budgets.directDeps})` })
    out.push({ id: 'no-new-runtime-dep', ok: added.length === 0, detail: added.length ? `new: ${added.join(', ')}` : 'none new' })
  }
  max('version-time', m.versionMs, budgets.versionMs, 'ms')
  max('free-scan-time', m.freeScanSeconds, budgets.freeScanSeconds, 's')
  max('rss', m.rssMb, budgets.rssMb, 'MB')
  if (num(m.proScanSeconds)) max('pro-scan-time', m.proScanSeconds, budgets.proScanSeconds, 's')
  else if (requirePro) out.push({ id: 'pro-scan-time', ok: false, detail: 'not measured: a real release needs RELEASE_GATE_PRO_SCAN_SECONDS (--pro-scan-seconds) from the dev run' })
  else out.push({ id: 'pro-scan-time', ok: true, skipped: true, detail: 'SKIP: measured by the dev run (W11), pass --pro-scan-seconds' })
  const modes = m.fetches && typeof m.fetches === 'object' ? Object.entries(m.fetches) : []
  if (modes.length === 0) out.push({ id: 'zero-fetch-modes', ok: false, detail: 'not measured' })
  for (const [mode, n] of modes) {
    out.push({ id: `fetches-${mode}`, ok: num(n) && n <= budgets.zeroFetchModes, detail: `${n} non-ping fetches (budget ${budgets.zeroFetchModes})` })
  }
  return out
}

const round = (n) => (Number.isInteger(n) ? n : Math.round(n * 100) / 100)

// ---- measuring -----------------------------------------------------------------------------

function dirBytes(dir) {
  let total = 0
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules') continue
    const p = join(dir, e.name)
    if (e.isDirectory()) total += dirBytes(p)
    else if (e.isFile()) total += statSync(p).size
  }
  return total
}

/** Where a package named `name` resolves from the package directory `fromReal` (pnpm or npm layout). */
function resolveDep(fromReal, name) {
  let dir = fromReal
  for (;;) {
    const cand = basename(dir) === 'node_modules' ? join(dir, name) : join(dir, 'node_modules', name)
    try {
      return realpathSync(cand)
    } catch {
      /* not here, go up */
    }
    const up = dirname(dir)
    if (up === dir) return null
    dir = up
  }
}

/** Unpacked bytes of the package's production dependency closure (what `npm install` would put on disk). */
export function measureInstallBytes(cliDir) {
  const pkg = JSON.parse(readFileSync(join(cliDir, 'package.json'), 'utf-8'))
  const seen = new Set()
  let total = 0
  const visit = (real) => {
    if (seen.has(real)) return
    seen.add(real)
    total += dirBytes(real)
    const p = JSON.parse(readFileSync(join(real, 'package.json'), 'utf-8'))
    for (const d of Object.keys({ ...(p.dependencies ?? {}), ...(p.optionalDependencies ?? {}) })) {
      const r = resolveDep(real, d)
      if (r) visit(r)
    }
  }
  for (const d of Object.keys(pkg.dependencies ?? {})) {
    const r = resolveDep(cliDir, d)
    if (!r) throw new Error(`dependency ${d} is not installed; run pnpm install first`)
    visit(r)
  }
  return total
}

const PRELOAD = `const fs = require('fs');
const out = process.env.SG_BUDGET_OUT;
const loop = process.env.SG_BUDGET_PING_URL || '';
const urls = [];
globalThis.fetch = function (u) { urls.push(String((u && u.url) || u)); return Promise.resolve(new Response('ok')); };
process.on('exit', () => {
  const nonPing = urls.filter((u) => !(loop && u.startsWith(loop)));
  fs.writeFileSync(out, JSON.stringify({ maxRssKb: process.resourceUsage().maxRSS, fetches: nonPing.length }));
});
`

function runCli(cliJs, args, { cwd, env, work }) {
  const out = join(work, `m-${Math.random().toString(36).slice(2)}.json`)
  const t0 = process.hrtime.bigint()
  const r = spawnSync(process.execPath, ['--require', join(work, 'preload.cjs'), cliJs, ...args], {
    cwd,
    env: { PATH: process.env.PATH, HOME: join(work, 'home'), SG_BUDGET_OUT: out, ...env },
    encoding: 'utf-8',
    timeout: 120_000,
  })
  const seconds = Number(process.hrtime.bigint() - t0) / 1e9
  if (r.error) throw r.error
  let rec = { maxRssKb: NaN, fetches: NaN }
  try {
    rec = JSON.parse(readFileSync(out, 'utf-8'))
  } catch (err) {
    throw new Error(`budget preload wrote nothing for "${args.join(' ')}" (exit ${r.status}): ${err.message}`)
  }
  return { seconds, status: r.status, ...rec }
}

export async function measure(cliDir, { proScanSeconds } = {}) {
  const dist = join(cliDir, 'dist', 'cli.js')
  const work = mkdtempSync(join(tmpdir(), 'sg-budgets-'))
  try {
    mkdirSync(join(work, 'home'), { recursive: true })
    writeFileSync(join(work, 'preload.cjs'), PRELOAD)
    const pkg = JSON.parse(readFileSync(join(cliDir, 'package.json'), 'utf-8'))
    const packJson = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: cliDir, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] }))
    const { generateRepo } = await import(join(cliDir, 'tests', 'helpers', 'synthetic-repo.mjs'))

    // --version time: median of 5 cold process starts
    const times = []
    for (let i = 0; i < 5; i++) {
      const t0 = process.hrtime.bigint()
      execFileSync(process.execPath, [dist, '--version'], { stdio: 'ignore', env: { PATH: process.env.PATH, HOME: join(work, 'home') } })
      times.push(Number(process.hrtime.bigint() - t0) / 1e6)
    }
    times.sort((a, b) => a - b)

    // Free scan of an 812-file generated tree (stand-in for the 812-file Next.js app; same file count).
    const big = join(work, 'tree812')
    generateRepo(big, 812, 1)
    const free = runCli(dist, ['scan', big, '--quiet'], { cwd: big, env: { SHIPGUARD_TELEMETRY: '0', DO_NOT_TRACK: '1' }, work })

    // Zero-fetch modes: a small project, tracking ON (pings go to a dead loopback address and are not
    // counted), so any other request in these modes is a public fetch.
    const small = join(work, 'small')
    generateRepo(small, 20, 2)
    const ping = 'http://127.0.0.1:9/ping'
    const on = { SHIPGUARD_TELEMETRY_URL: ping, SG_BUDGET_PING_URL: ping }
    const fetches = {}
    const modes = [
      ['ci', ['scan', small, '--quiet'], { CI: 'true' }],
      ['quiet', ['scan', small, '--quiet'], {}],
      ['safe-mode', ['scan', small, '--quiet'], { SHIPGUARD_SAFE_MODE: '1' }],
      ['do-not-track', ['scan', small, '--quiet'], { DO_NOT_TRACK: '1' }],
    ]
    for (const [name, args, extra] of modes) {
      fetches[name] = runCli(dist, args, { cwd: small, env: { ...on, ...extra }, work }).fetches
    }

    return {
      tarballBytes: packJson[0]?.size,
      unpackedBytes: packJson[0]?.unpackedSize,
      installBytes: measureInstallBytes(cliDir),
      dependencies: Object.keys(pkg.dependencies ?? {}),
      versionMs: times[2],
      freeScanSeconds: free.seconds,
      rssMb: free.maxRssKb / 1024,
      proScanSeconds,
      fetches,
    }
  } finally {
    rmSync(work, { recursive: true, force: true })
  }
}

async function main() {
  const here = dirname(fileURLToPath(import.meta.url))
  const cliDir = resolve(here, '..')
  const args = process.argv.slice(2)
  const json = args.includes('--json')
  const i = args.indexOf('--pro-scan-seconds')
  const proRaw = i >= 0 ? args[i + 1] : process.env.RELEASE_GATE_PRO_SCAN_SECONDS
  const proScanSeconds = proRaw === undefined || proRaw === '' ? undefined : Number(proRaw)
  if (proScanSeconds !== undefined && !Number.isFinite(proScanSeconds)) {
    console.error('FAIL [budgets] --pro-scan-seconds must be a number')
    process.exit(2)
  }
  let m
  try {
    m = await measure(cliDir, { proScanSeconds })
  } catch (err) {
    console.error(`FAIL [budgets] could not measure: ${err instanceof Error ? err.message : String(err)}`)
    process.exit(2)
  }
  const results = evaluateBudgets(m, BUDGETS, BASELINE_DEPS, { requirePro: args.includes('--require-pro') })
  if (json) console.log(JSON.stringify({ measurements: m, results }, null, 2))
  else for (const r of results) console.log(`${r.skipped ? 'SKIP' : r.ok ? 'ok  ' : 'FAIL'} ${r.id}: ${r.detail}`)
  process.exit(results.every((r) => r.ok) ? 0 : 1)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main()
