/**
 * `shipguard schema --json`.
 *
 * Specification:
 *   "`shipguard schema --json`: machine-readable contract — schemaVersion, enum values,
 *    exit-code meanings, and the **limits block** (maxFiles, maxFileSize, unanalyzable types)"
 *
 * The load-bearing property is not "a command exists" but "the contract it prints is TRUE":
 * the enum it advertises must be the enum `scan --json` emits, the schemaVersion must match,
 * and the limits must be the ones the scanned project actually uses. A contract document that
 * drifts from the thing it describes is worse than none.
 *
 * FAIL-BEFORE: the command did not exist — `shipguard schema --json` exited 2.
 *
 * DISCIPLINE.
 */
import { execSync } from 'node:child_process'
import { spawnNode, type SpawnResult } from '../helpers/spawn-cli.js'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest'

// Real-process e2e file: every test spawns the built CLI (each spawn ~0.3-1s idle, several x
// under load). Vitest's 5s default is below the cost of a 3-4 spawn test on a shared box, so
// state the budget explicitly (same 30s as the per-spawn kill timeout), file-scoped - not global.
vi.setConfig({ testTimeout: 30_000 })
import { buildSchemaContract, CURRENT_SCHEMA_VERSION } from '../../src/commands/schema.js'
import { DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_SIZE_BYTES, DEFAULT_MAX_TOTAL_BYTES } from '../../src/utils/fs.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

const tempDirs: string[] = []

function mkFixture(policyYaml?: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-schema-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  writeFileSync(join(dir, 'config.js'), "const k = 'AKIAIOSFODNN7EXAMPLE'\n", 'utf-8')
  if (policyYaml) writeFileSync(join(dir, 'shipguard.policy.yml'), policyYaml, 'utf-8')
  return dir
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
})

function runCli(args: string[], cwd = pkgRoot): Promise<SpawnResult> {
  return spawnNode(distCli, args, { cwd: cwd, timeoutMs: 25_000 })
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 180_000)

describe('#9 — the contract exists and is machine-readable', () => {
  it('`schema --json` prints valid JSON and exits 0', async () => {
    const { code, stdout } = (await runCli(['schema', '--json']))
    expect(code).toBe(0)
    expect(() => JSON.parse(stdout)).not.toThrow()
  })

  it('carries schemaVersion, the verdict enum, exit codes and the limits block', async () => {
    const c = JSON.parse((await runCli(['schema', '--json'])).stdout)
    expect(c.schemaVersion).toBe(CURRENT_SCHEMA_VERSION)
    expect(c.recommendation.values).toEqual(['SAFE_TO_SHIP', 'REVIEW_BEFORE_SHIP', 'DO_NOT_SHIP'])
    expect(c.exitCodes.map((e: { code: number }) => e.code)).toEqual([0, 1, 2, 3])
    expect(c.limits.maxFiles.value).toBe(DEFAULT_MAX_FILES)
    expect(c.limits.maxFileSizeBytes.value).toBe(DEFAULT_MAX_FILE_SIZE_BYTES)
    expect(c.limits.maxTotalBytes.value).toBe(DEFAULT_MAX_TOTAL_BYTES)
    expect(c.limits.unanalyzableTypes.length).toBeGreaterThan(0)
  })

  it('human mode prints the same facts without --json', async () => {
    const { code, stdout } = (await runCli(['schema']))
    expect(code).toBe(0)
    expect(stdout).toContain('DO_NOT_SHIP')
    expect(stdout).toContain('maxFiles')
    expect(stdout).toContain('UNVERIFIED')
  })
})

describe('#9 — the contract tells the truth about the running CLI', () => {
  it('its schemaVersion matches what `scan --json` actually emits', async () => {
    const contract = JSON.parse((await runCli(['schema', '--json'])).stdout)
    const scan = JSON.parse((await runCli(['scan', mkFixture(), '--json'])).stdout)
    expect(contract.schemaVersion).toBe(scan.schemaVersion)
  })

  it('its cliVersion matches what `scan --json` reports', async () => {
    const contract = JSON.parse((await runCli(['schema', '--json'])).stdout)
    const scan = JSON.parse((await runCli(['scan', mkFixture(), '--json'])).stdout)
    expect(contract.cliVersion).toBe(scan.cliVersion)
  })

  it('the advertised verdict enum contains the verdict a real scan produced', async () => {
    const contract = JSON.parse((await runCli(['schema', '--json'])).stdout)
    const scan = JSON.parse((await runCli(['scan', mkFixture(), '--json'])).stdout)
    expect(contract.recommendation.values).toContain(scan.recommendation)
  })

  it('the advertised degrade codes cover the ones a real degraded scan emits', async () => {
    const contract = JSON.parse((await runCli(['schema', '--json'])).stdout)
    const dir = mkFixture('version: 1\nlimits:\n  maxFiles: 1\n')
    const scan = JSON.parse((await runCli(['scan', dir, '--json'])).stdout)
    const advertised = contract.degradeCodes.map((d: { code: string }) => d.code)
    for (const r of scan.degradedReasons ?? []) {
      expect(advertised).toContain(r.code)
    }
    expect(scan.degraded).toBe(true)
  })
})

describe('#9 — the limits block reflects THIS project', () => {
  it('a project policy overrides the limits, and the source says so', async () => {
    const dir = mkFixture('version: 1\nlimits:\n  maxFiles: 42\n')
    const c = JSON.parse((await runCli(['schema', '--json'], dir)).stdout)
    expect(c.limits.maxFiles.value).toBe(42)
    expect(c.limits.maxFiles.source).toBe('policy')
    // Untouched limits are still labelled as defaults — provenance is per value.
    expect(c.limits.maxFileSizeBytes.source).toBe('default')
  })

  it('every limit says how a machine detects it was hit', async () => {
    const c = JSON.parse((await runCli(['schema', '--json'])).stdout)
    expect(c.limits.maxFiles.machineSignal).toContain('OUTPUT_TRUNCATED')
    expect(c.limits.maxFileSizeBytes.machineSignal).toContain('FILE_TOO_LARGE')
  })

  it('no limit claims to be verified until the boundary round measures it', async () => {
    const c = JSON.parse((await runCli(['schema', '--json'])).stdout)
    expect(c.limits.maxFiles.verifiedBy).toBeNull()
    expect(c.limits.maxFileSizeBytes.verifiedBy).toBeNull()
    expect(c.limits.maxTotalBytes.verifiedBy).toBeNull()
    for (const t of c.limits.unanalyzableTypes) expect(t.verifiedBy).toBeNull()
    expect(c.limits.verificationStatus).toContain('UNVERIFIED')
  })

  it('a broken policy file is a config error (exit 2), not a lie', async () => {
    const dir = mkFixture('version: 1\nlimits: [this is not a map\n')
    const { code } = (await runCli(['schema', '--json'], dir))
    expect(code).toBe(2)
  })
})

describe('#9 — buildSchemaContract is pure', () => {
  it('same inputs, same contract', async () => {
    const a = buildSchemaContract({ maxFiles: 10, maxFileSizeBytes: 20, maxTotalBytes: 30 })
    const b = buildSchemaContract({ maxFiles: 10, maxFileSizeBytes: 20, maxTotalBytes: 30 })
    expect(a).toEqual(b)
  })
})
