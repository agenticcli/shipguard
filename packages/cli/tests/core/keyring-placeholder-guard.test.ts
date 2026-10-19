/**
 * a PUBLISHED build must never ship an unfilled key-ceremony placeholder.
 *
 * The guard (scripts/check-keyring-placeholders.mjs) is wired into:
 *   - tsup onSuccess, only when SHIPGUARD_PUBLISHED_BUILD=1 (so `build:publish` fails), and
 *   - scripts/release-gate.sh gate G2d (so the release gate fails).
 * Dev builds and the test suite still work with placeholders present.
 */
import { describe, it, expect } from 'vitest'
import { spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const CLI_DIR = path.resolve(here, '..', '..')
const GUARD = path.join(CLI_DIR, 'scripts', 'check-keyring-placeholders.mjs')
const CRYPTO_TS = path.join(CLI_DIR, 'src', 'core', 'crypto.ts')
const CEREMONY_TS = path.join(CLI_DIR, 'src', 'core', 'keyring-ceremony-output.ts')

const { findPlaceholders } = await import(GUARD)
const { KEYRING, isKeyringPlaceholder, KEYRING_PLACEHOLDER_MARKER } = await import('../../src/core/crypto.js')

function runGuard(...files: string[]) {
  return spawnSync(process.execPath, [GUARD, ...files], { encoding: 'utf-8' })
}

describe('keyring placeholder publish guard', () => {
  it('detects placeholder values but not the bare marker constant', () => {
    expect(findPlaceholders(`x = '${KEYRING_PLACEHOLDER_MARKER}-ra-k2-2026'`)).toEqual([`${KEYRING_PLACEHOLDER_MARKER}-ra-k2-2026`])
    // The marker constant itself ships in every build; it must not trip the guard.
    expect(findPlaceholders(`const KEYRING_PLACEHOLDER_MARKER = '${KEYRING_PLACEHOLDER_MARKER}';`)).toEqual([])
  })

  it('fails (exit 1) on a bundle that still contains a placeholder', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'sg-ph-'))
    try {
      const f = path.join(dir, 'cli.js')
      writeFileSync(f, `const k = { publicKey: "${KEYRING_PLACEHOLDER_MARKER}-cf-k2-2026" };`)
      const r = runGuard(f)
      expect(r.status).toBe(1)
      expect(r.stderr).toMatch(/cf-k2-2026/)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('passes (exit 0) on a bundle with real keys only', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'sg-ph-'))
    try {
      const f = path.join(dir, 'cli.js')
      writeFileSync(f, `const MARK = '${KEYRING_PLACEHOLDER_MARKER}'; const k = '-----BEGIN PUBLIC KEY-----';`)
      expect(runGuard(f).status).toBe(0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('scans every chunk when given a directory (tsup code-splits the bundle)', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'sg-ph-'))
    try {
      writeFileSync(path.join(dir, 'cli.js'), 'import "./chunk-A.js"')
      writeFileSync(path.join(dir, 'chunk-A.js'), `export const k = '${KEYRING_PLACEHOLDER_MARKER}-ra-k2-2026'`)
      const r = runGuard(dir)
      expect(r.status).toBe(1)
      expect(r.stderr).toMatch(/chunk-A\.js/)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('the guard verdict on the REAL ceremony-output file (where the three public keys are filled in) matches whether KEYRING still has placeholders', () => {
    const hasPlaceholder = KEYRING.some(isKeyringPlaceholder)
    expect(runGuard(CEREMONY_TS).status).toBe(hasPlaceholder ? 1 : 0)
    if (hasPlaceholder) {
      // fail closed names every unfilled new key, including the k3-2026 bundle key 
      const r = runGuard(CEREMONY_TS)
      for (const kid of ['ra-k2-2026', 'cf-k2-2026', 'k3-2026']) expect(r.stderr).toContain(kid)
    }
  })

  it('crypto.ts itself no longer carries any placeholder literal (single source: the ceremony-output file)', () => {
    expect(runGuard(CRYPTO_TS).status).toBe(0)
  })

  it('a ceremony-output file where ONLY the k3-2026 bundle key is still unfilled is refused (state-independent fixture)', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'sg-ph-'))
    try {
      const f = path.join(dir, 'keyring-ceremony-output.ts')
      writeFileSync(
        f,
        [
          'export const CEREMONY_OUTPUT = {',
          '  ra: { kid: "ra-k2-2026", fingerprint: "aa", publicKey: "-----BEGIN PUBLIC KEY-----" },',
          '  cf: { kid: "cf-k2-2026", fingerprint: "bb", publicKey: "-----BEGIN PUBLIC KEY-----" },',
          `  bundle: { kid: "k3-2026", fingerprint: "${KEYRING_PLACEHOLDER_MARKER}-k3-2026", publicKey: "${KEYRING_PLACEHOLDER_MARKER}-k3-2026" },`,
          '};',
          '',
        ].join('\n'),
      )
      const r = runGuard(f)
      expect(r.status).toBe(1)
      expect(r.stderr).toContain('k3-2026')
      expect(r.stderr).not.toContain('ra-k2-2026')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })


  it('tsup runs the guard on publish builds only', () => {
    const cfg = readFileSync(path.join(CLI_DIR, 'tsup.config.ts'), 'utf-8')
    expect(cfg).toMatch(/publishedBuild \? ' && node scripts\/check-keyring-placeholders\.mjs dist'/)
  })

  it('release-gate.sh runs the guard as gate G2d', () => {
    const gate = readFileSync(path.resolve(CLI_DIR, '..', '..', 'scripts', 'release-gate.sh'), 'utf-8')
    expect(gate).toMatch(/check-keyring-placeholders\.mjs/)
    expect(gate).toMatch(/FAIL \[G2d\]/)
    // G2d must scan the one generated keys file, not only crypto.ts
    expect(gate).toMatch(/check-keyring-placeholders\.mjs"[^\n]*keyring-ceremony-output\.ts/)
  })
})
