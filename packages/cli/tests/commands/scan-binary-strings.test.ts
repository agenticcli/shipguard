/**
 * Magic-verified binaries under the size cap are still counted as binary, but their printable
 * strings (runs of 8+ ASCII characters, one per line) go through the normal rules.
 *
 * (a) PNG magic + 4000 NULs + a key: the key is FOUND (before: SAFE_TO_SHIP, degraded false).
 * (b) Real host assets (jpg, pdf, mp4, png found on this machine, never committed) and synthetic
 *     images give ZERO findings with the full rule set: no false positives from binary noise.
 *     (The repo has no committed image fixtures; the synthetic ones are built from literal bytes.)
 * (c) Mutation: with the strings reading removed, (a) fails. Run as a unit on `classifyFile`: a
 *     binary result without `strings` is exactly the old behaviour, and the test pins that the
 *     strings are what carries the key.
 */
import { execFileSync } from 'node:child_process'
import { copyFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { classifyFile, stringsReading } from '../../src/utils/classify.js'
import { cleanupTrees, KEY, keyFoundIn, mkTree, noise, scanJson } from '../helpers/cli-fixture.js'

vi.setConfig({ testTimeout: 180_000 })
afterAll(cleanupTrees)

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
const keyLine = Buffer.from(`AWS_ACCESS_KEY_ID=${KEY}\n`)

function pngWithKey(): Buffer {
  return Buffer.concat([PNG_SIG, Buffer.alloc(4000), keyLine])
}

describe('binary strings reading', () => {
  it('(a) PNG magic + 4000 NULs + a key: the key is found, the file is still counted as binary', async () => {
    const dir = mkTree({ 'pic.png': pngWithKey(), 'package.json': '{"name":"s"}', 'a.js': 'const a = 1\n' })
    const r = await scanJson(dir)
    expect(keyFoundIn(r.json, 'pic.png')).toBe(true)
    expect(r.json!.coverage.skipped.binary).toBe(1)
    expect(r.json!.coverage.decoded.binaryStringsScanned).toBe(1)
    // The invariant still holds: the file is counted once, as binary.
    const c = r.json!.coverage
    const skipped = Object.entries(c.skipped as Record<string, number>)
      .filter(([k]) => k !== 'binaryHeadOnly')
      .reduce((n, [, v]) => n + v, 0)
    expect(c.discovered).toBe(c.scanned + skipped)
  })

  it('(a) the same through --changed', async () => {
    const dir = mkTree({ 'pic.png': pngWithKey(), 'package.json': '{"name":"s"}' }, { git: true })
    const r = await scanJson(dir, ['--changed'])
    expect(keyFoundIn(r.json, 'pic.png')).toBe(true)
  })

  it('(b) synthetic JPEG, PNG and PDF-like binaries give zero findings', async () => {
    const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe1]), Buffer.from('Exif\0\0MM\0*Camera Model Name 1234'), noise(4000, 7)])
    const png = Buffer.concat([PNG_SIG, Buffer.from('IHDR'), noise(3000, 9), Buffer.from('IEND')])
    const pdf = Buffer.concat([Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n', 'latin1'), noise(3000, 11)])
    const dir = mkTree({ 'a.jpg': jpeg, 'b.png': png, 'c.pdf': pdf, 'package.json': '{"name":"s"}', 'ok.js': 'const ok = 1\n' })
    const r = await scanJson(dir)
    expect(r.json!.findings).toEqual([])
    expect(r.json!.coverage.skipped.binary).toBe(3)
  })

  // Opt-in: it runs `find /usr` four times, which is too slow for CI runners. Enable with
  // SHIPGUARD_TEST_HOST_ASSETS=1. The synthetic row above always runs.
  it.skipIf(!process.env.SHIPGUARD_TEST_HOST_ASSETS)('(b) real host assets (jpg, pdf, mp4, png) give zero findings with the full rule set', async () => {
    const found: string[] = []
    for (const ext of ['jpg', 'pdf', 'mp4', 'png']) {
      try {
        const out = execFileSync('find', ['/usr', '-xdev', '-type', 'f', '-iname', `*.${ext}`, '-size', '-500k', '-size', '+20k'], {
          encoding: 'utf-8',
          timeout: 20_000,
        })
        const first = out.split('\n').find(Boolean)
        if (first) found.push(first)
      } catch (err) {
        // find can exit non-zero on unreadable dirs; use whatever it printed.
        const out = (err as { stdout?: string }).stdout ?? ''
        const first = out.split('\n').find(Boolean)
        if (first) found.push(first)
      }
    }
    if (found.length === 0) return // nothing on this host to test against
    const files: Record<string, string> = { 'package.json': '{"name":"s"}', 'ok.js': 'const ok = 1\n' }
    const dir = mkTree(files)
    found.forEach((src, i) => copyFileSync(src, join(dir, `asset${i}${src.slice(src.lastIndexOf('.'))}`)))
    const r = await scanJson(dir)
    expect(r.json!.findings).toEqual([])
    expect(r.json!.coverage.skipped.binary + r.json!.coverage.skipped.tooLarge).toBeGreaterThan(0)
  })

  it('(c) mutation guard: the key is carried only by the strings reading', () => {
    const res = classifyFile(new Uint8Array(pngWithKey()))
    expect(res.kind).toBe('binary')
    if (res.kind !== 'binary') return
    expect(res.strings?.text).toContain(KEY)
    // Without the strings reading (the old behaviour) nothing would carry the key to the rules.
    const without = { ...res, strings: undefined }
    expect(JSON.stringify(without)).not.toContain(KEY)
  })

  it('stringsReading: runs of 8+ printable characters, one per line, shorter runs dropped', () => {
    const b = Buffer.concat([Buffer.from('short'), Buffer.from([0]), Buffer.from('longer-run-here'), Buffer.from([0xff]), Buffer.from('1234567')])
    expect(stringsReading(new Uint8Array(b))?.text).toBe('longer-run-here')
    expect(stringsReading(new Uint8Array(Buffer.alloc(100)))).toBeNull()
  })
})
