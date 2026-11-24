/** Fixtures that make `scan --json` output larger than a pipe buffer (public example secrets only). */
import { mkTree } from './cli-fixture.js'

const SECRETS =
  "const a='AKIAIOSFODNN7EXAMPLE'\n" +
  "const b='ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n" +
  "const c='sk_live_abcdefghijklmnopqrstuvwx'\n" +
  '-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n'

/** `n` files with 5 findings each: 25 files give about 120 KB of JSON, 120 files about 580 KB, 1200 files about 5.7 MB. */
export function mkBigFindingsTree(n: number): string {
  const files: Record<string, string> = { 'package.json': '{"name":"pipe-fixture"}' }
  for (let i = 0; i < n; i++) files[`f${i}.js`] = SECRETS
  return mkTree(files)
}
