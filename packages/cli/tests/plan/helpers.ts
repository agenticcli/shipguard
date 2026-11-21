/** Shared test helpers for the plan modules: the P0 test key and signed vectors, and a temp config dir. */
import { readFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { _testInjectKeyringEntry, computeSpkiFingerprint } from '../../src/core/crypto.js'

const dir = join(__dirname, '..', '..', '..', '..', 'docs', 'contracts')
export const vectorFile = JSON.parse(readFileSync(join(dir, 'plan-v2.vectors.json'), 'utf8')) as {
  key: { kid: string; publicKeyPem: string }
  vectors: Array<{ name: string; kind: 'account' | 'offer'; token: string; expect: string; ctx: { now: number; acct: string | null; nonce: string | null; scanId: string | null } }>
}

/** Pin the throwaway P0 test key as a BUNDLE-role key for one test file. Returns the cleanup function. */
export function injectTestKey(): () => void {
  return _testInjectKeyringEntry({
    kid: vectorFile.key.kid,
    role: 'bundle',
    epoch: 3,
    expiry: 4102444800,
    fingerprint: computeSpkiFingerprint(vectorFile.key.publicKeyPem),
    publicKey: vectorFile.key.publicKeyPem,
  })
}

export function vector(name: string) {
  const v = vectorFile.vectors.find((x) => x.name === name)
  if (!v) throw new Error(`no vector ${name}`)
  return v
}

export function tempConfigDir(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'sg-plan-'))
  return { dir: join(dir, 'shipguard'), cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}
