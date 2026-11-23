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

// ---- a signer of our own, for documents the P0 vectors do not cover (generic offer, per-stack counts, ...) ----
import { generateKeyPairSync, sign as nodeSign, createPublicKey } from 'node:crypto'

export interface TestSigner {
  kid: string
  /** Compact JWS signed with the test key. `typ` defaults to the account document type. */
  sign: (payload: Record<string, unknown>, opts?: { typ?: string; kid?: string }) => string
  cleanup: () => void
}

export function makeSigner(kid = 'test-signer-w1a'): TestSigner {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  void createPublicKey
  const cleanup = _testInjectKeyringEntry({ kid, role: 'bundle', epoch: 3, expiry: 4102444800, fingerprint: computeSpkiFingerprint(pem), publicKey: pem })
  const b64 = (v: unknown) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url')
  return {
    kid,
    cleanup,
    sign: (payload, opts = {}) => {
      const head = b64({ alg: 'EdDSA', kid: opts.kid ?? kid, typ: opts.typ ?? 'shipguard-account+jws' })
      const body = b64(payload)
      return `${head}.${body}.${nodeSign(null, Buffer.from(`${head}.${body}`), privateKey).toString('base64url')}`
    },
  }
}

export const NOW_S = 1800000000
export const NOW_MS = NOW_S * 1000
export const ACCT = 'acct-test-hash-aaaaaaaaaaaaaaaaaaaaaaaaaaaa'
export const NONCE = 'Zm9vYmFyYmF6cXV4MTIzNA'

export function accountPayload(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { dv: 1, iss: 'agenticcli.dev', aud: 'shipguard-cli', acct: ACCT, iat: NOW_S - 60, exp: NOW_S + 86400, nonce: NONCE, ...over }
}
export function offerPayload(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { dv: 1, iss: 'agenticcli.dev', aud: 'shipguard-cli-offer', iat: NOW_S - 60, exp: NOW_S + 3 * 86400, ...over }
}
