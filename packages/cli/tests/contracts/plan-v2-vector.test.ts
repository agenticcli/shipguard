/**
 * P0 contract test: the signed plan-block vectors in docs/contracts/plan-v2.vectors.json verify (or
 * are rejected) exactly as docs/contracts/plan-v2.json says, with the throwaway test key in the file.
 * This is a REFERENCE verifier written from the contract; W1a's real module must give the same answers
 * on the same vectors. It uses node webcrypto only and never touches the pinned production keyring.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const dir = join(__dirname, '..', '..', '..', '..', 'docs', 'contracts');
const contract = JSON.parse(readFileSync(join(dir, 'plan-v2.json'), 'utf8'));
const file = JSON.parse(readFileSync(join(dir, 'plan-v2.vectors.json'), 'utf8'));

interface Ctx { now: number; acct: string | null; nonce: string | null; scanId: string | null }

function parseStrictNoDup(text: string): Record<string, unknown> {
  // JSON.parse keeps the last duplicate; reject duplicates by tokenising keys per object level.
  const obj = JSON.parse(text) as Record<string, unknown>;
  const seen: Array<Set<string>> = [];
  let inStr = false, esc = false, key = '', expectKey: boolean[] = [];
  let cur = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (esc) { esc = false; cur += c; continue; }
      if (c === '\\') { esc = true; cur += c; continue; }
      if (c === '"') {
        inStr = false;
        if (expectKey[expectKey.length - 1]) {
          const s = seen[seen.length - 1];
          if (s.has(cur)) throw new Error('duplicate key');
          s.add(cur);
          expectKey[expectKey.length - 1] = false;
        }
        key = cur; continue;
      }
      cur += c; continue;
    }
    if (c === '"') { inStr = true; cur = ''; continue; }
    if (c === '{') { seen.push(new Set()); expectKey.push(true); continue; }
    if (c === '}') { seen.pop(); expectKey.pop(); continue; }
    if (c === '[') { expectKey.push(false); seen.push(new Set()); continue; }
    if (c === ']') { seen.pop(); expectKey.pop(); continue; }
    if (c === ',' && expectKey.length && seen.length) {
      // after a comma inside an object the next string is a key
      const top = text.lastIndexOf('{', i), topArr = text.lastIndexOf('[', i);
      expectKey[expectKey.length - 1] = top > topArr;
    }
  }
  void key;
  return obj;
}

const b64uToBuf = (s: string): Buffer => Buffer.from(s, 'base64url');

async function verify(kind: 'account' | 'offer', token: string, ctx: Ctx): Promise<'ok' | 'PLAN_UNVERIFIED'> {
  try {
    const max = contract.jws.maxBytes[kind] as number;
    if (token.length > max) return 'PLAN_UNVERIFIED';
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some(p => !/^[A-Za-z0-9_-]+$/.test(p))) return 'PLAN_UNVERIFIED';
    const header = parseStrictNoDup(b64uToBuf(parts[0]).toString('utf8'));
    for (const k of Object.keys(header)) if (!contract.jws.headerAllowlist.includes(k)) return 'PLAN_UNVERIFIED';
    if (header.alg !== contract.jws.alg || header.typ !== contract.jws.typ[kind]) return 'PLAN_UNVERIFIED';
    if (header.kid !== file.key.kid) return 'PLAN_UNVERIFIED';
    const spki = Buffer.from(file.key.publicKeyPem.replace(/-----[^-]+-----|\s/g, ''), 'base64');
    const key = await globalThis.crypto.subtle.importKey('raw', spki.subarray(spki.length - 32), 'Ed25519', false, ['verify']);
    const valid = await globalThis.crypto.subtle.verify('Ed25519', key, b64uToBuf(parts[2]), Buffer.from(`${parts[0]}.${parts[1]}`));
    if (!valid) return 'PLAN_UNVERIFIED';
    const p = parseStrictNoDup(b64uToBuf(parts[1]).toString('utf8')) as Record<string, any>;
    const spec = contract[kind];
    if (p.iss !== spec.iss || p.aud !== spec.aud || p.dv !== contract.dv) return 'PLAN_UNVERIFIED';
    for (const r of spec.required) if (!(r in p)) return 'PLAN_UNVERIFIED';
    if (kind === 'account') {
      if (ctx.acct !== null && p.acct !== ctx.acct) return 'PLAN_UNVERIFIED';
      if (ctx.nonce !== null && p.nonce !== ctx.nonce) return 'PLAN_UNVERIFIED';
      if (ctx.scanId !== null && p.binding?.scanId !== ctx.scanId) return 'PLAN_UNVERIFIED';
    }
    // Time window applies to live replies and cached copies alike (an expired live reply is plain Free).
    const maxLife = kind === 'account' ? 72 * 3600 : 7 * 86400;
    if (p.iat > ctx.now + 300 || ctx.now >= p.exp || p.exp - p.iat > maxLife) return 'PLAN_UNVERIFIED';
    return 'ok';
  } catch {
    return 'PLAN_UNVERIFIED';
  }
}

describe('plan-v2 vectors (reference verifier, throwaway test key)', () => {
  it('the vector file names the bundle role, only EdDSA and a public key', () => {
    expect(file.key.role).toBe(contract.jws.keyRole);
    expect(file.key.alg).toBe('EdDSA');
    expect(file.key.publicKeyPem).toContain('BEGIN PUBLIC KEY');
    expect(JSON.stringify(file)).not.toMatch(/PRIVATE KEY/);
  });

  it('covers every rejection class the plan asks for', () => {
    const names = file.vectors.map((v: { name: string }) => v.name);
    for (const n of ['valid-live', 'tampered-payload', 'expired', 'replayed-nonce', 'replayed-scanid', 'wrong-account', 'wrong-typ', 'header-jku', 'alg-none', 'valid-offer']) {
      expect(names).toContain(n);
    }
  });

  for (const v of file.vectors as Array<{ name: string; kind: 'account' | 'offer'; token: string; expect: string; ctx: Ctx }>) {
    it(`${v.name} -> ${v.expect}`, async () => {
      expect(await verify(v.kind, v.token, v.ctx)).toBe(v.expect);
    });
  }
});
