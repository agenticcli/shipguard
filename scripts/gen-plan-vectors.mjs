#!/usr/bin/env node
// gen-plan-vectors.mjs - regenerate docs/contracts/plan-v2.vectors.json.
// Makes a THROWAWAY Ed25519 key, signs the plan-block test vectors with it, writes the public key
// into the file and discards the private key (it is never written anywhere). Not a production key:
// the pinned bundle key is never read or used here. Run: node scripts/gen-plan-vectors.mjs
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'contracts', 'plan-v2.vectors.json');
const KID = 'test-plan-v2-dev';
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

const b64u = (b) => Buffer.from(b).toString('base64url');
const acct = (id) => createHash('sha256').update(id).digest('base64url');
const NOW = 1795000000;            // fixed test clock (unix seconds)
const NONCE = 'Zm9vYmFyYmF6cXV4MTIzNA'; // 22 base64url chars
const SCAN = 'scan-0123456789abcdef';
const ACCT = acct('test-account-1');

function jws(header, payloadText) {
  const h = b64u(JSON.stringify(header));
  const p = b64u(payloadText);
  const sig = sign(null, Buffer.from(`${h}.${p}`), privateKey);
  return `${h}.${p}.${b64u(sig)}`;
}
const hdr = (typ = 'shipguard-account+jws', extra = {}) => ({ alg: 'EdDSA', kid: KID, typ, ...extra });

const plan = (over = {}) => ({
  dv: 1, iss: 'agenticcli.dev', aud: 'shipguard-cli', acct: ACCT,
  iat: NOW - 60, exp: NOW + 24 * 3600, refreshAfter: 600,
  nonce: NONCE, binding: { scanId: SCAN },
  label: 'Test plan',
  account: { status: 'active', text: 'Test account text.' },
  usage: { percent: 40, state: 'ok', resetsAt: '2026-12-01T00:00:00Z', text: 'Test usage text.', counted: true },
  limit: { text: 'Test limit text.' },
  capabilities: { rulebookDefault: true, rulebookTiers: ['free', 'pro'] },
  proAdds: { planName: 'Test plan', rules: 7, stacks: ['nextjs'], areas: ['Test area'] },
  offer: { text: 'Test offer text.', slot: 'pricing' },
  updateNotice: null,
  ...over,
});
const offer = (over = {}) => ({
  dv: 1, iss: 'agenticcli.dev', aud: 'shipguard-cli-offer',
  iat: NOW - 60, exp: NOW + 6 * 24 * 3600,
  offer: { text: 'Test offer text.', slot: 'pricing' },
  counts: { nextjs: { rules: 7, areas: ['Test area'] } },
  ...over,
});

// ctx = what the client knows when it verifies; expect = the only allowed outcome.
const ok = { now: NOW, acct: ACCT, nonce: NONCE, scanId: SCAN };
const V = [];
const add = (name, kind, token, expect, ctx = ok, note = '') => V.push({ name, kind, expect, ctx, note, token });

const good = JSON.stringify(plan());
const goodJws = jws(hdr(), good);
const [gh, gp, gs] = goodJws.split('.');
const tamperedPayload = b64u(JSON.stringify(plan({ usage: { percent: 100, state: 'used', resetsAt: '2026-12-01T00:00:00Z', text: 'x', counted: true } })));

add('valid-live', 'account', goodJws, 'ok', ok, 'live reply: nonce and scanId match');
add('valid-used', 'account', jws(hdr(), JSON.stringify(plan({ usage: { percent: 100, state: 'used', resetsAt: '2026-12-01T00:00:00Z', text: 'Test used text.', counted: false } }))), 'ok', ok, 'the only state that may soften --pro');
add('valid-unknown-status', 'account', jws(hdr(), JSON.stringify(plan({ account: { status: 'paused', text: 'Server words.' } }))), 'ok', ok, 'verifies; the CLI shows the status as unsupported, never as none');
add('valid-update-notice', 'account', jws(hdr(), JSON.stringify(plan({ updateNotice: 'Test update text.' }))), 'ok', ok);
add('valid-cached', 'account', goodJws, 'ok', { now: NOW + 3600, acct: ACCT, nonce: null, scanId: null }, 'cached copy: within exp, nonce not checked');
add('tampered-payload', 'account', `${gh}.${tamperedPayload}.${gs}`, 'PLAN_UNVERIFIED', ok, 'payload changed after signing');
add('bad-signature', 'account', `${gh}.${gp}.${b64u(Buffer.alloc(64, 1))}`, 'PLAN_UNVERIFIED');
add('expired', 'account', jws(hdr(), JSON.stringify(plan({ iat: NOW - 7200, exp: NOW - 3600 }))), 'PLAN_UNVERIFIED', { now: NOW, acct: ACCT, nonce: null, scanId: null }, 'cached copy past exp');
add('too-long-lived', 'account', jws(hdr(), JSON.stringify(plan({ iat: NOW - 60, exp: NOW + 80 * 3600 }))), 'PLAN_UNVERIFIED', { now: NOW, acct: ACCT, nonce: null, scanId: null }, 'cached copy: exp - iat > 72 h');
add('issued-in-future', 'account', jws(hdr(), JSON.stringify(plan({ iat: NOW + 3600, exp: NOW + 7200 }))), 'PLAN_UNVERIFIED', { now: NOW, acct: ACCT, nonce: null, scanId: null }, 'cached copy: iat > now + 5 min');
add('live-expired', 'account', goodJws, 'PLAN_UNVERIFIED', { ...ok, now: NOW + 2 * 86400 }, 'live reply (nonce and scanId match) already past exp: plain Free, same as a cached copy');
add('live-issued-in-future', 'account', goodJws, 'PLAN_UNVERIFIED', { ...ok, now: NOW - 2 * 3600 }, 'live reply with iat > now + 5 min: plain Free');
add('wrong-account', 'account', jws(hdr(), JSON.stringify(plan({ acct: acct('test-account-2') }))), 'PLAN_UNVERIFIED', ok, 'bound to another account');
add('replayed-nonce', 'account', jws(hdr(), JSON.stringify(plan({ nonce: 'b2xkbm9uY2VvbGRub25jZQ' }))), 'PLAN_UNVERIFIED', ok, 'old nonce on a live reply');
add('replayed-scanid', 'account', jws(hdr(), JSON.stringify(plan({ binding: { scanId: 'scan-old' } }))), 'PLAN_UNVERIFIED', ok, 'old scanId on a live reply');
add('wrong-typ', 'account', jws(hdr('shipguard-bundle+jws'), good), 'PLAN_UNVERIFIED', ok, 'typ separates bundle, account and offer');
add('offer-as-account', 'account', jws(hdr('shipguard-offer+jws'), good), 'PLAN_UNVERIFIED', ok);
add('header-jku', 'account', jws(hdr('shipguard-account+jws', { jku: 'https://evil.example/keys' }), good), 'PLAN_UNVERIFIED', ok, 'header allowlist is alg, kid, typ only');
add('header-crit', 'account', jws(hdr('shipguard-account+jws', { crit: ['b64'], b64: false }), good), 'PLAN_UNVERIFIED');
add('alg-none', 'account', jws({ alg: 'none', kid: KID, typ: 'shipguard-account+jws' }, good), 'PLAN_UNVERIFIED');
add('unknown-kid', 'account', jws({ alg: 'EdDSA', kid: 'no-such-kid', typ: 'shipguard-account+jws' }, good), 'PLAN_UNVERIFIED');
add('wrong-aud', 'account', jws(hdr(), JSON.stringify(plan({ aud: 'something-else' }))), 'PLAN_UNVERIFIED');
add('unsupported-dv', 'account', jws(hdr(), JSON.stringify(plan({ dv: 99 }))), 'PLAN_UNVERIFIED');
add('duplicate-key', 'account', jws(hdr(), good.replace('"label":"Test plan"', '"label":"Test plan","label":"Other"')), 'PLAN_UNVERIFIED', ok, 'duplicate JSON keys are rejected');
add('not-three-parts', 'account', `${gh}.${gp}`, 'PLAN_UNVERIFIED');
add('valid-offer', 'offer', jws(hdr('shipguard-offer+jws'), JSON.stringify(offer())), 'ok', { now: NOW, acct: null, nonce: null, scanId: null }, 'public offer: no acct, no nonce');
add('offer-expired', 'offer', jws(hdr('shipguard-offer+jws'), JSON.stringify(offer({ iat: NOW - 9 * 86400, exp: NOW - 86400 }))), 'PLAN_UNVERIFIED', { now: NOW, acct: null, nonce: null, scanId: null });
add('offer-wrong-typ', 'offer', jws(hdr('shipguard-account+jws'), JSON.stringify(offer())), 'PLAN_UNVERIFIED', { now: NOW, acct: null, nonce: null, scanId: null });

const doc = {
  _comment: 'Test vectors for the plan block contract (plan-v2.json). Generated by scripts/gen-plan-vectors.mjs with a THROWAWAY test key whose private half was discarded. Not a production key. Platform keeps a byte-identical copy.',
  generatedWith: 'scripts/gen-plan-vectors.mjs',
  key: { kid: KID, role: 'bundle', alg: 'EdDSA', publicKeyPem },
  vectors: V,
};
writeFileSync(out, JSON.stringify(doc, null, 2) + '\n');
console.log(`wrote ${V.length} vectors to ${out}`);
