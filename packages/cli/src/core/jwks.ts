/**
 * JWKS fetch + cache module
 *
 * SCAFFOLD — not wired into bundle verification yet.
 *
 * Purpose: discovery path for emergency key rotation. When Convex emits a new
 * signing key (e.g. k3-2027) and the CLI is already deployed, the CLI can
 * fetch /.well-known/jwks.json and surface the new key WITHOUT a forced
 * upgrade. Current verification still resolves ONLY from PINNED_KEYS (see
 * crypto.ts). This module is the preparation work for wiring in the JWKS path
 * once the rotation procedure is approved.
 *
 * WIRING CHECKLIST (do not complete until runbook approved):
 *   [ ] Expose fetchJwks() result to verifyAndDecryptBundle as a fallback map
 *   [ ] Gate JWKS fallback on a CLI semver floor (≥ next minor release)
 *   [ ] Add TTL refresh logic (currently: single fetch per process lifetime)
 *   [ ] Add sig-verification of the JWKS document itself
 *   [ ] Integration test: rotation path without CLI upgrade
 */

const JWKS_URL = 'https://agenticcli.dev/.well-known/jwks.json';
const FETCH_TIMEOUT_MS = 3_000;

/** Shape of a single JWK entry as emitted by the Convex backend. */
interface JwkEntry {
  kty: string;   // 'OKP'
  crv: string;   // 'Ed25519'
  kid: string;   // e.g. 'k3-2026'
  x: string;     // base64url-encoded public key bytes (Ed25519 raw public key)
  use?: string;  // 'sig'
}

interface JwksDocument {
  keys: JwkEntry[];
}

/** A kid → PEM map derived from a JWKS document. */
export type JwksPemMap = Record<string, string>;

let _cached: { map: JwksPemMap; fetchedAt: number } | null = null;

/**
 * Fetch and cache the JWKS document from the backend.
 *
 * Returns a kid → SPKI PEM map. Result is cached for the lifetime of the
 * process (no TTL refresh yet — see WIRING CHECKLIST above).
 *
 * Throws on network error or malformed JWKS. Callers MUST handle the error
 * and fall back to PINNED_KEYS — never fail-open.
 *
 * @param opts.fresh  Set to true to bypass the in-process cache (for tests)
 */
export async function fetchJwks(opts?: { fresh?: boolean }): Promise<JwksPemMap> {
  if (_cached && !opts?.fresh) {
    return _cached.map;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let jwks: JwksDocument;
  try {
    const res = await fetch(JWKS_URL, { signal: controller.signal });
    if (!res.ok) {
      throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
    }
    jwks = (await res.json()) as JwksDocument;
  } finally {
    clearTimeout(timer);
  }

  if (!Array.isArray(jwks.keys)) {
    throw new Error('JWKS document missing "keys" array');
  }

  const map: JwksPemMap = {};
  for (const key of jwks.keys) {
    if (key.kty !== 'OKP' || key.crv !== 'Ed25519') {
      // Skip non-Ed25519 keys — shipguard only uses Ed25519
      continue;
    }
    if (!key.kid || !key.x) {
      continue;
    }
    // Convert base64url x-coordinate to SPKI PEM.
    // Ed25519 SPKI DER = 12-byte OID prefix + 32 raw public key bytes.
    const rawKeyBytes = Buffer.from(key.x, 'base64');
    if (rawKeyBytes.length !== 32) {
      throw new Error(`JWKS key "${key.kid}": unexpected x length (${rawKeyBytes.length})`);
    }
    // Ed25519 SubjectPublicKeyInfo DER prefix (OID 1.3.101.112)
    const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    const spkiDer = Buffer.concat([spkiPrefix, rawKeyBytes]);
    const b64 = spkiDer.toString('base64');
    const lines = b64.match(/.{1,64}/g)!.join('\n');
    const pem = `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
    map[key.kid] = pem;
  }

  _cached = { map, fetchedAt: Date.now() };
  return map;
}

/**
 * Clear the in-process JWKS cache.
 * Exposed for tests — production code should not call this.
 */
export function _clearJwksCache(): void {
  _cached = null;
}
