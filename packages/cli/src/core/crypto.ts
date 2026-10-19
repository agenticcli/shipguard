import { createHash } from 'node:crypto';
// The PUBLIC halves of the release-attestation, CI-freshness and bundle keys live in ONE generated
// file. Nothing below holds key material or a kid literal for them.
import { CEREMONY_OUTPUT } from './keyring-ceremony-output.js';

// The hkdf, sha256 and RuleBundlePayload imports were removed: they were only used by the
// retired verifyAndDecryptBundle and verifyRuleBundle paths.

// Pinned public key map — key id → PEM-encoded SPKI public key (bundle-role keys only).
//
// There is no env-based key override.
// The override was guarded by NODE_ENV !== 'production', which FAILS OPEN for
// end-user CLIs (NODE_ENV unset → undefined !== 'production' → override accepted).
// Verification key resolves ONLY from PINNED_KEYS by kid — no env var, no flag.
//
// Earlier bundle keys are not trusted any more: they are absent from PINNED_KEYS and KEYRING, and
// their SPKI fingerprints are on REVOKED_FINGERPRINTS so an accidental re-add is still refused.
// PINNED_KEYS is DERIVED from the bundle-role KEYRING entries (one source of truth) and never holds
// an unfilled ceremony placeholder.
let PINNED_KEYS: Record<string, string> = {};

// Default bundle kid: the current bundle key (k3-2026, from the ceremony-output file).
const DEFAULT_KID = CEREMONY_OUTPUT.bundle.kid;

// The HKDF_INFO constant was removed: it was only used by retired verifyAndDecryptBundle.

// ---------------------------------------------------------------------------
// 4-Key Typed Keyring
// ---------------------------------------------------------------------------

// CROSS-REPO SYNC: this KEYRING is manually synced with the platform's copy of the same keyring.
// Any change to key material, epoch, expiry, fingerprint, or role MUST be made in BOTH files
// atomically (same PR). Private halves are never stored in this repository.

export type KeyRole = 'auth' | 'release-attestation' | 'ci-freshness' | 'bundle';

export interface PinnedKeyEntry {
  /** Monotonically increasing integer; rollback protection. */
  epoch: number;
  /** Unix seconds; key MUST NOT be trusted after expiry. */
  expiry: number;
  /** SHA-256 of raw public-key DER bytes, hex-encoded. */
  fingerprint: string;
  /** Key identifier string. */
  kid: string;
  /** PEM-encoded SPKI public key. */
  publicKey: string;
  /**
   * Domain-purpose role.
   * Domain tag strings:
   *   auth                 → "shipguard-auth-v1"
   *   release-attestation  → "shipguard-release-attestation-v1"
   *   ci-freshness         → "shipguard-ci-freshness-v1"
   *   bundle               → "shipguard-bundle-v1"
   */
  role: KeyRole;
}

// The minimum acceptable epoch. Any key entry with epoch < MIN_ACCEPTABLE_EPOCH is REJECTED.
// Bump this on every key rotation to prevent epoch rollback.
// IMPORTANT: this is the compile-time constant; it is NOT fetched from the network.
// Epoch-1 keys are no longer trusted, so the floor is 2.
export const MIN_ACCEPTABLE_EPOCH = 2;

// ---------------------------------------------------------------------------
// Revoked keys and key placeholders
// ---------------------------------------------------------------------------

/**
 * SHA-256 (hex) of the SPKI DER of every public key that is no longer trusted.
 * Checked against the fingerprint COMPUTED from the key bytes (never the declared metadata), so a
 * re-added revoked PEM is refused even if someone edits its `fingerprint` field.
 * Never remove an entry. Fingerprints only — no key material here.
 */
export const REVOKED_FINGERPRINTS: ReadonlySet<string> = new Set([
  '855e81b870c16d377efd8354e9761fadca2d22d16536f291fb77e690f9d65abc', // keys no longer trusted
  '003837c9c656f66163a29e7b0d043a084fc83c2febc420a5e27889205a27b878', // keys no longer trusted
  '87787b86689151fd9a9b763e3baa2cae884bf897d51dc02a211c70640e2c4f9d', // keys no longer trusted
  '57873aac03421fa0740fdd9520729536223010067ea3012135db2b255a2b263c', // keys no longer trusted
]);

/**
 * Marker for keyring entries that have not been filled in yet. A build made with
 * SHIPGUARD_PUBLISHED_BUILD=1 refuses to complete while this marker is anywhere in the bundle
 * (scripts/check-keyring-placeholders.mjs, run by tsup onSuccess and release-gate.sh), and the
 * resolver refuses to use a placeholder entry at runtime.
 */
export const KEYRING_PLACEHOLDER_MARKER = 'SHIPGUARD_KEYRING_PLACEHOLDER';

export function isKeyringPlaceholder(entry: Pick<PinnedKeyEntry, 'publicKey' | 'fingerprint'>): boolean {
  return entry.publicKey.includes(KEYRING_PLACEHOLDER_MARKER) ||
    entry.fingerprint.includes(KEYRING_PLACEHOLDER_MARKER);
}

/** Decode a PEM SPKI public key to its DER bytes. Throws on anything that is not a PUBLIC KEY PEM. */
export function spkiDerFromPem(pem: string): Buffer {
  const m = /^-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PUBLIC KEY-----\s*$/.exec(pem.trim());
  if (!m) throw new Error('not a PEM-encoded SPKI public key');
  const der = Buffer.from(m[1].replace(/\s/g, ''), 'base64');
  if (der.length === 0) throw new Error('empty SPKI public key');
  return der;
}

/** SHA-256 (lower-case hex) over the SPKI DER bytes of a PEM public key. */
export function computeSpkiFingerprint(pem: string): string {
  return createHash('sha256').update(spkiDerFromPem(pem)).digest('hex');
}

// KEYRING is mutable (let) so tests can inject temporary entries via _testInjectKeyringEntry.
// CROSS-REPO SYNC: manually synced with the platform's copy of this keyring. Any change to
// key material, epoch, expiry, fingerprint, or role MUST be made in BOTH files atomically, and
// a parity test on the platform side checks the two stay identical.
//
// The current keys take their public halves from ./keyring-ceremony-output.ts. Until that file is
// filled in, entries are stand-ins that every trust path refuses, and a publish build fails
// (scripts/check-keyring-placeholders.mjs).
let KEYRING: PinnedKeyEntry[] = [
  // ----- RELEASE-ATTESTATION (ra-k2-2026, epoch 2) -----
  // Signs corpus manifest + release attestation objects. The private half is never shipped and never stored in this repository.
  {
    kid: CEREMONY_OUTPUT.ra.kid,
    role: 'release-attestation',
    epoch: 2,
    expiry: 1822348800, // 2027-10-01 00:00:00 UTC
    fingerprint: CEREMONY_OUTPUT.ra.fingerprint,
    publicKey: CEREMONY_OUTPUT.ra.publicKey,
  },

  // ----- CI-FRESHNESS (cf-k2-2026, epoch 2) -----
  // Signs short-TTL freshness tokens. The private half is never stored in this repository.
  {
    kid: CEREMONY_OUTPUT.cf.kid,
    role: 'ci-freshness',
    epoch: 2,
    expiry: 1822348800, // 2027-10-01 00:00:00 UTC
    fingerprint: CEREMONY_OUTPUT.cf.fingerprint,
    publicKey: CEREMONY_OUTPUT.cf.publicKey,
  },

  // ----- BUNDLE key (k3-2026, epoch 3; Convex-held; signs per-request bundle envelopes) -----
  {
    kid: CEREMONY_OUTPUT.bundle.kid,
    role: 'bundle',
    epoch: 3,
    expiry: 1822348800, // 2027-10-01 00:00:00 UTC
    fingerprint: CEREMONY_OUTPUT.bundle.fingerprint,
    publicKey: CEREMONY_OUTPUT.bundle.publicKey,
  },

  // AUTH key: managed separately via JWKS endpoint; the CLI does NOT pin auth keys for
  // release trust.
];

PINNED_KEYS = Object.fromEntries(
  KEYRING.filter(e => e.role === 'bundle' && !isKeyringPlaceholder(e)).map(e => [e.kid, e.publicKey]),
);

export { KEYRING };

// ---------------------------------------------------------------------------
// Epoch / expiry validation
// ---------------------------------------------------------------------------

/**
 * Validate that a keyring entry is acceptable: epoch must meet the minimum floor,
 * and the key must not have expired.
 *
 * @throws if epoch < MIN_ACCEPTABLE_EPOCH (rollback protection)
 * @throws if expiry is in the past (key expired)
 */
export function validateKeyringEntry(entry: PinnedKeyEntry): void {
  if (entry.epoch < MIN_ACCEPTABLE_EPOCH) {
    throw new Error(
      `Key "${entry.kid}" epoch ${entry.epoch} is below the minimum acceptable epoch ` +
      `${MIN_ACCEPTABLE_EPOCH} — epoch rollback rejected`,
    );
  }
  if (entry.expiry < Date.now() / 1000) {
    throw new Error(
      `Key "${entry.kid}" has expired (expiry=${entry.expiry}, now=${Math.floor(Date.now() / 1000)})`,
    );
  }
}

// ---------------------------------------------------------------------------
// Shared internal helper: resolve kid → PinnedKeyEntry, validate, import key
// ---------------------------------------------------------------------------

/**
 * Resolve kid → KEYRING entry, run every trust check, and import the key.
 * Exported for tests; production code reaches it via verifyAttestation / verifyFreshness /
 * verifyBundleEnvelopeSignature.
 *
 * Order: known kid → not a ceremony placeholder → epoch + expiry → role →
 * fingerprint COMPUTED over the actual SPKI DER must equal entry.fingerprint →
 * computed fingerprint must not be revoked → import from those same DER bytes.
 */
export async function resolveAndImportKey(kid: string, expectedRole: KeyRole): Promise<CryptoKey> {
  const entry = KEYRING.find(e => e.kid === kid);
  if (!entry) {
    throw new Error(
      `Unknown key "${kid}" — not found in KEYRING. ` +
      `Upgrade shipguard to a version that supports this key id.`,
    );
  }

  if (isKeyringPlaceholder(entry)) {
    throw new Error(
      `Key "${kid}" is an unfilled key-ceremony placeholder — this build cannot verify it. ` +
      `Upgrade shipguard to a released version.`,
    );
  }

  // Epoch + expiry check
  validateKeyringEntry(entry);

  // Cross-role replay rejection
  if (entry.role !== expectedRole) {
    throw new Error(
      `key role mismatch: expected ${expectedRole}, got ${entry.role} — cross-role replay rejected`,
    );
  }

  // Bind the declared fingerprint to the real key bytes, then deny on the COMPUTED value.
  let der: Buffer;
  try {
    der = spkiDerFromPem(entry.publicKey);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Key "${kid}" has an unreadable public key: ${msg}`);
  }
  const computed = createHash('sha256').update(der).digest('hex');
  if (computed !== entry.fingerprint.toLowerCase()) {
    throw new Error(
      `Key "${kid}" fingerprint mismatch: declared ${entry.fingerprint}, computed ${computed} — refusing key`,
    );
  }
  if (REVOKED_FINGERPRINTS.has(computed)) {
    throw new Error(
      `Key "${kid}" is revoked (fingerprint ${computed} is on the revoked-key denylist) — refusing key`,
    );
  }

  return globalThis.crypto.subtle.importKey(
    'spki',
    der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer,
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
}

// ---------------------------------------------------------------------------
// verifyAttestation
// ---------------------------------------------------------------------------

/**
 * Verify a corpus attestation signature against the pinned RELEASE-ATTESTATION key.
 *
 * The preimage is: "shipguard-attestation-v1\x00" + JCS(attestation-without-signature-field)
 * (JCS = RFC 8785 canonical JSON; this helper receives the pre-assembled preimage bytes
 * to keep it pure and testable without the full JCS machinery.)
 *
 * SECURITY: rejects if the kid maps to any key whose role is NOT "release-attestation".
 * A Bundle-key or CI-Freshness-key signature presented as an attestation → REJECTED (domain mismatch).
 */
export async function verifyAttestation(
  preimageBytesOrManifestBytes: Uint8Array,  // the domain-prefixed preimage bytes
  signatureB64url: string,                    // base64url-encoded Ed25519 signature
  kid: string,                                // the kid from the attestation object
): Promise<void> {
  const cryptoKey = await resolveAndImportKey(kid, 'release-attestation');

  // Decode base64url signature
  const signatureBytes = Buffer.from(signatureB64url.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

  const valid = await globalThis.crypto.subtle.verify(
    'Ed25519',
    cryptoKey,
    signatureBytes,
    // WHY: Buffer.from(...,'base64') is always ArrayBuffer-backed (never SharedArrayBuffer)
    // but TS lib.dom types Buffer as Uint8Array<ArrayBufferLike>. SubtleCrypto.verify
    // requires Uint8Array<ArrayBuffer>. The cast is safe: Node Buffer never uses SAB.
    preimageBytesOrManifestBytes as unknown as Uint8Array<ArrayBuffer>,
  );
  if (!valid) {
    throw new Error('release-attestation signature verification failed — possible tampering');
  }
}

// ---------------------------------------------------------------------------
// verifyFreshness
// ---------------------------------------------------------------------------

/**
 * Verify a CI freshness token signature against the pinned CI-FRESHNESS key.
 *
 * SECURITY: rejects if the kid maps to any key whose role is NOT "ci-freshness".
 * A Bundle-key or Release-Attestation-key sig presented as a freshness token → REJECTED.
 */
export async function verifyFreshness(
  preimageBytesOrFreshnessBytes: Uint8Array,  // the domain-prefixed preimage bytes
  signatureB64url: string,                      // base64url-encoded Ed25519 signature
  kid: string,                                  // the kid from the freshness token
): Promise<void> {
  const cryptoKey = await resolveAndImportKey(kid, 'ci-freshness');

  // Decode base64url signature
  const signatureBytes = Buffer.from(signatureB64url.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

  const valid = await globalThis.crypto.subtle.verify(
    'Ed25519',
    cryptoKey,
    signatureBytes,
    // WHY: Buffer.from(...,'base64') is always ArrayBuffer-backed (never SharedArrayBuffer)
    // but TS lib.dom types Buffer as Uint8Array<ArrayBufferLike>. SubtleCrypto.verify
    // requires Uint8Array<ArrayBuffer>. The cast is safe: Node Buffer never uses SAB.
    preimageBytesOrFreshnessBytes as unknown as Uint8Array<ArrayBuffer>,
  );
  if (!valid) {
    throw new Error('ci-freshness signature verification failed — possible tampering');
  }
}

// ---------------------------------------------------------------------------
// Legacy bundle verification — TOMBSTONES
// ---------------------------------------------------------------------------
// The AES-GCM encrypted bundle format and the JWT legacy format are RETIRED.
// The SignedBundle interface is removed. Both functions throw unconditionally.
// PINNED_KEYS and DEFAULT_KID are kept for keyring tests and legacy injection helpers.

// verifyAndDecryptBundle — PERMANENTLY DISABLED.
//
// The AES-GCM encrypted bundle format is RETIRED. All bundles MUST use the
// attested-release protocol: a BundleResponse with fullManifest + corpusAttestation
// signed by the pinned Release-Attestation key (role 2 in the 4-Key Typed Keyring).
//
// A bundle lacking corpusAttestation is REJECTED as legacy-format (non-safe exit).
// Reason: "legacy-bundle-rejected: attestation required"
//
// The SignedBundle interface and HKDF/AES-GCM body code are intentionally removed.
// If you see a compile error on this function's call site, the caller must be updated
// to use the attested-release path (verifyBundleResponse in release-verify.ts).
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function verifyAndDecryptBundle(_bundleB64: string, _accessToken: string): Promise<never> {
  // Legacy AES-GCM encrypted bundle path PERMANENTLY DISABLED.
  // All bundles MUST use the attested-release protocol (fullManifest + corpusAttestation).
  throw new Error(
    'legacy-bundle-rejected: attestation required — encrypted bundle format rejected. ' +
    'The server must deliver a BundleResponse with corpusAttestation signed by the ' +
    'Release-Attestation key. Exit non-safe.',
  );
}

// verifyRuleBundle — PERMANENTLY DISABLED.
//
// The legacy JWT verification path is RETIRED. All bundles MUST carry a valid
// corpusAttestation signed by the pinned Release-Attestation key (role 2).
// A bundle lacking corpusAttestation is REJECTED as legacy-format (non-safe exit).
// Reason: "legacy-bundle-rejected: attestation required"
//
// NOTE: PINNED_KEYS is kept (used by keyring tests and legacy test injection helpers).
// DEFAULT_KID is kept for the same reason.
// The jose.jwtVerify body is intentionally removed.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function verifyRuleBundle(_token: string): Promise<never> {
  // Legacy JWT verification path is PERMANENTLY DISABLED.
  // All bundles MUST carry a valid corpusAttestation signed by the pinned Release-Attestation key.
  // A bundle lacking corpusAttestation is REJECTED as legacy-format (non-safe exit).
  // Reason: "legacy-bundle-rejected: attestation required"
  throw new Error(
    'legacy-bundle-rejected: attestation required — this CLI no longer accepts ' +
    'un-attested rule bundles. The server must deliver a BundleResponse with ' +
    'fullManifest + corpusAttestation (attested-release protocol). Exit non-safe.',
  );
}

// ---------------------------------------------------------------------------
// Test injection helpers
// ---------------------------------------------------------------------------

/**
 * TEST-ONLY: inject a temporary key into PINNED_KEYS for the duration of a test.
 *
 * This function MUST only be called from test code. It returns a cleanup
 * function that restores the original PINNED_KEYS entry.
 *
 * Why this exists: with no env override, tests inject keys at the module level instead.
 * Using a module-level injection (vs a real private-key round-trip against the
 * pinned prod keys) keeps tests self-contained and avoids inlining secrets.
 *
 * @param kid   Key id to inject (e.g. 'test-k1-2026')
 * @param pem   PEM-encoded Ed25519 SPKI public key
 * @returns     Cleanup function — call in afterEach/finally to restore original state
 */
export function _testInjectPinnedKey(kid: string, pem: string): () => void {
  const original = PINNED_KEYS[kid];
  PINNED_KEYS = { ...PINNED_KEYS, [kid]: pem };
  return () => {
    if (original === undefined) {
      const next = { ...PINNED_KEYS };
      delete next[kid];
      PINNED_KEYS = next;
    } else {
      PINNED_KEYS = { ...PINNED_KEYS, [kid]: original };
    }
  };
}

// ---------------------------------------------------------------------------
// verifyBundleEnvelopeSignature
// ---------------------------------------------------------------------------

/**
 * Verify a bundle envelope signature against the pinned BUNDLE key.
 *
 * The preimage is: "shipguard-bundle-v1\x00" + JCS(envelope-without-signature-field)
 * (this helper receives the pre-assembled preimage bytes).
 *
 * SECURITY: rejects if the kid maps to any key whose role is NOT "bundle".
 * A Release-Attestation-key or CI-Freshness-key signature presented as a
 * bundle envelope signature → REJECTED (domain mismatch).
 */
export async function verifyBundleEnvelopeSignature(
  preimageBytes: Uint8Array,   // the domain-prefixed preimage bytes
  signatureB64url: string,     // base64url-encoded Ed25519 signature
  kid: string,                 // the kid from the bundle envelope
): Promise<void> {
  const cryptoKey = await resolveAndImportKey(kid, 'bundle');

  // Decode base64url signature
  const signatureBytes = Buffer.from(signatureB64url.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

  const valid = await globalThis.crypto.subtle.verify(
    'Ed25519',
    cryptoKey,
    signatureBytes,
    // WHY: Buffer.from(...,'base64') is always ArrayBuffer-backed (never SharedArrayBuffer)
    // but TS lib.dom types Buffer as Uint8Array<ArrayBufferLike>. SubtleCrypto.verify
    // requires Uint8Array<ArrayBuffer>. The cast is safe: Node Buffer never uses SAB.
    preimageBytes as unknown as Uint8Array<ArrayBuffer>,
  );
  if (!valid) {
    throw new Error('bundle-envelope signature verification failed — possible tampering or replay');
  }
}

/**
 * TEST-ONLY: inject or replace a PinnedKeyEntry in KEYRING for the duration of a test.
 *
 * Returns a cleanup function that restores the original KEYRING state.
 * Call the returned function in afterEach/finally.
 */
export function _testInjectKeyringEntry(entry: PinnedKeyEntry): () => void {
  const idx = KEYRING.findIndex(e => e.kid === entry.kid);
  if (idx >= 0) {
    const original = KEYRING[idx];
    KEYRING[idx] = entry;
    return () => { KEYRING[idx] = original; };
  } else {
    KEYRING.push(entry);
    return () => {
      const i = KEYRING.findIndex(e => e.kid === entry.kid);
      if (i >= 0) KEYRING.splice(i, 1);
    };
  }
}
