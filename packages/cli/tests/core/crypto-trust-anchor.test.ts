/**
 * SEC-BL3-REGRESSION — Trust-anchor override regression tests
 * Updated for the attested-release protocol.
 *
 * Root cause:
 *   `SHIPGUARD_PUBLIC_KEY` env var was honoured whenever NODE_ENV !== 'production'.
 *   End-user CLIs run with NODE_ENV unset → undefined !== 'production' → override
 *   accepted → attacker with local env injection can feed self-signed rule bundles
 *   and neutralise the gate.
 *
 * Fix (Option A): Remove the env override entirely. The verification key MUST
 *   resolve ONLY from PINNED_KEYS by kid.
 *
 * UPDATED behaviour: verifyAndDecryptBundle is now PERMANENTLY DISABLED (tombstone).
 * The AES-GCM encrypted bundle format is RETIRED.
 * The trust-anchor bypass attack is now categorically impossible: the function that
 * would have been vulnerable unconditionally throws 'legacy-bundle-rejected'.
 *
 * These tests confirm:
 *   TA-001  NODE_ENV unset + SHIPGUARD_PUBLIC_KEY set → bundle rejected (tombstone)
 *   TA-002  NODE_ENV=production + SHIPGUARD_PUBLIC_KEY set → bundle rejected (tombstone)
 *   TA-003  SHIPGUARD_PUBLIC_KEY has NO influence — function rejects unconditionally
 *   TA-004  Source code: SHIPGUARD_PUBLIC_KEY must NOT appear in crypto.ts
 */

import { describe, it, expect, afterEach } from 'vitest';

const { verifyAndDecryptBundle } = await import('../../src/core/crypto.js');

afterEach(() => {
  delete process.env.SHIPGUARD_PUBLIC_KEY;
  delete process.env.NODE_ENV;
});

// ---------------------------------------------------------------------------
// TA-001 — NODE_ENV unset + SHIPGUARD_PUBLIC_KEY override → TOMBSTONE rejects
//
// Pre-fix: NODE_ENV unset → allowEnvOverride=true → attacker key accepted (BUG)
// Post-tombstone: function unconditionally rejects, override has zero effect.
// ---------------------------------------------------------------------------

describe('TA-001: NODE_ENV unset + SHIPGUARD_PUBLIC_KEY set → bundle REJECTED (tombstone)', () => {
  it('rejects any bundle even when SHIPGUARD_PUBLIC_KEY is set and NODE_ENV is unset', async () => {
    delete process.env.NODE_ENV;
    process.env.SHIPGUARD_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----';

    await expect(
      verifyAndDecryptBundle('dGVzdA==', 'victim-access-token'),
    ).rejects.toThrow('legacy-bundle-rejected');
  });
});

// ---------------------------------------------------------------------------
// TA-002 — NODE_ENV=production + SHIPGUARD_PUBLIC_KEY set → TOMBSTONE rejects
// ---------------------------------------------------------------------------

describe('TA-002: NODE_ENV=production + SHIPGUARD_PUBLIC_KEY set → bundle REJECTED (tombstone)', () => {
  it('rejects any bundle when NODE_ENV=production and override is set', async () => {
    process.env.NODE_ENV = 'production';
    process.env.SHIPGUARD_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----';

    await expect(
      verifyAndDecryptBundle('dGVzdA==', 'victim-token'),
    ).rejects.toThrow('legacy-bundle-rejected');
  });
});

// ---------------------------------------------------------------------------
// TA-003 — SHIPGUARD_PUBLIC_KEY env var has NO influence
//
// The tombstone rejects before any key resolution occurs.
// Whether SHIPGUARD_PUBLIC_KEY is set, unset, garbage, or valid PEM — the
// result is always legacy-bundle-rejected.
// ---------------------------------------------------------------------------

describe('TA-003: SHIPGUARD_PUBLIC_KEY env var is completely ignored', () => {
  it('setting SHIPGUARD_PUBLIC_KEY to garbage still throws legacy-bundle-rejected (not a PEM error)', async () => {
    process.env.SHIPGUARD_PUBLIC_KEY = 'GARBAGE-NOT-A-REAL-KEY';

    let msg = '';
    try {
      await verifyAndDecryptBundle('dGVzdA==', 'any-token');
    } catch (err) {
      msg = err instanceof Error ? err.message : String(err);
    }

    // Must be the tombstone message, not a PEM parse error from using the garbage key
    expect(msg).toContain('legacy-bundle-rejected');
    expect(msg).not.toMatch(/pem|parse|key format|invalid key/i);
  });

  it('rejects even when SHIPGUARD_PUBLIC_KEY is unset', async () => {
    delete process.env.SHIPGUARD_PUBLIC_KEY;

    await expect(
      verifyAndDecryptBundle('dGVzdA==', 'any-token'),
    ).rejects.toThrow('legacy-bundle-rejected');
  });

  it('never resolves regardless of env state', async () => {
    for (const keyVal of [undefined, 'GARBAGE', '-----BEGIN PUBLIC KEY-----\nMCo=\n-----END PUBLIC KEY-----']) {
      if (keyVal === undefined) {
        delete process.env.SHIPGUARD_PUBLIC_KEY;
      } else {
        process.env.SHIPGUARD_PUBLIC_KEY = keyVal;
      }
      const result = await verifyAndDecryptBundle('dGVzdA==', 'token')
        .then(() => 'resolved')
        .catch(() => 'rejected');
      expect(result).toBe('rejected');
    }
  });
});

// ---------------------------------------------------------------------------
// TA-004 — Source-code static assertion: SHIPGUARD_PUBLIC_KEY removed from crypto.ts
// ---------------------------------------------------------------------------

describe('TA-004: SHIPGUARD_PUBLIC_KEY must NOT appear in packages/cli/src/core/crypto.ts', () => {
  it('crypto.ts source does not reference SHIPGUARD_PUBLIC_KEY', async () => {
    const { readFileSync } = await import('node:fs');
    const cryptoPath = new URL('../../src/core/crypto.ts', import.meta.url).pathname;
    const source = readFileSync(cryptoPath, 'utf-8');

    expect(source).not.toContain('SHIPGUARD_PUBLIC_KEY');
  });
});
