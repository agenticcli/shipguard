/**
 * trust.ts — Domain-pinning guard (BL-2).
 *
 * Prevents Bearer tokens from being sent to an attacker-controlled server when
 * a user is tricked into running `shipguard login --api-url evil.com` or when
 * a stored apiUrl in credentials has been tampered with.
 *
 * Call assertTrustedApiUrl(url) BEFORE every fetch() that attaches an
 * `Authorization: Bearer` header.  The function throws a clear Error on
 * mismatch so the caller's fetch is never reached.
 *
 * Trusted hostnames (built-in):
 *   agenticcli.dev      — production API
 *   localhost           — local dev / tests
 *   127.0.0.1           — local dev / tests
 *
 * The SCHEME is checked too (added 2026-08-04). Pinning only the hostname let
 * `http://api.agenticcli.dev` pass, so a Bearer token could be attached to a plaintext
 * request that any network position can read. A browser would be saved by HSTS; a CLI gets
 * no HSTS, so the check has to live here. `https:` is required everywhere except loopback,
 * where the local-dev server legitimately speaks plain HTTP and there is no network to
 * intercept. Loopback is decided by hostname, not by the scheme, so `http://evil.com` can
 * never opt itself out.
 *
 * Enterprise / CI escape hatch:
 *   SHIPGUARD_EXTRA_HOSTS=internal.corp.com,staging.corp.com
 *   Comma-separated list of additional trusted hostnames.
 *   Empty strings and whitespace-only entries are silently ignored.
 */

const BUILT_IN_TRUSTED: ReadonlySet<string> = new Set([
  'agenticcli.dev',
  'localhost',
  '127.0.0.1',
]);

/**
 * Assert that `url` resolves to a trusted hostname before a Bearer-authenticated
 * fetch is made.
 *
 * @throws {Error} if the URL's hostname is not on the trusted allowlist.
 */
export function assertTrustedApiUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(
      `[shipguard] Untrusted API URL "${url}" — URL is invalid. ` +
      `Only agenticcli.dev, localhost, and 127.0.0.1 are permitted. ` +
      `Set SHIPGUARD_EXTRA_HOSTS to add trusted hosts.`,
    );
  }

  const hostname = parsed.hostname.toLowerCase();
  const scheme = parsed.protocol.toLowerCase();

  // Scheme pin. Loopback may speak http: (the local dev server does, and there is no
  // network path to intercept); everything else must be https:.
  const isLoopback = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
  if (scheme !== 'https:' && !(isLoopback && scheme === 'http:')) {
    throw new Error(
      `[shipguard] Untrusted API URL "${url}" — scheme "${scheme.replace(':', '')}" is not permitted. ` +
      `A Bearer token must never travel over a plaintext or non-HTTP transport. ` +
      `Use https:// (http:// is allowed only for localhost and 127.0.0.1).`,
    );
  }

  if (BUILT_IN_TRUSTED.has(hostname)) return;

  // Parse optional extra hosts from env
  const extra = (process.env.SHIPGUARD_EXTRA_HOSTS ?? '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);

  if (extra.includes(hostname)) return;

  throw new Error(
    `[shipguard] Untrusted API URL "${url}" (hostname: "${hostname}"). ` +
    `Only agenticcli.dev, localhost, and 127.0.0.1 are permitted by default. ` +
    `To allow additional hosts, set SHIPGUARD_EXTRA_HOSTS=<comma-separated-hostnames>.`,
  );
}
