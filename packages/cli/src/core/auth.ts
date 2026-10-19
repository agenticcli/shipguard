import {
  readFileSync,
  writeFileSync,
  rmSync,
  existsSync,
  statSync,
} from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import type { AuthCredentials } from '@agenticcli/shared';
import { assertTrustedApiUrl } from '../utils/trust.js';
import { goLink } from './links.js';
import { ensureSecureDir, writeSecureFileSync } from '../utils/secure-fs.js';
import { PlatformUnavailableError, isPlatformUnavailable, parseRetryAfterSeconds, PLATFORM_UNAVAILABLE_DEFAULT_MESSAGE } from './platform-status.js';

// ── Credential file hardening  ───────────────────────
// We store the OAuth tokens in a plain 0600 file under ~/.config/shipguard — the same
// approach gh / aws-cli / npm use. We deliberately do NOT use a native OS keychain
// (keytar / @napi-rs.keyring): native install-scripts conflict with our zero-install-
// scripts supply-chain policy and break headless CI. See docs/tiered-identity-model.md
// (§ "CLI Token Storage") for the full threat model.
//
// "0600" alone is industry-standard but only safe if it is actually ENFORCED. So:
//   • on write we tighten the dir to 0700 and the file to 0600 (chmod, not just the
//     mkdir/writeFile `mode` option — that option is masked by umask and never tightens
//     an existing loose dir);
//   • on read we REFUSE to load a group/other-readable-or-writable file and warn loudly
//     rather than silently trusting credentials another user could have read or swapped;
//   • on logout we overwrite-then-unlink so the token is not left recoverable on disk.
//
// POSIX permission bits do not exist on win32, so every perm operation is guarded to
// POSIX and is a deliberate no-op on Windows.

const FILE_MODE = 0o600;
/** Any of these bits set on the creds file means group/other can read, write, or exec it. */
const UNSAFE_PERM_MASK = 0o077;

const isPosix = process.platform !== 'win32';

export function getCredentialsPath(): string {
  return join(homedir(), '.config', 'shipguard', 'credentials.json');
}

/**
 * Returns true when the file at `path` is reachable by group/other (readable, writable,
 * or executable). POSIX-only — on win32 there are no such bits, so it always returns false.
 */
function hasUnsafePermissions(path: string): boolean {
  if (!isPosix) return false;
  const mode = statSync(path).mode & 0o777;
  return (mode & UNSAFE_PERM_MASK) !== 0;
}

export function loadCredentials(): AuthCredentials | null {
  const p = getCredentialsPath();
  if (!existsSync(p)) return null;

  // Refuse to trust a credentials file that other users on this machine could read or
  // swap. Loading it anyway would silently defeat the whole point of a 0600 file.
  if (hasUnsafePermissions(p)) {
    console.warn(
      '[shipguard] credentials file has unsafe permissions (group/other-readable or writable) — refusing to use it. Run `shipguard login` again to re-create it with 0600 perms.',
    );
    return null;
  }

  try {
    return JSON.parse(readFileSync(p, 'utf-8')) as AuthCredentials;
  } catch {
    console.warn('[shipguard] credentials file is corrupt — run `shipguard login` again');
    return null;
  }
}

export async function saveCredentials(creds: AuthCredentials): Promise<void> {
  const p = getCredentialsPath();
  const dir = dirname(p);

  // Shared helpers create the dir (mkdir -p, 0700) and write the file (0600), chmod'ing
  // explicitly because `mode` is masked by the umask and never tightens an existing path.
  ensureSecureDir(dir);
  writeSecureFileSync(p, JSON.stringify(creds, null, 2));
}

export function clearCredentials(): void {
  const p = getCredentialsPath();
  if (!existsSync(p)) return;

  // Best-effort secure delete: overwrite the bytes with zeros before unlinking so the
  // token is not trivially recoverable from the freed blocks, then remove the file.
  try {
    const size = statSync(p).size;
    if (size > 0) writeFileSync(p, Buffer.alloc(size, 0), { mode: FILE_MODE });
  } catch {
    // Overwrite is a hardening nicety, not a correctness requirement — if it fails
    // (e.g. read-only FS) we still proceed to unlink below so the creds are gone.
  }
  rmSync(p, { force: true });
}

export function isTokenExpired(creds: AuthCredentials): boolean {
  return creds.expiresAt < Date.now();
}

// ── API-key exchange ──────────────────────────────────────────────
// The server's PF-D3 guard correctly REJECTS a raw SHIPGUARD_API_KEY sent directly
// as a Bearer token (401 "Auth expired" — /api/rules/fetch:44-53 sheds raw keys).
// A raw key must first be EXCHANGED for a short-lived (15m) access token via
// POST /api/agent/exchange, then that access token is used as the Bearer for the
// Pro rules-fetch / scan calls. Before this fix the CLI never called exchange, so
// every valid paid API key hit the guard and could never run a Pro scan.
//
// Same host as the rest of the call (--api-url / stored login apiUrl) — never a
// new hardcoded host; DEFAULT_API_URL below only mirrors the existing default
// already used by login.ts / scan.ts's --api-url option.
const DEFAULT_API_URL = 'https://agenticcli.dev';

/**
 * In-memory cache for an exchanged API-key access token. Never persisted to disk —
 * unlike the device-flow tokens (which are written via saveCredentials), the API
 * key is a long-lived secret supplied via env var; only the short-lived access
 * token it exchanges for is cached, and only for the lifetime of this process.
 */
let cachedExchangedToken: {
  apiKey: string;
  apiUrl: string;
  accessToken: string;
  expiresAt: number;
} | null = null;

/**
 * Exchange a raw ShipGuard API key for a short-lived Bearer access token.
 * Throws a clear, distinct error on failure (no silent fallback to
 * sending the raw key, and never the misleading "Auth expired" wording — that
 * belongs to the device-flow refresh path, not an API-key problem).
 */
async function exchangeApiKeyForToken(apiKey: string, apiUrl: string): Promise<string> {
  // Bearer-authenticated fetch — must be domain-pinned same as every other
  // Authorization: Bearer call (BL-2).
  assertTrustedApiUrl(apiUrl);

  let res: Response;
  try {
    res = await fetch(`${apiUrl}/api/agent/exchange`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}` },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[shipguard] SHIPGUARD_API_KEY exchange request to ${apiUrl} failed: ${msg}`);
    throw new Error(
      `Could not reach ${apiUrl}/api/agent/exchange to exchange SHIPGUARD_API_KEY: ${msg}`,
    );
  }

  if (res.status === 401) {
    console.error('[shipguard] SHIPGUARD_API_KEY exchange rejected — invalid or revoked key');
    throw new Error(
      'SHIPGUARD_API_KEY is invalid or has been revoked. Check the key value or generate ' +
      `a new one at ${goLink('dashboard')}.`,
    );
  }
  if (res.status === 402) {
    console.error('[shipguard] SHIPGUARD_API_KEY exchange rejected — monthly budget exhausted');
    throw new Error(
      'SHIPGUARD_API_KEY has exhausted its monthly credit budget. ' +
      `Buy more at ${goLink('billing')}`,
    );
  }
  if (!res.ok) {
    let detail = res.statusText;
    let body: { error_description?: string; error?: string; code?: unknown } | null = null;
    try {
      body = (await res.json()) as { error_description?: string; error?: string; code?: unknown };
      detail = body?.error_description ?? body?.error ?? detail;
    } catch {
      // Body wasn't parseable JSON — fall back to statusText; still throws below.
    }
    // The platform-unavailable 503 is the service being down, not a key problem.
    if (isPlatformUnavailable(res, body)) {
      throw new PlatformUnavailableError(
        typeof body?.error === 'string' ? body.error : PLATFORM_UNAVAILABLE_DEFAULT_MESSAGE,
        parseRetryAfterSeconds(res.headers),
      );
    }
    console.error(`[shipguard] SHIPGUARD_API_KEY exchange failed (${res.status}): ${detail}`);
    throw new Error(`SHIPGUARD_API_KEY exchange failed (${res.status}): ${detail}`);
  }

  const body = (await res.json()) as { access_token?: string; expires_in?: number };
  if (!body.access_token) {
    console.error('[shipguard] SHIPGUARD_API_KEY exchange returned 200 with no access_token');
    throw new Error('SHIPGUARD_API_KEY exchange succeeded but the server returned no access_token.');
  }

  cachedExchangedToken = {
    apiKey,
    apiUrl,
    accessToken: body.access_token,
    // Refresh 30s ahead of actual expiry so a long-running scan never races a
    // mid-request expiry against the server's 15-minute access-token TTL.
    expiresAt: Date.now() + (body.expires_in ?? 900) * 1000 - 30_000,
  };
  return body.access_token;
}

/**
 * Resolve the Bearer token to use for an authenticated API call.
 *
 * @param apiUrl Optional explicit API host (e.g. from --api-url). Used to target
 *   the API-key exchange call at the same configured API base. Falls back to a
 *   stored device-login apiUrl, then DEFAULT_API_URL, when not supplied.
 */
export async function getAuthToken(apiUrl?: string): Promise<string | null> {
  const apiKey = process.env.SHIPGUARD_API_KEY;
  if (apiKey) {
    // Lazy-evaluated: loadCredentials() (and its perm-check side effects) only
    // runs when the caller didn't pass an explicit apiUrl.
    const targetApiUrl = apiUrl ?? loadCredentials()?.apiUrl ?? DEFAULT_API_URL;

    if (
      cachedExchangedToken &&
      cachedExchangedToken.apiKey === apiKey &&
      cachedExchangedToken.apiUrl === targetApiUrl &&
      Date.now() < cachedExchangedToken.expiresAt
    ) {
      return cachedExchangedToken.accessToken;
    }

    return exchangeApiKeyForToken(apiKey, targetApiUrl);
  }

  const creds = loadCredentials();
  if (!creds) return null;
  if (!isTokenExpired(creds)) return creds.accessToken;

  // Access token is expired — attempt a refresh before giving up.
  if (creds.refreshToken && creds.apiUrl) {
    try {
      assertTrustedApiUrl(creds.apiUrl)
      const res = await fetch(`${creds.apiUrl}/api/auth/device/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: creds.refreshToken }),
      });
      if (res.ok) {
        const { access_token, refresh_token, expires_in } = await res.json() as {
          access_token: string;
          refresh_token?: string;
          expires_in?: number;
        };
        await saveCredentials({
          accessToken: access_token,
          refreshToken: refresh_token ?? creds.refreshToken,
          expiresAt: Date.now() + (expires_in ?? 900) * 1000,
          apiUrl: creds.apiUrl,
        });
        return access_token;
      }
      // The platform-unavailable 503 is NOT a refused refresh: the service is down on its own side
      // . Surface it as its own class instead of
      // returning null, which would read as "log in again".
      let refusedBody: { code?: unknown; error?: unknown } | null = null;
      try {
        // clone() so the body can still be read by anyone else; a minimal Response-like object (tests) may lack it.
        const probe = typeof res.clone === 'function' ? res.clone() : res;
        refusedBody = (await probe.json()) as { code?: unknown; error?: unknown };
      } catch {
        refusedBody = null; // unreadable body: the header check below still applies
      }
      if (isPlatformUnavailable(res, refusedBody)) {
        throw new PlatformUnavailableError(
          typeof refusedBody?.error === 'string' ? refusedBody.error : PLATFORM_UNAVAILABLE_DEFAULT_MESSAGE,
          parseRetryAfterSeconds(res.headers),
        );
      }
      // Non-2xx: the refresh was REFUSED, which is different from the network failing.
      // Without this branch the two were indistinguishable to the user — both produced a
      // bare "please log in again" with no way to tell a revoked token from a 503.
      console.error(
        `[shipguard] Token refresh refused by ${creds.apiUrl} (HTTP ${res.status} ${res.statusText}) — ` +
        `you will be asked to log in again.`,
      );
    } catch (err: unknown) {
      if (err instanceof PlatformUnavailableError) throw err; // the service is down, not the login
      // Refresh failed — fall through and return null so the caller prompts re-login.
      // never a silent catch. The reason matters: an expired refresh token, a
      // rejected API URL, a DNS failure and an offline laptop all landed here identically
      // before, so "log in again" was the only symptom of any of them.
      const detail = err instanceof Error ? err.message : String(err);
      console.error(
        `[shipguard] Token refresh failed — you will be asked to log in again. Reason: ${detail}`,
      );
    }
  }

  return null;
}
