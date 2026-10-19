import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const TEST_HOME = join(tmpdir(), 'shipguard-auth-test-' + process.pid);

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => TEST_HOME };
});

const { loadCredentials, saveCredentials, clearCredentials, isTokenExpired, getAuthToken } =
  await import('../../src/core/auth.js');

const VALID_CREDS = {
  accessToken: 'tok_abc',
  refreshToken: 'ref_xyz',
  expiresAt: Date.now() + 60_000,
  apiUrl: 'https://agenticcli.dev',
};

beforeEach(() => mkdirSync(TEST_HOME, { recursive: true }));
afterEach(() => rmSync(TEST_HOME, { recursive: true, force: true }));

describe('auth', () => {
  it('save/load roundtrip preserves all fields', async () => {
    await saveCredentials(VALID_CREDS);
    const loaded = loadCredentials();
    expect(loaded).toEqual(VALID_CREDS);
  });

  it('loadCredentials returns null when file missing', () => {
    expect(loadCredentials()).toBeNull();
  });

  it('isTokenExpired returns true for past expiresAt', () => {
    expect(isTokenExpired({ ...VALID_CREDS, expiresAt: Date.now() - 1000 })).toBe(true);
  });

  it('isTokenExpired returns false for future expiresAt', () => {
    expect(isTokenExpired(VALID_CREDS)).toBe(false);
  });

  // the server's PF-D3 guard rejects a raw API key sent directly as a
  // Bearer token (401 "Auth expired"). getAuthToken must EXCHANGE it via
  // POST /api/agent/exchange and return the resulting access_token — never the
  // raw env var value. See tests/core/auth-key-exchange.test.ts for the full
  // fail-before/pass-after regression coverage of this fix.
  it('getAuthToken exchanges SHIPGUARD_API_KEY for an access token, not the raw key', async () => {
    process.env.SHIPGUARD_API_KEY = 'ci_key_123';
    const originalFetch = globalThis.fetch;
    const fetchMock = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      statusText: 'OK',
      json: async () => ({ access_token: 'exchanged_ci_token', expires_in: 900 }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const token = await getAuthToken('https://agenticcli.dev');

    expect(fetchMock).toHaveBeenCalledWith(
      'https://agenticcli.dev/api/agent/exchange',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(token).toBe('exchanged_ci_token');
    expect(token).not.toBe('ci_key_123');

    globalThis.fetch = originalFetch;
    delete process.env.SHIPGUARD_API_KEY;
  });

  it('clearCredentials removes the file', async () => {
    await saveCredentials(VALID_CREDS);
    clearCredentials();
    expect(loadCredentials()).toBeNull();
  });
});
