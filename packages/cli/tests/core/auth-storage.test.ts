// auth-storage.test.ts — hardening of the 0600 credentials file.
//
// We deliberately do NOT use a native OS keychain (keytar/@napi-rs rejected). The decision
// is the gh/aws/npm approach: a 0600 file in ~/.config/shipguard, with the perms ENFORCED.
// These tests pin the three hardening guarantees:
//   (1) write     → file mode is 0600 and its parent dir is 0700
//   (2) read      → a group/other-readable (e.g. 0644) file is REFUSED + warned, not trusted
//   (3) logout    → clearCredentials removes the file from disk
//
// POSIX permission semantics do not exist on win32, so the perm-sensitive assertions are
// guarded to POSIX. The refuse-and-warn behavior is a no-op on win32 by design (mirrors auth.ts).

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdirSync, rmSync, existsSync, statSync, chmodSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';

const TEST_HOME = join(tmpdir(), 'shipguard-auth-storage-test-' + process.pid);
const isPosix = process.platform !== 'win32';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => TEST_HOME };
});

const { loadCredentials, saveCredentials, clearCredentials, getCredentialsPath } =
  await import('../../src/core/auth.js');

const VALID_CREDS = {
  accessToken: 'tok_abc',
  refreshToken: 'ref_xyz',
  expiresAt: Date.now() + 60_000,
  apiUrl: 'https://agenticcli.dev',
};

/** Low 12 bits = the permission bits (rwx for user/group/other + setuid/setgid/sticky). */
function permBits(path: string): number {
  return statSync(path).mode & 0o777;
}

beforeEach(() => mkdirSync(TEST_HOME, { recursive: true }));
afterEach(() => rmSync(TEST_HOME, { recursive: true, force: true }));

describe('auth credential-file hardening', () => {
  it('(1) saveCredentials writes the file as 0600 and the dir as 0700', async () => {
    await saveCredentials(VALID_CREDS);
    const file = getCredentialsPath();
    const dir = dirname(file);

    expect(existsSync(file)).toBe(true);
    if (isPosix) {
      expect(permBits(file)).toBe(0o600);
      expect(permBits(dir)).toBe(0o700);
    }
  });

  it('(1b) saveCredentials tightens a pre-existing loose dir down to 0700', async () => {
    if (!isPosix) return; // perms are meaningless on win32
    const file = getCredentialsPath();
    const dir = dirname(file);
    mkdirSync(dir, { recursive: true });
    chmodSync(dir, 0o755); // simulate a world-readable config dir

    await saveCredentials(VALID_CREDS);

    expect(permBits(dir)).toBe(0o700);
    expect(permBits(file)).toBe(0o600);
  });

  it('(2) loadCredentials REFUSES a group/other-readable (0644) file and warns loudly', async () => {
    if (!isPosix) return; // no POSIX perms on win32 — refuse-check is a no-op there
    await saveCredentials(VALID_CREDS);
    const file = getCredentialsPath();
    chmodSync(file, 0o644); // attacker/lax umask: now group + other can read the token

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const loaded = loadCredentials();

    expect(loaded).toBeNull(); // refused, not silently trusted
    expect(warn).toHaveBeenCalledTimes(1);
    const msg = String(warn.mock.calls[0]?.[0] ?? '');
    expect(msg).toMatch(/unsafe permission/i);
    expect(msg).toMatch(/shipguard login/i);
    warn.mockRestore();
  });

  it('(2b) loadCredentials also refuses a group/other-WRITABLE (0620) file', async () => {
    if (!isPosix) return;
    await saveCredentials(VALID_CREDS);
    const file = getCredentialsPath();
    chmodSync(file, 0o620); // group-writable: someone else could swap the token

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const loaded = loadCredentials();

    expect(loaded).toBeNull();
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('(2c) loadCredentials still loads a correctly-0600 file (no false refusal)', async () => {
    await saveCredentials(VALID_CREDS);
    if (isPosix) expect(permBits(getCredentialsPath())).toBe(0o600);
    expect(loadCredentials()).toEqual(VALID_CREDS);
  });

  it('(3) clearCredentials (logout) removes the file from disk', async () => {
    await saveCredentials(VALID_CREDS);
    const file = getCredentialsPath();
    expect(existsSync(file)).toBe(true);

    clearCredentials();

    expect(existsSync(file)).toBe(false);
    expect(loadCredentials()).toBeNull();
  });

  it('(3b) clearCredentials is a safe no-op when no file exists', () => {
    expect(existsSync(getCredentialsPath())).toBe(false);
    expect(() => clearCredentials()).not.toThrow();
    expect(existsSync(getCredentialsPath())).toBe(false);
  });

  it('does not warn for a simply-missing file (corrupt/absent path stays quiet here)', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(loadCredentials()).toBeNull();
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });
});
