import { createHmac, randomBytes } from 'node:crypto'
import { chmodSync, existsSync, linkSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs'

/**
 * Keyed finding identity for the history store.
 *
 * `finding_key` used to be a plain truncated SHA-256 of the matched text. For a low-entropy
 * secret (a weak database password) anyone holding the history file could test guesses offline.
 * It is now HMAC-SHA256(salt, identity digest), where the salt is 32 random bytes kept in a
 * separate mode-600 file next to the database (`<history path>.salt`). The salt travels with the
 * database, so identities stay comparable when the history directory is moved, but a copy of the
 * database file alone is not enough to test guesses.
 *
 * The identity digest passed in (see `computeFindingKey` in ../redact.ts) only ever lives in
 * memory; the history store never writes it.
 */

const SALT_BYTES = 32
const SALT_HEX = /^[0-9a-f]{64}$/

export type SaltResult = { ok: true; salt: Buffer } | { ok: false; reason: string }

/** Where the salt for a given history database lives. */
export function saltPathFor(dbPath: string): string {
  return `${dbPath}.salt`
}

/** HMAC-SHA256(salt, identityDigest), truncated to 16 hex like the plain digest it replaces. */
export function keyFindingIdentity(salt: Buffer, identityDigest: string): string {
  return createHmac('sha256', salt).update(identityDigest).digest('hex').slice(0, 16)
}

function readSalt(path: string): SaltResult {
  let text: string
  try {
    text = readFileSync(path, 'utf-8').trim()
  } catch (err) {
    return { ok: false, reason: `Could not read the history salt file ${path}: ${err instanceof Error ? err.message : err}` }
  }
  if (!SALT_HEX.test(text)) {
    return {
      ok: false,
      reason:
        `The history salt file ${path} is not a valid salt. Delete it (and the history file) to start fresh; ` +
        `finding identities recorded earlier will no longer match.`,
    }
  }
  // Keep the secret owner-only even if something loosened it. Best effort: a failure here
  // does not make the salt wrong, but it must not be silent.
  try {
    if ((statSync(path).mode & 0o077) !== 0) chmodSync(path, 0o600)
  } catch (err) {
    console.error(`shipguard: could not tighten permissions on ${path}: ${err instanceof Error ? err.message : err}`)
  }
  return { ok: true, salt: Buffer.from(text, 'hex') }
}

/**
 * Load the salt for this history database, creating it on first use. Creation is atomic (write a
 * private temp file, then hard-link it into place), so two processes starting together end up
 * with ONE salt and neither ever reads a half-written file.
 *
 * Never throws: a failure returns a reason, and the history store then stays off instead of
 * falling back to unkeyed identities.
 */
export function loadOrCreateSalt(dbPath: string): SaltResult {
  const path = saltPathFor(dbPath)
  if (existsSync(path)) return readSalt(path)

  const tmp = `${path}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`
  try {
    writeFileSync(tmp, randomBytes(SALT_BYTES).toString('hex') + '\n', { mode: 0o600, flag: 'wx' })
    try {
      linkSync(tmp, path)
    } catch (err) {
      // Lost the race to another process: use the salt it created.
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err
    }
  } catch (err) {
    return { ok: false, reason: `Could not create the history salt file ${path}: ${err instanceof Error ? err.message : err}` }
  } finally {
    try {
      unlinkSync(tmp)
    } catch {
      /* the temp file may never have been created */
    }
  }
  return readSalt(path)
}
