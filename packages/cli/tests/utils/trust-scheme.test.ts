/**
 * trust-scheme.test.ts — the domain pin must pin the SCHEME too.
 *
 * `assertTrustedApiUrl` lowercased and checked `parsed.hostname` and never looked at
 * `parsed.protocol`. So `http://api.agenticcli.dev` passed the pin, and every caller that
 * attaches `Authorization: Bearer …` after this guard would have sent the token over
 * plaintext. A browser is saved from that by HSTS. A CLI gets no HSTS, so the check has to
 * live in the guard itself.
 *
 * The exemption is loopback only, and it is decided by HOSTNAME, not by the scheme — so an
 * attacker's host can never opt itself out of TLS.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { assertTrustedApiUrl } from '../../src/utils/trust.js'

const ORIGINAL_EXTRA = process.env.SHIPGUARD_EXTRA_HOSTS

beforeEach(() => {
  delete process.env.SHIPGUARD_EXTRA_HOSTS
})

afterEach(() => {
  if (ORIGINAL_EXTRA === undefined) delete process.env.SHIPGUARD_EXTRA_HOSTS
  else process.env.SHIPGUARD_EXTRA_HOSTS = ORIGINAL_EXTRA
})

describe('assertTrustedApiUrl — scheme pinning', () => {
  it('rejects http:// on a trusted host (the reported defect)', () => {
    expect(() => assertTrustedApiUrl('http://agenticcli.dev')).toThrow(/scheme "http" is not permitted/)
  })

  it('rejects http:// on a trusted subdomain-shaped host', () => {
    process.env.SHIPGUARD_EXTRA_HOSTS = 'internal.corp.com'
    expect(() => assertTrustedApiUrl('http://internal.corp.com')).toThrow(/not permitted/)
  })

  it('rejects a non-HTTP scheme entirely', () => {
    expect(() => assertTrustedApiUrl('ftp://agenticcli.dev')).toThrow(/not permitted/)
    expect(() => assertTrustedApiUrl('file://agenticcli.dev')).toThrow(/not permitted/)
  })

  it('accepts https:// on a trusted host', () => {
    expect(() => assertTrustedApiUrl('https://agenticcli.dev')).not.toThrow()
    expect(() => assertTrustedApiUrl('https://agenticcli.dev/api/rules/fetch')).not.toThrow()
  })

  it('still allows http:// on loopback — the local dev server needs it', () => {
    expect(() => assertTrustedApiUrl('http://localhost:3000')).not.toThrow()
    expect(() => assertTrustedApiUrl('http://127.0.0.1:4080')).not.toThrow()
  })

  it('allows https:// on loopback too', () => {
    expect(() => assertTrustedApiUrl('https://localhost:3000')).not.toThrow()
  })

  it('the loopback exemption is decided by HOST, so an attacker host cannot claim it', () => {
    process.env.SHIPGUARD_EXTRA_HOSTS = 'localhost.evil.com'
    expect(() => assertTrustedApiUrl('http://localhost.evil.com')).toThrow(/not permitted/)
  })

  it('still rejects an untrusted host even over https', () => {
    expect(() => assertTrustedApiUrl('https://evil.com')).toThrow(/Untrusted API URL/)
  })

  it('still rejects a structurally invalid URL', () => {
    expect(() => assertTrustedApiUrl('not-a-url')).toThrow(/URL is invalid/)
  })
})
