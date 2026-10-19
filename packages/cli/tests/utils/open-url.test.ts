import { describe, it, expect } from 'vitest'
import { parseOpenableUrl, openerFor } from '../../src/utils/open-url.js'

const API = 'https://agenticcli.dev'

describe('parseOpenableUrl', () => {
  it('accepts https on the API host', () => {
    expect(parseOpenableUrl('https://agenticcli.dev/activate', API)?.href).toBe('https://agenticcli.dev/activate')
  })
  it('rejects https on a foreign host', () => {
    expect(parseOpenableUrl('https://evil.example/activate', API)).toBeNull()
  })
  it('rejects a lookalike subdomain of the API host', () => {
    expect(parseOpenableUrl('https://agenticcli.dev.evil.example/', API)).toBeNull()
  })
  it.each(['http://localhost:3000/a', 'http://127.0.0.1:3000/a', 'http://[::1]:3000/a'])('allows loopback dev %s', (u) => {
    expect(parseOpenableUrl(u, API)).not.toBeNull()
  })
  it('rejects plain http to a non-loopback host', () => {
    expect(parseOpenableUrl('http://agenticcli.dev/a', API)).toBeNull()
  })
  it('rejects userinfo', () => {
    expect(parseOpenableUrl('https://user:pw@agenticcli.dev/a', API)).toBeNull()
    expect(parseOpenableUrl('https://agenticcli.dev@evil.example/a', API)).toBeNull()
  })
  it.each([undefined, null, 42, {}, ['https://agenticcli.dev']])('rejects non-string %j', (v) => {
    expect(parseOpenableUrl(v, API)).toBeNull()
  })
  it('rejects a URI containing a newline, tab or other control character', () => {
    expect(parseOpenableUrl('https://agenticcli.dev/a\nb', API)).toBeNull()
    expect(parseOpenableUrl('https://agenticcli.dev/\t', API)).toBeNull()
    expect(parseOpenableUrl('https://agenticcli.dev/\u001b[31m', API)).toBeNull()
  })
})

describe('openerFor', () => {
  const href = 'https://agenticcli.dev/a?b=1&c=$(x)'
  it('darwin -> open', () => expect(openerFor('darwin', href)).toEqual({ cmd: 'open', args: [href] }))
  it('linux -> xdg-open', () => expect(openerFor('linux', href)).toEqual({ cmd: 'xdg-open', args: [href] }))
  it('win32 -> rundll32 with the URL as one argument', () =>
    expect(openerFor('win32', href)).toEqual({ cmd: 'rundll32', args: ['url.dll,FileProtocolHandler', href] }))
})
