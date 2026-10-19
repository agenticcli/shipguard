/**
 * open-url.ts — open a URL in the user's browser WITHOUT a shell.
 *
 * The URL can come from a server (`verification_uri` in the device-auth response), so it is
 * untrusted. It is validated with `new URL()` (https only; http only for loopback) and handed to
 * the OS opener as a single argv element via spawn() with `shell: false`. It is never
 * concatenated into a command string, so `$(...)`, backticks, `;`, `"` and `&` stay inert.
 */
import { spawn } from 'node:child_process'

const isLoopback = (host: string): boolean => host === 'localhost' || host === '127.0.0.1' || host === '[::1]'

/**
 * Returns the normalised URL if it is safe to open, otherwise null. An https URL must be on the
 * same host as `apiUrl` (the server we are logging in to); loopback http(s) is allowed for dev.
 */
export function parseOpenableUrl(raw: unknown, apiUrl?: string): URL | null {
  if (typeof raw !== 'string') return null
  // WHATWG URL silently strips \t \n \r, so reject control chars / whitespace before parsing.
  if (/[\u0000-\u0020\u007f]/.test(raw)) return null
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return null
  }
  if (u.username || u.password) return null
  const host = u.hostname.toLowerCase()
  const loopback = isLoopback(host)
  if (u.protocol === 'http:' && loopback) return u
  if (u.protocol !== 'https:') return null
  if (loopback) return u
  let apiHost: string | null = null
  try {
    apiHost = apiUrl ? new URL(apiUrl).hostname.toLowerCase() : null
  } catch {
    apiHost = null
  }
  return apiHost !== null && host === apiHost ? u : null
}

export function openerFor(platform: NodeJS.Platform, href: string): { cmd: string; args: string[] } {
  if (platform === 'darwin') return { cmd: 'open', args: [href] }
  // rundll32 takes the URL as a plain argument; `cmd /c start` would re-parse it as shell text.
  if (platform === 'win32') return { cmd: 'rundll32', args: ['url.dll,FileProtocolHandler', href] }
  return { cmd: 'xdg-open', args: [href] }
}

/**
 * Try to open `raw` in a browser. Returns true if an opener was launched, false if the URL was
 * rejected. A missing opener (e.g. headless box) is reported via `onError`, never thrown.
 */
export function openUrl(raw: unknown, apiUrl: string | undefined, onError: (err: Error) => void = () => {}): boolean {
  const url = parseOpenableUrl(raw, apiUrl)
  if (!url) return false
  const { cmd, args } = openerFor(process.platform, url.href)
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true, shell: false })
    child.on('error', onError)
    child.unref()
  } catch (err) {
    onError(err instanceof Error ? err : new Error(String(err)))
  }
  return true
}
