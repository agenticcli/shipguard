/**
 * platform-status.ts — one place that recognises the hosted backend's "platform unavailable" answer
 * (platform-unavailable-20261018). The server sends it when it is over its plan limits or its
 * deployment is disabled: HTTP 503, body `{"error": "...", "code": "PLATFORM_UNAVAILABLE"}`,
 * `Retry-After` and `X-Platform-Status: unavailable`. It can land on ANY authenticated call — the
 * rules fetch, the token refresh, the API-key exchange — so every one of them must map it to the
 * same stable class instead of "log in again" or a generic server error.
 */

export const PLATFORM_UNAVAILABLE_CODE = 'PLATFORM_UNAVAILABLE' as const

/** Thrown by the auth paths (refresh / exchange); fetchProRules re-wraps it as a ProFetchError. */
export class PlatformUnavailableError extends Error {
  readonly code = PLATFORM_UNAVAILABLE_CODE
  readonly retryAfterSeconds?: number
  constructor(message: string, retryAfterSeconds?: number) {
    super(message)
    this.name = 'PlatformUnavailableError'
    this.retryAfterSeconds = retryAfterSeconds
  }
}

/**
 * Reads a `Retry-After` header as whole seconds. Returns undefined when it is missing, empty, or
 * not a non-negative number (e.g. an HTTP-date) — never NaN.
 */
export function parseRetryAfterSeconds(headers: Headers | undefined): number | undefined {
  // A minimal Response-like object (some tests, some fetch shims) may carry no headers at all.
  const raw = typeof headers?.get === 'function' ? headers.get('Retry-After') : null
  if (raw === null || raw.trim() === '') return undefined
  const seconds = Number(raw.trim())
  return Number.isFinite(seconds) && seconds >= 0 ? Math.floor(seconds) : undefined
}

/**
 * True when a response is the platform-unavailable answer: the body code on any status, or the
 * `X-Platform-Status: unavailable` header on a 503 when the body is unreadable.
 */
export function isPlatformUnavailable(res: Response, body: { code?: unknown } | null | undefined): boolean {
  const header = typeof res.headers?.get === 'function' ? res.headers.get('X-Platform-Status') : null
  return body?.code === PLATFORM_UNAVAILABLE_CODE || (res.status === 503 && header === 'unavailable')
}

export const PLATFORM_UNAVAILABLE_DEFAULT_MESSAGE = 'Service temporarily unavailable. Please try again later.'
