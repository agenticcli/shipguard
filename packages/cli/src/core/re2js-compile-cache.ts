// Compile cache for re2js, kept OUTSIDE the frozen matcher-contract adapter.
//
// WHY THIS LIVES HERE: `packages/matcher-contract/src/adapters/re2js-v1.ts` is FROZEN — its
// content hash feeds RE2JS_V1_RUNTIME_ID, which published Pro bundles are bound to. Editing
// that file (commit a46a97f did) invalidates those bundles unless the engine is re-frozen.
// The adapter calls `RE2JS.compile(pattern, flags)` once per (rule, file); with 30 bundled
// rules on every scan that was ~100,000 compilations (a scan of packages/cli: ~1s -> 28.7s).
//
// So the memoisation is applied from the CLI side by wrapping the static `RE2JS.compile`.
// Behaviour is preserved: compilation is pure, a compiled RE2JS is stateless (matcher()
// mints a fresh Matcher per call), and compile FAILURES are never cached — they re-throw on
// every call, so the adapter's fail-closed contract (FIX 5) is unchanged.
//
// The cache is bounded (cleared on overflow). Installation is idempotent.

import { RE2JS } from 're2js'

const COMPILE_CACHE_MAX = 20_000
const cache = new Map<string, RE2JS>()
const INSTALLED = Symbol.for('agenticcli.re2js.compileCache')

type CompileFn = (pattern: string, flags?: number) => RE2JS

export function installRe2jsCompileCache(): void {
  const target = RE2JS as unknown as Record<symbol, unknown> & { compile: CompileFn }
  if (target[INSTALLED]) return
  const original: CompileFn = target.compile.bind(RE2JS) as CompileFn
  target.compile = (pattern: string, flags: number = 0): RE2JS => {
    const key = `${flags}\u0000${pattern}`
    const hit = cache.get(key)
    if (hit !== undefined) return hit
    // Not wrapped: a compile error propagates unchanged and is not remembered.
    const compiled = original(pattern, flags)
    if (cache.size >= COMPILE_CACHE_MAX) cache.clear()
    cache.set(key, compiled)
    return compiled
  }
  target[INSTALLED] = true
}

/** Cached compile for CLI-side callers (bundle validation shares the adapter's cache). */
export function compileCached(pattern: string, flags: number): RE2JS {
  installRe2jsCompileCache()
  return RE2JS.compile(pattern, flags)
}

/** Test hook. */
export function re2jsCompileCacheSize(): number {
  return cache.size
}
