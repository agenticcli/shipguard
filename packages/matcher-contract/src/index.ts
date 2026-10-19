// @agenticcli/matcher-contract — single semantics authority for Gate C and the CLI
// Phase A foundation: types and interfaces only; matching logic is Phase B.

export * from './matcher.js'
export * from './flags.js'
export * from './canonical.js'
export * from './finding.js'
export * from './normalize.js'
export * from './caps.js'
export * from './failure.js'
export * from './engine-meta.js'
export * from './runtime-id.js'
export * from './selector.js'
export * from './conformance/index.js'
// Phase B.1 — native-v1 executor adapter + frozen NATIVE_V1_RUNTIME_ID
export * from './adapters/native-v1.js'
// Phase D.1 — re2js-v1 executor adapter + frozen RE2JS_V1_RUNTIME_ID (linear-time, ReDoS-immune)
export * from './adapters/re2js-v1.js'
// Shared per-rule executableHash — single source of truth for CLI + server (matcher spec §3.1)
export * from './executable-hash.js'
