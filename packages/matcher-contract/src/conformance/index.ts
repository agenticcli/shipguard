// Conformance module public API
//
// Exports:
//   - vectors: structured conformance vector set (inputs + expected hashes)
//   - harness: runConformance(executor, vectors) — the executor-injected runner

export * from './vectors.js'
export * from './harness.js'
