import { defineConfig } from 'tsup'
import { readFileSync } from 'node:fs'

// Single source of truth: read version from package.json at build time.
// Injected as __SHIPGUARD_VERSION__ so cli.ts never hardcodes the string.
const { version } = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf-8')
) as { version: string }

// Provenance of this build, for usage pings. ONLY the release/publish path sets
// SHIPGUARD_PUBLISHED_BUILD=1 (`pnpm build:publish`, which `prepublishOnly` runs before the release
// gate). Any other build (`pnpm build`, `tsup --watch`, a source checkout, the test suite) is a
// "dev" build and never pings the production analytics endpoint. See src/core/telemetry.ts.
const publishedBuild = process.env.SHIPGUARD_PUBLISHED_BUILD === '1'

export default defineConfig({
  entry: ['src/cli.ts'],
  format: ['esm'],
  platform: 'node',
  target: 'node20',
  noExternal: [/^@agenticcli\/.*/],
  dts: false,
  sourcemap: false,
  clean: true,
  define: {
    __SHIPGUARD_VERSION__: JSON.stringify(version),
    __SHIPGUARD_PUBLISHED_BUILD__: JSON.stringify(publishedBuild),
  },
  // Post-build: generate dist/checksum-manifest.json so the CLI can verify
  // each dispatched coderef module against its build-time SHA-256 hash.
  // Runs AFTER tsup writes dist/ — zero new runtime deps (Node crypto only).
  // fail-closed on tampered coderef module (not a silent skip).
  // Post-build generators, in order:
  //  1. checksum-manifest.json — SHA-256 of each emitted chunk, for coderef dispatch.
  //  2. cli-facts.json — the machine-readable facts document the agenticcli web site and
  //     the agent-surface gate both read. It used to be produced only at release time,
  //     which is exactly why it drifted (a stale freeRuleCount aborted a prod deploy at
  //     Gate-0 once already). Generating it on every build means the committed truth and
  //     the built artifact cannot disagree for long.
  //  3. (publish builds only) check-keyring-placeholders.mjs — a published CLI must never
  //     ship an unfilled key-ceremony placeholder; the build fails instead.
  onSuccess:
    'node scripts/gen-checksum-manifest.mjs && node scripts/gen-cli-facts.mjs' +
    (publishedBuild ? ' && node scripts/check-keyring-placeholders.mjs dist' : ''),
})
