import { configDefaults, defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    // Fail-closed: no test may send telemetry to production analytics.
    setupFiles: ['./tests/setup/no-telemetry.ts'],
    // Slow lane (tests/slow/**) is excluded from the fast default suite and run explicitly by
    // `pnpm test:slow` and scripts/release-gate.sh (G8), which pass VITEST_SLOW=1.
    exclude: process.env.VITEST_SLOW ? configDefaults.exclude : [...configDefaults.exclude, 'tests/slow/**'],
  },
})
