/**
 * Global vitest setup (vitest.config.ts -> setupFiles): tests run as if on a developer machine.
 *
 * RCA (sg#53 red CI, 2026-11-22): GitHub's runner sets CI=true and GITHUB_ACTIONS=true. The CLI's CI mode
 * (spec 01 rule 9) then puts `shipguard: ` in front of every stderr line and the plan relay answers
 * reason "CI". Tests that spawn the real CLI inherit that env and assert the non-CI output, so 14 of them
 * failed on the hosted runner and passed locally. Fix in the test setup, not in the CLI: remove every CI
 * signal from this worker's env. A test that wants CI mode passes CI explicitly in its own env.
 */
import { CI_PROVIDER_VARS } from '../../src/core/telemetry.js'

for (const name of ['CI', ...CI_PROVIDER_VARS]) delete process.env[name]
