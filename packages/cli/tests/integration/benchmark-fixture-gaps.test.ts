/**
 * benchmark-fixture-gaps.test.ts — the two defects the published benchmark found in us.
 *
 * `content-pipeline/benchmarks/RESULTS.md` in the platform repo is a four-scanner
 * head-to-head we published, and it reported two problems against ShipGuard itself, in
 * writing, under a heading called "Where ShipGuard itself came up short":
 *
 *   1. FX-11 — `src/routes/debug.js` returns the whole `process.env` and ShipGuard did not
 *      flag it. `auth_route_without_guard` fired for `/api/admin` and never for
 *      `/api/debug`, because the rule was keyword-scoped to five business-y path segments.
 *   2. One false positive — the CORS wildcard rule fired on `EXPECTED.md:47`, a
 *      documentation file whose PROSE contains the literal `origin: '*'` while describing
 *      the defect. Documentation about a misconfiguration is not a misconfiguration.
 *
 * This suite runs the real check modules over a byte-faithful copy of the real fixture
 * files, not a paraphrase. A test written against a hand-made approximation is how the
 * mock-vs-real-payload class of bug ships (this has happened before), so the fixture content below is copied verbatim from the committed benchmark.
 */

import { describe, it, expect } from 'vitest'
import type { FileInfo, Policy } from '@agenticcli/shared'
import { authCheck } from '../../src/checks/auth.js'
import { deploymentCheck } from '../../src/checks/deployment.js'
import { runProRules } from '../../src/core/pro-scanner.js'
import { loadBundledRules } from '../../src/core/bundled-rules.js'
import { loadPolicy } from '../../src/core/policy.js'

const policy: Policy = await loadPolicy(process.cwd())

// ── Verbatim excerpts from content-pipeline/benchmarks/fixture/ ────────────────

const DEBUG_ROUTE: FileInfo = {
  path: '/fixture/src/routes/debug.js',
  relativePath: 'src/routes/debug.js',
  content: [
    '// Debug router — left in from local development.',
    "const express = require('express');",
    'const router = express.Router();',
    '',
    '// FX-11: debug endpoint exposing the full process environment (secrets and',
    '// all) with no auth guard and no route-level protection.',
    "router.get('/env', (_req, res) => {",
    '  res.json({ env: process.env });',
    '});',
    '',
    'module.exports = router;',
    '',
  ].join('\n'),
}

const EXPECTED_MD: FileInfo = {
  path: '/fixture/EXPECTED.md',
  relativePath: 'EXPECTED.md',
  content: [
    '# EXPECTED.md — ground truth for the TaskFlow API fixture',
    '',
    '| ID | Category | Location | Description |',
    '|---|---|---|---|',
    "| FX-07 | Misconfiguration | `server.js:23` | CORS wildcard (`origin: '*'`) combined with `credentials: true` |",
    '',
  ].join('\n'),
}

const SERVER_JS: FileInfo = {
  path: '/fixture/server.js',
  relativePath: 'server.js',
  content: [
    '// TaskFlow API — entry point (benchmark fixture, do not deploy).',
    "const express = require('express');",
    "const cors = require('cors');",
    '',
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
    '',
    'const app = express();',
    "app.use(cors({ origin: '*', credentials: true }));",
    '',
    "app.get('/health', (_req, res) => res.json({ ok: true, service: 'taskflow-api' }));",
    '',
  ].join('\n'),
}

describe('FX-11 — the debug endpoint that dumps process.env', () => {
  it('the bundled corpus rule fires on it (the sink, independent of the path name)', () => {
    const findings = runProRules(loadBundledRules(), [DEBUG_ROUTE], policy)
    const hit = findings.find((f) => f.id === 'generic.config.debug-endpoint-env-dump')
    expect(hit, 'generic.config.debug-endpoint-env-dump did not fire on the FX-11 fixture').toBeDefined()
    expect(hit!.file).toBe('src/routes/debug.js')
    expect(hit!.severity).toBe('critical')
  })

  it('the auth check now also fires on it — /debug is a sensitive segment', () => {
    const findings = authCheck.run([DEBUG_ROUTE], policy)
    expect(findings.map((f) => f.id)).toContain('auth_route_without_guard')
  })

  it('still does NOT fire on a route that returns one named variable', () => {
    const safe: FileInfo = {
      path: '/fixture/src/routes/mode.js',
      relativePath: 'src/routes/mode.js',
      content:
        "router.get('/mode', requireAuth, (_req, res) => {\n" +
        '  res.json({ nodeEnv: process.env.NODE_ENV });\n' +
        '});\n',
    }
    const findings = runProRules(loadBundledRules(), [safe], policy)
    expect(findings.map((f) => f.id)).not.toContain('generic.config.debug-endpoint-env-dump')
  })
})

describe('the published false positive — CORS wildcard on documentation prose', () => {
  it('does NOT fire on EXPECTED.md, whose prose describes the defect in English', () => {
    const findings = deploymentCheck.run([EXPECTED_MD], policy)
    expect(
      findings.map((f) => `${f.id}@${f.file}:${f.line}`),
      'a markdown file describing a CORS wildcard must not be reported as having one',
    ).toEqual([])
  })

  it('STILL fires on server.js, where the wildcard is real code', () => {
    // The fix must narrow the surface, not weaken the pattern. If this goes green while the
    // test above also goes green for the wrong reason, coverage was lost, not a FP removed.
    const corpus = runProRules(loadBundledRules(), [SERVER_JS], policy)
    expect(corpus.map((f) => f.id)).toContain('generic.cors.wildcard-origin')
  })

  it('still detects the TLS-verification kill switch in the same file (FX-08)', () => {
    // FX-08 was missed by all four benchmarked scanners including ShipGuard. It is caught
    // now purely because the corpus bundle ships — a direct, checkable consequence of the
    // "free CLI ships none of the corpus" fix.
    const corpus = runProRules(loadBundledRules(), [SERVER_JS], policy)
    expect(corpus.map((f) => f.id)).toContain('generic.tls.reject-unauthorized-disabled')
  })
})
