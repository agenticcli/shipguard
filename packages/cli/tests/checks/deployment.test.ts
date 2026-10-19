import { describe, it, expect, vi } from 'vitest'
import type { FileInfo, Policy } from '@agenticcli/shared'
import { deploymentCheck } from '../../src/checks/deployment.js'
import { logger } from '../../src/utils/logger.js'

// Minimal policy fixture — most checks don't use policy fields
const defaultPolicy: Policy = {
  version: 1,
  project: { name: 'test-app', framework: 'next', risk_profile: 'standard' },
  scan: { changed_files_only: false, generate_report: false },
  block: ['exposed_env'],
  warn: ['missing_error_handling'],
  ignore: { paths: [] },
  report: { output: '.shipguard/reports/latest.md', format: 'markdown' },
}

function makeFile(relativePath: string, content: string): FileInfo {
  return { path: `/project/${relativePath}`, relativePath, content }
}

// ─── next.config.js ───────────────────────────────────────────────────────────

describe('deployment check — next.config.js', () => {
  it('flags CORS wildcard Access-Control-Allow-Origin: *  (high)', () => {
    const file = makeFile(
      'next.config.js',
      `
/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
        ],
      },
    ]
  },
}
module.exports = nextConfig
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const corsFindings = findings.filter((f) => f.id === 'deployment_cors_wildcard')
    expect(corsFindings.length).toBeGreaterThan(0)
    expect(corsFindings[0].severity).toBe('high')
    expect(corsFindings[0].blocking).toBe(true)
  })

  it('does NOT flag CORS when origin is an explicit domain', () => {
    const file = makeFile(
      'next.config.js',
      `
const nextConfig = {
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: 'https://myapp.com' },
        ],
      },
    ]
  },
}
module.exports = nextConfig
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const corsFindings = findings.filter((f) => f.id === 'deployment_cors_wildcard')
    expect(corsFindings.length).toBe(0)
  })

  it('flags productionBrowserSourceMaps: true  (medium)', () => {
    const file = makeFile(
      'next.config.js',
      `
const nextConfig = {
  productionBrowserSourceMaps: true,
}
module.exports = nextConfig
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const smFindings = findings.filter((f) => f.id === 'deployment_source_maps_exposed')
    expect(smFindings.length).toBe(1)
    expect(smFindings[0].severity).toBe('medium')
  })

  it('does NOT flag productionBrowserSourceMaps when absent or false', () => {
    const file = makeFile(
      'next.config.js',
      `
const nextConfig = {
  productionBrowserSourceMaps: false,
}
module.exports = nextConfig
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const smFindings = findings.filter((f) => f.id === 'deployment_source_maps_exposed')
    expect(smFindings.length).toBe(0)
  })

  it('flags missing X-Frame-Options when headers() is defined but header is absent', () => {
    const file = makeFile(
      'next.config.js',
      `
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ]
  },
}
module.exports = nextConfig
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const frameFindings = findings.filter((f) => f.id === 'deployment_missing_x_frame_options')
    expect(frameFindings.length).toBe(1)
    expect(frameFindings[0].severity).toBe('medium')
  })

  it('does NOT flag security headers when both X-Frame-Options and X-Content-Type-Options present', () => {
    const file = makeFile(
      'next.config.mjs',
      `
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
        ],
      },
    ]
  },
}
export default nextConfig
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const headerFindings = findings.filter(
      (f) =>
        f.id === 'deployment_missing_x_frame_options' ||
        f.id === 'deployment_missing_x_content_type',
    )
    expect(headerFindings.length).toBe(0)
  })
})

// ─── Dockerfile ───────────────────────────────────────────────────────────────

describe('deployment check — Dockerfile', () => {
  it('flags Dockerfile without any USER directive  (medium)', () => {
    const file = makeFile(
      'Dockerfile',
      `
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["node", "server.js"]
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const rootFindings = findings.filter((f) => f.id === 'deployment_docker_root_user')
    expect(rootFindings.length).toBe(1)
    expect(rootFindings[0].severity).toBe('medium')
  })

  it('does NOT flag Dockerfile when USER node is present', () => {
    const file = makeFile(
      'Dockerfile',
      `
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
USER node
EXPOSE 3000
CMD ["node", "server.js"]
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const rootFindings = findings.filter((f) => f.id === 'deployment_docker_root_user')
    expect(rootFindings.length).toBe(0)
  })

  it('flags Dockerfile with USER root (still no non-root user)', () => {
    const file = makeFile(
      'Dockerfile',
      `
FROM node:18-alpine
USER root
WORKDIR /app
CMD ["node", "server.js"]
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const rootFindings = findings.filter((f) => f.id === 'deployment_docker_root_user')
    expect(rootFindings.length).toBe(1)
  })

  it('flags Dockerfile using :latest base image  (medium)', () => {
    const file = makeFile(
      'Dockerfile',
      `
FROM node:latest
WORKDIR /app
USER node
CMD ["node", "server.js"]
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const pinFindings = findings.filter((f) => f.id === 'deployment_docker_unpinned_image')
    expect(pinFindings.length).toBe(1)
    expect(pinFindings[0].severity).toBe('medium')
  })

  it('flags Dockerfile using image with no tag (implicit latest)', () => {
    const file = makeFile(
      'Dockerfile',
      `
FROM node
WORKDIR /app
USER node
CMD ["node", "server.js"]
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const pinFindings = findings.filter((f) => f.id === 'deployment_docker_unpinned_image')
    expect(pinFindings.length).toBe(1)
  })

  it('does NOT flag Dockerfile with pinned image version', () => {
    const file = makeFile(
      'Dockerfile',
      `
FROM node:18.20.4-alpine3.19
WORKDIR /app
USER node
CMD ["node", "server.js"]
`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const pinFindings = findings.filter((f) => f.id === 'deployment_docker_unpinned_image')
    expect(pinFindings.length).toBe(0)
  })
})

// ─── .env / .env.example ──────────────────────────────────────────────────────

describe('deployment check — .env files', () => {
  it('flags missing .env.example when .env exists  (low)', () => {
    const envFile = makeFile(
      '.env',
      `
DATABASE_URL=postgres://localhost/mydb
JWT_SECRET=supersecret
`,
    )
    const findings = deploymentCheck.run([envFile], defaultPolicy)
    const exFindings = findings.filter((f) => f.id === 'deployment_missing_env_example')
    expect(exFindings.length).toBe(1)
    expect(exFindings[0].severity).toBe('low')
  })

  it('does NOT flag when both .env and .env.example exist with matching keys', () => {
    const envFile = makeFile(
      '.env',
      `
DATABASE_URL=postgres://localhost/mydb
JWT_SECRET=supersecret
`,
    )
    const exampleFile = makeFile(
      '.env.example',
      `
DATABASE_URL=postgres://localhost/mydb
JWT_SECRET=your-secret-here
`,
    )
    const findings = deploymentCheck.run([envFile, exampleFile], defaultPolicy)
    const exFindings = findings.filter(
      (f) =>
        f.id === 'deployment_missing_env_example' ||
        f.id === 'deployment_env_undocumented_keys',
    )
    expect(exFindings.length).toBe(0)
  })

  it('flags .env keys not present in .env.example  (low)', () => {
    const envFile = makeFile(
      '.env',
      `
DATABASE_URL=postgres://localhost/mydb
JWT_SECRET=supersecret
UNDOCUMENTED_KEY=oops
`,
    )
    const exampleFile = makeFile(
      '.env.example',
      `
DATABASE_URL=your-db-url
JWT_SECRET=your-secret-here
`,
    )
    const findings = deploymentCheck.run([envFile, exampleFile], defaultPolicy)
    const undocFindings = findings.filter((f) => f.id === 'deployment_env_undocumented_keys')
    expect(undocFindings.length).toBe(1)
    expect(undocFindings[0].evidence).toContain('UNDOCUMENTED_KEY')
  })
})

// ─── package.json ─────────────────────────────────────────────────────────────

describe('deployment check — package.json', () => {
  it('flags DEBUG=true in scripts  (high)', () => {
    const file = makeFile(
      'package.json',
      JSON.stringify({
        name: 'my-app',
        scripts: {
          start: 'DEBUG=true node server.js',
        },
      }),
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const debugFindings = findings.filter((f) => f.id.startsWith('deployment_pkg_debug_true'))
    expect(debugFindings.length).toBeGreaterThan(0)
    expect(debugFindings[0].severity).toBe('high')
    expect(debugFindings[0].blocking).toBe(true)
  })

  it('flags NODE_ENV=development in scripts  (high)', () => {
    const file = makeFile(
      'package.json',
      JSON.stringify({
        name: 'my-app',
        scripts: {
          start: 'NODE_ENV=development node server.js',
        },
      }),
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const devFindings = findings.filter((f) => f.id.startsWith('deployment_pkg_node_env_dev'))
    expect(devFindings.length).toBeGreaterThan(0)
    expect(devFindings[0].severity).toBe('high')
    expect(devFindings[0].blocking).toBe(true)
  })

  it('does NOT flag clean package.json with no debug/dev env', () => {
    const file = makeFile(
      'package.json',
      JSON.stringify({
        name: 'my-app',
        scripts: {
          build: 'next build',
          start: 'next start',
        },
      }),
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const pkgFindings = findings.filter((f) => f.category === 'deployment' && f.file === 'package.json')
    expect(pkgFindings.length).toBe(0)
  })

  // ---------------------------------------------------------------------------
  // FAIL-BEFORE/PASS-AFTER regression (loud-errors fix, folded into
  // 
  // a malformed package.json used to be swallowed with a bare `catch { return
  // findings }` — NODE_ENV=development / DEBUG=true script checks silently
  // produced zero findings, with no warning distinguishing "clean" from
  // "couldn't check." every catch block must log.
  // ---------------------------------------------------------------------------
  it('FAIL-BEFORE regression: malformed package.json logs a warning to stderr ' +
     '(not a silent skip)', () => {
    const warnSpy = vi.spyOn(logger, 'warn').mockImplementation(() => {})
    const file = makeFile('package.json', '{not valid json')
    deploymentCheck.run([file], defaultPolicy)
    expect(warnSpy).toHaveBeenCalledWith(expect.stringMatching(/package\.json.*JSON|JSON.*package\.json/i))
    warnSpy.mockRestore()
  })

  it('FAIL-BEFORE regression: malformed package.json produces a visible, ' +
     'non-blocking informational finding — NOT indistinguishable from "no ' +
     'dangerous scripts found"', () => {
    const file = makeFile('package.json', '{not valid json')
    const findings = deploymentCheck.run([file], defaultPolicy)
    const parseFailureFinding = findings.find((f) => f.id === 'pkg-json-unparseable-deployment')
    expect(parseFailureFinding).toBeDefined()
    expect(parseFailureFinding?.blocking).toBe(false)
    expect(parseFailureFinding?.severity).toBe('info')
  })
})

// ─── checkGeneralConfigs — non-standard config filenames ─────────────────────

describe('deployment check — checkGeneralConfigs (dead-code fix)', () => {
  it('flags origin: * in a non-standard config file (e.g. config/server.config.js)', () => {
    const file = makeFile(
      'config/server.config.js',
      `module.exports = { origin: '*', port: 3000 }`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const corsFindings = findings.filter((f) => f.id === 'deployment_config_cors_wildcard_origin')
    expect(corsFindings.length).toBe(1)
    expect(corsFindings[0].severity).toBe('high')
    expect(corsFindings[0].blocking).toBe(true)
  })

  it('flags debug: true in a non-standard config file (e.g. config/server.config.js)', () => {
    const file = makeFile(
      'config/server.config.js',
      `module.exports = { debug: true, port: 3000 }`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const debugFindings = findings.filter((f) => f.id === 'deployment_config_debug_mode')
    expect(debugFindings.length).toBe(1)
    expect(debugFindings[0].severity).toBe('high')
    expect(debugFindings[0].blocking).toBe(true)
  })

  it('does NOT double-report for package.json already handled by checkPackageJson', () => {
    const file = makeFile(
      'package.json',
      JSON.stringify({
        name: 'my-app',
        scripts: { start: 'DEBUG=true node server.js' },
      }),
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    // checkPackageJson uses deployment_pkg_debug_true_* IDs (script-level);
    // checkGeneralConfigs would use deployment_config_debug_mode (key:value style).
    // package.json is handled by the specific branch (continue), so checkGeneralConfigs
    // is never called for it — no duplication.
    const generalDebugFindings = findings.filter((f) => f.id === 'deployment_config_debug_mode')
    expect(generalDebugFindings.length).toBe(0)
  })

  it('does NOT double-report for next.config.js already handled by checkNextConfig', () => {
    const file = makeFile(
      'next.config.js',
      `module.exports = { async headers() { return [] }, origin: '*' }`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    // next.config.js goes through checkNextConfig + continue, so checkGeneralConfigs
    // is NOT called for it — no duplicate origin: * finding under config_ id.
    const generalCorsFindings = findings.filter((f) => f.id === 'deployment_config_cors_wildcard_origin')
    expect(generalCorsFindings.length).toBe(0)
  })

  it('does NOT double-report for Dockerfile already handled by checkDockerfile', () => {
    const file = makeFile(
      'Dockerfile',
      `FROM node:18-alpine\nWORKDIR /app\nCMD ["node","server.js"]`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    // Dockerfile is handled by the specific branch (continue) — checkGeneralConfigs not called.
    const generalFindings = findings.filter((f) => f.id === 'deployment_config_debug_mode' || f.id === 'deployment_config_cors_wildcard_origin')
    expect(generalFindings.length).toBe(0)
  })

  it('returns zero findings for a clean non-standard config file', () => {
    const file = makeFile(
      'config/app.config.js',
      `module.exports = { port: 3000, logLevel: 'info', debug: false }`,
    )
    const findings = deploymentCheck.run([file], defaultPolicy)
    const generalFindings = findings.filter((f) => f.id === 'deployment_config_debug_mode' || f.id === 'deployment_config_cors_wildcard_origin')
    expect(generalFindings.length).toBe(0)
  })
})

// ─── Properly configured project (no findings) ───────────────────────────────

describe('deployment check — properly configured project', () => {
  it('returns zero findings for a clean, well-configured project', () => {
    const files: FileInfo[] = [
      makeFile(
        'next.config.mjs',
        `
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ]
  },
}
export default nextConfig
`,
      ),
      makeFile(
        'Dockerfile',
        `
FROM node:18.20.4-alpine3.19
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
USER node
EXPOSE 3000
CMD ["node", "server.js"]
`,
      ),
      makeFile(
        '.env',
        `
DATABASE_URL=postgres://localhost/mydb
JWT_SECRET=supersecret
`,
      ),
      makeFile(
        '.env.example',
        `
DATABASE_URL=your-db-url
JWT_SECRET=your-secret-here
`,
      ),
      makeFile(
        'package.json',
        JSON.stringify({
          name: 'my-app',
          scripts: {
            build: 'next build',
            start: 'next start',
            dev: 'next dev',
          },
        }),
      ),
    ]

    const findings = deploymentCheck.run(files, defaultPolicy)
    expect(findings.length).toBe(0)
  })
})

// ─── JSON-family general CORS check: prose vs real config ─────────────────────
// Regression (2026-09-30): ShipGuard's own shipped rules/free-bundle.json carries the
// sentence "(Access-Control-Allow-Origin: *)" inside a JSON string value; the unquoted
// legacy pattern matched it, so scanning the published package raised a BLOCKING finding.

describe('deployment check — generic CORS wildcard in JSON files', () => {
  const corsIds = (f: FileInfo) =>
    deploymentCheck.run([f], defaultPolicy).filter((x) => x.id === 'deployment_config_cors_wildcard_origin')

  it('does NOT flag prose that mentions the header inside a JSON string value', () => {
    const file = makeFile(
      'rules/bundle.json',
      `{"explanation": "A wildcard CORS origin (Access-Control-Allow-Origin: *) was detected."}`,
    )
    expect(corsIds(file)).toHaveLength(0)
  })

  it('flags an UNQUOTED-key JSON5 wildcard (value is quoted) - keys may be bare in JSON5', () => {
    expect(corsIds(makeFile('config/cors.json5', `{ origin: '*' }`))).toHaveLength(1)
    expect(corsIds(makeFile('config/headers.json5', `{ headers: { 'Access-Control-Allow-Origin': '*' } }`))).toHaveLength(1)
  })

  it('still flags a real quoted origin wildcard in a JSON config', () => {
    expect(corsIds(makeFile('config/server.json', `{"cors": {"origin": "*"}}`))).toHaveLength(1)
  })

  it('still flags a real quoted Access-Control-Allow-Origin header in a JSON config', () => {
    expect(corsIds(makeFile('config/headers.json', `{"Access-Control-Allow-Origin": "*"}`))).toHaveLength(1)
  })

  it('non-JSON config files keep the original (unquoted) behaviour', () => {
    expect(corsIds(makeFile('config/server.yaml', `origin: *\n`))).toHaveLength(1)
  })
})

// ─── legacy CORS findings carry the line where a MULTI-LINE match starts ───────
// A pretty-printed header entry spans lines. findLine() tests one line at a time and returned
// undefined for it; a line-less finding can never be de-duplicated against the governed corpus
// finding for the same issue, so once generic.cors.wildcard-origin learned that shape the same
// defect was reported twice (one blocking legacy finding with no line + one corpus finding).
describe('deployment check — CORS findings on multi-line matches keep a line number', () => {
  it('next.config.js: key and value on separate lines -> line of the header name', () => {
    const file = makeFile(
      'next.config.js',
      [
        'module.exports = {',
        '  async headers() {',
        '    return [{',
        '      source: "/api/:path*",',
        "      headers: [{ key: 'Access-Control-Allow-Origin',",
        "        value: '*' }],",
        '    }]',
        '  },',
        '}',
        '',
      ].join('\n'),
    )
    const found = deploymentCheck.run([file], defaultPolicy).filter((f) => f.id === 'deployment_cors_wildcard')
    expect(found).toHaveLength(1)
    expect(found[0].line).toBe(5)
    expect(found[0].blocking).toBe(true)
  })

  it('generic JSON config: header name and "*" on separate lines -> line of the header name', () => {
    const file = makeFile('config/server.json', '{\n  "Access-Control-Allow-Origin":\n    "*"\n}\n')
    const found = deploymentCheck
      .run([file], defaultPolicy)
      .filter((f) => f.id === 'deployment_config_cors_wildcard_origin')
    expect(found).toHaveLength(1)
    expect(found[0].line).toBe(2)
    expect(found[0].blocking).toBe(true)
  })

  it('single-line matches are unchanged (line 1 stays line 1)', () => {
    const file = makeFile('config/server.json', '{"Access-Control-Allow-Origin": "*"}\n')
    const found = deploymentCheck
      .run([file], defaultPolicy)
      .filter((f) => f.id === 'deployment_config_cors_wildcard_origin')
    expect(found).toHaveLength(1)
    expect(found[0].line).toBe(1)
  })
})
