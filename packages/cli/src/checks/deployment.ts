// Free-tier checks — governance + tiering basis: /rules.md. Source of truth is migrating to the Convex rule registry.
// Phase D.4: all content-scanning RegExp migrated to re2js via compileDetectorRegex().
import type { CheckModule, FileInfo, Finding, Policy } from '@agenticcli/shared'
import { basename, extname } from 'node:path'
import { compileDetectorRegex, type CompiledDetectorRegex } from '../core/re2-detector-engine.js'
import { logger } from '../utils/logger.js'

// ---------------------------------------------------------------------------
// Pre-compiled patterns (re2js, ReDoS-immune)
// ---------------------------------------------------------------------------
// checkNextConfig ─ CORS wildcard
const RE_CORS_NEXT_VALUE = compileDetectorRegex(
  `Access-Control-Allow-Origin['"]\\s*,\\s*value\\s*:\\s*['"]?\\s*\\*\\s*['"]?`,
  'i',
)
const RE_CORS_NEXT_HEADER = compileDetectorRegex(
  `Access-Control-Allow-Origin['"]?\\s*:\\s*['"]\\s*\\*\\s*['"]`,
  'i',
)

// checkNextConfig ─ source maps
const RE_SOURCE_MAPS = compileDetectorRegex(
  'productionBrowserSourceMaps\\s*:\\s*true',
)

// checkNextConfig ─ security headers presence checks
const RE_HEADERS_FN_PARENS = compileDetectorRegex('headers\\s*\\(\\s*\\)')
const RE_HEADERS_FN_ASYNC  = compileDetectorRegex('async\\s+headers')
const RE_X_FRAME_OPTIONS   = compileDetectorRegex('X-Frame-Options', 'i')
const RE_X_CONTENT_TYPE    = compileDetectorRegex('X-Content-Type-Options', 'i')

// checkDockerfile ─ USER directive filter and root guard (per-line)
const RE_DOCKER_USER_LINE  = compileDetectorRegex('^\\s*USER\\s+', 'i')
const RE_DOCKER_ROOT_USER  = compileDetectorRegex('^USER\\s+(root|0)\\s*$', 'i')

// checkDockerfile ─ FROM line filter, stage-alias strip, image parse
const RE_DOCKER_FROM_LINE  = compileDetectorRegex('^\\s*FROM\\s+', 'i')
const RE_DOCKER_AS_ALIAS   = compileDetectorRegex('\\s+AS\\s+\\w+', 'i')
const RE_DOCKER_FROM_IMAGE = compileDetectorRegex(
  '^FROM\\s+(?:--platform=\\S+\\s+)?(\\S+)',
  'i',
)

// checkDockerCompose ─ image line filter and image parse
const RE_COMPOSE_IMAGE_LINE = compileDetectorRegex('^\\s+image:\\s+\\S+')
const RE_COMPOSE_IMAGE_NAME = compileDetectorRegex('image:\\s+(\\S+)')

// checkVercelConfig ─ broad rewrite source and headers presence
const RE_VERCEL_BROAD_REWRITE = compileDetectorRegex(
  `["']source["']\\s*:\\s*["']/?\\*\\*?/?["']`,
)
const RE_VERCEL_HEADERS = compileDetectorRegex('"headers"\\s*:')

// checkNetlifyConfig ─ headers block presence
const RE_NETLIFY_HEADERS = compileDetectorRegex('\\[headers\\]')

// checkPackageJson ─ script value checks
const RE_PKG_NODE_ENV_DEV = compileDetectorRegex('NODE_ENV=development', 'i')
const RE_PKG_DEBUG_TRUE   = compileDetectorRegex('DEBUG\\s*=\\s*true', 'i')
const RE_PKG_DEBUG_STAR   = compileDetectorRegex('DEBUG\\s*=\\s*\\*', 'i')

// checkGeneralConfigs ─ generic CORS and debug checks
const RE_CONFIG_CORS_WILDCARD = compileDetectorRegex(
  `["']?origin["']?\\s*:\\s*["']?\\*["']?`,
  'i',
)
// JSON-family files (.json/.jsonc/.json5): the VALUE must be quoted ("*" / '*'). Real JSON and
// JSON5 configs always quote a string value, while the key may be bare in JSON5
// (`{ origin: '*' }`), so we anchor on the value, not the key. The lenient form above also
// matches PROSE inside a JSON string ("... (Access-Control-Allow-Origin: *) ..."), which made
// ShipGuard's own shipped rules/free-bundle.json block a scan of its own package.
const RE_CONFIG_CORS_WILDCARD_JSON = compileDetectorRegex(
  `["']?origin["']?\\s*:\\s*["']\\*["']`,
  'i',
)
const JSON_FAMILY_EXTENSIONS: ReadonlySet<string> = new Set(['.json', '.jsonc', '.json5'])
const RE_CONFIG_DEBUG_MODE = compileDetectorRegex(
  `["']?debug["']?\\s*:\\s*true`,
  'i',
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeId(suffix: string): string {
  return `deployment_${suffix}`
}

function isFile(file: FileInfo, names: string[]): boolean {
  const base = basename(file.relativePath)
  return names.includes(base)
}

/**
 * Find the 1-based line number of the FIRST line matching the given compiled
 * re2js pattern. Returns undefined if no line matches.
 */
function findLine(content: string, pattern: CompiledDetectorRegex): number | undefined {
  const lines = content.split('\n')
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return i + 1
  }
  return undefined
}

/**
 * Find the 1-based line number where the FIRST match of `pattern` STARTS, even when the
 * match spans several lines.
 *
 * findLine() above tests one line at a time, so it returns undefined for a match that
 * crosses a newline - e.g. a pretty-printed `"Access-Control-Allow-Origin":\n  "*"` or a
 * `{ key: 'Access-Control-Allow-Origin',\n value: '*' }` headers entry. A finding with no
 * line can never be de-duplicated against the governed corpus finding for the same issue
 * (dedupeLegacyAgainstCorpus keys on file+line and never drops a line-less legacy finding),
 * so the same defect was reported twice as soon as the corpus rule learned to see that shape.
 * Used only by the CORS checks, which is where the corpus rule overlaps.
 */
function findMatchStartLine(content: string, pattern: CompiledDetectorRegex): number | undefined {
  const m = pattern.exec(content)
  if (!m) return undefined
  let line = 1
  for (let i = 0; i < m.index; i++) {
    if (content.charCodeAt(i) === 10) line++
  }
  return line
}

/**
 * Find the 1-based line number of the FIRST line that CONTAINS the given literal
 * string (no regex). Used in place of `new RegExp(escaped_literal)` patterns so
 * that no native RegExp is needed for the escaped-literal findLine call.
 * Equivalent to: findLine(content, new RegExp(str.replace(/special-chars/, '\\$&')))
 */
function findLineStr(content: string, literal: string): number | undefined {
  const lines = content.split('\n')
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(literal)) return i + 1
  }
  return undefined
}

// ---------------------------------------------------------------------------
// Per-file checkers
// ---------------------------------------------------------------------------

function checkNextConfig(file: FileInfo): Finding[] {
  const findings: Finding[] = []
  const { content, relativePath } = file

  // CORS wildcard in headers() config or custom server.
  // Two patterns:
  //  1. Next.js headers() object form: { key: 'Access-Control-Allow-Origin', value: '*' }
  //  2. Direct assignment/HTTP form:   'Access-Control-Allow-Origin': '*'
  if (RE_CORS_NEXT_VALUE.test(content) || RE_CORS_NEXT_HEADER.test(content)) {
    const matchedPattern = RE_CORS_NEXT_VALUE.test(content) ? RE_CORS_NEXT_VALUE : RE_CORS_NEXT_HEADER
    const line = findMatchStartLine(content, matchedPattern)
    findings.push({
      id: makeId('cors_wildcard'),
      title: 'Permissive CORS: Access-Control-Allow-Origin set to wildcard (*)',
      severity: 'high',
      category: 'deployment',
      file: relativePath,
      line,
      evidence: 'Access-Control-Allow-Origin: *',
      confidence: 'HIGH',
      explanation:
        'A wildcard CORS policy allows any origin to read responses from your API. Combined with credentials, this can expose user data to malicious sites.',
      recommendation:
        'Replace the wildcard with an explicit list of trusted origins in the headers() configuration.',
      blocking: true,
    })
  }

  // Exposed production source maps
  if (RE_SOURCE_MAPS.test(content)) {
    const line = findLine(content, RE_SOURCE_MAPS)
    findings.push({
      id: makeId('source_maps_exposed'),
      title: 'Production source maps are enabled (productionBrowserSourceMaps: true)',
      severity: 'medium',
      category: 'deployment',
      file: relativePath,
      line,
      evidence: 'productionBrowserSourceMaps: true',
      confidence: 'HIGH',
      explanation:
        'Enabling production source maps exposes your original application source code to anyone inspecting browser devtools, aiding reverse engineering and vulnerability discovery.',
      recommendation:
        'Remove productionBrowserSourceMaps: true or set it to false for production builds.',
      blocking: false,
    })
  }

  // Missing security headers — look for absence of X-Frame-Options in headers config
  // Heuristic: if headers() is defined but X-Frame-Options is missing
  const hasHeadersFunction = RE_HEADERS_FN_PARENS.test(content) || RE_HEADERS_FN_ASYNC.test(content)
  const hasXFrameOptions = RE_X_FRAME_OPTIONS.test(content)
  const hasXContentType = RE_X_CONTENT_TYPE.test(content)

  if (hasHeadersFunction && !hasXFrameOptions) {
    findings.push({
      id: makeId('missing_x_frame_options'),
      title: 'Missing security header: X-Frame-Options not configured',
      severity: 'medium',
      category: 'deployment',
      file: relativePath,
      confidence: 'MEDIUM',
      explanation:
        'X-Frame-Options prevents your site from being embedded in an iframe, protecting users against clickjacking attacks.',
      recommendation:
        "Add { key: 'X-Frame-Options', value: 'DENY' } to your headers() configuration in next.config.js.",
      blocking: false,
    })
  }

  if (hasHeadersFunction && !hasXContentType) {
    findings.push({
      id: makeId('missing_x_content_type'),
      title: 'Missing security header: X-Content-Type-Options not configured',
      severity: 'medium',
      category: 'deployment',
      file: relativePath,
      confidence: 'MEDIUM',
      explanation:
        'X-Content-Type-Options: nosniff prevents MIME-type sniffing attacks where browsers execute content as a different type than declared.',
      recommendation:
        "Add { key: 'X-Content-Type-Options', value: 'nosniff' } to your headers() configuration.",
      blocking: false,
    })
  }

  return findings
}

function checkDockerfile(file: FileInfo): Finding[] {
  const findings: Finding[] = []
  const { content, relativePath } = file

  // Running as root — no USER directive (or only USER root)
  const userDirectives = content
    .split('\n')
    .filter((line) => RE_DOCKER_USER_LINE.test(line))
    .map((line) => line.trim())

  const hasNonRootUser = userDirectives.some(
    (line) => !RE_DOCKER_ROOT_USER.test(line),
  )

  if (!hasNonRootUser) {
    findings.push({
      id: makeId('docker_root_user'),
      title: 'Dockerfile runs container as root (no non-root USER directive)',
      severity: 'medium',
      category: 'deployment',
      file: relativePath,
      confidence: 'MEDIUM',
      explanation:
        'Running containers as root amplifies the blast radius of a container escape. A non-root user limits what an attacker can do if they gain code execution inside the container.',
      recommendation:
        'Add a USER directive with a non-root user (e.g., USER node or create a dedicated user with addgroup/adduser).',
      blocking: false,
    })
  }

  // Using latest tag or no tag (defaults to latest)
  // FROM image or FROM image:latest — but not FROM scratch or FROM --platform=...
  const fromLines = content.split('\n').filter((line) => RE_DOCKER_FROM_LINE.test(line))
  for (const line of fromLines) {
    // Skip scratch (no concept of versioning) and build-stage aliases like: FROM node:18 AS builder
    const stripped = RE_DOCKER_AS_ALIAS.replaceFirst(line, '').trim()
    const match = RE_DOCKER_FROM_IMAGE.exec(stripped)
    if (!match) continue
    const image = match.groups[0] ?? ''  // group 1 = the image name
    if (image.toLowerCase() === 'scratch') continue
    // Check for :latest or no tag at all (no colon means implicit latest)
    const hasTag = image.includes(':')
    const isLatest = image.toLowerCase().endsWith(':latest')
    if (!hasTag || isLatest) {
      const lineNum = findLineStr(content, line.trim())
      findings.push({
        id: makeId('docker_unpinned_image'),
        title: `Dockerfile uses unpinned base image: ${image}`,
        severity: 'medium',
        category: 'deployment',
        file: relativePath,
        line: lineNum,
        evidence: line.trim(),
        confidence: 'HIGH',
        explanation:
          'Using :latest or no tag means the base image can change silently between builds, introducing unreviewed dependency updates or security regressions.',
        recommendation:
          `Pin the image to a specific digest or version tag (e.g., ${image.split(':')[0]}:20-alpine or with a SHA digest).`,
        blocking: false,
      })
    }
  }

  return findings
}

function checkDockerCompose(file: FileInfo): Finding[] {
  const findings: Finding[] = []
  const { content, relativePath } = file

  // Check for image: someimage:latest or image: someimage (no tag)
  const imageLines = content.split('\n').filter((line) => RE_COMPOSE_IMAGE_LINE.test(line))
  for (const line of imageLines) {
    const match = RE_COMPOSE_IMAGE_NAME.exec(line)
    if (!match) continue
    const image = match.groups[0] ?? ''  // group 1 = image name
    const hasTag = image.includes(':')
    const isLatest = image.toLowerCase().endsWith(':latest')
    if (!hasTag || isLatest) {
      findings.push({
        id: makeId('compose_unpinned_image'),
        title: `docker-compose uses unpinned image: ${image}`,
        severity: 'medium',
        category: 'deployment',
        file: relativePath,
        evidence: line.trim(),
        confidence: 'HIGH',
        explanation:
          'Unpinned images in docker-compose can silently pull breaking or vulnerable upstream changes.',
        recommendation: `Pin to a specific version tag or SHA digest for ${image.split(':')[0]}.`,
        blocking: false,
      })
    }
  }

  return findings
}

function checkVercelConfig(file: FileInfo): Finding[] {
  const findings: Finding[] = []
  const { content, relativePath } = file

  // Broad wildcard rewrites / redirects (source: /**/*, destination: /...)
  // or permissive source patterns
  if (RE_VERCEL_BROAD_REWRITE.test(content)) {
    const line = findLine(content, RE_VERCEL_BROAD_REWRITE)
    findings.push({
      id: makeId('vercel_broad_rewrite'),
      title: 'vercel.json has overly broad rewrite/redirect rule (wildcard source)',
      severity: 'medium',
      category: 'deployment',
      file: relativePath,
      line,
      confidence: 'MEDIUM',
      explanation:
        'Catch-all rewrite rules can accidentally expose internal routes or proxy unintended paths, creating an open redirect or SSRF surface.',
      recommendation:
        'Narrow the source pattern to only the specific paths that need rewriting.',
      blocking: false,
    })
  }

  // Missing headers configuration in vercel.json
  const hasHeaders = RE_VERCEL_HEADERS.test(content)
  if (!hasHeaders) {
    findings.push({
      id: makeId('vercel_missing_headers'),
      title: 'vercel.json has no security headers configuration',
      severity: 'medium',
      category: 'deployment',
      file: relativePath,
      confidence: 'MEDIUM',
      explanation:
        'Without explicit headers in vercel.json, responses lack security headers like X-Frame-Options, X-Content-Type-Options, and CSP, leaving users exposed to clickjacking and XSS.',
      recommendation:
        'Add a "headers" block to vercel.json or configure security headers in next.config.js instead.',
      blocking: false,
    })
  }

  return findings
}

function checkNetlifyConfig(file: FileInfo): Finding[] {
  const findings: Finding[] = []
  const { content, relativePath } = file

  // Missing [headers] block in netlify.toml
  const hasHeaders = RE_NETLIFY_HEADERS.test(content)
  if (!hasHeaders) {
    findings.push({
      id: makeId('netlify_missing_headers'),
      title: 'netlify.toml has no [[headers]] security configuration',
      severity: 'medium',
      category: 'deployment',
      file: relativePath,
      confidence: 'MEDIUM',
      explanation:
        'Without a [[headers]] block, Netlify deployments lack security headers, exposing the app to clickjacking and content-type sniffing attacks.',
      recommendation:
        'Add a [[headers]] section to netlify.toml with X-Frame-Options, X-Content-Type-Options, and other security headers.',
      blocking: false,
    })
  }

  return findings
}

function checkEnvFiles(files: FileInfo[]): Finding[] {
  const findings: Finding[] = []

  const envFile = files.find((f) => basename(f.relativePath) === '.env')
  const envExampleFile = files.find(
    (f) =>
      basename(f.relativePath) === '.env.example' ||
      basename(f.relativePath) === '.env.sample',
  )

  // .env exists but .env.example is missing
  if (envFile && !envExampleFile) {
    findings.push({
      id: makeId('missing_env_example'),
      title: '.env file exists but .env.example is missing',
      severity: 'low',
      category: 'deployment',
      file: envFile.relativePath,
      confidence: 'HIGH',
      explanation:
        'Without a .env.example, new contributors have no template for required environment variables, increasing the risk of misconfigured deployments.',
      recommendation:
        'Create a .env.example file with all required variable keys (and safe placeholder values) so the team can onboard without guessing configuration.',
      blocking: false,
    })
    return findings
  }

  // .env has keys that .env.example doesn't list
  if (envFile && envExampleFile) {
    const parseKeys = (content: string): Set<string> => {
      const keys = new Set<string>()
      for (const line of content.split('\n')) {
        const trimmed = line.trim()
        if (!trimmed || trimmed.startsWith('#')) continue
        const eqIdx = trimmed.indexOf('=')
        if (eqIdx > 0) {
          keys.add(trimmed.slice(0, eqIdx).trim())
        }
      }
      return keys
    }

    const envKeys = parseKeys(envFile.content)
    const exampleKeys = parseKeys(envExampleFile.content)

    const undocumentedKeys = [...envKeys].filter((k) => !exampleKeys.has(k))
    if (undocumentedKeys.length > 0) {
      findings.push({
        id: makeId('env_undocumented_keys'),
        title: `.env has keys not present in .env.example: ${undocumentedKeys.join(', ')}`,
        severity: 'low',
        category: 'deployment',
        file: envFile.relativePath,
        evidence: undocumentedKeys.join(', '),
        confidence: 'HIGH',
        explanation:
          'Keys present in .env but missing from .env.example leave teammates and deployment pipelines without the full required configuration, causing runtime failures.',
        recommendation:
          `Add the following keys to .env.example: ${undocumentedKeys.join(', ')}`,
        blocking: false,
      })
    }
  }

  return findings
}

function checkPackageJson(file: FileInfo): Finding[] {
  const findings: Finding[] = []
  const { content, relativePath } = file

  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(content) as Record<string, unknown>
  } catch (err: unknown) {
    // Root cause: a
    // malformed package.json silently disabled the NODE_ENV=development /
    // DEBUG=true build-script detections here with zero warning. Every
    // catch block must log. See database.ts's identical
    // fix (same review finding) for the full rationale on why a Finding is
    // used as the visibility channel (check modules are pure Finding[]
    // producers with no other output path back to the scan result).
    const detail = err instanceof Error ? err.message : String(err)
    logger.warn(`[deployment] Could not parse ${relativePath} as JSON — NODE_ENV/DEBUG script checks skipped for this file: ${detail}`)
    findings.push({
      id: 'pkg-json-unparseable-deployment',
      title: `Could not parse ${relativePath} — deployment checks skipped for this file`,
      severity: 'info',
      category: 'deployment',
      file: relativePath,
      evidence: detail.slice(0, 200),
      confidence: 'HIGH',
      explanation:
        'package.json is not valid JSON, so the NODE_ENV=development / DEBUG=true script checks could not run against this file.',
      recommendation: 'Fix the JSON syntax error in package.json so ShipGuard can scan its scripts.',
      blocking: false,
    })
    return findings
  }

  const scripts = parsed['scripts']
  if (!scripts || typeof scripts !== 'object') return findings

  const scriptEntries = Object.entries(scripts as Record<string, unknown>)

  for (const [name, value] of scriptEntries) {
    if (typeof value !== 'string') continue

    // NODE_ENV=development in start/build scripts
    if (RE_PKG_NODE_ENV_DEV.test(value)) {
      findings.push({
        id: makeId(`pkg_node_env_dev_${name}`),
        title: `package.json script "${name}" sets NODE_ENV=development`,
        severity: 'high',
        category: 'deployment',
        file: relativePath,
        evidence: `"${name}": "${value}"`,
        confidence: 'HIGH',
        explanation:
          'Running with NODE_ENV=development in production disables performance optimisations and may enable verbose error output, leaking stack traces to end users.',
        recommendation:
          `Remove NODE_ENV=development from the "${name}" script or set NODE_ENV=production explicitly.`,
        blocking: true,
      })
    }

    // DEBUG=true in scripts
    if (RE_PKG_DEBUG_TRUE.test(value) || RE_PKG_DEBUG_STAR.test(value)) {
      findings.push({
        id: makeId(`pkg_debug_true_${name}`),
        title: `package.json script "${name}" enables DEBUG mode`,
        severity: 'high',
        category: 'deployment',
        file: relativePath,
        evidence: `"${name}": "${value}"`,
        confidence: 'HIGH',
        explanation:
          'DEBUG=true or DEBUG=* enables verbose logging in many Node.js libraries, which can leak internal paths, secrets, and request details in production logs.',
        recommendation: `Remove the DEBUG flag from the "${name}" script.`,
        blocking: true,
      })
    }
  }

  return findings
}

function checkGeneralConfigs(file: FileInfo): Finding[] {
  const findings: Finding[] = []
  const { content, relativePath } = file

  // CORS origin: '*' in any config file (e.g. express cors middleware config). NOTE: this only
  // detects the wildcard string; `origin: true` (reflect any origin) is NOT detected here.
  const corsRe = JSON_FAMILY_EXTENSIONS.has(extname(relativePath).toLowerCase())
    ? RE_CONFIG_CORS_WILDCARD_JSON
    : RE_CONFIG_CORS_WILDCARD
  if (corsRe.test(content)) {
    const line = findMatchStartLine(content, corsRe)
    findings.push({
      id: makeId('config_cors_wildcard_origin'),
      title: `CORS origin wildcard (*) detected in ${relativePath}`,
      severity: 'high',
      category: 'deployment',
      file: relativePath,
      line,
      evidence: 'origin: *',
      confidence: 'MEDIUM',
      explanation:
        'Setting CORS origin to * allows any website to make credentialed requests to your API, bypassing Same-Origin Policy protections.',
      recommendation:
        'Replace the wildcard origin with an explicit allowlist of trusted domains.',
      blocking: true,
    })
  }

  // Debug mode: debug: true  (common in express, winston, etc.)
  if (RE_CONFIG_DEBUG_MODE.test(content)) {
    const line = findLine(content, RE_CONFIG_DEBUG_MODE)
    findings.push({
      id: makeId('config_debug_mode'),
      title: `Debug mode enabled in ${relativePath}`,
      severity: 'high',
      category: 'deployment',
      file: relativePath,
      line,
      evidence: 'debug: true',
      confidence: 'MEDIUM',
      explanation:
        'Debug mode in production configs exposes verbose logs, internal stack traces, and configuration details that aid attackers.',
      recommendation:
        'Set debug: false or remove the debug flag from production configuration.',
      blocking: true,
    })
  }

  return findings
}

/**
 * Extensions `checkGeneralConfigs` is allowed to run over.
 *
 * WHY THIS EXISTS (a false positive we published against ourselves)
 * ================================================================
 * `checkGeneralConfigs` used to run on EVERY file in the project, prose included. The
 * platform repo's four-scanner benchmark recorded the consequence in writing: at
 * `EXPECTED.md:47` a ground-truth documentation file describes the CORS defect in
 * English, its prose contains the literal `origin: '*'`, and the wildcard rule fired on
 * the sentence (content-pipeline/benchmarks/RESULTS.md, "One false positive").
 *
 * Documentation ABOUT a misconfiguration is not a misconfiguration. A README that says
 * "never write origin: '*'" was flagged for saying so, and any security guide, ADR, or
 * changelog in a customer's repo hits the same trap. Narrowing the surface to file types
 * that can actually hold executable configuration removes that whole class without
 * weakening a single pattern — every real config shape these two checks target
 * (`origin: '*'` in a cors() call, `debug: true` in a config object) lives in one of
 * these extensions.
 *
 * Extension-less files (Dockerfile, Procfile, Makefile) are excluded here on purpose:
 * the specific handlers above already own the ones that matter, and the generic
 * JS-object-shaped patterns do not apply to their syntax.
 */
const CONFIG_CANDIDATE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.jsx',
  '.ts', '.mts', '.cts', '.tsx',
  '.json', '.jsonc', '.json5',
  '.yml', '.yaml', '.toml', '.ini', '.conf', '.cfg',
  '.env', '.py', '.rb', '.go', '.php',
])

/** Pure: (relativePath) -> may this file contain executable configuration? */
export function isConfigCandidate(relativePath: string): boolean {
  const base = basename(relativePath)
  // `.env`, `.env.production` — dotfiles whose "extension" is the name itself.
  if (base === '.env' || base.startsWith('.env.')) return true
  const dot = base.lastIndexOf('.')
  if (dot <= 0) return false // no extension, or a dotfile with no further suffix
  return CONFIG_CANDIDATE_EXTENSIONS.has(base.slice(dot).toLowerCase())
}

export const deploymentCheck: CheckModule = {
  id: 'deployment',
  name: 'Deployment & Configuration',

  run(files: FileInfo[], _policy: Policy): Finding[] {
    const findings: Finding[] = []

    for (const file of files) {
      const base = basename(file.relativePath)

      // next.config.js / next.config.mjs / next.config.ts
      if (['next.config.js', 'next.config.mjs', 'next.config.ts'].includes(base)) {
        findings.push(...checkNextConfig(file))
        continue
      }

      // Dockerfile
      if (base === 'Dockerfile' || base.startsWith('Dockerfile.')) {
        findings.push(...checkDockerfile(file))
        continue
      }

      // docker-compose.yml / docker-compose.yaml
      if (base === 'docker-compose.yml' || base === 'docker-compose.yaml') {
        findings.push(...checkDockerCompose(file))
        continue
      }

      // vercel.json
      if (base === 'vercel.json') {
        findings.push(...checkVercelConfig(file))
        continue
      }

      // netlify.toml
      if (base === 'netlify.toml') {
        findings.push(...checkNetlifyConfig(file))
        continue
      }

      // package.json
      if (base === 'package.json') {
        findings.push(...checkPackageJson(file))
        continue
      }

      // Any config-like file not matched by a specific handler above —
      // run generic CORS/debug checks so files like config/server.config.js
      // are not silently skipped (fixes dead-code bug: dead-code fix).
      if (isConfigCandidate(file.relativePath)) {
        findings.push(...checkGeneralConfigs(file))
      }
    }

    // Cross-file checks
    findings.push(...checkEnvFiles(files))

    return findings
  },
}
