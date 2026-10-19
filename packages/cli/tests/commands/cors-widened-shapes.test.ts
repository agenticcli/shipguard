/**
 * Widened wildcard-CORS detection (generic.cors.wildcard-origin v5, 2026-09-30), pinned through
 * the BUILT CLI: every newly-detected shape yields exactly ONE CORS finding, at canon severity,
 * WITHOUT changing the block/warn policy; and every look-alike stays quiet.
 *
 * Policy pinned here on purpose (do not "fix" it in this file): the corpus rule's action is
 * `warn`, and the legacy hand-written checks only ever blocked the shapes they already matched
 * (see cors-single-finding.test.ts). So a shape that ONLY the corpus rule sees is reported HIGH but
 * does not block `--strict` by itself. Making it block is a separate, deliberate policy change.
 *
 * Suppressed findings: an anti-pattern-suppressed finding is still RECORDED (suppressed:true,
 * blocking:false) by design (src/core/suppression.ts), so negatives assert "no ACTIVE finding"
 * and, for shapes that must not match at all, "no finding at all".
 */
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { spawnNode } from '../helpers/spawn-cli.js'

vi.setConfig({ testTimeout: 30_000 })

const distCli = resolve(dirname(fileURLToPath(import.meta.url)), '../../dist/cli.js')
const dirs: string[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

interface CorsFinding {
  id: string
  line?: number
  severity: string
  blocking: boolean
  suppressed?: boolean
}

async function scan(fileName: string, content: string) {
  expect(existsSync(distCli), 'build first').toBe(true)
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-cors5-'))
  dirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"cors-fixture"}', 'utf-8')
  mkdirSync(dirname(join(dir, fileName)), { recursive: true })
  writeFileSync(join(dir, fileName), content, 'utf-8')
  const res = await spawnNode(distCli, ['scan', dir, '--json'], { cwd: dir })
  const json = JSON.parse(res.stdout) as { findings: CorsFinding[] }
  const strict = await spawnNode(distCli, ['scan', dir, '--json', '--strict'], { cwd: dir })
  return {
    cors: json.findings.filter((f) => /cors/i.test(f.id)),
    strictExit: strict.code,
    recommendation: (json as { recommendation?: string }).recommendation,
  }
}

// [label, file name, content, expected 1-based line of the finding]
const NEWLY_DETECTED: Array<[string, string, string, number]> = [
  ['cors() origin: true', 'server.js', 'app.use(cors({ origin: true, credentials: true }))\n', 1],
  ['cors() origin: true, not the first option', 'server.ts', "app.use(cors({ credentials: true, methods: ['GET'], origin: true }))\n", 1],
  ['cors() origin: ["*"]', 'server.js', "app.use(cors({ origin: ['*'] }))\n", 1],
  ['cors option object origin: true', 'server.ts', 'const corsOptions = { origin: true, credentials: true }\napp.use(cors(corsOptions))\n', 1],
  ['socket.io cors object', 'io.ts', 'const io = new Server(srv, { cors: { origin: true } })\n', 1],
  ['NestJS enableCors', 'main.ts', 'app.enableCors({ origin: true })\n', 1],
  ['Fastify register(cors)', 'app.js', 'await fastify.register(cors, { origin: true })\n', 1],
  ['JSON cors config origin: true', 'config/cors.json', '{"cors":{"origin":true,"credentials":true}}\n', 1],
  ['JSON cors config origin: ["*"]', 'config/cors.json', '{"cors":{"origin":["*"]}}\n', 1],
  ['vercel.json headers array (compact)', 'vercel.json', '{"headers":[{"source":"/api/(.*)","headers":[{"key":"Access-Control-Allow-Origin","value":"*"}]}]}\n', 1],
  [
    'vercel.json headers array (pretty, key and value on separate lines)',
    'vercel.json',
    '{\n  "headers": [\n    {\n      "source": "/api/(.*)",\n      "headers": [\n        {\n          "key": "Access-Control-Allow-Origin",\n          "value": "*"\n        }\n      ]\n    }\n  ]\n}\n',
    7,
  ],
  [
    'firebase.json hosting headers',
    'firebase.json',
    '{\n  "hosting": {\n    "headers": [\n      { "source": "/api/**", "headers": [ { "key": "Access-Control-Allow-Origin", "value": "*" } ] }\n    ]\n  }\n}\n',
    4,
  ],
  ['generic headers array, value first', 'config/headers.json', '[{"value":"*","key":"Access-Control-Allow-Origin"}]\n', 1],
  ['generic headers array in a .ts config', 'server.config.ts', "export const headers = [{ key: 'Access-Control-Allow-Origin', value: '*' }]\n", 1],
  ['API Gateway HTTP API AllowOrigins list', 'apigw.json', '{"CorsConfiguration":{"AllowOrigins":["*"],"AllowMethods":["GET"]}}\n', 1],
  ['API Gateway HTTP API AllowOrigins block list', 'template.yaml', 'CorsConfiguration:\n  AllowOrigins:\n    - "*"\n', 2],
  ['SAM Cors.AllowOrigin (json)', 'template.json', '{"Resources":{"Api":{"Properties":{"Cors":{"AllowOrigin":"\'*\'"}}}}}\n', 1],
  ['SAM Cors.AllowOrigin (yaml)', 'template.yaml', "Cors:\n  AllowOrigin: \"'*'\"\n", 2],
  ['API Gateway method response header (json)', 'apigw-method.json', '{"responseParameters":{"method.response.header.Access-Control-Allow-Origin":"\'*\'"}}\n', 1],
]

describe('shapes the corpus rule newly detects: exactly one finding, HIGH, warn-only', () => {
  for (const [label, file, content, line] of NEWLY_DETECTED) {
    it(`${label} (${file})`, async () => {
      const { cors, strictExit } = await scan(file, content)
      expect(cors, JSON.stringify(cors)).toHaveLength(1)
      expect(cors[0].id).toBe('generic.cors.wildcard-origin')
      expect(cors[0].severity).toBe('high')
      expect(cors[0].line).toBe(line)
      expect(cors[0].suppressed ?? false).toBe(false)
      // Policy unchanged: corpus rule action stays warn, and no legacy check ever blocked these shapes.
      expect(cors[0].blocking).toBe(false)
      expect(strictExit).toBe(0)
    })
  }
})

describe('legacy <-> corpus dedup on shapes BOTH detectors now see: one finding, still blocking', () => {
  const cases: Array<[string, string, string, number]> = [
    ['JSON header map, "*" on the next line', 'config/server.json', '{\n  "Access-Control-Allow-Origin":\n    "*"\n}\n', 2],
    ['JSON header map (compact)', 'config/server.json', '{"Access-Control-Allow-Origin": "*"}\n', 1],
    ['JSON5 header map', 'config/headers.json5', "{ headers: { 'Access-Control-Allow-Origin': '*' } }\n", 1],
    [
      'next.config.js key and value on separate lines',
      'next.config.js',
      "module.exports = { async headers() { return [{ source: '/(.*)', headers: [{ key: 'Access-Control-Allow-Origin',\n  value: '*' }] }] } }\n",
      1,
    ],
    ['next.config.js key/value on one line', 'next.config.js', "module.exports = { async headers() { return [{ source: '/(.*)', headers: [{ key: 'Access-Control-Allow-Origin', value: '*' }] }] } }\n", 1],
  ]
  for (const [label, file, content, line] of cases) {
    it(`${label} (${file})`, async () => {
      const { cors, strictExit } = await scan(file, content)
      expect(cors, JSON.stringify(cors)).toHaveLength(1)
      expect(cors[0].id).toBe('generic.cors.wildcard-origin')
      expect(cors[0].severity).toBe('high')
      expect(cors[0].line).toBe(line)
      // The legacy check blocked this shape before; dedup promotes the surviving corpus finding.
      expect(cors[0].blocking).toBe(true)
      expect(strictExit).toBe(1)
    })
  }
})

describe('look-alikes stay quiet (no CORS finding at all)', () => {
  const NO_FINDING: Array<[string, string, string]> = [
    ['origin: false', 'server.ts', 'app.use(cors({ origin: false }))\n'],
    ['explicit origin list', 'server.ts', "app.use(cors({ origin: ['https://app.example.com'] }))\n"],
    ['origin: true that is not a CORS option', 'ui.ts', 'const overlay = createOverlay({ origin: true })\n'],
    ['origin: ["*"] that is not a CORS option', 'ui.ts', "const channel = { origin: ['*'] }\n"],
    ['identifier that merely starts with true', 'server.ts', 'app.use(cors({ origin: trueOrigins }))\n'],
    ['vercel.json with a specific origin', 'vercel.json', '{"headers":[{"source":"/api/(.*)","headers":[{"key":"Access-Control-Allow-Origin","value":"https://app.example.com"}]}]}\n'],
    ['wildcard on a different CORS header', 'vercel.json', '{"headers":[{"source":"/api/(.*)","headers":[{"key":"Access-Control-Allow-Headers","value":"*"}]}]}\n'],
    ['SAM with a specific origin', 'template.yaml', "Cors:\n  AllowOrigin: \"'https://app.example.com'\"\n"],
    ['HTTP API with specific + subdomain origins', 'apigw.json', '{"CorsConfiguration":{"AllowOrigins":["https://app.example.com","https://*.example.com"]}}\n'],
    ['identifier that merely starts with cors (corsair)', 'server.ts', 'const corsairConfig = { retries: 3, origin: true }\n'],
    ['header entry embedded as an escaped string', 'docs/rule.json', '{"note":"{\\"key\\":\\"Access-Control-Allow-Origin\\",\\"value\\":\\"*\\"}"}\n'],
  ]
  for (const [label, file, content] of NO_FINDING) {
    it(`${label} (${file})`, async () => {
      const { cors, strictExit } = await scan(file, content)
      expect(cors, JSON.stringify(cors)).toHaveLength(0)
      expect(strictExit).toBe(0)
    })
  }
})

describe('look-alikes the anti-patterns suppress: recorded but never active and never blocking', () => {
  const SUPPRESSED: Array<[string, string, string]> = [
    ['origin: true on a line marked as a test', 'server.ts', 'app.use(cors({ origin: true })) // test harness only\n'],
    [
      'Firebase Hosting docs example: wildcard on font files',
      'firebase.json',
      '{"hosting":{"headers":[{"source":"**/*.@(eot|otf|ttf|ttc|woff|font.css)","headers":[{"key":"Access-Control-Allow-Origin","value":"*"}]}]}}\n',
    ],
    ['JSON sentence that ends exactly like a config value', 'docs/rule.json', '{"note":"Do not send the header Access-Control-Allow-Origin: *"}\n'],
    ['JSON explanation that quotes the header (the self-scan false positive)', 'docs/rule.json', '{"explanation":"A wildcard CORS origin (Access-Control-Allow-Origin: *) was detected."}\n'],
    ['i18n JSON whose whole value is the header line', 'locale/en.json', '{"cors.example":"Access-Control-Allow-Origin: *"}\n'],
    ['i18n JSON whose whole value is a cors() call', 'locale/en.json', '{"cors.example2":"cors({ origin: true })"}\n'],
    ['JSON string that quotes a cors option', 'docs/rule.json', '{"recommendation":"Do not pass cors({ origin: true }) to a production server."}\n'],
  ]
  for (const [label, file, content] of SUPPRESSED) {
    it(`${label} (${file})`, async () => {
      const { cors, strictExit, recommendation } = await scan(file, content)
      const active = cors.filter((f) => !f.suppressed)
      expect(active, JSON.stringify(cors)).toHaveLength(0)
      expect(cors.every((f) => f.blocking === false)).toBe(true)
      expect(strictExit).toBe(0)
      // Design decision: a suppressed finding is recorded but does not move the verdict.
      expect(recommendation).toBe('SAFE_TO_SHIP')
    })
  }
})

describe('config-shaped wildcards v4 already matched keep matching', () => {
  const KEPT: Array<[string, string, string]> = [
    ['nginx unquoted with always', 'nginx.conf', 'location /api/ {\n  add_header Access-Control-Allow-Origin * always;\n}\n'],
    ['nginx unquoted', 'nginx.conf', 'add_header Access-Control-Allow-Origin *;\n'],
    ['Apache', 'httpd.conf', 'Header set Access-Control-Allow-Origin "*"\n'],
    ['yaml with trailing comment', 'headers.yaml', 'headers:\n  Access-Control-Allow-Origin: *   # public\n'],
    ['code string with escaped CRLF', 'server.js', "res.write('Access-Control-Allow-Origin: *\\r\\n')\n"],
    // The seven forms a first v5 draft lost: nginx/HAProxy/Apache with more after the star.
    ['nginx space before semicolon', 'nginx.conf', 'server {\n  add_header Access-Control-Allow-Origin * ;\n}\n'],
    ['nginx one-line server block', 'nginx.conf', 'server { add_header Access-Control-Allow-Origin * ; }\n'],
    ['nginx tab separated', 'nginx.conf', 'server {\n\tadd_header Access-Control-Allow-Origin\t*\t;\n}\n'],
    ['nginx semicolon then comment', 'nginx.conf', 'server {\n  add_header Access-Control-Allow-Origin * ; # dev\n}\n'],
    ['nginx if= parameter', 'nginx.conf', 'server {\n  add_header Access-Control-Allow-Origin * if=$cors_ok;\n}\n'],
    ['HAProxy if condition', 'haproxy.conf', 'backend b\n  http-response set-header Access-Control-Allow-Origin * if { req.hdr(origin) -m found }\n'],
    ['Apache expr condition', 'httpd.conf', 'Header set Access-Control-Allow-Origin * "expr=%{REQUEST_URI} =~ /api/"\n'],
  ]
  for (const [label, file, content] of KEPT) {
    it(`${label} (${file})`, async () => {
      const { cors } = await scan(file, content)
      expect(cors.filter((f) => !f.suppressed).length, JSON.stringify(cors)).toBeGreaterThanOrEqual(1)
    })
  }
})
