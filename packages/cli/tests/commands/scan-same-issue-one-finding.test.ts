/**
 * One issue, one finding — on the REAL binary .
 *
 * FAIL-BEFORE (verified on main @697b469): `shipguard scan <dir> --json` on a file containing
 * `res.setHeader('Access-Control-Allow-Origin', '*')` printed TWO `generic.cors.wildcard-origin`
 * findings (columns 7 and 18) for that one line, and `riskScore.score` was their double
 * (30 when the corpus severity is medium; 60 -> DO_NOT_SHIP when it is high).
 *
 * PASS-AFTER: exactly one finding per (rule, file, line); the survivor is the earliest column;
 * the score equals the sum of the findings actually reported; `totalFindings` matches
 * `findings.length`; and the verdict is the one that score implies.
 *
 * `--json` contract: no field is added, removed, or re-typed. What changes is only how many
 * entries `findings` holds when several patterns of one rule hit one line.
 *
 * DISCIPLINE: behavioral — spawns the built binary, asserts the serialized contract.
 */
import { spawnSync, execSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, it, expect, beforeAll, afterEach } from 'vitest'
import { SEVERITY_WEIGHTS } from '@agenticcli/shared'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const distCli = resolve(pkgRoot, 'dist/cli.js')

const tempDirs: string[] = []

function mkFixture(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-one-finding-'))
  tempDirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture"}', 'utf-8')
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body, 'utf-8')
  return dir
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
})

interface JsonFinding {
  id: string
  severity: string
  file: string
  line?: number
  column?: number
}
interface JsonScan {
  findings: JsonFinding[]
  recommendation: string
  riskScore: { score: number; totalFindings: number; recommendation: string }
}

function scanJson(dir: string): JsonScan {
  const res = spawnSync('node', [distCli, 'scan', dir, '--json'], {
    cwd: pkgRoot,
    encoding: 'utf-8',
    timeout: 60_000,
  })
  return JSON.parse(res.stdout ?? '') as JsonScan
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npx tsup', { cwd: pkgRoot, stdio: 'inherit' })
  }
}, 180_000)

const CORS_FILE =
  "export default function handler(req, res) {\n  res.setHeader('Access-Control-Allow-Origin', '*')\n  res.end('ok')\n}\n"

describe('--json: one line of wildcard CORS is one finding', () => {
  it('exactly one generic.cors.wildcard-origin finding, at the earliest column', () => {
    const json = scanJson(mkFixture({ 'api.ts': CORS_FILE }))
    const cors = json.findings.filter((f) => f.id === 'generic.cors.wildcard-origin')
    expect(cors).toHaveLength(1)
    expect(cors[0].line).toBe(2)
    expect(cors[0].column).toBe(7)
  })

  it('score, totalFindings and the verdict are all derived from the ONE finding', () => {
    const json = scanJson(mkFixture({ 'api.ts': CORS_FILE }))
    const expected = json.findings.reduce((n, f) => n + (SEVERITY_WEIGHTS[f.severity] ?? 0), 0)
    expect(json.riskScore.score).toBe(Math.min(100, expected))
    expect(json.riskScore.totalFindings).toBe(json.findings.length)
    // The verdict is the score's verdict, not an inflated one (thresholds: <=20 safe, <50 review).
    const implied = json.riskScore.score <= 20 ? 'SAFE_TO_SHIP' : json.riskScore.score < 50 ? 'REVIEW_BEFORE_SHIP' : 'DO_NOT_SHIP'
    expect(json.recommendation).toBe(implied)
    expect(json.riskScore.recommendation).toBe(implied)
  })

  it('a wildcard on two different lines is still two findings (no over-collapse)', () => {
    const body =
      "export function a(res) {\n  res.setHeader('Access-Control-Allow-Origin', '*')\n}\n" +
      "export function b(res) {\n  res.setHeader('Access-Control-Allow-Origin', '*')\n}\n"
    const json = scanJson(mkFixture({ 'api.ts': body }))
    const lines = json.findings
      .filter((f) => f.id === 'generic.cors.wildcard-origin')
      .map((f) => f.line)
      .sort()
    expect(lines).toEqual([2, 5])
  })
})

describe('--json: the whole finding list has no (rule, file, line) repeated', () => {
  it('holds for a file that trips several rules and several patterns of one rule', () => {
    const dir = mkFixture({
      'api.ts': CORS_FILE,
      'client.ts': "const client = new OpenAI({ apiKey: 'sk-proj-abc1234XYZabcXYZabc12345' })\n",
      'pay.ts': "const stripeKey = 'sk_live_abcdefghijklmnopqrstuvwx1234'\n",
    })
    const json = scanJson(dir)
    const counts = new Map<string, number>()
    for (const f of json.findings) {
      if (f.line === undefined) continue
      const k = `${f.id} ${f.file}:${f.line}`
      counts.set(k, (counts.get(k) ?? 0) + 1)
    }
    const repeated = [...counts].filter(([, n]) => n > 1).map(([k]) => k)
    expect(repeated).toEqual([])
  })
})
