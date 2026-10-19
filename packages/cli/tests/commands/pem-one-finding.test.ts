/**
 * One PEM private key is ONE finding. The legacy secrets check (`hardcoded_secret`, critical) and
 * the corpus rule `generic.secrets.private-key-pem` (high) both fire on the header line; dedup used
 * to keep both because legacy was more severe, reporting one key twice and scoring it 80.
 * It now folds into the corpus finding at the higher severity.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
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

const BODY = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj'

async function scan(content: string) {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-pem-'))
  dirs.push(dir)
  writeFileSync(join(dir, 'package.json'), '{"name":"pem"}', 'utf-8')
  writeFileSync(join(dir, 'k.js'), content, 'utf-8')
  const res = await spawnNode(distCli, ['scan', dir, '--json'], { cwd: dir })
  return JSON.parse(res.stdout) as {
    riskScore: { score: number }
    findings: Array<{ id: string; severity: string; blocking: boolean; explanation: string }>
  }
}

describe('a single PEM private key is a single finding', () => {
  it('multi-line PEM block: one finding, critical, blocking, scored once', async () => {
    const j = await scan(`const k = \`-----BEGIN PRIVATE KEY-----\n${BODY}\n-----END PRIVATE KEY-----\n\`\n`)
    expect(j.findings.map((f) => f.id), JSON.stringify(j.findings)).toEqual(['generic.secrets.private-key-pem'])
    expect(j.findings[0].severity).toBe('critical')
    expect(j.findings[0].blocking).toBe(true)
    expect(j.findings[0].explanation).toContain('Severity raised from high to critical')
    expect(j.riskScore.score).toBe(50)
  })

  it('two DIFFERENT keys stay two findings', async () => {
    const one = `-----BEGIN PRIVATE KEY-----\n${BODY}\n-----END PRIVATE KEY-----\n`
    const j = await scan(`const a = \`${one}\`\n\nconst b = \`${one.replace('MIIE', 'MIIF')}\`\n`)
    expect(j.findings.length, JSON.stringify(j.findings)).toBe(2)
  })
})
