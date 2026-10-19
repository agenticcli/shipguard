import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { loadPolicy, createPolicyFile, createShipguardDir, DEFAULT_POLICY } from '../../src/core/policy.js'

const tempDirs: string[] = []

function mkTemp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shipguard-test-'))
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // ignore cleanup errors
    }
  }
})

describe('loadPolicy', () => {
  it('returns defaults when no policy file exists', async () => {
    const dir = mkTemp()
    const policy = await loadPolicy(dir)
    expect(policy.version).toBe(1)
    expect(policy.project.name).toBe('my-app')
    expect(policy.block).toContain('exposed_env')
    expect(policy.warn).toContain('missing_error_handling')
  })

  it('parses valid YAML policy file', async () => {
    const dir = mkTemp()
    const yaml = `version: 1\nproject:\n  name: test-app\n  framework: next\n  risk_profile: strict\nscan:\n  changed_files_only: false\n  generate_report: false\nblock: []\nwarn: []\nignore:\n  paths: []\nreport:\n  output: .shipguard/reports/latest.md\n  format: markdown\n`
    writeFileSync(join(dir, 'shipguard.policy.yml'), yaml, 'utf-8')
    const policy = await loadPolicy(dir)
    expect(policy.project.name).toBe('test-app')
    expect(policy.project.framework).toBe('next')
    expect(policy.scan.changed_files_only).toBe(false)
  })

  it('throws on invalid YAML', async () => {
    const dir = mkTemp()
    writeFileSync(join(dir, 'shipguard.policy.yml'), ': invalid: yaml: [{{', 'utf-8')
    await expect(loadPolicy(dir)).rejects.toThrow('Invalid policy file')
  })
})

describe('createPolicyFile', () => {
  it('creates the policy file and returns true', async () => {
    const dir = mkTemp()
    const result = await createPolicyFile(dir)
    expect(result).toBe(true)
    expect(existsSync(join(dir, 'shipguard.policy.yml'))).toBe(true)
    const content = readFileSync(join(dir, 'shipguard.policy.yml'), 'utf-8')
    expect(content).toContain('version: 1')
  })

  it('returns false if file already exists', async () => {
    const dir = mkTemp()
    await createPolicyFile(dir)
    const result = await createPolicyFile(dir)
    expect(result).toBe(false)
  })
})

describe('createShipguardDir', () => {
  it('creates the .shipguard/reports directory', async () => {
    const dir = mkTemp()
    await createShipguardDir(dir)
    expect(existsSync(join(dir, '.shipguard', 'reports'))).toBe(true)
  })

  it('does not throw if directory already exists', async () => {
    const dir = mkTemp()
    await createShipguardDir(dir)
    await expect(createShipguardDir(dir)).resolves.toBeUndefined()
  })
})
