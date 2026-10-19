/**
 * Placement-kit docs.
 *
 * Specification:
 *   "Placement-kit docs: AGENTS.md snippet + CLAUDE.md import line + GitHub Actions
 *    verdict-job example (`shipguard scan --json --strict`)"
 *
 * A docs item still gets a regression test, because the failure mode for docs is DRIFT: the
 * CI example here and the workflow `shipguard hook --target ci` writes are the same thing
 * said twice, and the moment they disagree one of them is lying. These tests pin the
 * snippets to the behaviour they describe.
 *
 * FAIL-BEFORE: the file did not exist.
 *
 * DISCIPLINE.
 */
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { ciWorkflowYaml, GATE_COMMAND } from '../../src/core/hook-templates.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(__dirname, '../../')
const kitPath = join(pkgRoot, 'docs', 'placement-kit.md')

function kit(): string {
  return readFileSync(kitPath, 'utf-8')
}

describe('the placement kit exists and is shipped', () => {
  it('lives in the published docs directory', () => {
    expect(existsSync(kitPath)).toBe(true)
    const pkg = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf-8'))
    // `docs` is in package.json "files", so this ships with the npm tarball.
    expect(pkg.files).toContain('docs')
  })

  it('has all three placements the plan names', () => {
    const text = kit()
    expect(text).toContain('AGENTS.md')
    expect(text).toContain('CLAUDE.md')
    expect(text).toContain('GitHub Actions')
  })
})

describe('the snippets say the right thing', () => {
  it('every placement uses the ratified invocation', () => {
    const text = kit()
    // Once in the AGENTS.md snippet, once inside the CI job (as
    // `npx --yes @agenticcli/shipguard scan --json --strict`). The CLAUDE.md placement
    // deliberately re-uses the AGENTS.md block rather than restating the command, so two
    // is the correct count, not a shortfall.
    expect(text.split(GATE_COMMAND).length - 1).toBeGreaterThanOrEqual(2)
    // And it must appear in each of the two sections, not twice in one.
    const agentsSection = text.slice(text.indexOf('## 1.'), text.indexOf('## 2.'))
    const ciSection = text.slice(text.indexOf('## 3.'))
    expect(agentsSection).toContain(GATE_COMMAND)
    expect(ciSection).toContain(GATE_COMMAND)
  })

  it('the AGENTS.md snippet teaches "never trust exit 0 alone"', () => {
    const text = kit()
    expect(text).toContain('Exit code 0 does NOT mean "safe"')
    expect(text).toContain('`recommendation`')
    expect(text).toContain('degradedReasons')
  })

  it('it states plainly that Claude Code does not read AGENTS.md', () => {
    // This is the whole reason the CLAUDE.md line is a separate placement (research
    // finding 10) — an AGENTS.md-only setup silently misses Claude Code callers.
    expect(kit()).toMatch(/Claude Code\s+does not|Claude Code\*\* does not|\*\*Claude Code\*\* does not/)
  })

  it('it does not oversell the snippet — snippet teaches, hook enforces', () => {
    const text = kit()
    expect(text).toContain('a snippet TEACHES, a hook ENFORCES')
    expect(text).toContain('--no-verify')
  })
})

describe('the CI example cannot drift from what `shipguard hook --target ci` installs', () => {
  it('the documented job matches the installed workflow, line for line', () => {
    const installed = ciWorkflowYaml()
    const documented = kit()
    // Compare the meaningful lines, ignoring the managed-block markers the installer adds
    // and the comment header it carries.
    const meaningful = installed
      .split('\n')
      .filter((l) => l.trim().length > 0 && !l.trimStart().startsWith('#'))
    for (const line of meaningful) {
      expect(documented).toContain(line)
    }
  })

  it('both tell the reader that branch protection is what makes CI binding', () => {
    expect(ciWorkflowYaml().toLowerCase()).toContain('branch protection')
    expect(kit().toLowerCase()).toContain('branch protection')
  })
})
