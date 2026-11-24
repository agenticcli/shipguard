/**
 * Hooks and CI never spend credits on their own: no `--pro` is written into any hook or CI template.
 * (The full rulebook is something a person or agent asks for with `shipguard scan --pro`.)
 */
import { describe, expect, it } from 'vitest'
import { CLAUDE_HOOK_COMMAND, GATE_COMMAND, GIT_HOOK_NAMES, ciWorkflowYaml, gitHookScript } from '../../src/core/hook-templates.js'

describe('hook and CI templates carry no --pro', () => {
  it('git hooks', () => {
    for (const name of GIT_HOOK_NAMES) expect(gitHookScript(name)).not.toContain('--pro')
  })
  it('Claude Code hook', () => {
    expect(CLAUDE_HOOK_COMMAND).not.toContain('--pro')
  })
  it('CI workflow', () => {
    expect(ciWorkflowYaml()).not.toContain('--pro')
  })
  it('the gate command stays scan --json --strict', () => {
    expect(GATE_COMMAND).toBe('shipguard scan --json --strict')
  })
})
