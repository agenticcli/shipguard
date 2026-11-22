/**
 * setup-templates.ts: the text `shipguard setup` writes that is NOT a hook script (hook scripts are
 * core/hook-templates.ts): the CLAUDE.md / AGENTS.md managed block and the CI workflow (spec 07).
 * Pure strings, no filesystem. No plan facts and no prices here (the CLI holds none).
 */
import { ACTION_CHECKOUT, ACTION_SETUP_NODE, HOOK_MARKER_END, HOOK_MARKER_START } from './hook-templates.js'

/** Bumped when the instructions block text changes. */
export const AGENT_BLOCK_VERSION = 1
/** Markers for a managed block inside a markdown file (HTML comments: invisible when rendered). */
export const MD_MARKER_PREFIX = '<!-- >>> shipguard managed block'
export const MD_MARKER_START = `${MD_MARKER_PREFIX} v${AGENT_BLOCK_VERSION} >>> -->`
export const MD_MARKER_END = '<!-- <<< shipguard managed block <<< -->'

const COMMON = [
  '## ShipGuard',
  '- Before every `git push` or merge, run `shipguard scan --json --strict`. It runs on this machine; code never leaves it.',
  '- Exit 0 means the scan completed: read `recommendation` in the JSON. Exit 1 means blocked: fix each finding with `blocking: true`, commit, then scan again.',
  '- If the ShipGuard hook blocks a push or merge, read its message and the last `shipguard-gate:` line. Do not re-run the same command unchanged; fix, commit, retry. After 3 blocks on the same finding, ask the user.',
  '- Never use `--no-verify` and never edit or remove the hook to get past ShipGuard. Ask the user before running `shipguard ignore`.',
  '- `shipguard status` shows what is installed here and when the gate last ran.',
]

/** The managed block for CLAUDE.md (6 lines with its two markers). */
export function claudeMdBlock(): string {
  return [MD_MARKER_START, ...COMMON, MD_MARKER_END].join('\n')
}

/** The managed block for AGENTS.md, read by Codex and Cursor (7 lines with its two markers: one more bullet). */
export function agentsMdBlock(): string {
  return [
    MD_MARKER_START,
    ...COMMON,
    '- The git hooks (`pre-push`, `pre-merge-commit`) run the same check; they are skipped by `--no-verify` and do not cover `gh pr merge`, so keep the CI check.',
    MD_MARKER_END,
  ].join('\n')
}

/** Version in a block start marker (0 when there is none). */
export function mdBlockVersion(content: string): number {
  const m = new RegExp(`${MD_MARKER_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} v(\\d+) >>> -->`).exec(content)
  return m ? Number(m[1]) : 0
}

/** Replace the marked block in `content`; undefined when the file has no complete block. */
export function replaceMdBlock(content: string, replacement: string): string | undefined {
  const start = content.indexOf(MD_MARKER_PREFIX)
  if (start === -1) return undefined
  const endAt = content.indexOf(MD_MARKER_END, start)
  if (endAt === -1) return undefined
  return content.slice(0, start) + replacement + content.slice(endAt + MD_MARKER_END.length)
}

/** The marked block as it stands in `content` (undefined when absent). */
export function extractMdBlock(content: string): string | undefined {
  const start = content.indexOf(MD_MARKER_PREFIX)
  if (start === -1) return undefined
  const endAt = content.indexOf(MD_MARKER_END, start)
  if (endAt === -1) return undefined
  return content.slice(start, endAt + MD_MARKER_END.length)
}

/** Version of the CI workflow text; line 1 carries it. */
export const CI_TEMPLATE_VERSION = 3

/**
 * The CI workflow (`shipguard setup --agent ci`): Node 22 (history needs Node 22.5 or newer), the package
 * pinned to an exact version, and an optional SHIPGUARD_API_KEY repository secret (the existing key exchange).
 * The check is named "ShipGuard" so branch protection can require it.
 */
export function ciWorkflowText(packageVersion: string): string {
  return `${HOOK_MARKER_START} v${CI_TEMPLATE_VERSION} (github-actions)
# Installed by \`shipguard setup --agent ci\`. Re-run that command to update this file.
#
# This is the one layer nothing local can skip: it runs on GitHub on every pull request.
# It only becomes a hard stop when branch protection requires the "ShipGuard" check.
name: ShipGuard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  shipguard:
    name: ShipGuard
    runs-on: ubuntu-latest
    steps:
      - uses: ${ACTION_CHECKOUT}
      - uses: ${ACTION_SETUP_NODE}
        with:
          node-version: '22'
      - name: Run ShipGuard
        # Optional: add a repository secret named SHIPGUARD_API_KEY to scan with your account.
        # Without it the scan still runs with the rules that ship in the package.
        env:
          SHIPGUARD_API_KEY: \${{ secrets.SHIPGUARD_API_KEY }}
        run: npx --yes @agenticcli/shipguard@${packageVersion} scan --strict
${HOOK_MARKER_END}
`
}
