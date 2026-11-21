/**
 * screen-context.ts: two small read-only facts the scan screen needs, read from the scanned folder only.
 *
 *  - gate state (is a ShipGuard gate really installed here?) for the `Next:` line of a clean scan
 *  - the manifest that made the folder a project, for the `Stack:` honesty line
 *
 * Read-only: nothing here writes. "The gate is on" may be claimed only for a VERIFIED installed state
 * (a record that parses, or a hook entry that names ShipGuard), never because a suggestion was hidden.
 * W4a owns `.shipguard/installed.json` (core/install-state.ts); until it lands this reads the same file
 * defensively and falls back to the Claude project settings.
 */

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { detectAgent } from './telemetry.js'

export type NextAgent = 'claude' | 'codex' | 'cursor' | 'git'
export type GateState = 'none' | 'current' | 'stale'

export interface GateProbe {
  state: GateState
  /** Short label of the installed gate, e.g. `Claude project hook`. */
  label: string | null
}

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    return null
  }
}

/** Is there a verified gate in this folder? Conservative: unknown shapes count as "none", never "on". */
export function probeGate(cwd: string): GateProbe {
  const rec = readJson(join(cwd, '.shipguard', 'installed.json'))
  if (rec && typeof rec === 'object') {
    const r = rec as Record<string, unknown>
    const hookVersion = r.hookVersion ?? r.hook_version
    const targets = Array.isArray(r.targets) ? (r.targets as unknown[]) : Array.isArray(r.agents) ? (r.agents as unknown[]) : []
    if (targets.length > 0 || r.hook !== undefined || hookVersion !== undefined) {
      if (typeof hookVersion === 'number' && hookVersion < 2) return { state: 'stale', label: 'Claude project hook' }
      return { state: 'current', label: typeof hookVersion === 'number' ? `Claude project hook v${hookVersion}` : 'project hook' }
    }
  }
  const settings = readJson(join(cwd, '.claude', 'settings.json'))
  if (settings && typeof settings === 'object') {
    const hooks = (settings as Record<string, unknown>).hooks
    if (hooks && JSON.stringify(hooks).includes('shipguard')) return { state: 'current', label: 'Claude project hook' }
  }
  return { state: 'none', label: null }
}

/** Which agent should a setup suggestion name? The one running the scan, else repo signals (spec 07). */
export function detectNextAgent(cwd: string, env: NodeJS.ProcessEnv = process.env): NextAgent | null {
  const a = detectAgent(env)
  if (a === 'claude_code') return 'claude'
  if (a === 'codex') return 'codex'
  if (a === 'cursor') return 'cursor'
  if (existsSync(join(cwd, '.claude'))) return 'claude'
  if (existsSync(join(cwd, 'AGENTS.md'))) return 'codex'
  if (existsSync(join(cwd, '.cursor'))) return 'cursor'
  if (existsSync(join(cwd, '.git'))) return 'git'
  return null
}

const MANIFESTS = ['package.json', 'pyproject.toml', 'requirements.txt', 'go.mod', 'Cargo.toml', 'Gemfile', 'composer.json', 'pom.xml', 'build.gradle', 'mix.exs']

/** The manifest that makes the folder a project (named in the `Stack:` line); null when none is found. */
export function detectManifest(cwd: string): string | null {
  for (const m of MANIFESTS) if (existsSync(join(cwd, m))) return m
  return null
}
