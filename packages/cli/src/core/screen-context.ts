/**
 * screen-context.ts: two small read-only facts the scan screen needs, read from the scanned folder only.
 *
 *  - gate state (is a ShipGuard gate really installed here?) for the `Next:` line of a clean scan
 *  - the manifest that made the folder a project, for the `Stack:` honesty line
 *
 * Read-only: nothing here writes. "The gate is on" may be claimed only for a VERIFIED installed state
 * (an install record that parses, core/install-state.ts), never because a suggestion was hidden.
 */

import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { detectAgent } from './telemetry.js'
import { readInstallState } from './install-state.js'

export type NextAgent = 'claude' | 'codex' | 'cursor' | 'git'
export type GateState = 'none' | 'current' | 'stale'

export interface GateProbe {
  state: GateState
  /** Short label of the installed gate, e.g. `Claude project hook`. */
  label: string | null
}

/** Is there a verified gate in this folder? Reads the install record only; anything else counts as "none", never "on". */
export function probeGate(cwd: string): GateProbe {
  const rec = readInstallState(cwd)
  if (rec && rec.agents.length > 0) {
    const label = rec.agents.includes('claude') ? 'Claude project hook' : 'project hook'
    if (rec.hookVersion < 2) return { state: 'stale', label }
    return { state: 'current', label: rec.agents.includes('claude') ? `Claude project hook v${rec.hookVersion}` : `project hook v${rec.hookVersion}` }
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
