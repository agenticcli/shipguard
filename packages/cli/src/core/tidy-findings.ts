// Two small clean-ups applied to the fully assembled findings, after dedupe and collapse:
//
//  1. Every finding that names a file also names a line. The hand-written checks report whole-file
//     facts ("webhook has no signature check", ".env is tracked") with no line; a tool that jumps
//     to `file:line` or reads `line` as a number then gets nothing. The nearest honest line is the
//     handler for webhook findings (first match) and line 1 for everything else.
//  2. A secret that is obviously a stand-in (repeated characters, `EXAMPLE`, an alphabet run) keeps
//     its finding but drops to LOW confidence. Never removes a finding, never touches a real-looking one.
//
// This runs AFTER collapse-findings on purpose: collapse refuses to merge line-less findings, and
// giving legacy findings a line earlier would change which same-id findings it folds together.

import type { FileInfo, Finding } from '@agenticcli/shared'
import { compileDetectorRegex } from './re2-detector-engine.js'
import { looksFakeKey } from '../checks/secrets.js'

// The handler itself: Next.js route export or default export. Preferred over `.post(` calls, which
// also match any earlier outgoing request (`axios.post(`).
const HANDLER_DECL_RE = compileDetectorRegex(
  '\\bexport\\s+(?:async\\s+)?function\\s+POST\\b|\\bexport\\s+const\\s+POST\\b|\\bexport\\s+default\\s+(?:async\\s+)?function\\b',
)
// Express/Fastify-style `.post(` registration, used only when no handler declaration exists.
const HANDLER_CALL_RE = compileDetectorRegex('\\.post\\s*\\(')

/** Findings whose natural home is the request handler rather than the top of the file. */
const HANDLER_ANCHORED = new Set([
  'payment_webhook_without_signature_check',
  'missing_idempotency',
  'missing_error_handling',
])

function firstHandlerLine(content: string): number | undefined {
  const lines = content.split('\n')
  for (const re of [HANDLER_DECL_RE, HANDLER_CALL_RE]) {
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) return i + 1
    }
  }
  return undefined
}

/** Give every file finding a line. Mutates the findings in place; returns how many were filled. */
export function fillMissingLines(findings: Finding[], files: FileInfo[]): number {
  const byPath = new Map<string, FileInfo>()
  for (const f of files) if (!byPath.has(f.relativePath)) byPath.set(f.relativePath, f)
  let filled = 0
  for (const f of findings) {
    if (f.line !== undefined && f.line !== null) continue
    if (!f.file) continue
    const file = byPath.get(f.file)
    const anchored = HANDLER_ANCHORED.has(f.id) && file ? firstHandlerLine(file.content) : undefined
    f.line = anchored ?? 1
    filled++
  }
  return filled
}

/**
 * Lower confidence to LOW on secrets findings whose matched text is a stand-in value. Must run
 * BEFORE evidence redaction (it reads the matched text). Legacy check findings (no column) carry
 * redacted evidence; those are judged in checks/secrets.ts where the raw value is still in hand.
 */
export function lowerFakeKeyConfidence(findings: Finding[]): number {
  let lowered = 0
  for (const f of findings) {
    const isSecret = f.category === 'secrets' || f.id.includes('.secrets.')
    if (!isSecret || f.column === undefined || f.confidence === 'LOW' || !f.evidence) continue
    const value = f.evidence.trim().replace(/^['"`]+|['"`]+$/g, '')
    // Only a bare token can be judged; a whole matched line (`KEY=value`) is not a key.
    if (/\s/.test(value) || !looksFakeKey(value)) continue
    f.confidence = 'LOW'
    lowered++
  }
  return lowered
}
