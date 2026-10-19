/**
 * Shared inline-suppression helper.
 *
 * Syntax: `// shipguard-ignore: <ruleId> -- <reason>`
 *   - Honored when on the SAME line as the finding, or the line ABOVE it.
 *   - A `<reason>` after `--` is REQUIRED — an undocumented suppression is not
 *     honored (forces the author to record WHY).
 *
 * This logic previously lived only in pro-scanner.ts, so free-tier findings
 * could never be suppressed. It is factored here so BOTH the free CheckModules
 * (applied as a post-pass in scanner.ts) and the pro engine share identical
 * semantics.
 *
 * Semantics (match the pro engine exactly): a suppressed finding is NOT dropped.
 * It is still RECORDED and COUNTED — it is only marked `suppressed:true` and
 * forced `blocking:false` so it cannot fail a gate. This preserves visibility
 * (the finding still appears in --json / reports) while honoring the author's
 * accepted-risk decision.
 */
import type { Finding, FileInfo } from '@agenticcli/shared'

/**
 * Matches `// shipguard-ignore: <ruleId> -- <reason>`.
 * Group 1 = ruleId, Group 2 = reason (required).
 */
export const SUPPRESS_RE = /\/\/\s*shipguard-ignore:\s*([\w.-]+)\s*--\s*(.+)/

/**
 * True if the given rule id is suppressed at lineIndex (0-based) — checking the
 * same line and the line immediately above.
 */
export function isLineSuppressed(lines: string[], lineIndex: number, ruleId: string): boolean {
  // Same line
  const sameLine = lines[lineIndex]
  if (sameLine !== undefined) {
    const sameMatch = SUPPRESS_RE.exec(sameLine)
    if (sameMatch && sameMatch[1] === ruleId) return true
  }

  // Line above
  if (lineIndex > 0) {
    const aboveLine = lines[lineIndex - 1]
    if (aboveLine !== undefined) {
      const aboveMatch = SUPPRESS_RE.exec(aboveLine)
      if (aboveMatch && aboveMatch[1] === ruleId) return true
    }
  }

  return false
}

/**
 * Post-process a finding list against the scanned files, honoring inline
 * suppression comments. Mutates each suppressed finding in place
 * (suppressed:true, blocking:false) and returns the SAME array — suppressed
 * findings are retained (counted/recorded), never removed.
 *
 * Findings without a `line` (file-level findings) cannot be matched against a
 * specific suppression comment and are left as-is.
 */
export function applySuppressions(findings: Finding[], files: FileInfo[]): Finding[] {
  if (findings.length === 0) return findings

  // Index file content lines by relativePath once — avoids re-splitting per
  // finding (a file with N findings would otherwise split N times).
  const linesByPath = new Map<string, string[]>()
  const linesFor = (relativePath: string): string[] | undefined => {
    if (linesByPath.has(relativePath)) return linesByPath.get(relativePath)
    const file = files.find((f) => f.relativePath === relativePath)
    if (!file) {
      linesByPath.set(relativePath, [])
      return undefined
    }
    const split = file.content.split('\n')
    linesByPath.set(relativePath, split)
    return split
  }

  for (const finding of findings) {
    if (finding.line === undefined) continue
    const lines = linesFor(finding.file)
    if (!lines || lines.length === 0) continue
    // finding.line is 1-based; isLineSuppressed expects a 0-based index.
    if (isLineSuppressed(lines, finding.line - 1, finding.id)) {
      finding.suppressed = true
      finding.blocking = false
    }
  }

  return findings
}
