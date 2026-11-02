import { lstat, realpath } from 'node:fs/promises'
import { sha256 } from '@noble/hashes/sha2.js'
import { join } from 'node:path'
import { loadPolicy } from './policy.js'
import { computeRiskScore } from './risk-score.js'
import { applyVerdict } from './verdict.js'
import { isGitRepo, getChangedFilesDetailed } from './git.js'
import {
  readFiles,
  readCandidate,
  capReached,
  createReadState,
  compareScanPaths,
  MAX_SKIPPED_NAMES,
  DEFAULT_MAX_FILE_SIZE_BYTES,
  DEFAULT_MAX_TOTAL_BYTES,
  DEFAULT_MAX_FILES,
  type ReadFilesResult,
} from '../utils/fs.js'
import { buildIgnoreRules, classifyIgnored, isShipguardArtifactPath, selfArtifactIgnorePatterns } from './ignore.js'
import { logger } from '../utils/logger.js'
import { secretsCheck } from '../checks/secrets.js'
import { authCheck } from '../checks/auth.js'
import { databaseCheck } from '../checks/database.js'
import { payments } from '../checks/payments.js'
import { deploymentCheck } from '../checks/deployment.js'
import type { FileInfo, Finding, ScanOptions, ScanResult, QualityGateRule, DegradeReason, ScanCoverage } from '@agenticcli/shared'
import { runProRulesWithDispatch, runProRules } from './pro-scanner.js'
import { loadChecksumManifest } from './coderef-dispatch.js'
import { applySuppressions, isLineSuppressed } from './suppression.js'
import { loadBundledRules } from './bundled-rules.js'
import { dedupeLegacyAgainstCorpus } from './legacy-corpus-map.js'
import { collapseSameIssueFindings } from './collapse-findings.js'
import { redactFindingsEvidence } from './redact.js'

const CHECK_MODULES = [secretsCheck, authCheck, databaseCheck, payments, deploymentCheck]

// Kept for callers/tests that import it from here; the implementation moved to core/ignore.ts so the
// full scan and `--changed` share ONE ignore list.
export { selfArtifactIgnorePatterns }

/** The scan result plus what was scanned, skipped and ignored (always present on a real scan). */
export interface ScanResultWithMeta extends ScanResult {
  coverage: ScanCoverage
}

/**
 * Content-addressed digest of everything the scan read.
 *
 * `sha256( for each reading, in sorted path order: path + NUL + hex(sha256(content)) + LF )`.
 *
 * Sorted path order (the same `compareScanPaths` ordering rec #7 established) makes it
 * reproducible; hashing per-file content rather than concatenating raw bytes keeps a
 * rename from being invisible and keeps file boundaries unambiguous.
 *
 * Note what it covers: the NORMALIZED content the checks actually ran against (BOM
 * stripped, CRLF folded to LF, UTF-16 decoded, NUL replaced by a space), not the raw bytes on
 * disk. A file with several plausible readings contributes one line per reading. That is the honest
 * thing to attest to, because it is what produced the findings. NUL-bearing and UTF-16 files that
 * used to be unread now enter the digest, so the digest of such trees differs from 0.8.1.
 *
 * Returns undefined when nothing was read - an empty digest would falsely imply "I looked
 * and there was nothing", which is not the same as "I read no files".
 */
export function computeTreeDigest(files: FileInfo[]): string | undefined {
  if (files.length === 0) return undefined
  const encoder = new TextEncoder()
  const lines = files
    .map((f) => `${f.relativePath}\0${toHex(sha256(encoder.encode(f.content)))}\n`)
    .sort(compareScanPaths)
  return toHex(sha256(encoder.encode(lines.join(''))))
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * A path with several plausible readings is checked once per reading. Drop the repeats that
 * come from readings of the SAME file (same rule, file and line); findings of other files and
 * `collapseSameIssueFindings` are untouched.
 */
function dedupeAcrossReadings(findings: Finding[], files: FileInfo[]): Finding[] {
  const counts = new Map<string, number>()
  for (const f of files) counts.set(f.relativePath, (counts.get(f.relativePath) ?? 0) + 1)
  const multi = new Set([...counts].filter(([, n]) => n > 1).map(([p]) => p))
  if (multi.size === 0) return findings
  const seen = new Set<string>()
  return findings.filter((f) => {
    if (!f.file || !multi.has(f.file)) return true
    const key = `${f.id}\0${f.file}\0${f.line ?? ''}\0${f.line === undefined ? `${f.title}\0${f.evidence ?? ''}` : ''}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

const sortedCapped = (names: string[]): string[] => [...names].sort(compareScanPaths).slice(0, MAX_SKIPPED_NAMES)

function buildCoverage(
  state: ReadFilesResult,
  mode: 'full' | 'changed',
  changed?: { listed: number; outsideScope: number },
): ScanCoverage {
  return {
    discovered: state.discovered,
    scanned: state.acceptedPaths,
    skipped: {
      binary: state.skippedBinary,
      tooLarge: state.skippedTooLarge,
      symlink: state.skippedSymlinks,
      unknownBinary: state.skippedUnknownBinary,
      invalidUtf8: state.invalidUtf8Files.length,
      unreadable: state.unreadableFiles.length,
      special: state.skippedSpecial,
      binaryHeadOnly: state.skippedBinaryHeadOnly,
    },
    decoded: {
      utf16: state.utf16Decoded,
      nulSubstituted: state.nulSubstituted,
      multiReading: state.multiReading,
      asciiStrings: state.asciiStrings,
      binaryStringsScanned: state.binaryStringsScanned,
    },
    truncated: state.truncated && state.truncatedBy ? { by: state.truncatedBy, notReached: state.notReached } : false,
    ignoredByDefault: state.ignoredByDefault,
    ignoredByUser: state.ignoredByUser,
    selfArtifacts: state.selfArtifacts,
    mode,
    ...(changed ? { changed } : {}),
    files: {
      binary: sortedCapped(state.skippedBinaryFiles),
      tooLarge: sortedCapped(state.skippedTooLargeFiles),
      symlink: sortedCapped(state.skippedSymlinkFiles),
      unknownBinary: sortedCapped(state.skippedUnknownBinaryFiles),
      special: sortedCapped(state.skippedSpecialFiles),
      nulSubstituted: sortedCapped(state.nulSubstitutedFiles),
    },
  }
}

export async function scan(
  options: ScanOptions,
  proRules?: QualityGateRule[],
  onProgress?: (current: number, total: number, file: string) => void,
): Promise<ScanResultWithMeta> {
  const cwd = process.cwd()
  const policy = await loadPolicy(cwd)

  // ONE ignore list for both read paths: defaults, ShipGuard's own artifacts (wherever the policy put
  // them) and policy.ignore.paths.
  const ignoreRules = buildIgnoreRules(policy)

  // Resolve limits from policy - merged with defaults in loadPolicy, but fall back to constants
  // in case an older/minimal policy object is passed (e.g. from test mocks without limits).
  const limits = {
    maxFileSizeBytes: policy.limits?.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES,
    maxTotalBytes: policy.limits?.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES,
    maxFiles: policy.limits?.maxFiles ?? DEFAULT_MAX_FILES,
  }

  let state: ReadFilesResult
  let mode: 'full' | 'changed' = 'full'
  let changedInfo: { listed: number; outsideScope: number } | undefined

  if (options.changedOnly && isGitRepo(cwd)) {
    mode = 'changed'
    state = createReadState()
    // getChangedFilesDetailed() throws GitCommandError on a genuine git failure - intentionally NOT
    // caught here: a git failure must map to exit 3 (RUNTIME_ERROR), never to "0 files, SAFE".
    const changed = getChangedFilesDetailed(cwd)
    const listed = changed.paths.length + changed.unaddressable.length + changed.outsideScope
    changedInfo = { listed, outsideScope: changed.outsideScope }

    // The same ignore rules as the full scan, counted exactly per rule.
    const defaultCounts = new Map<string, number>()
    const candidates: string[] = []
    for (const rp of changed.paths) {
      const rule = classifyIgnored(rp, ignoreRules)
      if (!rule && isShipguardArtifactPath(rp)) state.selfArtifacts++
      else if (!rule) candidates.push(rp)
      else if (rule.by === 'user') state.ignoredByUser++
      else defaultCounts.set(rule.pattern, (defaultCounts.get(rule.pattern) ?? 0) + 1)
    }
    state.ignoredByDefault = [...defaultCounts].map(([pattern, files]) => ({ pattern, files }))
    // Rec #7: sort BEFORE the cap; git's diff order is not a contract.
    candidates.sort(compareScanPaths)

    // A name that is not valid UTF-8 cannot be addressed safely: degraded, never aliased.
    for (const display of changed.unaddressable) {
      logger.warn(`[shipguard] Changed file name is not valid UTF-8 and cannot be addressed safely: ${display}`)
      state.unreadableFiles.push(display)
      state.unaddressableCount++
    }
    // Folders git warned about ("could not open directory"): their files are not in the listing, so
    // the scan is incomplete. DEGRADED (UNREADABLE_FILE), counted, never silent.
    for (const display of changed.unreadable ?? []) {
      logger.warn(`[shipguard] git could not read ${display}; files under it are NOT scanned`)
      state.unreadableFiles.push(display)
    }
    state.discovered = candidates.length + changed.unaddressable.length + (changed.unreadable ?? []).length

    if (listed === 0) {
      // Git ran successfully and genuinely found nothing changed.
      logger.info('--changed: git ran successfully - 0 changed files to scan.')
    }
    if (candidates.length === 0 && !options.json) {
      logger.warn(
        '`--changed` scans only files that differ from git; on a clean checkout it scans nothing. ' +
        'Run `shipguard scan` for the whole tree.',
      )
    }

    const canonicalCwd = await realpath(cwd).catch(() => cwd)
    const cwdWithSep = canonicalCwd.endsWith('/') ? canonicalCwd : canonicalCwd + '/'
    let processed = 0

    for (let i = 0; i < candidates.length; i++) {
      const hit = capReached(state, limits)
      if (hit) {
        state.truncated = true
        state.truncatedBy = hit
        state.notReached = candidates.length - i
        break
      }
      const relPath = candidates[i]
      const fullPath = join(cwd, relPath)
      // Symlink / root-containment guard - matches the normal path's followSymbolicLinks:false.
      // realpath() throws ENOENT for dangling symlinks (and files deleted since git listed them)
      // -> accumulated as unreadable (degraded, never silently skipped).
      // A symlink is never followed (privacy): same SYMLINK_SKIPPED as the full scan, not "unreadable".
      let isLink = false
      try {
        isLink = (await lstat(fullPath)).isSymbolicLink()
      } catch {
        isLink = false // gone since git listed it: the realpath step below reports it as unreadable
      }
      if (isLink) {
        state.skippedSymlinks++
        if (state.skippedSymlinkFiles.length < MAX_SKIPPED_NAMES) state.skippedSymlinkFiles.push(relPath)
        onProgress?.(++processed, candidates.length, relPath)
        continue
      }
      let resolvedPath: string | undefined
      try {
        resolvedPath = await realpath(fullPath)
      } catch (realpathErr: unknown) {
        const detail = realpathErr instanceof Error ? realpathErr.message : String(realpathErr)
        logger.warn(`[shipguard] Could not resolve path for changed file ${relPath}: ${detail}`)
        state.unreadableFiles.push(relPath)
      }
      if (resolvedPath !== undefined) {
        if (!resolvedPath.startsWith(cwdWithSep) && resolvedPath !== canonicalCwd) {
          logger.warn(
            `[shipguard] Refusing out-of-root path for changed file ${relPath}: ` +
            `resolved to ${resolvedPath} which is outside ${canonicalCwd}`,
          )
          state.unreadableFiles.push(relPath)
        } else {
          await readCandidate(state, { readPath: resolvedPath, path: fullPath, rel: relPath }, limits.maxFileSizeBytes)
        }
      }
      onProgress?.(++processed, candidates.length, relPath)
    }
  } else {
    if (options.changedOnly && !isGitRepo(cwd)) {
      logger.warn('--changed flag set but not a git repository - scanning all files')
    }
    state = await readFiles(cwd, ['**/*'], [], {
      maxFileSizeBytes: limits.maxFileSizeBytes,
      maxTotalBytes: limits.maxTotalBytes,
      maxFiles: limits.maxFiles,
      onProgress,
      ignoreRules,
    })
  }

  const files = state.files
  const skippedTooLarge = state.skippedTooLarge
  const skippedTooLargeFiles = state.skippedTooLargeFiles
  const skippedSymlinks = state.skippedSymlinks
  const skippedSymlinkFiles = state.skippedSymlinkFiles
  const truncated = state.truncated
  const changedInvalidUtf8 = state.invalidUtf8Files
  const changedUnreadable = state.unreadableFiles

  // Free-tier findings. Apply inline suppression  so
  // `// shipguard-ignore: <ruleId> -- <reason>` works on free findings too, not
  // just pro ones. Suppressed findings are RETAINED (counted/recorded), only
  // marked suppressed:true + blocking:false — identical to the pro engine. The
  // pro path (runProRulesWithDispatch) applies its own per-finding suppression
  // internally, so we only post-process the free findings here.
  // The secrets check masks its own evidence at the source (checks/secrets.ts `redact()`);
  // remember which findings are its so the central redaction below leaves them byte-identical.
  const sourceRedacted = new Set<Finding>()
  const legacyFindings = applySuppressions(
    CHECK_MODULES.flatMap((mod) => {
      const found = mod.run(files, policy)
      if (mod === secretsCheck) for (const f of found) sourceRedacted.add(f)
      return found
    }),
    files,
  )

  // Bundled corpus rules — the governed offline free set. These run
  // for EVERY scan including anonymous/offline ones: the bundle is compiled into this
  // binary, so there is no network call, no auth, and no credit to spend. They go through
  // runProRules (the declarative re2js-v1 engine) because that is the same engine the
  // platform's Gate C certifies each rule against — running them through a second,
  // different matcher would mean the shipped behaviour was never the certified behaviour.
  //
  // Not wrapped in try/catch: loadBundledRules() throws only when the bundle is absent,
  // empty, or a schema this build cannot read, and each of those means the scan applied
  // fewer rules than it claims. Letting it propagate maps to exit 3 in commands/scan.ts,
  // which is the honest outcome — a silently rule-less scan reporting "clean" is the
  // failure this whole change exists to remove.
  const bundledFindings = applySuppressions(runProRules(loadBundledRules(), files, policy), files)

  // Where a hand-written legacy check and a governed corpus rule both fired on the SAME
  // line, keep the corpus finding and drop the legacy duplicate. This can
  // never remove a detection — it only ever fires when both already matched.
  const { findings: dedupedLegacy, corpusFindings: dedupedCorpus, notes: dedupNotes, severityDisagreements } =
    dedupeLegacyAgainstCorpus(legacyFindings, bundledFindings, (cf) => {
      // A corpus finding is `suppressed` for two different reasons: the user's shipguard-ignore
      // comment, or the rule's own antiPattern exemption. Only the former may retire a legacy twin.
      if (cf.line === undefined) return false
      const file = files.find((x) => x.relativePath === cf.file)
      return file !== undefined && isLineSuppressed(file.content.split('\n'), cf.line - 1, cf.id)
    })
  for (const n of dedupNotes) {
    logger.debug(
      `[shipguard] ${n.file}:${n.line} — legacy finding "${n.legacyId}" superseded by governed ` +
      `corpus rule "${n.corpusId}" (same line, same defect).` +
      (n.blockingPromoted
        ? ` The legacy finding was blocking, so the corpus finding is reported as blocking to keep the gate behaviour.`
        : ''),
    )
  }
  // A same-line pair where the legacy check rates the defect HIGHER than the corpus rule.
  // Both findings are kept (dedup never softens a report), and the disagreement is warned
  // about rather than logged at debug: it is a real governance question about the corpus's
  // severity, and a silent resolution is how a `critical` quietly becomes a `high`.
  for (const d of severityDisagreements) {
    logger.warn(
      `[shipguard] ${d.file}:${d.line} — "${d.legacyId}" (${d.legacySeverity}) and ` +
      `"${d.corpusId}" (${d.corpusSeverity}) describe the same defect with different severities. ` +
      `They are folded into one finding at the higher severity.`,
    )
  }

  let allFindings = [...dedupedLegacy, ...dedupedCorpus]

  let coderefDegraded = false

  if (proRules?.length) {
    // Load the build-time checksum manifest so coderef dispatch verifies each
    // module against its SHA-256 hash. Returns undefined if dist/checksum-manifest.json
    // does not exist (pre-build / test-injection path — dispatch skips check gracefully).
    // a tampered or absent-from-manifest module is fail-closed (not silent).
    const checksumManifest = loadChecksumManifest()
    const { findings: proFindings, degraded, warnings } = runProRulesWithDispatch(
      proRules,
      files,
      policy,
      undefined,  // cliVersion — use default (reads from package.json)
      undefined,  // table — use default dispatch table
      checksumManifest,
    )
    allFindings = [...allFindings, ...proFindings]
    coderefDegraded = degraded
    for (const w of warnings) {
      logger.warn(w)
    }
  }

  // One issue = one finding. Several patterns of one rule (or several legacy secret patterns)
  // can match the same line; severity is additive in the risk score, so each extra match
  // would otherwise inflate the score and the verdict. See core/collapse-findings.ts.
  // A path read under several plausible readings is checked once per reading: drop the repeats.
  allFindings = dedupeAcrossReadings(allFindings, files)

  const collapsed = collapseSameIssueFindings(allFindings)
  for (const n of collapsed.notes) {
    logger.debug(
      `[shipguard] ${n.file}:${n.line} — "${n.id}" matched more than once (columns ` +
      `${n.keptColumn ?? '?'} and ${n.droppedColumn ?? '?'}); reported as one finding.`,
    )
  }
  allFindings = collapsed.findings

  // Redact secrets in every finding's evidence — the ONE central point (core/redact.ts).
  // Runs on the fully assembled list (legacy checks + bundled corpus + Pro rules) BEFORE
  // anything downstream reads it, so the JSON, text, SARIF, report files, history and hook
  // output can never carry a raw key. Corpus/Pro findings otherwise ship the matched text
  // verbatim (matcher-contract keeps evidence unredacted by design).
  redactFindingsEvidence(allFindings, sourceRedacted)

  const riskScore = computeRiskScore(allFindings)

  // Receipt: what bytes did this verdict actually look at? (rec #8)
  const treeDigest = computeTreeDigest(files)

  // Build machine-readable degradedReasons alongside the degraded boolean.
  // Each reason carries a stable code safe to key on in agent/CI logic.
  // scan.ts OR-merges its own pro-fetch-failure entry AFTER this point.
  const degradedReasons: DegradeReason[] = []

  if (skippedTooLarge > 0) {
    const named = skippedTooLargeFiles.slice(0, 10).join(', ')
    const extra = skippedTooLarge > skippedTooLargeFiles.length || skippedTooLargeFiles.length > 10
      ? ` (and others)`
      : ''
    degradedReasons.push({
      code: 'FILE_TOO_LARGE',
      detail: `${skippedTooLarge} file(s) exceeded the per-file size cap and were not scanned: ${named}${extra}`,
    })
  }

  if (truncated && state.truncatedBy) {
    const capName = state.truncatedBy === 'maxFiles' ? `limits.maxFiles (${limits.maxFiles})` : `limits.maxTotalBytes (${limits.maxTotalBytes})`
    degradedReasons.push({
      code: 'OUTPUT_TRUNCATED',
      detail:
        `Collection stopped at ${capName}: ${state.notReached} file(s) were never reached. ` +
        `Results are incomplete. Raise the limit in shipguard.policy.yml or narrow the scan with ignore.paths.`,
    })
  }

  // Symlinks discovered but not followed: followSymbolicLinks:false means an entire subtree behind
  // a symlinked directory - or a symlinked file - is never scanned. That is an INCOMPLETE-scan
  // condition exactly like FILE_TOO_LARGE above (never silently SAFE over a tree ShipGuard never opened).
  if (skippedSymlinks > 0) {
    const named = skippedSymlinkFiles.slice(0, 10).join(', ')
    const extra = skippedSymlinks > skippedSymlinkFiles.length || skippedSymlinkFiles.length > 10
      ? ` (and others)`
      : ''
    degradedReasons.push({
      code: 'SYMLINK_SKIPPED',
      detail: `${skippedSymlinks} symlink(s) were not followed (privacy moat) and were not scanned: ${named}${extra}`,
    })
  }

  if (coderefDegraded) {
    degradedReasons.push({
      code: 'CODEREF_SKIPPED',
      detail: 'One or more pro coderef rules were skipped because they require a newer CLI version.',
    })
  }

  // Invalid-UTF-8 files (and UTF-16 with a BOM that does not decode): cannot scan without risking
  // false-negatives (secrets straddling a boundary destroyed by replacement chars).
  if (changedInvalidUtf8.length > 0) {
    const named = changedInvalidUtf8.slice(0, 10).map(f => f.relativePath).join(', ')
    const extra = changedInvalidUtf8.length > 10 ? ` (and ${changedInvalidUtf8.length - 10} more)` : ''
    degradedReasons.push({
      code: 'INVALID_UTF8',
      detail: `${changedInvalidUtf8.length} file(s) contained invalid UTF-8 (or UTF-16 with a BOM that does not decode) and were not scanned: ${named}${extra}`,
    })
  }

  // Unreadable files: I/O errors, permission issues, or a file NAME that is not valid UTF-8.
  // These are incomplete-scan conditions - NEVER safe.
  if (changedUnreadable.length > 0) {
    const named = changedUnreadable.slice(0, 10).join(', ')
    const extra = changedUnreadable.length > 10 ? ` (and ${changedUnreadable.length - 10} more)` : ''
    const badNames = state.unaddressableCount > 0
      ? ` ${state.unaddressableCount} of them have a file name that is not valid UTF-8, cannot be addressed safely and were never read.`
      : ''
    degradedReasons.push({
      code: 'UNREADABLE_FILE',
      detail: `${changedUnreadable.length} file(s) could not be read and were not scanned: ${named}${extra}.${badNames}`,
    })
  }

  // Files with NUL or control data that no reading explains and that show no real-binary evidence.
  if (state.skippedUnknownBinary > 0) {
    const named = state.skippedUnknownBinaryFiles.slice(0, 10).join(', ')
    const extra = state.skippedUnknownBinary > Math.min(10, state.skippedUnknownBinaryFiles.length) ? ' (and others)' : ''
    degradedReasons.push({
      code: 'UNSCANNED_UNKNOWN_BINARY',
      detail:
        `${state.skippedUnknownBinary} file(s) contain NUL or control data that no text reading explains and show no sign of a known binary format, so they were not scanned: ${named}${extra}. ` +
        `If they are safe, add their paths to ignore.paths in shipguard.policy.yml.`,
    })
  }

  // Nothing at all was scanned: never SAFE. Evaluated last so the detail can name every cause.
  if (state.acceptedPaths === 0) {
    const parts: string[] = []
    const add = (n: number, label: string): void => {
      if (n > 0) parts.push(`${n} ${label}`)
    }
    add(state.skippedBinary, 'binary')
    add(skippedTooLarge, 'too large')
    add(skippedSymlinks, 'symlink')
    add(state.skippedUnknownBinary, 'unknown binary')
    add(changedInvalidUtf8.length, 'invalid UTF-8')
    add(changedUnreadable.length, 'unreadable')
    add(state.skippedSpecial, 'special')
    add(state.notReached, 'not reached')
    degradedReasons.push({
      code: 'NO_FILES_SCANNED',
      detail:
        `0 files were scanned (${state.discovered} candidate file(s)${parts.length > 0 ? `: ${parts.join(', ')}` : ''}, 0 readable). ` +
        `A scan that read nothing cannot report that shipping is safe.`,
    })
  }

  const isDegraded = degradedReasons.length > 0 || undefined

  const coverage = buildCoverage(state, mode, changedInfo)

  const result: ScanResultWithMeta = {
    findings: allFindings,
    riskScore,
    filesScanned: state.acceptedPaths,
    timestamp: new Date().toISOString(),
    policyUsed: policy.project.name,
    // Degraded when ANY of: coderef version-skip, truncation, an oversized file, a symlink not
    // followed, an unreadable/invalid/unknown-binary file, OR nothing scanned at all. Real binaries
    // (skipped.binary) are NORMAL and intentionally EXCLUDED: a real image has no source to scan.
    // scan.ts OR-merges this with its own pro-fetch-failure flag.
    treeDigest,
    degraded: isDegraded,
    // Machine-readable WHY for each degrade source - safe to key on in agent logic.
    // scan.ts OR-merges its own PRO_RULES_UNAVAILABLE entry after pro-fetch failure.
    degradedReasons: degradedReasons.length > 0 ? degradedReasons : undefined,
    coverage,
  }

  // Stamp the fail-closed verdict. A direct `scan` caller gets a correct, already-mirrored verdict
  // without having to know the rule. commands/scan.ts re-applies this AFTER it OR-merges the
  // pro-fetch degradation; applyVerdict is idempotent, so both calls are safe.
  applyVerdict(result)

  return result
}
