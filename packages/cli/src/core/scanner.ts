import { readFile, stat, realpath } from 'node:fs/promises'
import { sha256 } from '@noble/hashes/sha2.js'
import { dirname, join } from 'node:path'
import { loadPolicy } from './policy.js'
import { computeRiskScore } from './risk-score.js'
import { applyVerdict } from './verdict.js'
import { RUNS_SUBDIR } from './report.js'
import { isGitRepo, getChangedFiles } from './git.js'
import { readFiles, compareScanPaths, DEFAULT_MAX_FILE_SIZE_BYTES, DEFAULT_MAX_TOTAL_BYTES, DEFAULT_MAX_FILES } from '../utils/fs.js'
import { logger } from '../utils/logger.js'
import { secretsCheck } from '../checks/secrets.js'
import { authCheck } from '../checks/auth.js'
import { databaseCheck } from '../checks/database.js'
import { payments } from '../checks/payments.js'
import { deploymentCheck } from '../checks/deployment.js'
import type { FileInfo, Finding, Policy, ScanOptions, ScanResult, QualityGateRule, DegradeReason } from '@agenticcli/shared'
import { HISTORY_PATH_ENV_VAR } from '@agenticcli/shared'
import { runProRulesWithDispatch, runProRules } from './pro-scanner.js'
import { loadChecksumManifest } from './coderef-dispatch.js'
import { applySuppressions, isLineSuppressed } from './suppression.js'
import { loadBundledRules } from './bundled-rules.js'
import { dedupeLegacyAgainstCorpus } from './legacy-corpus-map.js'
import { collapseSameIssueFindings } from './collapse-findings.js'
import { redactFindingsEvidence } from './redact.js'
import {
  decodeUtf8Strict,
  detectBinary,
  stripBom,
  normalizeNewlines,
} from '@agenticcli/matcher-contract'

const CHECK_MODULES = [secretsCheck, authCheck, databaseCheck, payments, deploymentCheck]

const DEFAULT_IGNORE = [
  'node_modules/**',
  'dist/**',
  'build/**',
  '.next/**',
  'coverage/**',
  '.git/**',
  // ShipGuard's own report output — never scan the tool's own artifacts
  '.shipguard/**',
]

/**
 * Ignore patterns for ShipGuard's OWN artifacts when the policy points them somewhere
 * other than the default `.shipguard/` directory.
 *
 * "Exclude `.shipguard/` from ShipGuard's own scan surface."
 * `.shipguard/**` was already excluded, but `report.output` and `history.path` are
 * user-configurable — set `report.output: reports/latest.md` and from the second scan
 * onward ShipGuard reads its own report and history back in. Verified before this fix:
 * a two-file project reported `filesScanned: 6` on its second run. Self-scan recursion is
 * a demonstrated hazard class (the test round's own gitleaks probe self-contaminated), and
 * today it only fails to produce phantom findings because report evidence happens to be
 * masked — one format change away from a finding ShipGuard reported about itself.
 *
 * Pure: (policy) -> patterns. No filesystem access.
 */
export function selfArtifactIgnorePatterns(policy: Policy): string[] {
  const patterns: string[] = []

  const add = (p: string | undefined): void => {
    if (!p) return
    // Only project-relative paths can be matched against fast-glob's relative results;
    // an absolute path is outside the scan root's pattern space anyway.
    if (p.startsWith('/')) return
    const rel = p.replace(/^\.\//, '')
    if (!rel) return
    patterns.push(rel)
  }

  const reportOutput = policy.report?.output
  add(reportOutput)
  if (reportOutput) {
    // generateReport() writes a .json sibling next to the .md — exclude it too.
    add(reportOutput.replace(/\.md$/, '.json'))
    // ...and the whole per-run report directory (rec #8). Excluding a NAMED directory is
    // what makes this tractable: run filenames are unpredictable run ids, so there is
    // nothing else stable to match on, and without it every scan leaves two more files
    // for the next scan to read.
    const reportDir = dirname(reportOutput)
    add(join(reportDir === '.' ? '' : reportDir, RUNS_SUBDIR, '**'))
  }
  add(policy.history?.path)
  // The env override wins over the policy value (see history/path.ts), so honour it here too.
  add(process.env[HISTORY_PATH_ENV_VAR])

  return patterns
}

/**
 * Internal result that extends ScanResult with skip/truncation metadata.
 * These counts are used only by the human-output path in commands/scan.ts
 * and are NOT included in the frozen --json schema.
 */
export interface ScanResultWithMeta extends ScanResult {
  /**
   * Count of files skipped because they exceeded the per-file size cap.
   * This is a DEGRADED condition: a skipped file
   * was NOT scanned, so the scan is incomplete and must not report SAFE.
   */
  _skippedTooLarge?: number
  /** Relative paths of the oversized-skipped files — used to NAME them in the warning. */
  _skippedTooLargeFiles?: string[]
  /** Files skipped due to binary content detection. NORMAL — not a degradation. */
  _skippedBinary?: number
  /**
   * Relative paths of the binary-skipped files — used to NAME them in the human-output
   * line (symlink reporting: this file's own docs already admitted binary skips happen,
   * but never named which files, unlike every other skip category). Still NORMAL — not
   * wired into degraded/degradedReasons; a binary file has no source to scan (see the
   * comment on `degradedReasons` below for why this is deliberately excluded).
   */
  _skippedBinaryFiles?: string[]
  /**
   * Count of symlinks discovered but not followed (symlink reporting). Unlike
   * skippedBinary this IS a degraded condition (see degradedReasons below) — kept here
   * too so the human-output path can print the same warning shape as the other skip
   * categories.
   */
  _skippedSymlinks?: number
  /** Relative paths of the skipped symlinks — used to NAME them in the warning. */
  _skippedSymlinkFiles?: string[]
  /** true if collection was truncated (total bytes or file count cap hit). Degraded condition. */
  _truncated?: boolean
}

/**
 * Content-addressed digest of everything the scan read.
 *
 * `sha256( for each file, in sorted path order: path + NUL + hex(sha256(content)) + LF )`.
 *
 * Sorted path order (the same `compareScanPaths` ordering rec #7 established) makes it
 * reproducible; hashing per-file content rather than concatenating raw bytes keeps a
 * rename from being invisible and keeps file boundaries unambiguous.
 *
 * Note what it covers: the NORMALIZED content the checks actually ran against (BOM
 * stripped, CRLF folded to LF — see utils/fs.ts Gate 5), not the raw bytes on disk. That
 * is the honest thing to attest to, because it is what produced the findings.
 *
 * Returns undefined when nothing was read — an empty digest would falsely imply "I looked
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

export async function scan(
  options: ScanOptions,
  proRules?: QualityGateRule[],
  onProgress?: (current: number, total: number, file: string) => void,
): Promise<ScanResultWithMeta> {
  const cwd = process.cwd()
  const policy = await loadPolicy(cwd)

  const ignorePatterns = [
    ...DEFAULT_IGNORE,
    // Rec #6 — ShipGuard's own artifacts, wherever the policy put them.
    ...selfArtifactIgnorePatterns(policy),
    ...policy.ignore.paths,
  ]

  // Resolve limits from policy — merged with defaults in loadPolicy, but fall back to constants
  // in case an older/minimal policy object is passed (e.g. from test mocks without limits).
  const limits = {
    maxFileSizeBytes: policy.limits?.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES,
    maxTotalBytes: policy.limits?.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES,
    maxFiles: policy.limits?.maxFiles ?? DEFAULT_MAX_FILES,
  }

  let files: FileInfo[]
  let skippedTooLarge = 0
  const skippedTooLargeFiles: string[] = []
  let skippedBinary = 0
  const skippedBinaryFiles: string[] = []
  let skippedSymlinks = 0
  const skippedSymlinkFiles: string[] = []
  let truncated = false
  // Degraded-file accumulators for the --changed path (the normal path uses readFiles()
  // which returns its own invalidUtf8Files/unreadableFiles that are merged below).
  const changedInvalidUtf8: Array<{ relativePath: string; reason: string }> = []
  const changedUnreadable: string[] = []

  if (options.changedOnly && isGitRepo(cwd)) {
    // getChangedFiles() throws GitCommandError on a genuine git failure — it
    // is intentionally NOT caught here. RCA (git.ts:45-47): the old
    // implementation silently returned [] on ANY git error, so `--changed`
    // would report "0 files scanned, SAFE" for a git failure indistinguishably
    // from "genuinely nothing changed." Letting the throw propagate up to
    // scan.ts's existing try/catch maps a real git failure to exit 3
    // (RUNTIME_ERROR) with the git stderr in the message — fail loud, not safe.
    const changedRelPaths = getChangedFiles(cwd)
    if (changedRelPaths.length === 0) {
      // Git ran successfully and genuinely found nothing changed — this is
      // the OTHER branch of the fix: an explicit, distinguishable message
      // for "0 files, and that's correct" vs a swallowed git failure.
      logger.info('--changed: git ran successfully — 0 changed files to scan.')
    }
    // Filter out ignored patterns (simple prefix/suffix check against default ignores),
    // including ShipGuard's own relocated artifacts (rec #6).
    const changedIgnore = [...DEFAULT_IGNORE, ...selfArtifactIgnorePatterns(policy)]
    const filteredPaths = changedRelPaths
      .filter((rp) =>
        !changedIgnore.some((pat) => {
          const prefix = pat.replace('/**', '')
          return rp.startsWith(prefix + '/') || rp === prefix
        })
      )
      // Rec #7 — sort BEFORE the cap. git's diff order is not a contract, so an
      // over-cap `--changed` run would otherwise scan a different subset run to run.
      .sort(compareScanPaths)

    files = []
    let totalBytes = 0
    const changedTotal = filteredPaths.length
    let changedProcessed = 0

    for (const relPath of filteredPaths) {
      // Stop collecting if cumulative caps are reached
      if (files.length >= limits.maxFiles || totalBytes >= limits.maxTotalBytes) {
        truncated = true
        break
      }

      const fullPath = join(cwd, relPath)
      try {
        // Symlink / root-containment guard — matches the normal path's behaviour
        // (readFiles uses followSymbolicLinks:false in fast-glob). The --changed
        // path resolves a git-reported path with join(cwd,rel); a symlink in that
        // path could escape the project root. We resolve the real path and verify
        // it starts with cwd before reading.
        //
        // Note: realpath() throws ENOENT for dangling symlinks → caught below →
        // accumulated as an unreadable file (intentionally degraded, not silently
        // skipped), which is the correct conservative behaviour.
        let resolvedPath: string
        try {
          resolvedPath = await realpath(fullPath)
        } catch (realpathErr: unknown) {
          // Dangling symlink or path-not-found: degrade loudly.
          const detail = realpathErr instanceof Error ? realpathErr.message : String(realpathErr)
          logger.warn(`[shipguard] Could not resolve path for changed file ${relPath}: ${detail}`)
          changedUnreadable.push(relPath)
          onProgress?.(++changedProcessed, changedTotal, relPath)
          continue
        }

        // Containment check: resolved path must start with the canonical cwd.
        // We compare against the canonicalised cwd (also realpath'd once at the top
        // of the changed-path block so we don't call realpath(cwd) per file).
        // If the resolved path escapes the root, refuse it — same policy as
        // followSymbolicLinks:false in the normal path.
        const canonicalCwd = await realpath(cwd).catch(() => cwd)
        const cwdWithSep = canonicalCwd.endsWith('/') ? canonicalCwd : canonicalCwd + '/'
        if (!resolvedPath.startsWith(cwdWithSep) && resolvedPath !== canonicalCwd) {
          logger.warn(
            `[shipguard] Refusing out-of-root path for changed file ${relPath}: ` +
            `resolved to ${resolvedPath} which is outside ${canonicalCwd}`,
          )
          // Count as unreadable (degraded) so the scan is non-safe — just like
          // encountering an out-of-root symlink on the normal path would be.
          changedUnreadable.push(relPath)
          onProgress?.(++changedProcessed, changedTotal, relPath)
          continue
        }

        // Gate 1: size cap — never allocate buffer for oversized files
        const fileStat = await stat(resolvedPath)
        if (fileStat.size > limits.maxFileSizeBytes) {
          skippedTooLarge++
          if (skippedTooLargeFiles.length < 50) {
            skippedTooLargeFiles.push(relPath)
          }
          onProgress?.(++changedProcessed, changedTotal, relPath)
          continue
        }

        // Gate 2: read as Buffer (bounded by maxFileSizeBytes)
        const buffer = await readFile(resolvedPath)

        // Gate 3: binary detection — scan the ENTIRE buffer using the contract's
        // detectBinary (NUL-anywhere + density heuristic). The old code checked
        // only the first 8192 bytes.
        if (detectBinary(new Uint8Array(buffer))) {
          skippedBinary++
          onProgress?.(++changedProcessed, changedTotal, relPath)
          continue
        }

        // Gate 4: strict UTF-8 decoding — NEVER use buffer.toString('utf-8').
        // See fs.ts Gate 4 comment for full rationale.
        const decoded = decodeUtf8Strict(new Uint8Array(buffer))
        if (!decoded.ok) {
          changedInvalidUtf8.push({ relativePath: relPath, reason: decoded.reason })
          onProgress?.(++changedProcessed, changedTotal, relPath)
          continue
        }

        // Gate 5: BOM + CRLF normalization — same as readFiles() Gate 5.
        const content = normalizeNewlines(stripBom(decoded.text))

        totalBytes += buffer.length
        files.push({ path: fullPath, content, relativePath: relPath })
      } catch (err: unknown) {
        // Unreadable file — degrade loudly (not silently swallowed).
        // Previously a bare catch{} at scanner.ts:131-133 silently skipped
        // unreadable files. Now accumulated for degradation.
        const detail = err instanceof Error ? err.message : String(err)
        logger.warn(`[shipguard] Could not read changed file ${relPath}: ${detail}`)
        changedUnreadable.push(relPath)
      }

      onProgress?.(++changedProcessed, changedTotal, relPath)
    }
  } else {
    if (options.changedOnly && !isGitRepo(cwd)) {
      logger.warn('--changed flag set but not a git repository — scanning all files')
    }
    const readResult = await readFiles(cwd, ['**/*'], ignorePatterns, {
      maxFileSizeBytes: limits.maxFileSizeBytes,
      maxTotalBytes: limits.maxTotalBytes,
      maxFiles: limits.maxFiles,
      onProgress,
    })
    files = readResult.files
    skippedTooLarge = readResult.skippedTooLarge
    skippedTooLargeFiles.push(...readResult.skippedTooLargeFiles)
    skippedBinary = readResult.skippedBinary
    skippedBinaryFiles.push(...readResult.skippedBinaryFiles)
    skippedSymlinks = readResult.skippedSymlinks
    skippedSymlinkFiles.push(...readResult.skippedSymlinkFiles)
    truncated = readResult.truncated
    // Merge the new degraded-file accumulators from readFiles into the changed-path
    // accumulators (both start empty for the normal path; only one set is non-empty).
    changedInvalidUtf8.push(...readResult.invalidUtf8Files)
    changedUnreadable.push(...readResult.unreadableFiles)
  }

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

  if (truncated) {
    degradedReasons.push({
      code: 'OUTPUT_TRUNCATED',
      detail: 'File count or total size ceiling was reached; collection stopped early — results are incomplete.',
    })
  }

  // Symlinks discovered but not followed (symlink reporting): followSymbolicLinks:false
  //  means an entire
  // subtree behind a symlinked directory — or a symlinked file — is never scanned. That
  // is an INCOMPLETE-scan condition exactly like FILE_TOO_LARGE above, so it degrades
  // the verdict the same way (never silently SAFE over a tree ShipGuard never opened).
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

  // Invalid-UTF-8 files: cannot scan without risking false-negatives (secrets
  // straddling a boundary destroyed by replacement chars).
  // Degrade loudly so the user knows the scan is incomplete.
  if (changedInvalidUtf8.length > 0) {
    const named = changedInvalidUtf8.slice(0, 10).map(f => f.relativePath).join(', ')
    const extra = changedInvalidUtf8.length > 10 ? ` (and ${changedInvalidUtf8.length - 10} more)` : ''
    degradedReasons.push({
      code: 'INVALID_UTF8',
      detail: `${changedInvalidUtf8.length} file(s) contained invalid UTF-8 and were not scanned: ${named}${extra}`,
    })
  }

  // Unreadable files: skipped due to I/O errors or permission issues.
  // These are incomplete-scan conditions — NEVER safe.
  if (changedUnreadable.length > 0) {
    const named = changedUnreadable.slice(0, 10).join(', ')
    const extra = changedUnreadable.length > 10 ? ` (and ${changedUnreadable.length - 10} more)` : ''
    degradedReasons.push({
      code: 'UNREADABLE_FILE',
      detail: `${changedUnreadable.length} file(s) could not be read and were not scanned: ${named}${extra}`,
    })
  }

  const isDegraded = degradedReasons.length > 0 || undefined

  const result: ScanResultWithMeta = {
    findings: allFindings,
    riskScore,
    filesScanned: files.length,
    timestamp: new Date().toISOString(),
    policyUsed: policy.project.name,
    // Degraded when ANY of: coderef version-skip, collection truncation, a file
    // skipped for being too large, OR a symlink not followed (symlink reporting).
    // The oversized-skip case  and the symlink-skip
    // case both mean content was NOT scanned — the scan is incomplete, so it must
    // NOT be reported SAFE. Binary skips (skippedBinary) are NORMAL and
    // intentionally EXCLUDED — a binary file legitimately has no source to scan.
    // scan.ts OR-merges this with its own pro-fetch-failure flag.
    treeDigest,
    degraded: isDegraded,
    // Machine-readable WHY for each degrade source — safe to key on in agent logic.
    // scan.ts OR-merges its own PRO_RULES_UNAVAILABLE entry after pro-fetch failure.
    degradedReasons: degradedReasons.length > 0 ? degradedReasons : undefined,
    // Internal metadata for the human-output path — NOT included in --json output
    _skippedTooLarge: skippedTooLarge,
    _skippedTooLargeFiles: skippedTooLargeFiles,
    _skippedBinary: skippedBinary,
    _skippedBinaryFiles: skippedBinaryFiles,
    _skippedSymlinks: skippedSymlinks,
    _skippedSymlinkFiles: skippedSymlinkFiles,
    _truncated: truncated,
  }

  // Stamp the fail-closed verdict . A direct `scan` caller
  // tests, the future boundary harness — gets a correct, already-mirrored verdict
  // without having to know the rule. commands/scan.ts re-applies this AFTER it
  // OR-merges the pro-fetch degradation, which is the first point the FINAL
  // `degraded` value is known; applyVerdict is idempotent, so both calls are safe.
  applyVerdict(result)

  return result
}
