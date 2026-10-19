import fg from 'fast-glob'
import { readFile, stat } from 'node:fs/promises'
import { join, relative } from 'node:path'
import type { FileInfo } from '@agenticcli/shared'
import {
  decodeUtf8Strict,
  detectBinary,
  stripBom,
  normalizeNewlines,
} from '@agenticcli/matcher-contract'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default max size for a single file (512 KB). Files larger than this are skipped entirely. */
export const DEFAULT_MAX_FILE_SIZE_BYTES = 512 * 1024

/** Default max cumulative bytes across all files (256 MB). Collection stops if exceeded. */
export const DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024

/** Default max number of files to collect. Collection stops if exceeded. */
export const DEFAULT_MAX_FILES = 5000

// ---------------------------------------------------------------------------
// Extended default ignore list (merged with existing node_modules/dist/etc.)
// These prevent reading large, irrelevant artifacts and avoid OOM on big repos.
// ---------------------------------------------------------------------------

const DEFAULT_IGNORE = [
  'node_modules/**',
  'dist/**',
  'build/**',
  '.next/**',
  'coverage/**',
  '.git/**',
  '*.lock',
  'pnpm-lock.yaml',
  'package-lock.json',
  // Extended — large artifact directories
  '.cache/**',
  '.turbo/**',
  '.venv/**',
  'venv/**',
  'vendor/**',
  'tmp/**',
  'out/**',
  // Large file extensions — binary and generated
  '*.log',
  '*.min.js',
  '*.map',
  '*.png',
  '*.jpg',
  '*.jpeg',
  '*.gif',
  '*.webp',
  '*.ico',
  '*.pdf',
  '*.zip',
  '*.gz',
  '*.tar',
  '*.mp4',
  '*.mov',
  '*.wasm',
  '*.node',
  '.DS_Store',
  // ShipGuard's own report output — never scan the tool's own artifacts
  '.shipguard/**',
]

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ReadFilesOptions {
  /** Max size for a single file in bytes (default: DEFAULT_MAX_FILE_SIZE_BYTES). */
  maxFileSizeBytes?: number
  /** Max cumulative bytes across all files (default: DEFAULT_MAX_TOTAL_BYTES). */
  maxTotalBytes?: number
  /** Max number of files to collect (default: DEFAULT_MAX_FILES). */
  maxFiles?: number
  /**
   * Optional progress callback invoked after each file is accepted (or skipped).
   * @param current  - files processed so far (accepted + skipped)
   * @param total    - total files discovered (before filtering)
   * @param file     - relative path of the current file being processed
   */
  onProgress?: (current: number, total: number, file: string) => void
}

export interface ReadFilesResult {
  files: FileInfo[]
  /** Count of files skipped because they exceeded maxFileSizeBytes. */
  skippedTooLarge: number
  /**
   * Relative paths of files skipped because they exceeded maxFileSizeBytes.
   * Used to emit a LOUD warning that NAMES what was not scanned (oversized-file skip): an oversized skip is an INCOMPLETE scan, so the user
   * must be told which file(s) went unscanned. Capped to avoid unbounded
   * memory on pathological trees.
   */
  skippedTooLargeFiles: string[]
  /** Count of files skipped because they contained a NUL byte (binary detection). */
  skippedBinary: number
  /**
   * Relative paths of files skipped because they were detected as binary (Gate 3
   * below). Binary skips are NORMAL — a binary file has no source text to pattern
   * match, so this does NOT make a scan degraded/incomplete (see scanner.ts's
   * explicit exclusion of skippedBinary from degradedReasons). What was missing,
   * unlike every other skip category in this file, is naming WHICH files — only a
   * count was ever kept. Named here so callers can report them loudly (symlink
   * reporting) without changing the safe/degraded verdict. Capped like
   * skippedTooLargeFiles.
   */
  skippedBinaryFiles: string[]
  /**
   * Count of symlinks (file or directory) that were discovered but NOT followed,
   * per followSymbolicLinks:false above.
   *
   * Unlike every other skip category in this file, this one used to carry ZERO
   * signal anywhere — not even a count (symlink reporting): fast-glob's own
   * deep/entry filters silently drop a symlink entry when followSymbolicLinks is
   * false, so a symlinked directory's entire subtree is never even enumerated by
   * `filePaths` above. A project whose `src/` is a symlink would scan
   * filesScanned=1, degraded=false, stderr empty — a near-clean verdict over a
   * tree ShipGuard never opened.
   */
  skippedSymlinks: number
  /**
   * Relative paths of the symlinks named in skippedSymlinks (symlink reporting).
   * A skipped symlink means an entire subtree may be unscanned — this is an
   * INCOMPLETE-scan condition exactly like skippedTooLargeFiles, so the scanner
   * marks the result DEGRADED and non-safe when this list is non-empty (no silent failures). Capped like skippedTooLargeFiles.
   */
  skippedSymlinkFiles: string[]
  /**
   * true if collection was stopped early because maxTotalBytes or maxFiles was hit.
   * This is a LOUD warning condition: scan results are incomplete.
   * A binary skip (skippedBinary) is normal and does NOT set truncated.
   * NOTE: an oversized-file skip (skippedTooLarge) is treated as a DEGRADED
   * condition by the scanner (it means a file was not scanned), but it does not
   * set `truncated` here — `truncated` specifically means the whole collection
   * was cut short by the total-bytes/file-count cap.
   */
  truncated: boolean
  /**
   * Files that could not be decoded as valid UTF-8.
   *
   * These files were SKIPPED (not scanned) because invalid UTF-8 byte sequences
   * could silently destroy secrets straddling the boundary (the replacement-char
   * bug — GROUND-TRUTH §1). The scanner MUST mark the result degraded and
   * non-safe when this list is non-empty.
   *
   * Each entry carries the relative path and the decode error reason.
   */
  invalidUtf8Files: Array<{ relativePath: string; reason: string }>
  /**
   * Files that could not be read from disk at all (permission error, deleted
   * during scan, I/O error, etc.).
   *
   * Previously these were silently swallowed by a bare `catch{}` (fs.ts:213-215).
   * Now they are accumulated and propagated so the scanner can mark the result
   * degraded (a skipped file is an incomplete scan — NEVER safe).
   */
  unreadableFiles: string[]
}

/** Cap on how many skipped-too-large file names we retain for the warning. */
const MAX_SKIPPED_NAMES = 50

/**
 * The documented cross-platform traversal order.
 *
 * Verbatim: "Sort-before-cap deterministic traversal (documented cross-platform ordering
 * before the 5,000-file ceiling applies)."
 *
 * WHY: `fast-glob` returns paths in whatever order the filesystem hands them back. That is
 * not the same on ext4, APFS and NTFS, and it is not even stable across runs on some of
 * them. Once `maxFiles`/`maxTotalBytes` truncates collection, traversal order stops being
 * an implementation detail and becomes POLICY: the same repository on two machines scans a
 * DIFFERENT subset of files and can produce a different verdict.
 *
 * The order: byte-wise ascending comparison of the project-relative path, using plain `<`
 * on UTF-16 code units. Deliberately NOT `localeCompare` — that is locale-sensitive, so it
 * would reintroduce exactly the machine-dependence this removes.
 *
 * This is also a precondition for the boundary/scale round: a test that
 * plants a finding at position 4,999 / 5,000 / 5,001 is only reproducible if position means
 * the same thing everywhere.
 */
export function compareScanPaths(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

// ---------------------------------------------------------------------------
// Core function
// ---------------------------------------------------------------------------

export async function readFiles(
  rootDir: string,
  patterns: string[] = ['**/*'],
  ignorePatterns: string[] = [],
  options: ReadFilesOptions = {},
): Promise<ReadFilesResult> {
  const maxFileSizeBytes = options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES
  const maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES
  const { onProgress } = options

  const allIgnore = [...DEFAULT_IGNORE, ...ignorePatterns]

  const filePaths = await fg(patterns, {
    cwd: rootDir,
    ignore: allIgnore,
    dot: true,
    absolute: false,
    onlyFiles: true,
    // Privacy moat: NEVER follow symlinks. A symlink inside
    // the project pointing out of the root (e.g. `ln -s /home escape`) would
    // otherwise cause the scan to descend out-of-tree, reading and reporting
    // files the user never intended to scan (and risking a hang on huge external
    // trees). The user's code must never leave their machine; out-of-tree files
    // must never enter the scan. fast-glob defaults this to true, so it is
    // load-bearing that we set it false explicitly.
    followSymbolicLinks: false,
  })

  // Rec #7 — SORT BEFORE THE CAP. Must happen before the collection loop below, which
  // stops at maxFiles/maxTotalBytes; sorting after truncation would be meaningless.
  filePaths.sort(compareScanPaths)

  // symlink reporting: name what followSymbolicLinks:false silently drops.
  //
  // fast-glob's own filters (providers/filters/deep.js _isSkippedSymbolicLink,
  // providers/filters/entry.js _onlyFileFilter) reject a symlink dirent from the
  // `filePaths` call above with ZERO signal: a symlinked directory is never
  // descended into (its entire subtree is never even enumerated), and a symlinked
  // file fails the onlyFiles:true check because @nodelib/fs.scandir uses the raw
  // (lstat-based) dirent when followSymbolicLinks is false, whose isFile()/
  // isDirectory() are both false for a symlink. The correct, documented privacy
  // decision (never follow symlinks) was therefore also a
  // SILENT one: a project whose `src/` is a symlink scanned filesScanned=1,
  // degraded=false, stderr empty.
  //
  // This second pass walks the identical pattern/ignore space (so it prunes the
  // same directories) but with onlyFiles:false + onlyDirectories:false (neither
  // entry-filter predicate rejects on dirent type) and objectMode:true so the
  // dirent is available. It reads no file content — same cost class as the
  // stat() call Gate 1 already pays per file — and its ONLY purpose is to name
  // every symlink entry that the primary call above silently swallowed.
  const symlinkProbeEntries = await fg(patterns, {
    cwd: rootDir,
    ignore: allIgnore,
    dot: true,
    absolute: false,
    onlyFiles: false,
    followSymbolicLinks: false,
    objectMode: true,
  })
  const allSkippedSymlinkPaths = symlinkProbeEntries
    .filter((entry) => entry.dirent.isSymbolicLink())
    .map((entry) => entry.path)
    .sort(compareScanPaths)
  const skippedSymlinks = allSkippedSymlinkPaths.length
  const skippedSymlinkFiles = allSkippedSymlinkPaths.slice(0, MAX_SKIPPED_NAMES)

  if (skippedSymlinks > 0) {
    // Unconditional — fires regardless of --json/--quiet, matching the loud
    // precedent the --changed path already sets for a symlink-adjacent refusal
    // (scanner.ts's out-of-root containment warning) and this file's own existing
    // console.warn for unreadable files below.
    const named = skippedSymlinkFiles.join(', ')
    const more = skippedSymlinks > skippedSymlinkFiles.length ? ' (and others)' : ''
    console.warn(
      `[shipguard] Scan INCOMPLETE: ${skippedSymlinks} symlink(s) not followed (privacy protection) and NOT scanned: ${named}${more}`,
    )
  }

  const total = filePaths.length
  const files: FileInfo[] = []
  let skippedTooLarge = 0
  const skippedTooLargeFiles: string[] = []
  let skippedBinary = 0
  const skippedBinaryFiles: string[] = []
  let truncated = false
  let totalBytes = 0
  let processed = 0
  const invalidUtf8Files: Array<{ relativePath: string; reason: string }> = []
  const unreadableFiles: string[] = []

  for (const fp of filePaths) {
    // Stop collecting if either cumulative cap is reached.
    // This is a LOUD degraded condition — callers must surface a warning.
    if (files.length >= maxFiles || totalBytes >= maxTotalBytes) {
      truncated = true
      break
    }

    const fullPath = join(rootDir, fp)

    try {
      // Gate 1: size cap — stat before allocating any buffer.
      // This is the primary OOM prevention: we NEVER allocate a buffer for oversized files.
      const fileStat = await stat(fullPath)
      if (fileStat.size > maxFileSizeBytes) {
        skippedTooLarge++
        if (skippedTooLargeFiles.length < MAX_SKIPPED_NAMES) {
          skippedTooLargeFiles.push(fp)
        }
        onProgress?.(++processed, total, fp)
        continue
      }

      // Gate 2: read as Buffer (bounded by maxFileSizeBytes).
      // Every allocation is now ≤ maxFileSizeBytes.
      const buffer = await readFile(fullPath)

      // Gate 3: binary detection — scan the ENTIRE buffer for NUL bytes (primary
      // signal) plus a non-printable-byte density heuristic (secondary signal).
      // The old code checked only the first 8192 bytes — a NUL at position 9000
      // would be missed, causing binary content to be decoded as garbage/replacement
      // chars and pattern-matched (GROUND-TRUTH §1 binary-check bug).
      // detectBinary() from the matcher-contract scans the full buffer.
      if (detectBinary(new Uint8Array(buffer))) {
        skippedBinary++
        if (skippedBinaryFiles.length < MAX_SKIPPED_NAMES) {
          skippedBinaryFiles.push(fp)
        }
        onProgress?.(++processed, total, fp)
        continue
      }

      // Gate 4: strict UTF-8 decoding — NEVER use buffer.toString('utf-8') here.
      // buffer.toString silently replaces invalid byte sequences with U+FFFD (the
      // replacement character ''), which can destroy secrets straddling an
      // invalid-UTF-8 boundary and cause a silent false-negative scan (live bug
      // documented in GROUND-TRUTH §1 / fs.ts:205).
      //
      // decodeUtf8Strict uses TextDecoder({fatal:true}) — throws on any invalid
      // byte sequence. On failure we accumulate the file in invalidUtf8Files so
      // the scanner can mark the result DEGRADED + non-safe (no silent
      // failures). NEVER scan with garbage content.
      const decoded = decodeUtf8Strict(new Uint8Array(buffer))
      if (!decoded.ok) {
        invalidUtf8Files.push({ relativePath: fp, reason: decoded.reason })
        // Do NOT push to files — the content is unusable. The caller must degrade.
        onProgress?.(++processed, total, fp)
        continue
      }

      // Gate 5: BOM stripping + newline normalization (CRLF → LF, bare CR → "").
      // Must happen AFTER decode and BEFORE line slicing. stripBom removes the
      // UTF-8 BOM (U+FEFF) if present; normalizeNewlines strips all \r so that
      // CRLF files produce clean LF-only content for line/column computations.
      const content = normalizeNewlines(stripBom(decoded.text))

      totalBytes += buffer.length

      files.push({
        path: fullPath,
        content,
        relativePath: fp,
      })
    } catch (err: unknown) {
      // Unreadable file (permission error, deleted during scan, I/O error, etc.)
      // Previously swallowed silently (fs.ts:213-215 bare catch{}). Now accumulated
      // in unreadableFiles so the scanner can mark the result DEGRADED + non-safe
      // (loud errors; a skipped file = incomplete scan, NEVER safe).
      const detail = err instanceof Error ? err.message : String(err)
      console.warn(`[shipguard] Could not read file ${fp}: ${detail}`)
      unreadableFiles.push(fp)
    }

    // Notify progress after every file (accepted, skipped, or errored).
    onProgress?.(++processed, total, fp)
  }

  return {
    files,
    skippedTooLarge,
    skippedTooLargeFiles,
    skippedBinary,
    skippedBinaryFiles,
    skippedSymlinks,
    skippedSymlinkFiles,
    truncated,
    invalidUtf8Files,
    unreadableFiles,
  }
}

export async function readFileContent(filePath: string): Promise<string> {
  return readFile(filePath, 'utf-8')
}
