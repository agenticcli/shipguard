# Session: scan-honest-coverage-20261102

- Repo: agenticcli/shipguard (public, npm 0.8.1), base 2bf3a7d. Branch: scan-honest-coverage-20261102.
- Stakes: HIGH (security control in a release gate).
- Phase: PLANS ONLY. No code changed. Plan: docs/plans/scan-honest-coverage-20261102.md.

## Goal
1. BUG 1: `shipguard scan` must never say SAFE_TO_SHIP over files it did not read. JSON always reports coverage counts; UTF-16 and NUL-bearing text files are scanned; real binaries are counted; unclassifiable blobs, truncation and "nothing scanned" are degraded (DO_NOT_SHIP).
2. BUG 2: `scan --json --strict` must not lose piped stdout (re-implement archive PR #71 in this repo with its own test).

## Choices made in the plan
- NUL-bearing text: scan with each NUL replaced by one space; not degraded. NUL-heavy unknown blobs: skipped and degraded (`UNSCANNED_UNKNOWN_BINARY`).
- BOM-less UTF-16: detected only for ASCII-dominant text (NUL parity signature) and validated by strict decode; anything else falls to the degraded path.
- Zero scanned: `degraded:true` with `NO_FILES_SCANNED`, verdict DO_NOT_SHIP via the existing fail-closed rule. No new verdict value.
- `--strict`: unchanged function; every degraded case exits 1, non-degraded counts never change the exit code.
- matcher-contract: not touched (no byte-identity risk; the platform vendors the 0.5.1 tarball and uses only selector and canonical).
- JSON: new top-level `coverage` object, schemaVersion 5 to 6.

## Open questions for the main session
Q1 default-ignored text files (`*.log`, `*.min.js`, `vendor/`); Q2 `--changed` with zero diff; Q3 schema bump; Q4 extension list. See plan section E.

## Not done
No PR, no version bump, no tag, no publish.

## Round 2 (after NO-GO from the Opus judge and Codex)
Plan revised: magic bytes only for flagged, binary-dominant files and never by extension; no empty-diff exemption for `--changed`; `git -z` exact names plus one shared ignore helper; UTF-16 validated before NUL-to-space; bug 2 never calls `process.exit` with queued output (exitCode and return, EPIPE handler, handshake test); `--check-regressions` needs `--strict`; behavioural mutation matrix over both read paths; mandatory tarball rehearsal before publish. Map in plan section R.
Round 3 (final): plan revised again; see plan section R3. Decisions: check-regressions kept as is, EPIPE handlers at startup, probe without touching exitCode, ambiguity union, UTF-8-aware Gate 3, strict-UTF-8 head shortcut, nested-root and Buffer filename handling.
