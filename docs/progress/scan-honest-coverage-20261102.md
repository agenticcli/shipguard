# scan-honest-coverage-20261102 - progress

- 2026-11-02: plans written (implementation, test plan, verification plan, risks): docs/plans/scan-honest-coverage-20261102.md. Session note: docs/sessions/scan-honest-coverage-20261102.md.
- No source code changed. Next: Opus judge + Codex review of the plans, then build.
- 2026-11-02 round 2: plan revised after NO-GO (see plan section R). Still plans only; no source code changed.
- 2026-11-02 round 3: plan revised after second NO-GO (section R3). Plans only.
- 2026-11-02 build: classifier, shared read path, coverage object, schemaVersion 6, new degrade codes, exact git names, shared ignore helper, BUG 2 fix (exitCode + return, startup EPIPE handlers, drain-safe exit), old tests updated, docs, C0 tarball rehearsal all done. Full suite 3524 passed, 7 skipped (baseline 3381); slow lane B13 and G8 pass. Fail-before evidence: docs/testlab/2026-11-02/fail-before/ (BUG 2: U4-...txt). C0: docs/testlab/2026-11-02/C0-tarball-rehearsal.txt. Draft PR open. No version bump, no tag, no publish. Review and QA agent mutation table still to run.
- 2026-11-02 after code review: binary strings reading for magic-verified binaries under the cap (coverage.decoded.binaryStringsScanned); tests scan-binary-strings (a)(b)(c); full suite 3530 passed, 7 skipped; plan line 336, ignore.ts comment, CHANGELOG, freeze test updated.
- 2026-11-02 after QA: non-UTF-8 folder names degrade (UNREADABLE_FILE); ShipGuard's own .gitignore counted in coverage.selfArtifacts, never scanned; 3 red QA rows now pass; full suite 3547 passed, 7 skipped; C0 rerun C0-rerun-703d0093.txt. Open decision: scans write .gitignore into the scan root.
- 2026-11-02 after QA re-check: unentered folders re-listed (class fix), own artifacts at any depth, git unreadable-folder warnings, changed-path symlinks, CI host-asset test opt-in; full suite 3562 passed, 8 skipped; C0-rerun-7f92ceb4.
