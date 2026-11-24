# Releasing @agenticcli/shipguard

Release tags (`vX.Y.Z`) are protected: they cannot be deleted or moved. A tag on a commit that cannot pass the
release gate would burn that version for good. So the gate runs first, and only a workflow creates the tag.

**Humans and sessions never push a release tag by hand.** Not with `git tag`, not with the API, not from the web UI.

## Steps

1. Land the version bump on `main` through a PR: `packages/cli/package.json`, the top `CHANGELOG.md` entry (with a real
   date), `CITATION.cff`, the OpenVEX purl and the pinned versions. `bash scripts/release-facts.sh sync --tag vX.Y.Z`
   rewrites them.
2. **Preflight.** The `Release preflight` workflow runs by itself on every push to `main` that changes
   `packages/cli/package.json`. To run it by hand: `gh workflow run release-preflight.yml --ref main`. It runs the same
   steps as the release build (install, build, lint, test, `scripts/release-gate.sh` G1-G12 in real mode, pack),
   from one shared composite action (`.github/actions/release-build`), and it never publishes. Fix any failure with a
   normal PR, then preflight again.
3. **Tag.** `gh workflow run release-tag.yml --ref main -f version=X.Y.Z`. The `Release tag` workflow refuses unless
   `main` HEAD has a green preflight for its exact SHA and `package.json` says `X.Y.Z`. Then it creates the annotated
   tag and starts `release.yml` on it.
4. **Release.** `release.yml` first checks again that the tagged SHA has a green preflight (it fails before anything
   else if not), then builds with the same shared action, publishes to npm with provenance (trusted publishing, no
   token) and creates the GitHub Release. It needs the `npm-publish` environment approval.

## Why it is built this way

- One definition of the gate (`.github/actions/release-build`) is called by both `release-preflight.yml` and
  `release.yml`, so what passes before the tag is exactly what runs at release time.
- The proof is a successful `release-preflight.yml` run whose `head_sha` is the commit being tagged
  (`scripts/check-preflight.sh`, covered by `packages/cli/tests/release/preflight.test.ts`). The preflight always tests
  the commit it runs on; it cannot vouch for another SHA.
- `release-tag.yml` starts `release.yml` itself: a tag created with the workflow token does not fire the tag push event.
- A rehearsal that skips a real check is a bug. `RELEASE_GATE_DRY_RUN=1` exists for local rehearsals only; it is never
  set in these workflows.

## Settings these workflows rely on

- The tag ruleset `release tags are immutable` blocks delete, move and update of `v*` tags. It must not add a
  `creation` rule that excludes the GitHub Actions app, or `release-tag.yml` cannot create tags.
- The `npm-publish` environment and the npm trusted publisher (workflow `release.yml`) are unchanged.
