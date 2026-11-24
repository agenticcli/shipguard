#!/usr/bin/env bash
# check-preflight.sh - is there a green release-preflight run for this exact commit?
#
#   check-preflight.sh <40-hex sha> [--repo OWNER/REPO]
#
# Exit 0 only when release-preflight.yml has a completed, successful run on branch main whose head_sha is exactly
# <sha>. Exit 1 when there is none; exit 2 on bad usage. Fails closed: a missing gh, a gh error or an
# unparseable answer is exit 1, never a pass. Needs `gh` and `node` on PATH and GH_TOKEN (actions: read).
# Used by release-tag.yml (before it creates a tag) and release.yml (first job, before anything else).
set -euo pipefail

WORKFLOW="release-preflight.yml"
die() { echo "check-preflight: FAIL: $*" >&2; [[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::error::check-preflight: $*"; exit 1; }

SHA="${1:-}"; [[ -n "$SHA" ]] || { echo "usage: check-preflight.sh <sha> [--repo OWNER/REPO]" >&2; exit 2; }
shift
REPO="${GITHUB_REPOSITORY:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="${2:-}"; shift 2 ;;
    *) echo "check-preflight: unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "check-preflight: sha must be 40 lowercase hex characters" >&2; exit 2; }
[[ "$REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || { echo "check-preflight: --repo OWNER/REPO (or GITHUB_REPOSITORY) is required" >&2; exit 2; }

RUNS="$(gh api "repos/$REPO/actions/workflows/$WORKFLOW/runs?head_sha=$SHA&branch=main&status=success&per_page=100")" \
  || die "could not list $WORKFLOW runs for $SHA (gh api failed)"

MATCH="$(printf '%s' "$RUNS" | node -e '
  let d = ""; process.stdin.on("data", (c) => (d += c)).on("end", () => {
    let j; try { j = JSON.parse(d); } catch (e) { console.error("unparseable runs answer: " + e.message); process.exit(3); }
    const sha = process.argv[1];
    // The endpoint is already scoped to release-preflight.yml; re-check every field that matters anyway.
    const ok = (Array.isArray(j.workflow_runs) ? j.workflow_runs : []).filter((r) =>
      r && r.head_sha === sha && r.status === "completed" && r.conclusion === "success" &&
      r.head_branch === "main" && (r.event === "push" || r.event === "workflow_dispatch"));
    if (ok.length) process.stdout.write(String(ok[0].html_url || ok[0].id));
  });' "$SHA")" || die "could not read the $WORKFLOW runs answer"

[[ -n "$MATCH" ]] || die "no green $WORKFLOW run for $SHA on main. Run the release-preflight workflow on main first (see RELEASING.md); a tag must never be created before it passes."
echo "check-preflight: OK: $WORKFLOW passed for $SHA ($MATCH)"
