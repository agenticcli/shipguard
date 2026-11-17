#!/usr/bin/env bash
# rebuild-verify.sh <version> - check that the npm package is what the public repo builds.
# Downloads @agenticcli/shipguard@<version> from npm, checks out tag v<version>, builds it the way the
# release does (pnpm install --frozen-lockfile --ignore-scripts; pnpm run build:publish) and compares
# SHA-256 of dist/*.js and dist/*.js.map. Read-only on your repo; works in a temp folder.
# Needs: node 24, pnpm 9.15.0, git, npm, network. Exit 0 = MATCH, 1 = MISMATCH, 2 = could not run.
set -euo pipefail
VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: rebuild-verify.sh <version, e.g. 0.12.1>" >&2; exit 2; }
REPO_URL="${SHIPGUARD_REPO_URL:-https://github.com/agenticcli/shipguard.git}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "1/4 fetch published package @agenticcli/shipguard@$VERSION"
(cd "$WORK" && npm pack "@agenticcli/shipguard@$VERSION" --silent >/dev/null && mkdir pub && tar -xzf agenticcli-shipguard-"$VERSION".tgz -C pub) \
  || { echo "could not download the package from npm" >&2; exit 2; }

echo "2/4 check out tag v$VERSION"
git clone --quiet --depth 1 --branch "v$VERSION" "$REPO_URL" "$WORK/src" || { echo "could not clone tag v$VERSION" >&2; exit 2; }

echo "3/4 build (install with scripts blocked, then build:publish)"
(cd "$WORK/src" && pnpm install --frozen-lockfile --ignore-scripts >/dev/null && pnpm run build >/dev/null && pnpm --filter @agenticcli/shipguard run build:publish >/dev/null) \
  || { echo "build failed" >&2; exit 2; }

echo "4/4 compare"
node "$WORK/src/packages/cli/scripts/compare-dist.mjs" "$WORK/pub/package/dist" "$WORK/src/packages/cli/dist"
