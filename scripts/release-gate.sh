#!/usr/bin/env bash
# release-gate.sh — Pre-publish gate for @agenticcli/shipguard
# Referenced by packages/cli/package.json prepublishOnly.
# ALL gates must PASS (exit 0) before npm publish proceeds.
# A gate failure exits non-zero → npm aborts the publish.

set -euo pipefail

# Never ping production analytics from the gate: G2 runs the built CLI, G8 runs the self-scan
# (vitest also forces this via tests/setup/no-telemetry.ts).
export SHIPGUARD_TELEMETRY=0
export DO_NOT_TRACK=1

CLI_DIR="$(git rev-parse --show-toplevel)/packages/cli"
DIST="$CLI_DIR/dist/cli.js"
PKG="$CLI_DIR/package.json"

# DRY RUN (RELEASE_GATE_DRY_RUN=1): run every gate against a local/dev build, report each result,
# never stop at the first failure, skip only the published-provenance check, and NEVER write the
# publish sentinel. Exit 1 if any gate failed. For rehearsals and CI — it can never authorise a release.
DRY_RUN="${RELEASE_GATE_DRY_RUN:-0}"
GATE_FAILURES=0
gate_fail() {
  if [[ "$DRY_RUN" == "1" ]]; then
    GATE_FAILURES=$((GATE_FAILURES + 1))
    echo "  (dry run: continuing after failure)" >&2
  else
    exit 1
  fi
}

echo "=== ShipGuard release-gate ==="
[[ "$DRY_RUN" == "1" ]] && echo "*** DRY RUN — no sentinel will be written; result cannot authorise a release ***"

# Gate 1: dist/cli.js must exist
if [[ ! -f "$DIST" ]]; then
  echo "FAIL [G1] dist/cli.js not found — run pnpm build first" >&2
  gate_fail
fi
echo "PASS [G1] dist/cli.js exists"

# Gate 2: --version must match package.json version
PKG_VERSION="$(node -e "const p=require('$PKG');process.stdout.write(p.version)")"
CLI_VERSION="$(node "$DIST" --version 2>/dev/null)"
if [[ "$PKG_VERSION" != "$CLI_VERSION" ]]; then
  echo "FAIL [G2] version mismatch: package.json=$PKG_VERSION dist/cli.js=$CLI_VERSION" >&2
  gate_fail
fi
echo "PASS [G2] version match: $PKG_VERSION"

# Gate 2b: cli-facts.json must exist, parse as valid JSON, and match package.json version
CLI_FACTS="$CLI_DIR/dist/cli-facts.json"
if [[ ! -f "$CLI_FACTS" ]]; then
  echo "  Generating cli-facts.json..." >&2
  node "$CLI_DIR/scripts/gen-cli-facts.mjs" >&2
fi
if [[ ! -f "$CLI_FACTS" ]]; then
  echo "FAIL [G2b] dist/cli-facts.json missing — gen-cli-facts.mjs did not produce it" >&2
  gate_fail
fi
# Validate JSON and version match
FACTS_VERSION="$(node -e "
  const fs=require('fs');
  let facts;
  try { facts=JSON.parse(fs.readFileSync('$CLI_FACTS','utf-8')); }
  catch(e) { process.stderr.write('invalid JSON: '+e.message+'\n'); process.exit(1); }
  process.stdout.write(facts.version||'');
" 2>&1)"
NODE_EXIT=$?
if [[ $NODE_EXIT -ne 0 ]]; then
  echo "FAIL [G2b] dist/cli-facts.json is not valid JSON: $FACTS_VERSION" >&2
  gate_fail
fi
if [[ "$PKG_VERSION" != "$FACTS_VERSION" ]]; then
  echo "FAIL [G2b] cli-facts.json version mismatch: package.json=$PKG_VERSION facts=$FACTS_VERSION" >&2
  gate_fail
fi
echo "PASS [G2b] cli-facts.json valid, version=$FACTS_VERSION"

# Gate 2c: the artifact must be a PUBLISHED build. A plain `pnpm build` is a dev build, which by design
# never pings the production analytics endpoint; shipping one would silently blind all usage metrics
# (and `pnpm build:publish` is what sets the marker). Behavioural check: ask the built binary.
GATE_TMP="$(mktemp -d)"
PROVENANCE="$(cd "$GATE_TMP" && HOME="$GATE_TMP" node "$DIST" telemetry status --json 2>/dev/null \
  | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{process.stdout.write(String(JSON.parse(d).provenance))}catch(e){process.stderr.write('unparseable: '+e.message+'\n');process.exit(1)}})")" || PROVENANCE="unreadable"
rm -rf "$GATE_TMP"
if [[ "$DRY_RUN" == "1" && "$PROVENANCE" != "published" ]]; then
  echo "SKIP [G2c] dry run: build provenance is '$PROVENANCE' (a real release requires 'published')"
elif [[ "$PROVENANCE" != "published" ]]; then
  echo "FAIL [G2c] dist/cli.js provenance is '$PROVENANCE', expected 'published' — rebuild with: pnpm --filter @agenticcli/shipguard run build:publish" >&2
  gate_fail
fi
[[ "$PROVENANCE" == "published" ]] && echo "PASS [G2c] build provenance: published"

# Gate 2d: neither the bundle nor the source may contain an unfilled key-ceremony
# placeholder. With one, the CLI cannot verify ANY Pro release (ra-k2-2026 / cf-k2-2026 / k3-2026
# public keys missing). The three public keys live in ONE file, src/core/keyring-ceremony-output.ts,
# which is generated - it is scanned as source too, not only as part of dist.
if ! node "$CLI_DIR/scripts/check-keyring-placeholders.mjs" "$CLI_DIR/dist" "$CLI_DIR/src/core/crypto.ts" "$CLI_DIR/src/core/keyring-ceremony-output.ts"; then
  echo "FAIL [G2d] unfilled key-ceremony placeholder in the keyring — fill in the public keys first" >&2
  gate_fail
else
  echo "PASS [G2d] keyring has no ceremony placeholders"
fi

# Gate 3: No @agenticcli/* runtime imports in bundle (must all be bundled in via noExternal)
# Allow string literals (npx @agenticcli/shipguard in help text) — only flag import/require
if grep -qE "^import\s+.*from\s+'@agenticcli/|\"@agenticcli/" "$DIST" 2>/dev/null; then
  echo "FAIL [G3] @agenticcli/* runtime import found in dist/cli.js — bundling broken" >&2
  gate_fail
fi
echo "PASS [G3] no @agenticcli/* runtime imports in bundle"

# Gate 4: Tarball size sanity (< 500 kB packed)
# Loud on every failure: a pack error or unparseable output must FAIL the gate, never default to 0.
PACK_ERR="$(mktemp)"
PACK_JSON="$(cd "$CLI_DIR" && npm pack --dry-run --json --ignore-scripts 2>"$PACK_ERR")" || {
  echo "FAIL [G4] npm pack --dry-run failed: $(cat "$PACK_ERR")" >&2
  rm -f "$PACK_ERR"
  gate_fail
}
rm -f "$PACK_ERR"
TARBALL_SIZE="$(printf '%s' "$PACK_JSON" | node -e "
  const chunks=[]; process.stdin.on('data',c=>chunks.push(c)); process.stdin.on('end',()=>{
    let d; try { d=JSON.parse(Buffer.concat(chunks).toString()); }
    catch (e) { console.error('unparseable npm pack output: '+e.message); process.exit(1); }
    const size=d[0]&&d[0].size;
    if (!Number.isFinite(size) || size<=0) { console.error('npm pack reported no size'); process.exit(1); }
    process.stdout.write(String(size));
  });
")" || {
  echo "FAIL [G4] could not read the packed tarball size" >&2
  gate_fail
}
if [[ "$TARBALL_SIZE" -gt 512000 ]]; then
  echo "FAIL [G4] packed tarball is ${TARBALL_SIZE} bytes — exceeds the 500 kB sanity ceiling" >&2
  gate_fail
fi
# Fallback: just check dist size
DIST_SIZE=$(du -k "$CLI_DIR/dist" | tail -1 | cut -f1)
if [[ "$DIST_SIZE" -gt 1000 ]]; then
  echo "FAIL [G4] dist/ is ${DIST_SIZE}KB — exceeds 1MB sanity ceiling" >&2
  gate_fail
fi
echo "PASS [G4] dist size ${DIST_SIZE}KB, packed tarball ${TARBALL_SIZE} bytes within limits"

# Gate 5: checksum-manifest.json must exist (gen-checksum-manifest.mjs onSuccess)
if [[ ! -f "$CLI_DIR/dist/checksum-manifest.json" ]]; then
  echo "FAIL [G5] dist/checksum-manifest.json missing — rebuild required" >&2
  gate_fail
fi
echo "PASS [G5] checksum-manifest.json present"

# Gate 6: re2js must appear in dependencies (not devDependencies) — it's a runtime dep
RE2JS_IN_DEPS=$(node -e "const p=require('$PKG'); process.stdout.write(p.dependencies?.re2js?'yes':'no')" 2>/dev/null || echo "no")
if [[ "$RE2JS_IN_DEPS" != "yes" ]]; then
  echo "FAIL [G6] re2js not found in dependencies — add re2js to runtime deps" >&2
  gate_fail
fi
echo "PASS [G6] re2js in dependencies"

# Gate 7: the offline rule bundle must be present, non-empty, and actually compiled into
# the binary. THIS IS THE GATE THAT WOULD HAVE CAUGHT THE ORIGINAL DEFECT: for months the
# CLI shipped ZERO rules from the governed corpus while the platform's rules.md §9 promised
# anonymous users exactly those rules, and every existing gate passed the whole time,
# because none of them looked at what the artifact contained.
#
# Two separate assertions, because either alone can be true while the product is broken:
#   (a) rules/free-bundle.json exists, parses, and carries >0 rules — the data file;
#   (b) every one of those rule IDs appears inside dist/cli.js — proof the running binary
#       can actually reach them, rather than the file riding along unread.
BUNDLE="$CLI_DIR/rules/free-bundle.json"
if [[ ! -f "$BUNDLE" ]]; then
  echo "FAIL [G7] rules/free-bundle.json missing — the CLI would ship no corpus rules at all" >&2
  gate_fail
fi
BUNDLE_REPORT="$(node -e "
const fs = require('fs');
const b = JSON.parse(fs.readFileSync('$BUNDLE', 'utf-8'));
const ids = b.rules.map(r => r.id);
if (ids.length === 0) { console.error('empty bundle'); process.exit(1); }
if (ids.length !== b.ruleCount) { console.error('ruleCount ' + b.ruleCount + ' != ' + ids.length + ' rules'); process.exit(1); }
const js = fs.readFileSync('$CLI_DIR/dist/cli.js', 'utf-8');
const missing = ids.filter(id => !js.includes(id));
if (missing.length) { console.error('not compiled into dist/cli.js: ' + missing.join(', ')); process.exit(1); }
process.stdout.write(ids.length + ' rules, corpusVersion ' + b.corpusVersion + ', ' + b.contentHash);
")" || {
  echo "FAIL [G7] offline rule bundle is missing, empty, inconsistent, or not compiled into dist/cli.js" >&2
  gate_fail
}
echo "PASS [G7] offline rule bundle: $BUNDLE_REPORT"

# Gate 8: shipped-tree self-scan (slow lane, excluded from the default fast suite).
# Scans exactly the files `npm pack` would publish and requires zero blocking findings and
# `--strict` exit 0 - a package that blocks itself must not ship. See
# packages/cli/tests/slow/shipped-tree-self-scan.slow.test.ts.
if ! (cd "$CLI_DIR" && VITEST_SLOW=1 npx --no-install vitest run tests/slow >&2); then
  echo "FAIL [G8] shipped-tree self-scan raised a blocking finding (or could not run)" >&2
  gate_fail
fi
echo "PASS [G8] shipped-tree self-scan: no blocking findings, --strict exit 0"

if [[ "$DRY_RUN" == "1" ]]; then
  echo ""
  if [[ "$GATE_FAILURES" -gt 0 ]]; then
    echo "=== DRY RUN: $GATE_FAILURES gate(s) FAILED — no sentinel written ==="
    exit 1
  fi
  echo "=== DRY RUN: all gates passed (G2c skipped) — no sentinel written ==="
  exit 0
fi

echo ""
echo "=== All release gates PASSED (10/10) — proceed with the package release ==="

# Write the sentinel npm-publish-guard.sh checks for: "<sha> <version> <epoch>".
# Only written here, after every gate above has exited 0 — never on failure
# (set -euo pipefail aborts the script before this point on any gate FAIL).
SENTINEL="/tmp/shipguard-release-gate-pass"
GATE_SHA="$(git rev-parse HEAD)"
GATE_EPOCH="$(date +%s)"
echo "$GATE_SHA $PKG_VERSION $GATE_EPOCH" > "$SENTINEL"
echo "Wrote release-gate sentinel: $SENTINEL"
