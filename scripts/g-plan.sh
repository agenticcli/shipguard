#!/usr/bin/env bash
# g-plan.sh - G-PLAN gate, first cut (P0). The public CLI holds no plan facts and no banned words.
#   scripts/g-plan.sh [path...]   scan files/dirs (default: CLI src, README.md, docs, package.json)
#   scripts/g-plan.sh --pack      scan the extracted `npm pack` output of packages/cli
#   scripts/g-plan.sh --self-test fixtures: price string and 'release gate' fail, clean passes
# Exit 0 = clean, 1 = hits (printed file:line:match), 2 = usage/could not run.
# A line carrying the marker g-plan:allow is skipped (use only with a reason next to it).
# W0 wires this into scripts/release-gate.sh; this file is the first cut (regexes below are the contract).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Plan facts: prices, scan/credit counts, packs, trial length, plan names with a price or count.
PLAN_RE='\$[0-9]+(\.[0-9]+)? ?(a |per |/)? ?(month|year|yr|mo)\b|\$[0-9]{2,}|[0-9][0-9,]* (rulebook |full )?(scans|credits)( a| per| each| /)? ?(month|year)?|credit packs?|[0-9]+[- ]day (free )?trial|\b(per|a|each) (month|year)\b|/month\b|/year\b'
# Banned words in any CLI string.
BAN_RE='release gate|\bcloud\b|our servers'

scan_paths() {
  local hits=0 out
  # -I skip binaries; -n line numbers; -E regexes; -i for banned words only (plan regex is case-sensitive on purpose)
  out="$( { grep -rInE --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=contracts --exclude='*.map' "$PLAN_RE" "$@" || true; \
            grep -rInEi --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=contracts --exclude='*.map' "$BAN_RE" "$@" || true; } | grep -v 'g-plan:allow' | sort -u )"
  if [[ -n "$out" ]]; then printf '%s\n' "$out"; hits=1; fi
  return $hits
}

self_test() {
  local d; d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  printf 'const a = "Pro costs $29 a month";\n' > "$d/price.ts"
  printf '// this is the release gate\n' > "$d/ban.ts"
  printf 'const b = "100 scans a month";\n' > "$d/count.ts"
  printf 'const c = "Scan finished. Nothing matched.";\n// regex $1 and $2 are group refs\n' > "$d/clean.ts"
  local f
  for f in price ban count; do
    if scan_paths "$d/$f.ts" >/dev/null; then echo "SELF-TEST FAIL: $f.ts should have failed" >&2; return 1; fi
  done
  scan_paths "$d/clean.ts" >/dev/null || { echo "SELF-TEST FAIL: clean.ts should pass" >&2; return 1; }
  echo "G-PLAN self-test: PASS (price, count, banned word fail; clean passes)"
}

case "${1:-}" in
  --self-test) self_test ;;
  --pack)
    d="$(mktemp -d)"; trap 'rm -rf "$d"' EXIT
    (cd "$ROOT/packages/cli" && npm pack --silent --pack-destination "$d" >/dev/null) || { echo "npm pack failed" >&2; exit 2; }
    mkdir "$d/x" && tar -xzf "$d"/*.tgz -C "$d/x"
    if scan_paths "$d/x"; then echo "G-PLAN: clean (pack)"; else echo "G-PLAN: FAIL (pack)" >&2; exit 1; fi ;;
  --*) echo "usage: g-plan.sh [path...] | --pack | --self-test" >&2; exit 2 ;;
  *)
    if [[ $# -eq 0 ]]; then set -- "$ROOT/packages/cli/src" "$ROOT/README.md" "$ROOT/docs" "$ROOT/packages/cli/package.json"; fi
    if scan_paths "$@"; then echo "G-PLAN: clean"; else echo "G-PLAN: FAIL" >&2; exit 1; fi ;;
esac
