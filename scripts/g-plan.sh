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

# Exact-phrase allowlist (scripts/g-plan.allow): lines `path-suffix|exact phrase`. A hit is dropped only when
# its file ends with the path AND its text contains the phrase, so a legit provider name ("Google Cloud")
# is allowed in that one rule text and the word stays banned everywhere else.
ALLOW_FILE="${G_PLAN_ALLOW_FILE:-$ROOT/scripts/g-plan.allow}"

# One grep run: rc 0 = hits, 1 = none, anything else = the grep itself failed (fail closed, exit 2).
run_grep() {
  local rc=0 out
  out="$(grep -rHInE"$1" --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=contracts --exclude='*.map' "$2" "${@:3}")" || rc=$?
  if [[ $rc -gt 1 ]]; then echo "G-PLAN: grep failed (rc=$rc) - failing closed" >&2; return 2; fi
  printf '%s' "$out"
}

filter_allowed() {
  local line file text entry apath aphrase keep
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    file="${line%%:*}"; text="${line#*:*:}"; keep=1
    if [[ -f "$ALLOW_FILE" ]]; then
      while IFS= read -r entry; do
        [[ -z "$entry" || "$entry" == \#* ]] && continue
        apath="${entry%%|*}"; aphrase="${entry#*|}"
        if [[ "$file" == *"$apath" && "$text" == *"$aphrase"* ]]; then keep=0; break; fi
      done < "$ALLOW_FILE"
    fi
    [[ $keep -eq 1 ]] && printf '%s\n' "$line"
  done
  return 0
}

scan_paths() {
  local p out
  [[ $# -gt 0 ]] || { echo "G-PLAN: no paths to scan" >&2; exit 2; }
  for p in "$@"; do
    [[ -e "$p" ]] || { echo "G-PLAN: path not found: $p - failing closed" >&2; exit 2; }
  done
  # -I skip binaries; -n line numbers; -E regexes; -i for banned words only (plan regex is case-sensitive on purpose)
  # Two plain assignments (no pipeline) so a failing grep stops the script; the filters run after.
  local plan_hits ban_hits
  plan_hits="$(run_grep "" "$PLAN_RE" "$@")" || exit 2
  ban_hits="$(run_grep i "$BAN_RE" "$@")" || exit 2
  out="$(printf '%s\n%s\n' "$plan_hits" "$ban_hits" | { grep -v 'g-plan:allow' || true; } | filter_allowed | sort -u)"
  if [[ -n "$out" ]]; then printf '%s\n' "$out"; return 1; fi
  return 0
}

self_test() {
  local d; d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  printf 'const a = "Pro costs $29 a month";\n' > "$d/price.ts"
  printf '// this is the release gate\n' > "$d/ban.ts"
  printf 'const b = "100 scans a month";\n' > "$d/count.ts"
  printf 'const c = "Scan finished. Nothing matched.";\n// regex $1 and $2 are group refs\n' > "$d/clean.ts"
  printf 'x: "access Google Cloud services"\n' > "$d/allowed.ts"
  printf 'y: "our cloud"\n' > "$d/notallowed.ts"
  printf 'allowed.ts|Google Cloud services\n' > "$d/allow"
  local f
  for f in price ban count; do
    if (scan_paths "$d/$f.ts") >/dev/null 2>&1; then echo "SELF-TEST FAIL: $f.ts should have failed" >&2; return 1; fi
  done
  (scan_paths "$d/clean.ts") >/dev/null || { echo "SELF-TEST FAIL: clean.ts should pass" >&2; return 1; }
  # fail closed: a missing path is an error (exit 2), never "clean"
  local rc=0; (scan_paths "$d/missing.ts") >/dev/null 2>&1 || rc=$?
  [[ $rc -eq 2 ]] || { echo "SELF-TEST FAIL: missing path should exit 2, got $rc" >&2; return 1; }
  # exact-phrase allowlist: the phrase passes in its file, the same word elsewhere still fails
  (ALLOW_FILE="$d/allow"; scan_paths "$d/allowed.ts") >/dev/null || { echo "SELF-TEST FAIL: allowlisted phrase should pass" >&2; return 1; }
  if (ALLOW_FILE="$d/allow"; scan_paths "$d/notallowed.ts") >/dev/null 2>&1; then echo "SELF-TEST FAIL: cloud outside the allowlist should fail" >&2; return 1; fi
  echo "G-PLAN self-test: PASS (price, count, banned word fail; clean passes; missing path exits 2; allowlist is exact-phrase)"
}

case "${1:-}" in
  --self-test) self_test ;;
  --pack)
    d="$(mktemp -d)"; trap 'rm -rf "$d"' EXIT
    (cd "$ROOT/packages/cli" && npm pack --silent --ignore-scripts --pack-destination "$d" >/dev/null) || { echo "npm pack failed" >&2; exit 2; }
    [[ "$(ls "$d"/*.tgz 2>/dev/null | wc -l)" == 1 ]] || { echo "G-PLAN: expected exactly one tarball" >&2; exit 2; }
    mkdir "$d/x" && tar -xzf "$d"/*.tgz -C "$d/x"
    if scan_paths "$d/x"; then echo "G-PLAN: clean (pack)"; else echo "G-PLAN: FAIL (pack)" >&2; exit 1; fi ;;
  --*) echo "usage: g-plan.sh [path...] | --pack | --self-test" >&2; exit 2 ;;
  *)
    if [[ $# -eq 0 ]]; then set -- "$ROOT/packages/cli/src" "$ROOT/README.md" "$ROOT/docs" "$ROOT/packages/cli/package.json"; fi
    if scan_paths "$@"; then echo "G-PLAN: clean"; else echo "G-PLAN: FAIL" >&2; exit 1; fi ;;
esac
