#!/usr/bin/env bash
# release-facts.sh - release facts for @agenticcli/shipguard (plan W12).
#
#   check --tag vX.Y.Z [--root DIR]
#       Pre-publish, fail closed. The tag, packages/cli/package.json, the top CHANGELOG entry
#       (version + a real date, not "unreleased") and, for a stable version, every place in this repo
#       that names the latest version (CITATION.cff, the OpenVEX product purl, pinned versions in
#       README / docs / REBUILD.md) must all agree. Prints every mismatch, exits 1 on any.
#   sync --tag vX.Y.Z [--root DIR]
#       Rewrites those places from package.json + the CHANGELOG date (stable versions only), then runs check.
#   emit --tag vX.Y.Z --tarball FILE --out FILE [--root DIR]
#       Post-publish. Waits for the registry dist-tag (latest; next for a prerelease) to show the version,
#       checks the registry integrity equals the sha512 of the tarball the build job made and that a provenance
#       attestation exists, then writes release-facts.json (version, dates, CHANGELOG entry, tarball size,
#       provenance) and, in CI, appends it to the job summary.
#
# Needs bash, node, npm (emit only). Needs no credentials, no network except `npm view` in emit, and it never publishes
# or changes a dist-tag. The platform repo (agenticcli) consumes the result by hand: see the release runbook.
set -euo pipefail

PKG_NAME="@agenticcli/shipguard"
SEMVER='[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?'

die() {
  echo "release-facts: FAIL: $*" >&2
  [[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::error::release-facts: $*"
  exit 1
}

usage() { sed -n '2,19p' "$0" >&2; exit 2; }

MODE="${1:-}"; [[ -n "$MODE" ]] || usage
shift
TAG=""; ROOT=""; TARBALL=""; OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="${2:-}"; shift 2 ;;
    --root) ROOT="${2:-}"; shift 2 ;;
    --tarball) TARBALL="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ -n "$ROOT" ]] || ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -n "$TAG" ]] || die "--tag vX.Y.Z is required (the workflow passes \$GITHUB_REF_NAME)"

PKG_JSON="$ROOT/packages/cli/package.json"
CHANGELOG="$ROOT/packages/cli/CHANGELOG.md"
[[ -f "$PKG_JSON" ]] || die "missing $PKG_JSON"
[[ -f "$CHANGELOG" ]] || die "missing $CHANGELOG"

# jq-free JSON read: json_get FILE 'js expression on d'
json_get() { node -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const v=eval(process.argv[2]);process.stdout.write(v==null?"":String(v))' "$1" "$2"; }

VERSION="$(json_get "$PKG_JSON" 'd.version')"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "package.json version '$VERSION' is not X.Y.Z or X.Y.Z-pre"
BASE="${VERSION%%-*}"
STABLE=1; [[ "$VERSION" == *-* ]] && STABLE=0
EXPECT_TAG=latest; [[ "$STABLE" == 0 ]] && EXPECT_TAG=next

# The CHANGELOG entry text of the top "## " heading (same cut as the github-release job).
changelog_top_heading() { grep -m1 '^## ' "$CHANGELOG" || true; }
changelog_top_entry() { awk '/^## /{ if (on) exit; on=1; next } on { print }' "$CHANGELOG"; }

CL_DATE=""
read_changelog() {
  local h; h="$(changelog_top_heading)"
  [[ -n "$h" ]] || { ERRORS+=("CHANGELOG.md has no '## ' entry"); return; }
  if [[ "$h" =~ ^##\ ([0-9]+\.[0-9]+\.[0-9]+)\ -\ ([0-9]{4}-[0-9]{2}-[0-9]{2})$ ]]; then
    [[ "${BASH_REMATCH[1]}" == "$BASE" ]] || ERRORS+=("CHANGELOG.md top entry is ${BASH_REMATCH[1]}, expected $BASE (heading: '$h')")
    CL_DATE="${BASH_REMATCH[2]}"
    node -e '
      const d=process.argv[1], t=new Date(d+"T00:00:00Z");
      if(isNaN(t)||t.toISOString().slice(0,10)!==d){console.log("not a real calendar date");process.exit(1)}
      if(t.getTime()>Date.now()+36*3600*1000){console.log("date is in the future");process.exit(1)}
    ' "$CL_DATE" >/dev/null || ERRORS+=("CHANGELOG.md top entry date '$CL_DATE' is not a real, non-future date")
  else
    ERRORS+=("CHANGELOG.md top heading must read '## $BASE - YYYY-MM-DD' (got: '$h'; 'unreleased' is not allowed at release)")
  fi
  changelog_top_entry | grep -q '^- ' || ERRORS+=("CHANGELOG.md top entry has no bullet lines")
}

# Files that may pin the latest version in text.
doc_files() {
  local f
  for f in README.md REBUILD.md packages/cli/README.md; do [[ -f "$ROOT/$f" ]] && echo "$ROOT/$f"; done
  find "$ROOT/docs" "$ROOT/packages/cli/docs" -type f -name '*.md' 2>/dev/null | LC_ALL=C sort
}
# Pinned-version shapes, each is a full semver that must be the release version.
PIN_PATTERNS=(
  "--branch v$SEMVER"
  "rebuild-verify\.sh $SEMVER"
  "$PKG_NAME@$SEMVER"
  "agenticcli-shipguard-$SEMVER\.tgz"
)

check_locations() {
  local f cit_v cit_d m ver n=0 p
  # CITATION.cff
  if [[ -f "$ROOT/CITATION.cff" ]]; then
    cit_v="$(sed -nE 's/^version:[[:space:]]*"?([^"[:space:]]+)"?[[:space:]]*$/\1/p' "$ROOT/CITATION.cff" | head -1)"
    cit_d="$(sed -nE 's/^date-released:[[:space:]]*"?([^"[:space:]]+)"?[[:space:]]*$/\1/p' "$ROOT/CITATION.cff" | head -1)"
    [[ "$cit_v" == "$VERSION" ]] || ERRORS+=("CITATION.cff version is '$cit_v', expected $VERSION")
    [[ -z "$CL_DATE" || "$cit_d" == "$CL_DATE" ]] || ERRORS+=("CITATION.cff date-released is '$cit_d', expected $CL_DATE (the CHANGELOG date)")
  else
    ERRORS+=("CITATION.cff is missing")
  fi
  # OpenVEX product purl
  f="$ROOT/docs/security/shipguard.openvex.json"
  if [[ -f "$f" ]]; then
    n=0
    while read -r m; do
      n=$((n+1)); ver="$(printf '%s\n' "${m##*@}" | grep -oE "$SEMVER" | head -1)"
      [[ "$ver" == "$VERSION" ]] || ERRORS+=("docs/security/shipguard.openvex.json names $PKG_NAME@$ver, expected $VERSION")
    done < <(grep -oE "pkg:npm/%40agenticcli/shipguard@$SEMVER" "$f" | sort -u || true)
    [[ "$n" -gt 0 ]] || ERRORS+=("docs/security/shipguard.openvex.json has no pkg:npm/%40agenticcli/shipguard@<version> purl")
  else
    ERRORS+=("docs/security/shipguard.openvex.json is missing")
  fi
  # Pinned versions in README / docs / REBUILD.md (REBUILD.md must have some: a guard that matches nothing is blind)
  local rebuild_hits=0
  while read -r f; do
    for p in "${PIN_PATTERNS[@]}"; do
      while read -r m; do
        [[ -n "$m" ]] || continue
        ver="$(printf '%s\n' "${m#*:}" | grep -oE "$SEMVER" | head -1)"
        [[ "$f" == "$ROOT/REBUILD.md" ]] && rebuild_hits=$((rebuild_hits+1))
        [[ "$ver" == "$VERSION" ]] || ERRORS+=("${f#"$ROOT"/}:${m%%:*} pins $ver, expected $VERSION")
      done < <(grep -noE -e "$p" "$f" || true)
    done
  done < <(doc_files)
  [[ "$rebuild_hits" -gt 0 ]] || ERRORS+=("REBUILD.md has no pinned version to check (--branch vX, rebuild-verify.sh X, ...): the check would be blind")
}

run_check() {
  ERRORS=()
  [[ "$TAG" == "v$VERSION" ]] || ERRORS+=("tag $TAG != package.json version v$VERSION")
  read_changelog
  if [[ "$STABLE" == 1 ]]; then
    check_locations
  else
    echo "release-facts: prerelease $VERSION: tag, package.json and CHANGELOG checked; repo-wide version places are checked for stable releases only"
  fi
  if [[ "${#ERRORS[@]}" -gt 0 ]]; then
    local e
    for e in "${ERRORS[@]}"; do
      echo "release-facts: MISMATCH: $e" >&2
      [[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::error::release-facts: $e"
    done
    die "${#ERRORS[@]} mismatch(es) above; fix them (or run: bash scripts/release-facts.sh sync --tag $TAG) before the release"
  fi
  echo "release-facts: OK $VERSION (tag, package.json, CHANGELOG${CL_DATE:+ $CL_DATE}$([[ "$STABLE" == 1 ]] && echo ', CITATION, OpenVEX, pinned docs'))"
}

run_sync() {
  [[ "$STABLE" == 1 ]] || die "sync is for stable versions only"
  ERRORS=(); read_changelog
  [[ "${#ERRORS[@]}" -eq 0 ]] || { printf 'release-facts: MISMATCH: %s\n' "${ERRORS[@]}" >&2; die "fix the CHANGELOG entry first; sync takes the date from it"; }
  local f
  if [[ -f "$ROOT/CITATION.cff" ]]; then
    sed -i -E "s/^(version:[[:space:]]*)\"?[^\"[:space:]]+\"?[[:space:]]*$/\1$VERSION/; s/^(date-released:[[:space:]]*)\"?[^\"[:space:]]+\"?[[:space:]]*$/\1$CL_DATE/" "$ROOT/CITATION.cff"
  fi
  f="$ROOT/docs/security/shipguard.openvex.json"
  [[ -f "$f" ]] && sed -i -E "s#(pkg:npm/%40agenticcli/shipguard@)$SEMVER#\1$VERSION#g" "$f"
  while read -r f; do
    sed -i -E \
      -e "s#(--branch v)$SEMVER#\1$VERSION#g" \
      -e "s#(rebuild-verify\.sh )$SEMVER#\1$VERSION#g" \
      -e "s#($PKG_NAME@)$SEMVER#\1$VERSION#g" \
      -e "s#(agenticcli-shipguard-)$SEMVER(\.tgz)#\1$VERSION\2#g" "$f"
  done < <(doc_files)
  echo "release-facts: synced version $VERSION and date $CL_DATE"
  run_check
}

run_emit() {
  [[ -n "$TARBALL" && -n "$OUT" ]] || die "emit needs --tarball FILE and --out FILE"
  case "$(basename "$TARBALL")" in agenticcli-shipguard-*.tgz) ;; *) die "unexpected tarball name: $(basename "$TARBALL")" ;; esac
  [[ -f "$TARBALL" ]] || die "tarball not found: $TARBALL"
  [[ "$TAG" == "v$VERSION" ]] || die "tag $TAG != package.json version v$VERSION"
  ERRORS=(); read_changelog
  [[ "${#ERRORS[@]}" -eq 0 ]] || { printf 'release-facts: MISMATCH: %s\n' "${ERRORS[@]}" >&2; die "CHANGELOG entry is not release-ready"; }

  # Registry: the dist-tag may take a moment to show up after publish.
  local tries=0 seen="" tags
  while :; do
    tags="$(npm view "$PKG_NAME" dist-tags --json --registry=https://registry.npmjs.org/ 2>&1)" || tags=""
    seen="$(node -e 'try{const d=JSON.parse(process.argv[1]);process.stdout.write(String(d[process.argv[2]]||""))}catch(e){}' "$tags" "$EXPECT_TAG")"
    [[ "$seen" == "$VERSION" ]] && break
    tries=$((tries+1))
    [[ "$tries" -lt "${RELEASE_FACTS_TRIES:-12}" ]] || die "registry dist-tag '$EXPECT_TAG' shows '${seen:-nothing}', expected $VERSION after $tries tries"
    echo "release-facts: registry $EXPECT_TAG='${seen:-?}', waiting for $VERSION ($tries)" >&2
    sleep "${RELEASE_FACTS_SLEEP:-10}"
  done
  local dist time_v
  dist="$(npm view "$PKG_NAME@$VERSION" dist --json --registry=https://registry.npmjs.org/)" || die "npm view $PKG_NAME@$VERSION dist failed"
  time_v="$(npm view "$PKG_NAME" time --json --registry=https://registry.npmjs.org/ | node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(0,"utf8"))[process.argv[1]]||""))' "$VERSION")" || die "npm view $PKG_NAME time failed"
  [[ -n "$time_v" ]] || die "registry has no publish time for $VERSION"

  local entry run_url=""
  entry="$(changelog_top_entry)"
  [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_RUN_ID:-}" ]] && run_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
  # shellcheck disable=SC2016  # the JS below is one single-quoted argument on purpose
  node -e '
    const fs=require("fs"),crypto=require("crypto"),path=require("path");
    const [pkg,version,tag,distTag,date,publishedAt,distJson,entry,tarball,out,commit,runUrl,summary]=process.argv.slice(1);
    const dist=JSON.parse(distJson), buf=fs.readFileSync(tarball);
    const integrity="sha512-"+crypto.createHash("sha512").update(buf).digest("base64");
    if(dist.integrity!==integrity){console.error("release-facts: FAIL: registry integrity "+dist.integrity+" != built tarball "+integrity);process.exit(1)}
    const prov=dist.attestations&&dist.attestations.provenance&&dist.attestations.provenance.predicateType;
    if(!prov){console.error("release-facts: FAIL: registry shows no provenance attestation for "+version);process.exit(1)}
    const facts={
      schema:1, package:pkg, version, tag, distTag, changelogDate:date, publishedAt,
      changelogEntry:entry.replace(/^\n+|\s+$/g,""),
      tarball:{name:path.basename(tarball), bytes:buf.length, sha256:crypto.createHash("sha256").update(buf).digest("hex"), integrity},
      provenance:prov, commit:commit||null, run:runUrl||null
    };
    fs.writeFileSync(out, JSON.stringify(facts,null,2)+"\n");
    if(summary){
      fs.appendFileSync(summary,
        "### Release facts "+version+"\n\n- registry `"+distTag+"` = "+version+", published "+publishedAt+"\n- tarball "+facts.tarball.name+", "+buf.length+" bytes, integrity matches the registry\n- provenance: "+prov+"\n- CHANGELOG date "+date+"\n\nNext (release session, owner go for the web deploy): open the facts PR in agenticcli with `apps/web/scripts/release-sync-facts.mjs --version "+version+"`.\n");
    }
    console.log("release-facts: wrote "+out+" ("+version+", "+buf.length+" bytes)");
  ' "$PKG_NAME" "$VERSION" "$TAG" "$EXPECT_TAG" "$CL_DATE" "$time_v" "$dist" "$entry" "$TARBALL" "$OUT" "${GITHUB_SHA:-}" "$run_url" "${GITHUB_STEP_SUMMARY:-}"
}

case "$MODE" in
  check) run_check ;;
  sync) run_sync ;;
  emit) run_emit ;;
  *) usage ;;
esac
