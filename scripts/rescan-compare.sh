#!/usr/bin/env bash
# Step 6: scan the patched image, compare it with the baseline, and apply VEX.
#
# Usage:  IMAGE=<patched image> ./scripts/rescan-compare.sh
#         make rescan IMAGE=<patched image>
#
# What it does, in order:
#   1. Scans IMAGE with Trivy and Grype into OUT (same layout as scans/baseline/).
#   2. Lists the result in one table              -> OUT/triage.csv (input for step 4)
#   3. Scans again with every VEX file applied    -> OUT/reports/trivy-vex.*, grype-vex.*
#   4. Compares with the baseline and checks VEX  -> OUT/diff.md, diff.csv
#
# Environment:
#   IMAGE     the patched image (required; it is not pulled if it exists locally)
#   OUT       where to write (default: scans/patched)
#   BASELINE  the "before" scan (default: scans/baseline)
#   VEX       space-separated OpenVEX files (default: every vex/*.json)
#   TRIVY_FLAGS  extra flags for `trivy image` (for example "--skip-db-update")
#
# Use the same scanner versions as the baseline, and scan soon after it, or the
# comparison also picks up changes in the scanners' databases.
set -euo pipefail

: "${IMAGE:?set IMAGE to the patched image, for example IMAGE=echo-nginx:1.25-bookworm}"
OUT="${OUT:-scans/patched}"
BASELINE="${BASELINE:-scans/baseline}"
cd "$(dirname "$0")/.."

[ -f "$BASELINE/triage.csv" ] || { echo "ERROR: $BASELINE/triage.csv not found; run make scan-baseline and make triage first" >&2; exit 1; }
if [ -z "${VEX+x}" ]; then VEX="$(ls vex/*.json 2>/dev/null | tr '\n' ' ' || true)"; fi

echo "==> 1/4 Scanning $IMAGE into $OUT"
IMAGE="$IMAGE" OUT="$OUT" TRIVY_FLAGS="${TRIVY_FLAGS:-}" ./scripts/scan-baseline.sh

echo "==> 2/4 Merging the two reports"
python3 scripts/compare-scans.py "$OUT/reports/trivy.json" "$OUT/reports/grype.json" --out-dir "$OUT" --csv-only

REP="$(cd "$OUT/reports" && pwd)"
rm -f "$REP"/trivy-vex.* "$REP"/grype-vex.*
VEX_ARGS=()
if [ -n "${VEX// /}" ]; then
  echo "==> 3/4 Scanning again with VEX: $VEX"
  if command -v trivy >/dev/null; then TW="$REP"; trivy_() { trivy "$@"; }; tv() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
  else TW=/work; trivy_() { docker run --rm -v "$REP:/work" -v "$PWD:/repo:ro" -v scan-cache-trivy:/root/.cache aquasec/trivy:latest "$@"; }; tv() { echo "/repo/$1"; }; fi
  if command -v grype >/dev/null; then GW="$REP"; grype_() { grype "$@"; }; gv() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
  else GW=/work; grype_() { docker run --rm -v "$REP:/work" -v "$PWD:/repo:ro" -v scan-cache-grype:/cache -e GRYPE_DB_CACHE_DIR=/cache anchore/grype:latest "$@"; }; gv() { echo "/repo/$1"; }; fi
  T_VEX=(); G_VEX=()
  for f in $VEX; do
    [ -f "$f" ] || { echo "ERROR: VEX file not found: $f" >&2; exit 1; }
    T_VEX+=(--vex "$(tv "$f")"); G_VEX+=(--vex "$(gv "$f")"); VEX_ARGS+=(--vex "$f")
  done
  docker save "$IMAGE" -o "$REP/image.tar"
  trap 'rm -f "$REP/image.tar"' EXIT
  # shellcheck disable=SC2086
  trivy_ image --quiet --scanners vuln --skip-db-update ${TRIVY_FLAGS:-} "${T_VEX[@]}" --input "$TW/image.tar" --format json --output "$TW/trivy-vex.json"
  trivy_ convert --format table --output "$TW/trivy-vex.txt" "$TW/trivy-vex.json"
  grype_ "docker-archive:$GW/image.tar" -q "${G_VEX[@]}" -o "json=$GW/grype-vex.json" -o "table=$GW/grype-vex.txt"
  rm -f "$REP/image.tar"
else
  echo "==> 3/4 No VEX files (vex/*.json); skipping the VEX scan"
fi

echo "==> 4/4 Comparing with $BASELINE"
python3 scripts/diff-scans.py "$BASELINE" "$OUT" ${VEX_ARGS[@]+"${VEX_ARGS[@]}"}
echo
echo "Read $OUT/diff.md."
