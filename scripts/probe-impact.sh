#!/usr/bin/env bash
# Measure how many vulnerabilities would disappear from an image by
#   (a) removing one or more packages, (b) updating its Debian packages, (c) both.
# Builds throwaway variants of the image, scans each with Trivy and Grype, prints a
# comparison table, then deletes the variants and all scan output. Nothing is left in
# the repository or in Docker unless KEEP=1 is set.
#
# Usage:  ./scripts/probe-impact.sh PACKAGE [PACKAGE...]
#         make probe REMOVE="nginx-module-image-filter"
#
# Environment:
#   IMAGE          image to probe (default: nginx:1.25-bookworm)
#   KEEP=1         keep the reports in scans/probe-<timestamp>/ and the variant images
#   PROBE_PRELUDE  file with extra Dockerfile lines inserted before the update step,
#                  for networks that need a proxy certificate; its folder becomes the
#                  build context
#   PROBE_BUILD_FLAGS  extra flags for `docker build` (for example "--network host")
#   TRIVY_FLAGS    extra flags for `trivy image` (for example "--skip-db-update")
set -euo pipefail

[ $# -ge 1 ] || { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
PKGS="$*"
IMAGE="${IMAGE:-nginx:1.25-bookworm}"
KEEP="${KEEP:-0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="probe-impact-$$"
WORK="$(mktemp -d)"
VARIANTS="original removed updated updated-removed"

cleanup() {
  if [ "$KEEP" = "1" ]; then
    dest="$ROOT/scans/probe-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$dest"
    for v in $VARIANTS; do [ -d "$WORK/$v" ] && cp -r "$WORK/$v" "$dest/"; done
    [ -f "$WORK/summary.md" ] && cp "$WORK/summary.md" "$dest/"
    echo "Kept reports in ${dest#"$ROOT"/} and images $TAG:*"
  else
    for v in removed updated updated-removed; do docker rmi -f "$TAG:$v" >/dev/null 2>&1 || true; done
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "ERROR: docker not found in PATH" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"

if command -v trivy >/dev/null; then trivy_() { trivy "$@"; }; TW() { echo "$1"; }
else trivy_() { docker run --rm -v "$WORK:/work" -v scan-cache-trivy:/root/.cache aquasec/trivy:latest "$@"; }; TW() { echo "/work${1#"$WORK"}"; }; fi
if command -v grype >/dev/null; then grype_() { grype "$@"; }; GW() { echo "$1"; }
else grype_() { docker run --rm -v "$WORK:/work" -v scan-cache-grype:/cache -e GRYPE_DB_CACHE_DIR=/cache anchore/grype:latest "$@"; }; GW() { echo "/work${1#"$WORK"}"; }; fi

CONTEXT="$WORK/ctx"; mkdir -p "$CONTEXT"
PRELUDE=""
if [ -n "${PROBE_PRELUDE:-}" ]; then PRELUDE="$(cat "$PROBE_PRELUDE")"; CONTEXT="$(cd "$(dirname "$PROBE_PRELUDE")" && pwd)"; fi
REMOVE="RUN apt-get remove --purge --auto-remove -y $PKGS"
UPDATE="RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*"

build() {  # variant, dockerfile body
  echo "==> Building variant: $1"
  printf 'FROM %s\nUSER root\n%s\n' "$IMAGE" "$2" > "$WORK/Dockerfile.$1"
  # shellcheck disable=SC2086
  docker build -q ${PROBE_BUILD_FLAGS:-} -f "$WORK/Dockerfile.$1" -t "$TAG:$1" "$CONTEXT" >/dev/null
}
build removed         "$REMOVE"
build updated         "$PRELUDE
$UPDATE"
build updated-removed "$PRELUDE
$UPDATE
$REMOVE"

scan() {  # variant, image ref
  echo "==> Scanning variant: $1"
  d="$WORK/$1"; mkdir -p "$d"
  docker run --rm --entrypoint "" "$2" dpkg-query -W -f='${Package}\t${Version}\n' > "$d/packages.tsv"
  docker save "$2" -o "$d/image.tar"
  # shellcheck disable=SC2086
  trivy_ image --quiet --scanners vuln ${TRIVY_FLAGS:-} --input "$(TW "$d/image.tar")" --format json --output "$(TW "$d/trivy.json")"
  grype_ "docker-archive:$(GW "$d/image.tar")" -q -o "json=$(GW "$d/grype.json")"
  rm -f "$d/image.tar"
  linked="$ROOT/scans/baseline/linked-packages.txt"
  python3 "$ROOT/scripts/compare-scans.py" "$d/trivy.json" "$d/grype.json" \
    $([ -f "$linked" ] && echo --linked "$linked") --out-dir "$d" >/dev/null 2>&1
}
scan original "$IMAGE"
for v in removed updated updated-removed; do scan "$v" "$TAG:$v"; done

python3 - "$WORK" "$IMAGE" "$PKGS" <<'PY' | tee "$WORK/summary.md"
import csv, sys
work, image, pkgs = sys.argv[1:4]
def load(v):
    rows = list(csv.DictReader(open(f"{work}/{v}/triage.csv")))
    names = {l.split("\t")[0] for l in open(f"{work}/{v}/packages.tsv") if l.strip()}
    return rows, names
hi = lambda r: "Critical" in (r["trivy"], r["grype"]) or "High" in (r["trivy"], r["grype"])
data = {v: load(v) for v in ("original", "removed", "updated", "updated-removed")}
gone = data["original"][1] - data["removed"][1]          # packages the removal takes away
touch = lambda rows: [r for r in rows if set(r["packages"].split()) & gone]
label = {"original": "Original", "removed": "Packages removed only",
         "updated": "Debian packages updated only", "updated-removed": "Updated and removed"}
print(f"\n## Impact of removing `{pkgs}` from `{image}`\n")
print(f"Removing takes away {len(gone)} packages: {', '.join(sorted(gone))}.\n")
print("| Variant | Packages | Unique CVEs | Critical or High | CVEs in the removed packages |")
print("|---|---|---|---|---|")
for v in ("original", "removed", "updated", "updated-removed"):
    rows, names = data[v]
    print(f"| {label[v]} | {len(names)} | {len(rows)} | {sum(map(hi, rows))} | {len(touch(rows))} |")
o, u = touch(data["original"][0]), touch(data["updated"][0])
print(f"\nOf the {len(o)} CVEs in those packages, updating alone fixes {len(o) - len(u)} and "
      f"leaves {len(u)} ({sum(1 for r in u if r['fix_available'] == 'yes')} with a fix available). "
      "Only removal clears the rest.")
print("\nCounts are unique CVE IDs across Trivy and Grype. These are throwaway probe images; "
      "re-measure on the image that is actually shipped.")
PY
