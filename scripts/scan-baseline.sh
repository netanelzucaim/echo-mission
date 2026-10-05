#!/usr/bin/env bash
# Step 1: pull the original image and scan it with Trivy and Grype.
# Usage: ./scripts/scan-baseline.sh        (or: make scan-baseline)
# Optional env: IMAGE, OUT, PLATFORM (e.g. linux/amd64), MODULES, TRIVY_FLAGS
#
# Only Docker is required. Trivy/Grype are used from the host if installed,
# otherwise they run as containers. Both scan the same `docker save` tarball,
# so the two reports describe exactly the same image bytes.
set -euo pipefail

IMAGE="${IMAGE:-nginx:1.25-bookworm}"
OUT="${OUT:-scans/baseline}"
PLATFORM="${PLATFORM:-}"

cd "$(dirname "$0")/.."
mkdir -p "$OUT/reports" "$OUT/image"
OUT_ABS="$(cd "$OUT" && pwd)"
REP="$OUT_ABS/reports"   # scanner output
IMG="$OUT_ABS/image"     # facts about the image itself

command -v docker >/dev/null || { echo "ERROR: docker not found in PATH" >&2; exit 1; }
docker info >/dev/null 2>&1   || { echo "ERROR: docker daemon is not running" >&2; exit 1; }

echo "==> Pulling $IMAGE ${PLATFORM:+($PLATFORM)}"
if ! docker pull ${PLATFORM:+--platform "$PLATFORM"} "$IMAGE"; then
  docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "ERROR: cannot pull $IMAGE and no local copy exists" >&2; exit 1; }
  echo "WARNING: pull failed (registry rate limit?); using the local copy of $IMAGE" >&2
fi

echo "==> Recording image metadata"
docker inspect "$IMAGE"            > "$IMG/inspect.json"
docker history --no-trunc "$IMAGE" > "$IMG/history.txt"
docker inspect --format '{{index .RepoDigests 0}} {{.Os}}/{{.Architecture}}' "$IMAGE" > "$IMG/digest.txt"
RUN=(docker run --rm ${PLATFORM:+--platform "$PLATFORM"} --entrypoint "")
"${RUN[@]}" "$IMAGE" nginx -V   > "$IMG/nginx-V.txt" 2>&1
"${RUN[@]}" "$IMAGE" dpkg-query -W -f='${Package}\t${Version}\t${Source}\n' > "$IMG/packages.tsv"
"${RUN[@]}" "$IMAGE" sh -c 'ls -la / /docker-entrypoint.d /etc/nginx /etc/nginx/conf.d /usr/lib/nginx/modules; id nginx' > "$IMG/layout.txt" 2>&1
# The nginx package itself plus the packages whose shared libraries its binary loads. Used by compare-scans.py
# to tell "nginx runs this code" apart from "this merely sits in the image".
"${RUN[@]}" "$IMAGE" sh -c '
  { echo /usr/sbin/nginx; ldd /usr/sbin/nginx | awk "{for(i=1;i<=NF;i++) if (\$i ~ /^\//) print \$i}"; } |
  while read -r p; do
    r=$(readlink -f "$p")
    dpkg -S "$r" 2>/dev/null || dpkg -S "${r#/usr}" 2>/dev/null || dpkg -S "$p" 2>/dev/null
  done | cut -d: -f1 | sort -u' > "$IMG/linked-packages.txt"
# Optional modules: packages that are installed only because of them. One line per
# module and package. Default: every nginx-module-* package in the image.
MODULES="${MODULES:-$("${RUN[@]}" "$IMAGE" dpkg-query -W -f='${db:Status-Abbrev}${Package}\n' 'nginx-module-*' 2>/dev/null | sed -n 's/^ii *//p' | tr '\n' ' ')}"
: > "$IMG/modules.tsv"
if [ -n "${MODULES// /}" ]; then
  "${RUN[@]}" "$IMAGE" sh -c '
    only=$(apt-get -s remove --auto-remove "$@" 2>/dev/null | awk "/^Remv/ {print \$2}" | sort -u)
    for c in "$@"; do
      apt-cache depends --recurse --installed --no-recommends --no-suggests --no-conflicts \
        --no-breaks --no-replaces --no-enhances "$c" 2>/dev/null | grep -v "^ " | grep -v "^<" | sort -u |
      while read -r p; do
        [ "$p" = "$c" ] && continue
        if echo "$only" | grep -qx "$p"; then printf "%s\t%s\n" "$c" "$p"; fi
      done
    done' sh $MODULES > "$IMG/modules.tsv"
fi

echo "==> Saving image tarball"
docker save "$IMAGE" -o "$REP/image.tar"

if command -v trivy >/dev/null; then
  TW="$REP"; trivy_() { trivy "$@"; }
else
  TW=/work; trivy_() { docker run --rm -v "$REP:/work" -v scan-cache-trivy:/root/.cache aquasec/trivy:latest "$@"; }
fi
if command -v grype >/dev/null; then
  GW="$REP"; grype_() { grype "$@"; }
else
  GW=/work; grype_() { docker run --rm -v "$REP:/work" -v scan-cache-grype:/cache -e GRYPE_DB_CACHE_DIR=/cache anchore/grype:latest "$@"; }
fi

echo "==> Trivy scan"
# shellcheck disable=SC2086
trivy_ image --scanners vuln ${TRIVY_FLAGS:-} --input "$TW/image.tar" --format json --output "$TW/trivy.json"
trivy_ convert --format table --output "$TW/trivy.txt" "$TW/trivy.json"

echo "==> Grype scan"
grype_ "docker-archive:$GW/image.tar" -o "json=$GW/grype.json" -o "table=$GW/grype.txt"

{
  echo "date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "image:  $(cat "$IMG/digest.txt")"
  echo "trivy:  $(trivy_ --version 2>&1 | head -1)"
  echo "grype:  $(grype_ version 2>&1 | grep -i '^Version' | head -1)"
} > "$REP/versions.txt"

rm -f "$REP/image.tar"
echo
echo "==> Done. Scanner reports in $OUT/reports/, image facts in $OUT/image/"
echo "    Next: make triage"
ls -lh "$REP" "$IMG"
