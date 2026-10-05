#!/usr/bin/env bash
# Step 1: pull the original image and scan it with Trivy and Grype.
# Usage: ./scripts/scan-baseline.sh        (or: make scan-baseline)
# Optional env: IMAGE, OUT, PLATFORM (e.g. linux/amd64)
#
# Only Docker is required. Trivy/Grype are used from the host if installed,
# otherwise they run as containers. Both scan the same `docker save` tarball,
# so the two reports describe exactly the same image bytes.
set -euo pipefail

IMAGE="${IMAGE:-nginx:1.25-bookworm}"
OUT="${OUT:-scans/baseline}"
PLATFORM="${PLATFORM:-}"

cd "$(dirname "$0")/.."
mkdir -p "$OUT"
OUT_ABS="$(cd "$OUT" && pwd)"

command -v docker >/dev/null || { echo "ERROR: docker not found in PATH" >&2; exit 1; }
docker info >/dev/null 2>&1   || { echo "ERROR: docker daemon is not running" >&2; exit 1; }

echo "==> Pulling $IMAGE ${PLATFORM:+($PLATFORM)}"
docker pull ${PLATFORM:+--platform "$PLATFORM"} "$IMAGE"

echo "==> Recording image metadata"
docker inspect "$IMAGE"            > "$OUT_ABS/inspect.json"
docker history --no-trunc "$IMAGE" > "$OUT_ABS/history.txt"
docker inspect --format '{{index .RepoDigests 0}} {{.Os}}/{{.Architecture}}' "$IMAGE" > "$OUT_ABS/digest.txt"
RUN=(docker run --rm ${PLATFORM:+--platform "$PLATFORM"} --entrypoint "")
"${RUN[@]}" "$IMAGE" nginx -V   > "$OUT_ABS/nginx-V.txt" 2>&1
"${RUN[@]}" "$IMAGE" dpkg-query -W -f='${Package}\t${Version}\t${Source}\n' > "$OUT_ABS/packages.tsv"
"${RUN[@]}" "$IMAGE" sh -c 'ls -la / /docker-entrypoint.d /etc/nginx /etc/nginx/conf.d /usr/lib/nginx/modules; id nginx' > "$OUT_ABS/layout.txt" 2>&1
# Packages whose shared libraries the nginx binary loads. Used by compare-scans.py
# to tell "nginx runs this code" apart from "this merely sits in the image".
"${RUN[@]}" "$IMAGE" sh -c '
  ldd /usr/sbin/nginx | awk "{for(i=1;i<=NF;i++) if (\$i ~ /^\//) print \$i}" |
  while read -r p; do
    r=$(readlink -f "$p")
    dpkg -S "$r" 2>/dev/null || dpkg -S "${r#/usr}" 2>/dev/null || dpkg -S "$p" 2>/dev/null
  done | cut -d: -f1 | sort -u' > "$OUT_ABS/linked-packages.txt"

echo "==> Saving image tarball"
docker save "$IMAGE" -o "$OUT_ABS/image.tar"

if command -v trivy >/dev/null; then
  TW="$OUT_ABS"; trivy_() { trivy "$@"; }
else
  TW=/work; trivy_() { docker run --rm -v "$OUT_ABS:/work" -v scan-cache-trivy:/root/.cache aquasec/trivy:latest "$@"; }
fi
if command -v grype >/dev/null; then
  GW="$OUT_ABS"; grype_() { grype "$@"; }
else
  GW=/work; grype_() { docker run --rm -v "$OUT_ABS:/work" -v scan-cache-grype:/cache -e GRYPE_DB_CACHE_DIR=/cache anchore/grype:latest "$@"; }
fi

echo "==> Trivy scan"
trivy_ image --scanners vuln --input "$TW/image.tar" --format json --output "$TW/trivy.json"
trivy_ convert --format table --output "$TW/trivy.txt" "$TW/trivy.json"

echo "==> Grype scan"
grype_ "docker-archive:$GW/image.tar" -o "json=$GW/grype.json" -o "table=$GW/grype.txt"

{
  echo "date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "image:  $(cat "$OUT_ABS/digest.txt")"
  echo "trivy:  $(trivy_ --version 2>&1 | head -1)"
  echo "grype:  $(grype_ version 2>&1 | grep -i '^Version' | head -1)"
} > "$OUT_ABS/versions.txt"

rm -f "$OUT_ABS/image.tar"
echo
echo "==> Done. Reports in $OUT/"
ls -lh "$OUT_ABS"
