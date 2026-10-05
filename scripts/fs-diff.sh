#!/usr/bin/env bash
# Compare the files in the original image and the patched image.
# Usage: make fsdiff   (or: ORIGINAL=... IMAGE=... ./scripts/fs-diff.sh)
#
# The compatibility test inspects only the nginx paths. This lists every regular
# file in both images (outside caches, logs, docs and package lists) and reports
# files that exist in one image but not the other. Run it after any build change.
#
# Expected differences are reported separately and do not fail the check:
# files that come from the newer Debian base (debian-archive keyrings, tzdata,
# the CA certificate store). Anything else is a real difference: exit code 1.
set -euo pipefail
cd "$(dirname "$0")/.."

ORIGINAL="${ORIGINAL:-nginx:1.25-bookworm}"
IMAGE="${IMAGE:-echo-nginx:1.25-bookworm}"
EXPECTED='/etc/ssl/certs/|/usr/share/ca-certificates/|/usr/lib/ssl/|/usr/share/zoneinfo/|debian-archive-'

for i in "$ORIGINAL" "$IMAGE"; do
  docker image inspect "$i" >/dev/null 2>&1 || { echo "ERROR: image not found: $i" >&2; exit 2; }
done

list() {
  docker run --rm --entrypoint sh "$1" -c '
    find / -xdev \( -path /proc -o -path /sys -o -path /tmp -o -path /run -o -path /var/cache \
      -o -path /var/log -o -path /var/lib/apt/lists -o -path /var/lib/dpkg -o -path /usr/share/doc \
      -o -path /usr/share/man \) -prune -o -type f -print 2>/dev/null | sort'
}

diffs=$(diff <(list "$ORIGINAL") <(list "$IMAGE") | grep -E '^[<>]' || true)
expected=$(echo "$diffs" | grep -E "$EXPECTED" || true)
unexpected=$(echo "$diffs" | grep -vE "$EXPECTED" | grep . || true)

echo "Files only in $ORIGINAL (<) or only in $IMAGE (>)"
echo
echo "Expected (from the newer Debian base): $(echo "$expected" | grep -c . || true) files"
if [ -n "$unexpected" ]; then
  echo "UNEXPECTED: $(echo "$unexpected" | grep -c .) files"
  echo "$unexpected" | sed 's/^/  /'
  exit 1
fi
echo "Unexpected: none. The file layout matches the original."
