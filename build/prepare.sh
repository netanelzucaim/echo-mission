#!/bin/sh
# Assemble the nginx build tree from upstream sources, with our backport applied.
#
# This fetches nginx's official packaging (pkg-oss) at the exact commit that
# targets nginx 1.25.5 + njs 0.8.4, injects our CVE backport into its quilt
# series, and applies three local adjustments so it builds offline-friendly and
# matches the original image. It does NOT compile anything; build/Dockerfile
# runs `make` afterwards.
set -eu

# Pinned so the build is reproducible: this pkg-oss commit sets NGINX_VERSION
# 1.25.5 and NJS_VERSION 0.8.4 (the versions the original image ships).
PKGOSS_COMMIT=aaeb9a9
NJS_TAG=0.8.4
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

echo "==> Fetching nginx packaging (pkg-oss @ $PKGOSS_COMMIT)"
rm -rf pkg-oss
git clone -q https://github.com/nginx/pkg-oss.git
git -C pkg-oss checkout -q "$PKGOSS_COMMIT"

echo "==> Applying the CVE patches in patches/"
# Every patches/CVE-*.patch is applied. What it changes decides how:
#  - nginx source (paths src/, auto/, conf/): a backport. It is copied into
#    pkg-oss/contrib/src/nginx/; pkg-oss adds every *.patch there to the quilt
#    series and applies it to the nginx source during the build.
#  - nginx's packaging (paths debian/): for example a version bump that raises a
#    package's minimum dependency version. Applied to pkg-oss directly.
#  - njs source (paths external/, nginx/, src/njs_*): not wired up yet; stop with
#    a message instead of building without it. See patches/README.md.
for p in patches/CVE-*.patch; do
  [ -e "$p" ] || continue
  paths=$(sed -n 's|^+++ b/||p' "$p")
  if [ -z "$paths" ]; then
    echo "ERROR: $p changes no files (missing '+++ b/' lines?)" >&2; exit 1
  elif ! echo "$paths" | grep -qvE '^debian/'; then
    echo "    $p: packaging change, applied to pkg-oss"
    patch -p1 -d pkg-oss < "$p"
  elif echo "$paths" | grep -qE '^(external/|nginx/|src/njs_)'; then
    echo "ERROR: $p patches the njs source, which prepare.sh does not apply yet." >&2
    echo "       See build/patches/README.md, 'Adding another fix'." >&2
    exit 1
  elif ! echo "$paths" | grep -qvE '^(src|auto|conf)/'; then
    echo "    $p: nginx source change, added to the quilt series"
    cp "$p" pkg-oss/contrib/src/nginx/
  else
    echo "ERROR: $p mixes nginx source and other paths; split it." >&2
    echo "$paths" | sed 's/^/       /' >&2
    exit 1
  fi
done

echo "==> Applying packaging adjustments"
# echo-pkg-oss.patch: (1) use a static Debian changelog instead of generating it
# with xslscript (which pkg-oss fetches over the network); (2) build the njs
# module and CLI without QuickJS, matching the original image's njs 0.8.4;
# (3) set the njs package release to 3, matching the original's version string.
patch -p1 -d pkg-oss < echo-pkg-oss.patch
cp changelog/nginx.deb-changelog            pkg-oss/debian/
cp changelog/nginx-module-xslt.deb-changelog        pkg-oss/debian/
cp changelog/nginx-module-geoip.deb-changelog       pkg-oss/debian/
cp changelog/nginx-module-image-filter.deb-changelog pkg-oss/debian/
cp changelog/nginx-module-njs.deb-changelog         pkg-oss/debian/

echo "==> Vendoring njs $NJS_TAG source"
# The njs module is a separate upstream. We vendor the source tarball from the
# njs git tag; its hg.nginx.org archive URL is not reliably reachable.
rm -rf njs
git clone -q https://github.com/nginx/njs.git
git -C njs archive --format=tar.gz --prefix="njs-$NJS_TAG/" "$NJS_TAG" \
    > "pkg-oss/contrib/tarballs/njs-$NJS_TAG.tar.gz"
rm -rf njs

echo "==> Ready. Build with:  cd pkg-oss/debian && make base module-xslt module-geoip module-image-filter module-njs"
