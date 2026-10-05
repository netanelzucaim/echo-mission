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

echo "==> Injecting the backport into the quilt series"
# pkg-oss adds every contrib/src/nginx/*.patch to debian/patches/series and
# applies it during the build, so this is all it takes to backport our fix.
cp patches/CVE-2026-42945.patch pkg-oss/contrib/src/nginx/

echo "==> Applying the version bump"
# CVE-2024-6119.patch raises the nginx package's minimum libssl3 version to the
# one Debian fixed it in, so installing the package always brings a fixed OpenSSL.
# It changes nginx's packaging (pkg-oss), not nginx's source.
patch -p1 -d pkg-oss < patches/CVE-2024-6119.patch

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
