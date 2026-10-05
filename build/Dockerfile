# Step 3: build the patched nginx .deb (and the four module .debs) from source,
# in a clean debian:bookworm-slim, with no pre-baked binaries.
#
#   docker build -f build/Dockerfile -t echo-nginx-build build/
#   # then copy the .debs out of the image's /out into ./out/  (see `make deb`)
#
# The build uses nginx's official packaging (pkg-oss) with our CVE-2026-42945
# backport injected into its quilt series; build/prepare.sh assembles the tree.
FROM debian:bookworm-slim

# Build tooling + nginx and module build dependencies.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential devscripts debhelper quilt lsb-release fakeroot dpkg-dev \
      git curl ca-certificates xz-utils \
      libssl-dev libpcre2-dev zlib1g-dev \
      libxml2-dev libxslt1-dev libgd-dev libgeoip-dev libedit-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY prepare.sh echo-pkg-oss.patch ./
COPY patches/ ./patches/

# Fetch upstream source, inject the backport, vendor njs, apply packaging tweaks.
RUN sh ./prepare.sh

# Compile nginx 1.25.5 (with the backport) and the four dynamic modules.
WORKDIR /build/pkg-oss/debian
RUN make base module-xslt module-geoip module-image-filter module-njs

# Collect the five packages the final image installs (not the -dbg symbol debs).
RUN mkdir -p /out \
 && find /build -maxdepth 1 -name 'nginx_*.deb' -exec cp {} /out/ \; \
 && for m in xslt geoip image-filter njs; do \
      find /build -maxdepth 1 -name "nginx-module-${m}_*.deb" -exec cp {} /out/ \; ; \
    done \
 && ls -la /out
