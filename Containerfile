# Final image: drop-in replacement for nginx:1.25-bookworm.
# Every setting below is copied from the original image
# (see scans/baseline/inspect.json and scans/baseline/history.txt).
# Requires the patched package in out/ (built by build/, step 3).
FROM debian:bookworm-slim

# Deliberate difference from the original (see README): this image is not built by NGINX.
LABEL maintainer="Netanel Zucaim <netanelzucaim100@gmail.com>"

ENV NGINX_VERSION=1.25.5
ENV NJS_VERSION=0.8.4
ENV NJS_RELEASE=3~bookworm
ENV PKG_RELEASE=1~bookworm

COPY out/nginx_*.deb /tmp/

RUN set -x \
 # same user and IDs as the original
 && groupadd --system --gid 101 nginx \
 && useradd --system --gid nginx --no-create-home --home /nonexistent \
      --comment "nginx user" --shell /bin/false --uid 101 nginx \
 # current Debian packages = the version-bump fixes
 && apt-get update \
 && apt-get upgrade -y \
 # patched nginx + the helper packages the original keeps
 && apt-get install --no-install-recommends --no-install-suggests -y \
      /tmp/nginx_*.deb gettext-base curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* /tmp/nginx_*.deb \
 # logs go to the container's stdout/stderr
 && ln -sf /dev/stdout /var/log/nginx/access.log \
 && ln -sf /dev/stderr /var/log/nginx/error.log \
 && mkdir /docker-entrypoint.d

# Startup scripts, extracted unchanged from the original image
COPY --chmod=0755 entrypoint/docker-entrypoint.sh /
COPY --chmod=0755 entrypoint/docker-entrypoint.d/ /docker-entrypoint.d/

ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 80

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
