# build/ — the patched `.deb`s from source (step 3)

One command, from a clean `debian:bookworm-slim`, with no pre-baked binaries:

```sh
make deb      # builds build/Dockerfile and copies the five .debs into ./out/
```

Output in `out/`: `nginx_*.deb` plus `nginx-module-{xslt,geoip,image-filter,njs}_*.deb`
(the `-dbg` symbol packages are built too but not copied — the original image does not
ship them). `make image` then installs these into the final image.

## How it works

The original image is built with nginx's **official packaging** (`pkg-oss`): that is
what produces the exact `nginx -V` flags, the `nginx` + `nginx-debug` binaries, the
conffiles, logrotate and systemd units, and the four dynamic modules with their debug
twins. Reproducing all of that by hand would not match, and the compatibility test
treats the original as the specification — so this build drives `pkg-oss` and injects
our backport into it, rather than re-inventing the packaging.

`prepare.sh` assembles the source tree; `Dockerfile` compiles it. `prepare.sh`:

1. **Fetches `pkg-oss`** at the pinned commit `aaeb9a9`, which targets nginx **1.25.5**
   and njs **0.8.4** — the versions the original image ships.
2. **Applies every `patches/CVE-*.patch`**, deciding how from the paths it changes:
   - nginx source (`src/`, `auto/`, `conf/`): a **backport**, copied into
     `contrib/src/nginx/`, where `pkg-oss` adds it to its quilt `series` and applies
     it during the build. Here: `CVE-2026-42945.patch`.
   - nginx's packaging (`debian/`): for example a **version bump**, applied to pkg-oss
     directly. Here: `CVE-2024-6119.patch`, which raises the nginx package's minimum
     `libssl3` to `3.0.14-1~deb12u2`, the version Debian fixed the CVE in.
   - njs source: not supported yet; the script stops with an error.
   How to add another fix: `patches/README.md`, "Adding another fix".
3. **Applies `echo-pkg-oss.patch`**, three small packaging adjustments:
   - use a **static Debian changelog** instead of generating it with `xslscript`
     (which `pkg-oss` fetches over the network from a host that is not always reachable);
   - build the njs **module and CLI without QuickJS**, matching the original image's
     njs 0.8.4 (its `ngx_http_js_module.so` links no QuickJS and its `/usr/bin/njs` links
     only libedit — both verified with `ldd`). The njs package still ships `/usr/bin/njs`;
   - set the njs package's **release number to 3**, so its version is
     `1.25.5+0.8.4-3~bookworm`, exactly as in the original image (pkg-oss at this commit
     says 1). All five nginx package versions then match the original.
   The static changelogs are in `changelog/`.
4. **Vendors the njs 0.8.4 source** from the njs git tag (its `hg.nginx.org` archive URL
   is not reliably reachable), into `pkg-oss/contrib/tarballs/`.

The nginx 1.25.5 source itself is downloaded by `pkg-oss` from `nginx.org` during the
build, with `pkg-oss`'s own SHA512 checksum verification.

## Files

| Path | What it is |
|---|---|
| `Dockerfile` | Clean build (no environment-specific settings); runs `prepare.sh` then `make` |
| `prepare.sh` | Fetches and assembles the source tree (our orchestration script) |
| `echo-pkg-oss.patch` | The three packaging adjustments above, applied to `pkg-oss` |
| `changelog/` | Static Debian changelog templates (one per package) |
| `patches/CVE-2024-6119.patch` | The version bump: minimum `libssl3` version in the nginx package |
| `patches/CVE-2026-42945.patch` | The backport, applied to the nginx source by `pkg-oss` |
| `patches/README.md` | What each patch fixes, how it was verified, and how to add another fix |

## Building behind an HTTPS-only proxy

The committed files carry no proxy or CA settings. To build behind such a proxy, pass
them at build time:
`docker build --network host --build-arg https_proxy=$HTTPS_PROXY ...` with the proxy CA
trusted inside the build and the apt sources switched to `https://`.
