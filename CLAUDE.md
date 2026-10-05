# Project guide for Claude

Take-home assignment, "Software Engineer: Build It, Patch It, Ship It". The brief
names the company Echo, which rebuilds container images from source to patch CVEs.
Owner: Netanel Zucaim. The human-facing write-up is `README.md`; this file is the
working context.

## The mission

Ship a drop-in replacement for `nginx:1.25-bookworm` with at least 2 CVEs eliminated:

1. At least one by **version bump** of a dependency (system library or upstream source).
2. At least one by **backporting** a patch from a newer upstream commit onto the nginx
   version being shipped (1.25.x).

Removing a vulnerable component is allowed as an extra and does not count toward the two.

Also required: an automated compatibility test proving the new image behaves like the
original for a representative set of HTTP scenarios.

### Steps in the brief

| # | Step | Status |
|---|---|---|
| 1 | Scan the original with Trivy and Grype, save reports | Done (`scans/baseline/`) |
| 2 | Triage: per CVE, where it lives, is there a fix, how to fix; pick targets and justify | In progress |
| 3 | Build a `.deb` from source in a clean `debian:bookworm-slim`, one command, patches applied | Not started |
| 4 | Final image: install the `.deb` into a minimal Debian base, match the original | `Containerfile` drafted, never built |
| 5 | Compatibility test in Go or Python, `make test`, non-zero exit on mismatch | Not started |
| 6 | Bonus: rescan, diff against baseline, VEX document for the backported CVE | Not started |

### Required deliverables

- `build/`: Dockerfile or script that produces the `.deb`, plus `build/patches/` with
  each backport named after its CVE (`CVE-YYYY-NNNN.patch`).
- `Containerfile`: builds the final image from the `.deb`.
- `test/`: the compatibility test, runnable with `make test`.
- `README.md`: build instructions, image size (original vs new), per-CVE table
  (ID, severity, fix method, evidence link), residual risk, surprises and what would be
  done differently, how AI tools were used.

### What is graded

Depth over breadth (two well-fixed CVEs beat ten half-fixed), engineering judgment and
triage reasoning, an honest residual-risk assessment, and documenting dead ends
truthfully. Do not overstate what a fix achieves.

## The solution so far

### Decided

- **Base:** fresh `debian:bookworm-slim` plus `apt-get upgrade`. This is where all
  version-bump fixes come from.
- **Image settings:** copied from the original (`scans/baseline/inspect.json`,
  `history.txt`). One deliberate difference: the `maintainer` label names the owner,
  because the image is not built by NGINX.
- **Startup scripts:** extracted unchanged from the original into `entrypoint/`.
- **Kerberos CVE-2024-37371:** considered and rejected by the owner as the headline
  bump. The library is only present because `curl` depends on it; nginx never calls it.
  It is still upgraded by the fresh base, just not claimed as one of the two fixes.

### Proposed, awaiting the owner's confirmation

- **Version bump:** OpenSSL `3.0.11` to `3.0.22`, headline CVE-2024-6119 (denial of
  service in X.509 name checks; reachable when nginx is a reverse proxy that verifies
  upstream certificates). On a probe image the same bump removed 42 of 49 OpenSSL CVEs.
  Rejected alternative: CVE-2025-15467 is in CMS parsing, which nginx does not use.
- **Backport:** CVE-2024-7347 (mp4 module over-read). Upstream fix is in nginx
  1.27.1 / 1.26.2; 1.25.5 is affected. The upstream commit has not been read yet.

### Open

- **Dynamic modules.** The original installs five packages: `nginx` plus
  `nginx-module-xslt`, `-geoip`, `-image-filter`, `-njs`. None is loaded by default (no
  `load_module` line). Keeping them means building five packages; dropping them removes
  37 libraries and about a quarter of the baseline findings but breaks configs that
  load a module. If njs is dropped, remove `NJS_VERSION` and `NJS_RELEASE` from the
  `Containerfile`.
- **Signing key leftover.** The original contains
  `/etc/apt/keyrings/nginx-archive-keyring.gpg`; the new image will not. Document it as
  a deliberate filesystem difference or copy it in.

## Findings worth keeping in mind

- **Scanners miss nginx's own CVEs.** The `nginx` package comes from nginx.org, but
  Trivy and Grype compare its version against Debian's fixed versions (Debian ships
  1.22.1 with backports). `1.25.5 > 1.22.1-9+deb12u2`, so the CVE looks fixed. Triage
  nginx CVEs from https://nginx.org/en/security_advisories.html, not from the reports.
  A backported fix may therefore show no before/after scan difference, leaving the VEX
  document nothing to suppress. Confirm after the real build.
- **The `.deb` must be named `nginx` and register `/etc/nginx/conf.d/default.conf` as a
  conffile**, with the original's exact content. See `entrypoint/README.md`.
- **Use the original's configure flags** from `scans/baseline/nginx-V.txt`; they decide
  the filesystem layout.
- **Loaded versus unloaded packages** are described in their own section below.
- **Targets are chosen by danger and reach, not by severity label.** The owner's rule:
  prefer what is most likely to be exploited and what every deployment actually runs.
  `make triage` scores this; see `scripts/CLAUDE.md`.

## Loaded and unloaded packages

The original image has 144 packages. The triage score (`make triage`) weights a
vulnerability by whether nginx runs the affected code.

**Loaded (weight 1.0):** the `nginx` package itself and the five libraries its binary
loads, taken from `ldd /usr/sbin/nginx` and saved in
`scans/baseline/linked-packages.txt`. A bug here is inside every running container.

| Package | What nginx uses it for |
|---|---|
| `nginx` | The server itself |
| `libssl3` (OpenSSL) | HTTPS encryption |
| `libpcre2-8-0` | Pattern matching in config rules |
| `zlib1g` | Compressing responses (gzip) |
| `libc6` | Basic system functions |
| `libcrypt1` | Password checking for basic authentication |

**Unloaded (weight 0.4):** everything else. Installed, but the nginx program never
opens it. It still counts because a user can switch a module on, and an attacker
already inside the container can run the tools.

| Group | Examples | Why it is in the image |
|---|---|---|
| Separate tools | `curl`, `perl-base`, `apt`, `bash` | Can be run by hand; nginx does not use them |
| Libraries those tools need | `libkrb5-3` (Kerberos), `libcurl4`, `libssh2-1` | `curl` needs them |
| Libraries for the four optional modules | See the next table | Used only if a config loads the module |

### Libraries brought in by each optional module

These 37 packages are in the image only because of the four module packages
(`apt-get -s remove --auto-remove` on the modules lists exactly these). No module is
loaded by default. CVE counts are unique CVEs in the baseline scan that touch the
module's libraries; a CVE in a shared library is counted for each module that needs it.

| Module package | Plugin files | Libraries only it (or another module) needs | Baseline CVEs | Critical or High |
|---|---|---|---|---|
| `nginx-module-xslt` | `ngx_http_xslt_filter_module.so` | `libxslt1.1`, `libxml2`, `libicu72` | 42 | 23 |
| `nginx-module-geoip` | `ngx_http_geoip_module.so`, `ngx_stream_geoip_module.so` | `libgeoip1` | 0 | 0 |
| `nginx-module-image-filter` | `ngx_http_image_filter_module.so` | `libgd3` and the 31 packages it pulls in: `libtiff6`, `libpng16-16`, `libjpeg62-turbo`, `libwebp7`, `libavif15`, `libheif1`, `libaom3`, `libde265-0`, `libx265-199`, `libdav1d6`, `libgav1-1`, `librav1e0`, `libsvtav1enc1`, `libyuv0`, `libabsl20220623`, `libfreetype6`, `libfontconfig1`, `fontconfig-config`, `fonts-dejavu-core`, `libexpat1`, `libxpm4`, `libx11-6`, `libx11-data`, `libxcb1`, `libxau6`, `libxdmcp6`, `libbsd0`, `libjbig0`, `liblerc4`, `libdeflate0`, `libnuma1` | 166 | 65 |
| `nginx-module-njs` | `ngx_http_js_module.so`, `ngx_stream_js_module.so` | `libedit2`, `libbsd0`, `libxml2`, `libicu72` | 34 | 20 |

- Shared between modules: `libxml2` and `libicu72` (xslt and njs), `libbsd0`
  (image-filter and njs). All four together account for 208 unique CVEs.
- njs also needs `libssl3`, `libpcre2-8-0` and `zlib1g`, but nginx loads those anyway,
  so they are not module-only.
- Each `.so` also ships a `-debug` twin, 12 files in total in `/usr/lib/nginx/modules/`.
- image-filter is by far the largest source. It also brings in `libfreetype6`, which
  has the only known-exploited CVE among the libraries (CVE-2025-27363).
- The loaded check covers the default nginx binary only. It does not follow the
  modules, so their libraries count as unloaded even though a config could load them.

### A ranking result to treat with care

CVE-2023-44487 (HTTP/2 Rapid Reset) is first in the ranking: it is on the
known-exploited list and Grype reports it against the `nginx` package. Trivy does not
report it, and Debian's data has no fixed version for it. nginx 1.25.3 added
"improved detection of misbehaving clients when using HTTP/2" (nginx.org CHANGES),
which is upstream's response to this attack, and the image ships 1.25.5. Whether that
fully covers the CVE has not been checked against the advisory. Do not present it as an
open vulnerability or as fixed by this project without doing that.

## Rules for working in this repo

- Explain in plain language. The owner is learning this domain: short sentences, define
  terms, one idea at a time. For Hebrew, start paragraphs with a Hebrew word so they
  render right-to-left.
- Never claim a fix or a match that has not been verified by a command. Say what was
  checked and what was assumed.
- Record deliberate differences from the original image in `README.md` as they are made.
- Everything must be reproducible with one command through the `Makefile`.
- Do not download prebuilt nginx binaries or packages; the brief forbids it.
- Commit as Netanel Zucaim with the Claude co-author trailer, then push to `origin main`.
- More specific guidance lives in `scans/CLAUDE.md`, `scripts/CLAUDE.md` and
  `entrypoint/CLAUDE.md`.

## Running things from a Claude cloud session

The owner's Mac sandbox shell has no Docker, so builds and scans run in the cloud
workspace and results are copied to the Mac folder.

- Start the daemon with `dockerd` in the background if `docker info` fails.
- Processes inside containers cannot use the workspace proxy as-is. `docker build` needs
  `--network host --build-arg https_proxy=$HTTPS_PROXY`, the proxy CA
  (`/root/.ccr/ca-bundle.crt`) trusted inside the build, and `https://` apt sources,
  because the proxy only accepts HTTPS. Keep this plumbing out of the committed
  `Containerfile` and `build/` files.
- Trivy and Grype run as host binaries in `/usr/local/bin` (extracted from their
  official images), because their containers cannot verify the proxy's certificate.
- The Mac folder cannot reach GitHub with credentials. Push from the cloud clone, then
  sync the Mac folder with a temporary `git bundle` and delete the bundle.
