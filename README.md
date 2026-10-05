# Patched drop-in replacement for `nginx:1.25-bookworm`

A drop-in replacement for `nginx:1.25-bookworm`, rebuilt from source so CVEs can be
fixed on our own timeline. Two CVEs are eliminated, one by a dependency **version bump**
and one by **backporting** an upstream fix onto the shipped nginx 1.25.5. An automated
test shows the image still behaves like the original.

| | Original | This image (`echo-nginx:1.25-bookworm`) |
|---|---|---|
| nginx | 1.25.5 + njs 0.8.4 (prebuilt by nginx.org) | 1.25.5 + njs 0.8.4, **built from source here**, same versions and flags |
| Size | 276 MB | 291 MB |
| Compatibility test (`make test`) | the specification | 92 checks: **91 match, 1 allowed difference, 0 mismatch** |
| CVEs reported by Trivy + Grype | 497 | **253** |
| nginx/njs CVEs from upstream advisories (the scanners can't see these) | 26 | 25 (CVE-2026-42945 backported) |

## Build and run

Needs Docker, plus Python 3 for the test. Trivy and Grype only for the scans.

```sh
make all     # everything below, in order
make deb     # step 3: build nginx + the four module .debs from source in a clean
             #         debian:bookworm-slim, patches applied, into out/
make image   # step 4: build the final image echo-nginx:1.25-bookworm from out/*.deb
make test    # step 5: compare it with the original (exit code 1 on any mismatch)
make fsdiff  # list every file in both images; exit 1 on an unexplained difference
make rescan  # step 6: rescan, compare with the baseline, apply the VEX files
docker run --rm -p 8080:80 echo-nginx:1.25-bookworm
```

`make scan-baseline` and `make triage` redo steps 1 and 2 on the original image. No
prebuilt nginx binary or package is downloaded: `make deb` fetches nginx's own packaging
(`pkg-oss`, pinned to the commit that shipped 1.25.5), adds the patches from
`build/patches/` and compiles. Details: [`build/README.md`](build/README.md).

| Folder | Content |
|---|---|
| `build/` | The from-source `.deb` build; `build/patches/` holds one patch per CVE |
| `Containerfile` | The final image, built from the `.deb`s |
| `rootfs/` | Files copied unchanged from the original image (the startup scripts) |
| `test/` | The compatibility test ([what it checks](test/README.md)) |
| `scans/` | Scanner reports before and after, the triage and the decision ([guide](scans/README.md)) |
| `vex/` | OpenVEX documents |
| `docs/` | The longer explanations linked below |

## The two fixed CVEs

| CVE | Where it lives | Severity | Fix method | Evidence |
|---|---|---|---|---|
| **CVE-2024-6119** | OpenSSL (`libssl3`), loaded by nginx | High / High (Trivy / Grype), EPSS 66.6% | **Version bump**: [`build/patches/CVE-2024-6119.patch`](build/patches/CVE-2024-6119.patch) makes the nginx package require `libssl3 (>= 3.0.14-1~deb12u2)`, Debian's fixed version. The image gets 3.0.22 (was 3.0.11) | Gone from both scanners ([`scans/patched/diff.md`](scans/patched/diff.md)); dpkg refuses to install the `.deb` next to OpenSSL 3.0.11; [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2024-6119) |
| **CVE-2026-42945** | nginx's rewrite module, built from source here | Medium (nginx.org), heap overflow, potential code execution | **Backport** of upstream commit [`2046b45a`](https://github.com/nginx/nginx/commit/2046b45aa0c6e712c216b9075886f3f26e9b4ca9) (nginx 1.31.0) onto 1.25.5: [`build/patches/CVE-2026-42945.patch`](build/patches/CVE-2026-42945.patch) | [nginx advisory](https://nginx.org/en/security_advisories.html) (vulnerable 0.6.27–1.30.0); patch applies cleanly and shows in the build log; `make test` runs the patched code path with output identical to the original; VEX `status: fixed` in `vex/`. Not visible to scanners (below) |

**Why these two.** Targets were chosen by how likely a CVE is to be exploited and how
much of a real deployment runs the vulnerable code, not by severity label alone. The
OpenSSL bug is reached whenever nginx verifies an upstream server's certificate and has
the highest exploitation estimate of anything nginx loads. The rewrite bug sits in code
almost every configuration runs (`rewrite`, `set`, `return` with captures) and can lead
to code execution. Rejected candidates, such as an OpenSSL CMS bug nginx never calls,
and the full argument are in [`scans/baseline/priorities.md`](scans/baseline/priorities.md).

**Why 244 CVEs went away when only two are claimed.** The image is built on a fresh
`debian:bookworm-slim` with `apt-get upgrade` and every dependency at its newest
version, so every Debian package gets its current fixes (OpenSSL, libexpat, libxml2,
gnutls, curl…). Only CVE-2024-6119 is claimed: it was chosen, verified, and written into
the package as a minimum version, so it cannot silently come back. The rest is a side
effect of the fresh base. No component was removed.

## Finding: the scanners cannot see nginx's own CVEs

The `nginx` package comes from nginx.org, but Trivy and Grype compare it with
**Debian's** security data, where nginx is 1.22.1 with Debian's own backported fixes.
Since 1.25.5 > 1.22.1-9+deb12u2, every nginx CVE Debian has fixed looks fixed here too,
although nginx.org's 1.25.5 never got those patches. So nginx's 24 CVEs and njs's 2 were
taken from the upstream advisories and added to the triage by hand, and the backport
cannot show up as a before/after scan difference. Full explanation, with CVE-2024-7347
as the worked example: [`docs/scanner-blind-spot.md`](docs/scanner-blind-spot.md).

## Rescan and VEX (bonus)

`make rescan` scans the new image and compares it with the baseline
([`scans/patched/diff.md`](scans/patched/diff.md)): scanner-reported CVEs went from
**497 to 253** (244 gone, 0 new), and CVE-2024-6119 is gone from both scanners.

- `vex/CVE-2026-42945.openvex.json` (`status: fixed`) is the VEX for the backport. It
  changes nothing in the scan, because the scanners never reported that CVE.
- To show the VEX mechanism actually works, `vex/CVE-2023-52355.openvex.json`
  (`not_affected`, libtiff6) targets a CVE both scanners do report, that has no Debian
  fix, and that this image cannot reach (image-filter never asks libgd for TIFF). With
  it applied, the CVE disappears from both Trivy and Grype.

Details: [`docs/vex.md`](docs/vex.md).

## Compatibility test

`make test` starts the original and the new image side by side, sends both the same
HTTP requests (default site, errors, methods, a user-supplied config with proxying,
rewrites, gzip and more) and compares status, headers and body. It also compares the
image settings, file layout, startup logs and shutdown behaviour. It exits 1 on any
mismatch. The only allowed difference is the `maintainer` label: this image is not built
by NGINX. The test was also run against the original itself (all match) and against a
deliberately altered image (it fails). `make fsdiff` adds a full file-by-file comparison;
the only differences are newer files from the current Debian base (keyrings, tzdata, CA
certificates), plus nginx.org's apt signing key, which is fetched the same way the
original's build did and so now carries the key's renewed expiry date. Settings and
differences: [`docs/image-config.md`](docs/image-config.md).

## Residual risk

- **253 scanner-reported CVEs remain** (Debian has no fix for them yet), plus **25 nginx
  and njs CVEs** from upstream advisories. Most are low severity or in code nginx does
  not run. `scans/baseline/triage.md` ranks every CVE by danger and reach.
- **The four optional modules are kept**, so customers whose configs load them keep
  working. Their libraries carry 89 CVEs with no Debian fix, mostly in `libheif1` and
  `libtiff6` under image-filter. None is loaded by default. Measured cost and the
  alternative: [`docs/modules.md`](docs/modules.md).
- **njs CVE-2026-78689** (Critical, XML canonicalization) is in the kept njs module. It
  needs the module loaded and a script using `exclusiveC14n`; there is no fix on the
  0.8.x line here, so it is accepted, not fixed.
- **The other nginx CVEs are not fixed in this pass.** Most need a specific feature or
  module (mp4, DAV, HTTP/3…). Reasoning per CVE in `scans/baseline/priorities.md`.
- **CVE-2023-44487** (HTTP/2 Rapid Reset, known exploited) is reported by Grype but was
  already mitigated upstream in 1.25.3. It is neither open nor claimed as a fix here.
- **The backport is proven by applying and exercising it, not by triggering the bug.**
  Building an exploit was out of scope.

## Surprises, and what I would do differently

- **The scanners never report nginx's own CVEs.** This drove the whole triage (read
  nginx's advisories, not the scan) and makes the backport invisible to a rescan. The
  brief warned that scanners don't shrink the list for backports; here they never listed
  the CVE at all.
- **A fresh base fixes far more than any single patch,** but what mattered for picking
  targets was whether the running server reaches the code.
- **With more time:** publish a second, slimmer image without image-filter; test the njs
  and mp4 modules with real requests, not just loading; backport the sibling rewrite CVE
  (CVE-2026-9256) and the DAV CVE (CVE-2026-27654).

## Dead ends

- **Writing the packaging by hand.** Matching the `nginx -V` flags, `nginx-debug`,
  conffiles and twelve module files by hand was not realistic, so the build drives
  nginx's own `pkg-oss` and adds the patches to it.
- **`pkg-oss` at its latest commit** targets nginx 1.31 and needs QuickJS. Pinned to
  `aaeb9a9`, which shipped 1.25.5 with njs 0.8.4.
- **Network fetches inside the build** (`xslscript`, njs from `hg.nginx.org`) failed
  through the proxy. Replaced with static changelogs and njs from its git tag.
- **Dropping the njs command-line tool** along with QuickJS. `make fsdiff` found
  `/usr/bin/njs` missing; it is built again without QuickJS, as in the original.
- **Proxy settings leaking into the image.** The first image contained this workspace's
  proxy CA and apt settings. Found by the file diff and removed.
- **A VEX pinned to the wrong version.** It named the baseline's libtiff6 version, which
  `apt-get upgrade` had changed, so the CVE stayed reported. Regenerated from the
  patched image's package list.
- **Counting unfixed CVEs as fixed.** The first comparison said "523 → 253" because the
  26 hand-added advisory CVEs are absent from the patched scan. Only one is fixed. The
  comparison now counts scanner-reported CVEs only.
- **A version bump that happened by chance.** At first OpenSSL was "bumped" only because
  the build happened to install a current one; nothing required it. The patch now writes
  the fixed version into the package as a minimum.

## How AI tools were used

Built with Claude (Claude Code). It wrote and iterated the triage, comparison and VEX
scripts and the compatibility test; researched the nginx and njs advisories and read the
upstream commits; drove the `pkg-oss` build; and wrote the documentation. Every claim
that a command can check was checked: patch applicability, the installed OpenSSL
version, the test, the file diff, the rescan and the VEX result. Where something is
assumed, the text says so. The decisions (which CVEs to target, keeping the modules, how
to read the scanners) were made by me, with the reasoning in
[`scans/baseline/priorities.md`](scans/baseline/priorities.md). The project-specific
skills Claude followed are in `.claude/skills/`.
