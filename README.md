# Patched drop-in replacement for `nginx:1.25-bookworm`

A drop-in replacement for `nginx:1.25-bookworm`, rebuilt from source so CVEs are fixed
on our own timeline. Two CVEs are eliminated — one by a dependency **version bump**, one
by **backporting** an upstream patch onto the shipped nginx 1.25.5 — and an automated
test proves the image still behaves like the original.

## The two fixes

| CVE | Where it lives | Severity | Fix method | Evidence |
|---|---|---|---|---|
| **CVE-2024-6119** | OpenSSL (`libssl3`), which nginx loads | High / High (Trivy / Grype), EPSS 66.6% | **Version bump** — `build/patches/CVE-2024-6119.patch` makes the nginx package require `libssl3 (>= 3.0.14-1~deb12u2)`, Debian's fixed version; the image build installs 3.0.22 (was 3.0.11) | Gone from both scanners in the rescan (`scans/patched/diff.md`); `nginx -V` reports OpenSSL 3.0.22; installing the `.deb` on the original image (OpenSSL 3.0.11) is refused by dpkg. [Debian tracker: fixed in 3.0.14-1~deb12u2](https://security-tracker.debian.org/tracker/CVE-2024-6119) |
| **CVE-2026-42945** | nginx `ngx_http_rewrite_module` (built from source here) | medium, potential code execution | **Backport** — upstream commit `2046b45a` (nginx 1.31.0) onto 1.25.5 | [nginx advisory](https://nginx.org/en/security_advisories.html) (vulnerable 0.6.27–1.30.0) · [upstream fix 2046b45a](https://github.com/nginx/nginx/commit/2046b45aa0c6e712c216b9075886f3f26e9b4ca9) · `build/patches/CVE-2026-42945.patch`, applied in the from-source build and exercised by `make test`; VEX `status: fixed` in `vex/`. Not scanner-visible — see "the scanners miss nginx's own CVEs" below. |

Why these two: full reasoning in `scans/baseline/priorities.md`. Targets are chosen by
how likely a CVE is to be exploited here and how much of the deployment runs the code
(reach), not by severity label alone.

**Two fixes are claimed, but many more CVEs went away.** The image is built against
Debian's current packages: a fresh base, `apt-get update` and `upgrade`, and every
dependency installed at its newest version. That updates *every* Debian package to its
patched version, not only OpenSSL. So the scanner-reported CVEs
fell from **497 to 253** (244 no longer reported: OpenSSL, libexpat, libxml2, gnutls,
curl and others). Only CVE-2024-6119 is claimed, because it is the one that was
deliberately chosen, verified, and written into the package as a minimum version, so it
cannot silently regress; the others are a side effect of building against current
Debian packages.
The 26 nginx and njs CVEs the scanners cannot see are counted separately: 1 is fixed
(the backport), 25 are still present (see `scans/patched/diff.md`).

Removing a component is allowed as an extra but was not needed; the four optional modules
are kept for compatibility (see "Dynamic modules are kept" below).

## Two kinds of CVEs in this image

The image holds two kinds of code, and their CVEs are found and fixed in different ways.

| | Code built from source here | Debian packages |
|---|---|---|
| What it is | nginx and the njs module | Libraries and tools: OpenSSL, libxml2, libtiff, curl… |
| Who wrote that code | NGINX | Other projects |
| Who builds it in this image | This project, from source | Debian (the image installs its packages) |
| Where its CVEs are published | nginx.org and njs advisories | Debian's security data |
| Seen by Trivy and Grype? | **No**: they compare it with Debian's data (see below) | Yes |
| CVEs in the original image | **26** (24 in nginx, 2 in njs), found by reading the advisories | **497**, reported by the scanners |
| How to fix one | Patch the source and rebuild: **backport** | Install Debian's newer package: **version bump** |
| Fixed in this image | 1 (CVE-2026-42945) | 244 (including CVE-2024-6119) |

The two required fixes are one of each: the backport is in nginx's own code, the
version bump is in a Debian library.

Two things are easy to mix up:

- **nginx's built-in modules are part of nginx.** nginx's source is divided into parts
  it calls modules (rewrite, mp4, DAV, HTTP/3…). Most of the 24 nginx CVEs are in parts
  like these, which are compiled into the main nginx program.
- **The four optional module packages bring Debian libraries with them.** The 208 CVEs
  listed for the modules under "Dynamic modules" below are in those libraries (libtiff,
  libxml2…), not in the module code. They are part of the 497.

### Where the Debian libraries are, and when they run

All library packages install their files into one folder,
`/usr/lib/x86_64-linux-gnu/` (357 shared library files in this image), for example
`libtiff.so.6`, `libheif.so.1`, `libxml2.so.2`, `libgd.so.3` and `libssl.so.3`.
Debian records every installed package and the files it owns in
`/var/lib/dpkg/status` (149 packages); that file is what Trivy and Grype read to decide
what is in the image. `dpkg -S <file>` names the package a file belongs to.

Being installed is not the same as running. A library's code runs only when a program
loads it:

- **The main nginx program** loads six libraries: libc, libcrypt, libpcre2, libssl,
  libcrypto and zlib (`ldd /usr/sbin/nginx`). These are the packages the triage treats
  as reached by every running container.
- **A module loads its own chain.** `ngx_http_image_filter_module.so` loads libgd, which
  loads libpng, libjpeg, libtiff, libheif and the rest
  (`ldd /usr/lib/nginx/modules/ngx_http_image_filter_module.so`). That happens only when
  a configuration loads the module, and even then image-filter asks libgd only for
  JPEG, GIF, PNG and WebP, so the TIFF and HEIF code is installed but never called.

This difference between installed and used is why the triage ranks CVEs by reach, not
by count.

## Build and run

Everything is reproducible with one command each, through the `Makefile`:

```sh
make deb     # step 3: build nginx + the four module .debs from source, into out/
make image   # step 4: build the final image echo-nginx:1.25-bookworm from those .debs
make test    # step 5: prove it behaves like the original (non-zero exit on any mismatch)
make rescan  # step 6: rescan, diff against the baseline, apply the VEX files
```

`make deb` builds in a clean `debian:bookworm-slim` with no pre-baked binaries; details
in `build/README.md`. (Behind an HTTPS-only proxy the build needs extra build-args; see
`build/README.md`.)

### Image size

| Image | Size |
|---|---|
| Original `nginx:1.25-bookworm` | 276 MB |
| Patched `echo-nginx:1.25-bookworm` | 291 MB |

The ~15 MB increase comes from `apt-get upgrade` (newer package versions) plus
`curl` and `ca-certificates`, which the original image also carries.

### Result of the compatibility test

`make test` runs 92 checks across image settings, the default site and a user-supplied
config. On the built image: **91 match, 1 allowed difference, 0 mismatch** (92 checks). The one
allowed difference is the `maintainer` label (this image is rebuilt by its owner, not by
NGINX); it is listed in `ALLOWED` in `test/compat_test.py`. What the test covers is
described under "Compatibility test" below.

## Baseline

The original image was scanned with Trivy and Grype (`make scan-baseline`).
Reports and image metadata are in `scans/baseline/`.

| | Trivy 0.75.0 | Grype 0.120.0 |
|---|---|---|
| Findings | 775 | 751 |
| Unique CVEs | 494 | 471 |
| Critical | 20 | 47 |
| High | 181 | 253 |
| With a fix available | 342 | 336 |

Image: nginx 1.25.5 on Debian 12.5, linux/amd64,
`nginx@sha256:a484819eb60211f5299034ac80f6a681b06f89e65866ce91f356ed7c72af059c`.

## Finding: the scanners miss nginx's own CVEs

Neither scanner reports nginx's own vulnerabilities in the baseline. Trivy lists nothing
against the `nginx` package. Grype lists three entries (CVE-2023-44487, CVE-2009-4487,
CVE-2013-0337), all of which Debian marks as "not fixed" or "won't fix".

**Why.** Trivy and Grype do not inspect code. They read the installed package list
(name and version) and compare it with a vulnerability database. Both correctly detect
the OS as Debian 12, so they check every package against Debian's security data
(Grype labels each match `debian:distro:debian:12`). That is right for the ~140 Debian
packages, but the `nginx` package in this image is not Debian's:

| Source | nginx version on bookworm | Maintained by |
|---|---|---|
| Debian | 1.22.1 (`1.22.1-9+deb12uN`) | Debian, security fixes backported onto 1.22 |
| nginx.org (used by the original image) | 1.25.5 (`1.25.5-1~bookworm`) | NGINX |

The package list does not record which repository a package came from, so the scanners
treat `nginx 1.25.5-1~bookworm` as a Debian package and compare its version with
Debian's fixed versions.

**Example, CVE-2024-7347** (mp4 module over-read):

- Debian fixed it in `1.22.1-9+deb12u2` by backporting
  ([Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2024-7347)).
- Upstream nginx fixed it in 1.27.1, so upstream 1.25.5 is vulnerable.
- The scanner compares `1.25.5` > `1.22.1-9+deb12u2` and concludes "fixed". False negative.

The three CVEs Grype does report fit this explanation: they have no fixed version in
Debian's data, so there is no version to compare and they match any nginx.

Only CVE-2024-7347 was checked against the Debian tracker. The same mechanism is
assumed, not verified, for the other nginx CVEs.

**Consequences for this project.**

- nginx's own CVEs have to be triaged from the
  [nginx security advisories](https://nginx.org/en/security_advisories.html),
  not from the scan reports.
- A backported nginx fix shows no before/after difference in the scan diff, which
  leaves the VEX document nothing to suppress. Confirmed on the built image:
  CVE-2026-42945 appears in neither scanner's report, before or after (see
  "Rescan and VEX" below).

**Why not just use Debian's nginx package.** It is 1.22, a downgrade from 1.25 that
lacks features the original has (HTTP/3, for one), so it would not be a drop-in
replacement, and the assignment asks for a package built from source. Debian's
backported patches for 1.22 are public and are a useful reference when writing the
backport for 1.25.

## Rescan and VEX (bonus)

The bonus asks for a VEX document for a backport-patched CVE, and for the scanner to be
re-run with it applied so the CVE disappears from the report. Our image splits that into
a deliverable, a documented reason, and an optional proof — on purpose, because of the
finding above.

**1. The deliverable: a VEX for the backported CVE.** The backport is CVE-2026-42945
(rewrite module), so `vex/CVE-2026-42945.openvex.json` is a VEX with `status: fixed`
pointing at `build/patches/CVE-2026-42945.patch`. This is the document the bonus asks
for, and it is the formal record that the fix is in the build.

**2. Why it does not shrink the rescan — and why that is expected.** The CVE never
appears in the scan in the first place, for exactly the reason in the finding above:
nginx is the nginx.org package, so the scanners compare it with Debian's data and do
not report its CVEs at all. A VEX can only remove a finding that exists, so a `fixed`
VEX for a backported nginx CVE has nothing to suppress. This is not a gap in the work;
it is a sharper case of the brief's own heads-up that *"scanners won't shrink your CVE
list for backported fixes"* — here they never listed it to begin with. The real
evidence that the backport works is the patch itself plus the rewrite scenario added to
the compatibility test, not a scan diff.

**3. Optional proof that the VEX mechanic works.** Because the backported CVE cannot
visibly disappear, the "re-run and watch it vanish" is demonstrated on a CVE the
scanners *do* report: `vex/CVE-2023-52355.openvex.json`, a `not_affected` statement for
libtiff6 (CVE-2023-52355). `not_affected` means the vulnerable code is present but
unreachable here — image-filter links libtiff only through libgd and asks it for
JPEG/GIF/PNG/WebP, never TIFF, and the module is not loaded by default
(justification `vulnerable_code_not_in_execute_path`). This CVE has no Debian fix, so
the base upgrade cannot remove it, which is what makes it a stable demonstration.
Verified on the baseline image on 2026-10-05: with the VEX applied, CVE-2023-52355
disappears from Trivy (dropped) and from Grype (moved to `ignoredMatches`).

So: the backport VEX is the deliverable; the foreign-nginx situation is the documented
reason it does not change the scan; the libtiff `not_affected` VEX is the optional
end-to-end proof that the mechanic works.

## Compatibility test

`make test` boots the original image and the patched image side by side, sends both
the same requests and compares status line, headers and body, plus image settings,
file layout, logs and shutdown behaviour. It exits non-zero on any mismatch.
[`test/README.md`](test/README.md) defines what "working correctly" means, lists the
checks, and says what is not covered.

On the built image: 92 checks, 91 match, 1 allowed difference (the maintainer label),
0 mismatch. The test was also validated against the original image (everything
matches) and against a deliberately altered image (it fails, as it should), so a false
"match" cannot slip through.

## Image configuration: what matches the original and what does not

The assignment requires the filesystem layout, user, working directory, ports and
entrypoint to match the original exactly. The `Containerfile` copies those, and also
the settings the assignment does not name, so the image behaves as a drop-in replacement.
All values were taken from `scans/baseline/image/inspect.json` and
`scans/baseline/image/history.txt`.

| Setting | Original | This image |
|---|---|---|
| User | root, with `nginx` user/group (UID/GID 101) for workers | Same |
| Working directory | Not set | Same |
| Exposed port | 80/tcp | Same |
| Entrypoint | `/docker-entrypoint.sh` | Same (script extracted unchanged, in `entrypoint/`) |
| Startup scripts | Four files in `/docker-entrypoint.d/` | Same (extracted unchanged) |
| Command | `nginx -g "daemon off;"` | Same |
| Stop signal | `SIGQUIT` (graceful shutdown) | Same |
| Environment | `NGINX_VERSION`, `NJS_VERSION`, `NJS_RELEASE`, `PKG_RELEASE` | Same |
| Label `maintainer` | `NGINX Docker Maintainers <docker-maint@nginx.com>` | **Changed**, see below |

### Deliberate differences

- **`maintainer` label.** Set to `Netanel Zucaim <netanelzucaim100@gmail.com>`.
  This image is rebuilt and patched by me, not by the NGINX maintainers, so keeping
  their name on it would misstate who is responsible for it. The label is metadata
  only and nothing functional depends on it.
- **Base-evolution differences.** The image is rebuilt on a current `debian:bookworm-slim`
  (plus `apt-get upgrade`), so a few base-provided files differ from the original's
  May-2024 base: the `debian-archive-*` keyrings (buster-era → trixie-era) and a `tzdata`
  entry or two. These come from Debian moving forward, not from anything this project
  changed, and are the expected, desirable result of patching via a fresh base.

A full filesystem diff against the original shows no other differences: every file under
the nginx paths, the `nginx -V` flags, the Docker config (entrypoint, cmd, ports, env,
stop signal, user), the conffiles, the four modules with their debug twins, and the njs
CLI (`/usr/bin/njs`) all match, and so do the version strings of all five nginx packages
(`dpkg-query`). That includes nginx.org's apt signing key
(`/etc/apt/keyrings/nginx-archive-keyring.gpg`), a leftover in the original from
installing nginx from nginx.org's repository. Nothing in this image uses it, since nginx
is built from source, but it is copied byte-for-byte from the original so the layout
matches exactly.

### Dynamic modules are kept, including image-filter

The original installs four optional module packages next to nginx. None is loaded by
default: the shipped configuration has no `load_module` line. Their libraries are in
the image only because of them, and they carry 208 of the 497 unique baseline CVEs.

| Module | What it does | Libraries it brings in | CVEs in those libraries (baseline) | Of which Critical or High |
|---|---|---|---|---|
| `nginx-module-xslt` | Transforms XML responses | 3 (`libxslt1.1`, `libxml2`, `libicu72`) | 42 | 23 |
| `nginx-module-geoip` | Country lookup from the client IP | 1 (`libgeoip1`) | 0 | 0 |
| `nginx-module-image-filter` | Resizes, crops and rotates images on the fly | 32 (`libgd3` and its image-format, font and X11 dependencies) | 166 | 65 |
| `nginx-module-njs` | nginx logic written in JavaScript | 4 (`libedit2`, `libbsd0`, `libxml2`, `libicu72`) | 34 | 20 |

Counts overlap where modules share a library. "Critical or High" means rated so by at
least one of the two scanners (by both: 20, 0, 44 and 17). Source: `scans/baseline/triage.csv` and `apt-get -s remove --auto-remove` on the module packages in the original image.

The CVEs are in the libraries, not in the modules: the libraries are written by other
projects and packaged by Debian, and the scanners report them correctly. They are
grouped by module because each module is why its libraries are installed, so keeping or
removing a module keeps or removes them. The table does not include CVEs in the module
code itself, which the scanners cannot see (the same blind
spot as nginx). From njs's own advisories, njs 0.8.4 has one more:
**CVE-2026-78689** (Critical), reachable only when the njs module is loaded and a script
uses XML canonicalization (`exclusiveC14n`), so 35 for njs in all. A second njs
advisory, CVE-2026-18329, does not apply to 0.8.4. None of nginx's own 24 advisories
concern xslt, geoip or image-filter.

**What this costs, measured.** All four modules are built from source and shipped, and
their libraries stay in the image. On 2026-10-05 three throwaway variants of
the original image were built (image-filter removed, Debian packages updated, and
both), and each was scanned with both tools. The variants were deleted afterwards:

| Variant of the original image | Packages | Unique CVEs | Critical or High | CVEs in image-filter's packages |
|---|---|---|---|---|
| Original | 149 | 494 | 203 | 166 |
| image-filter removed, nothing else | 117 | 328 | 138 | 0 |
| Debian packages updated, image-filter kept (the shipped approach) | 149 | 253 | 80 | 89 |
| Updated and image-filter removed | 117 | 164 | 55 | 0 |

- Removing the module takes 32 packages with it: the module and 31 libraries.
- Updating alone fixes 77 of the 166 CVEs in those packages. The known-exploited
  CVE-2025-27363 in `libfreetype6` is one of them.
- The other 89 have no fixed version in Debian bookworm today, so only removal clears
  them. Most are in `libheif1` and `libtiff6`. These 89 are the measured price of
  keeping image-filter, accepted for the sake of compatibility.
- Updating does more than removing: 253 CVEs remain after updating alone, 328 after
  removing alone.
- "Original" shows 494 here and 497 in the baseline because the scanner database of
  2026-10-05 no longer lists three `libxml2` CVEs that it listed a day earlier.

The "updated" variants upgrade the original image in place, so they still contain the
unpatched nginx 1.25.5. They estimate the final image; the final scan replaces them.

**What I would do with more time.** Publish a second, slimmer variant without
image-filter for users who do not need it, so the default stays compatible and the
smaller attack surface is available by choice.

## Residual risk

What remains after the two fixes, honestly:

- **253 scanner-reported CVEs remain** (down from 497), plus **25 nginx and njs CVEs**
  from upstream advisories that the scanners do not report. Most are low-severity or in code the
  running server never executes; `scans/patched/triage.*` ranks them by reach. The
  largest cluster is the **89 CVEs in the image-filter libraries** (`libheif1`,
  `libtiff6` and friends) that Debian has no fix for — the measured, accepted price of
  keeping that module for compatibility. They are reachable only if a config loads
  `image-filter`, which is off by default.
- **nginx's own CVEs are not shown by the scanners** (the nginx.org-vs-Debian blind
  spot, explained above), so the reported count understates nginx's surface. They are
  triaged from nginx's advisories in `scans/baseline/priorities.md`. Of those, the
  backported CVE-2026-42945 is fixed; the rest are mostly `config`-reach (need a
  specific feature or module) and are recorded there, not fixed in this pass.
- **njs CVE-2026-78689** (Critical, CVSS 9.2) is in the kept njs module — unreachable
  by default (needs the module loaded and a `js_import` using XML c14n), no in-version
  fix, so it is accepted, not fixed. See the njs example in the `triage-cves` skill.
- **CVE-2023-44487** (HTTP/2 Rapid Reset, known-exploited) is already mitigated in
  1.25.5; it is not claimed as a fix and is recorded as such.
- **The backported fix leaves no scan difference**, so there is nothing for a rescan to
  show for it. The patch and the compatibility test are its evidence; the VEX file is
  the formal record.

## Surprises, and what I would do differently

- **The scanners never report nginx's own CVEs.** The biggest surprise: because the
  nginx package is from nginx.org and the scanners compare it against Debian's 1.22
  data, every nginx 1.25.5 CVE reads as "fixed". This drove the whole triage approach
  (read nginx's advisories, not the scan) and means the backport is invisible to a
  rescan. The brief hinted at it ("scanners won't shrink your CVE list for backported
  fixes"); in this image it is stronger still — they never listed it.
- **A version bump beats removal for numbers, but reach beats both.** Early what-if
  measurements (in the modules section) showed updating fixes more than removing, but
  what actually mattered for choosing the two targets was whether the running server
  reaches the code.
- **With more time:** publish a second, slimmer variant without `image-filter` (the
  89 unfixable CVEs live there); exercise the njs and mp4 modules in the compatibility
  test, not just load them; and backport the sibling rewrite CVE-2026-9256 and the
  reachable DAV CVE-2026-27654 as a second round.

## Dead ends and what I tried

- **Building the packaging by hand.** The compatibility test requires the exact
  `nginx -V` flags, the `nginx-debug` binary, conffiles, logrotate and systemd files,
  and twelve module `.so` files. A hand-rolled `.deb` would not match all of that, so
  the build drives nginx's own packaging (`pkg-oss`) instead and injects the backport.
  The trade-off: `build/prepare.sh` is a thin orchestration script around upstream's
  packaging rather than a packaging script written from scratch.
- **`pkg-oss` at its latest commit.** It targets nginx 1.31 and builds njs with QuickJS,
  which njs 0.8.4 does not need. Pinned instead to commit `aaeb9a9`, the one that
  shipped nginx 1.25.5 with njs 0.8.4.
- **Network fetches inside the build.** `pkg-oss` downloads `xslscript` to generate its
  changelog, and the njs source, from `hg.nginx.org`, which returned only a small stub
  page through this workspace's proxy. Replaced with a static changelog and with the
  njs source taken from its git tag.
- **QuickJS.** First removed from the njs build along with the njs command-line tool;
  a full filesystem diff then showed `/usr/bin/njs` missing. The original's tool links
  only libedit, so it is now built again without QuickJS.
- **Proxy settings leaking into the image.** The first validated image contained this
  workspace's proxy CA and apt settings. The committed files were clean, but the built
  artifact was not. Found by the same filesystem diff; the proxy build now removes them.
- **VEX pinned to the wrong version.** The first VEX for CVE-2023-52355 named the
  baseline's libtiff6 version; `apt-get upgrade` had moved it, so the rescan reported
  the CVE as still present. Regenerated against the patched image's package list.
- **Counting CVEs that were never fixed as fixed.** The first comparison said
  "523 → 253, 270 no longer reported". 26 of the 523 were nginx and njs CVEs added by
  hand from upstream advisories; the patched scan never lists them, so they looked
  gone. Only one was fixed. The comparison now counts scanner-reported CVEs only
  (497 → 253) and lists the 26 advisory CVEs with their real status.
- **A version bump that only happened by chance.** The first version claimed OpenSSL
  was bumped by `apt-get upgrade`. In fact a fresh `debian:bookworm-slim` has no
  OpenSSL at all; it was installed as a dependency of nginx at whatever version was
  current, and nothing required a fixed one. Now `build/patches/CVE-2024-6119.patch`
  writes the minimum fixed version into the nginx package, and dpkg refuses to install
  it next to the vulnerable 3.0.11.
- **Proving the backport by triggering the bug.** Not done on purpose: building a
  trigger is exploit work. The evidence is that the upstream fix applies cleanly, the
  patched code path is exercised by `make test` with matching output, and the build log
  shows the patch applied.

## How AI tools were used

This project was built with Claude (Claude Code). AI was used to: scaffold and iterate
the triage, fix-method and VEX scripts and the compatibility test; research nginx and
njs advisories and read the upstream commits to confirm the backport applies; drive the
pkg-oss build and work through its packaging; and write this documentation. Every claim
that could be checked by a command was checked (patch applicability, the OpenSSL version
the base installs, the compatibility test, the rescan and the VEX suppression); where
something was assumed rather than verified, the text says so. Engineering judgment — which
CVEs to target, keeping the modules, how to read the scanners — was made by the owner
with the reasoning recorded in `scans/baseline/priorities.md` and `CLAUDE.md`.
