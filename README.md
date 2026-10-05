# Patched drop-in replacement for `nginx:1.25-bookworm`

Work in progress. Sections are added as each step of the assignment is completed.

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
- A backported nginx fix may show no before/after difference in the scan diff, which
  would leave the VEX document nothing to suppress. This can only be confirmed once
  the patched image is built and rescanned.

**Why not just use Debian's nginx package.** It is 1.22, a downgrade from 1.25 that
lacks features the original has (HTTP/3, for one), so it would not be a drop-in
replacement, and the assignment asks for a package built from source. Debian's
backported patches for 1.22 are public and are a useful reference when writing the
backport for 1.25.

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

### Dynamic modules are kept, including image-filter

The original installs four optional module packages next to nginx. None is loaded by
default: the shipped configuration has no `load_module` line. Their libraries are in
the image only because of them, and they carry 208 of the 497 unique baseline CVEs.

| Module | What it does | Libraries it brings in | Baseline CVEs | Critical or High |
|---|---|---|---|---|
| `nginx-module-xslt` | Transforms XML responses | 3 (`libxslt1.1`, `libxml2`, `libicu72`) | 42 | 23 |
| `nginx-module-geoip` | Country lookup from the client IP | 1 (`libgeoip1`) | 0 | 0 |
| `nginx-module-image-filter` | Resizes, crops and rotates images on the fly | 32 (`libgd3` and its image-format, font and X11 dependencies) | 166 | 65 |
| `nginx-module-njs` | nginx logic written in JavaScript | 4 (`libedit2`, `libbsd0`, `libxml2`, `libicu72`) | 34 | 20 |

Counts overlap where modules share a library. Source: `scans/baseline/triage.csv` and
`apt-get -s remove --auto-remove` on the module packages in the original image.

**The option that was considered: remove image-filter.** It is the obvious candidate.
It accounts for about a third of all baseline CVEs, its libraries parse complex image
files, which is a classic source of memory bugs, and they include `libfreetype6` with
CVE-2025-27363, the only library CVE in the image on CISA's known-exploited list.
Nothing loads the module by default, so the compatibility test would still pass
without it. The assignment also allows removing a vulnerable component.

**Why it was rejected.** Anyone whose configuration contains
`load_module modules/ngx_http_image_filter_module.so;` would find nginx refusing to
start after switching images. The brief asks for "a drop-in replacement, not a
re-imagining", and an image that breaks existing users has failed at that, however
clean its scan looks. Compatibility was given priority over the scan result, and the
same reasoning applies to the other three modules.

**What this costs, measured.** All four modules are built from source and shipped, and
their libraries stay in the image. `make probe REMOVE=nginx-module-image-filter` builds
throwaway variants of the original image, scans each with both tools, prints this
table and deletes the variants again (run on 2026-10-05):

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
