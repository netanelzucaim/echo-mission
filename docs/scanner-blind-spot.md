# The scanners miss nginx's own CVEs

Back to the [README](../README.md).

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
  CVE-2026-42945 appears in neither scanner's report, before or after (see [vex.md](vex.md)).

**Why not just use Debian's nginx package.** It is 1.22, a downgrade from 1.25 that
lacks features the original has (HTTP/3, for one), so it would not be a drop-in
replacement, and the assignment asks for a package built from source. Debian's
backported patches for 1.22 are public and are a useful reference when writing the
backport for 1.25.

## Two kinds of CVEs in this image

The image holds two kinds of code, and their CVEs are found and fixed in different ways.

| | Code built from source here | Debian packages |
|---|---|---|
| What it is | nginx and the njs module | Libraries and tools: OpenSSL, libxml2, libtiff, curl… |
| Who wrote that code | NGINX | Other projects |
| Who builds it in this image | This project, from source | Debian (the image installs its packages) |
| Where its CVEs are published | nginx.org and njs advisories | Debian's security data |
| Seen by Trivy and Grype? | **No**: they compare it with Debian's data (see above) | Yes |
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
  listed for the modules in [modules.md](modules.md) are in those libraries (libtiff,
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
