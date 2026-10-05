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
| 2 | Triage: per CVE, where it lives, is there a fix, how to fix; pick targets and justify | Done by judgment, written in `scans/baseline/priorities.md` (the `choose-cve-fix` skill). Targets decided: bump CVE-2024-6119 (OpenSSL), backport CVE-2026-42945 (rewrite). `make fix-plan` is the script's starting proposal |
| 3 | Build a `.deb` from source in a clean `debian:bookworm-slim`, one command, patches applied | Done (`make deb`, `build/`). Drives nginx's pkg-oss packaging with the CVE-2026-42945 backport injected into the quilt series; njs 0.8.4 built without QuickJS. Produces nginx + 4 module `.debs` |
| 4 | Final image: install the `.deb` into a minimal Debian base, match the original | Done (`make image`, `Containerfile`). Built `echo-nginx:1.25-bookworm`; OpenSSL bump from `apt-get upgrade` (3.0.11 → 3.0.22), 291 MB vs 276 MB |
| 5 | Compatibility test in Go or Python, `make test`, non-zero exit on mismatch | Done. 92 checks on the built image: 91 match, 1 allowed difference (maintainer label), 0 mismatch — a verified drop-in |
| 6 | Bonus: rescan, diff against baseline, VEX | Done (`make rescan`, `scans/patched/`). 523 → 253 CVEs; CVE-2024-6119 gone; CVE-2023-52355 VEX suppressed in both scanners; CVE-2026-42945 VEX is status:fixed (never scanner-reported) |

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
- **Image settings:** copied from the original (`scans/baseline/image/inspect.json`,
  `history.txt`). One deliberate difference: the `maintainer` label names the owner,
  because the image is not built by NGINX.
  - **What "match exactly" covers.** The brief requires the new image to match the
    original's **filesystem layout, user, working directory, ports and entrypoint**
    exactly — labels are **not** in that list. So changing the `maintainer` label is
    within the brief, and it is a correct, honest change (this image is not NGINX's).
    Do **not** "fix" the maintainer label back to NGINX's to chase a byte-for-byte
    match: that would be the only inaccurate thing in the image. The compatibility
    test encodes this — `maintainer` is in `ALLOWED` in `test/compat_test.py`, every
    other setting must match.
- **Startup scripts:** extracted unchanged from the original into `entrypoint/`.
- **Kerberos CVE-2024-37371:** considered and rejected by the owner as the headline
  bump. The library is only present because `curl` depends on it; nginx never calls it.
  It is still upgraded by the fresh base, just not claimed as one of the two fixes.

- **Dynamic modules: keep all four.** Decided by the owner on 2026-10-05: customers
  whose configs load a module must keep working, so compatibility wins over removing
  the vulnerable libraries. The image must ship `nginx-module-xslt`, `-geoip`,
  `-image-filter` and `-njs`, built from source, with the same `.so` files in
  `/usr/lib/nginx/modules/`. Their libraries get whatever fixes the fresh base
  provides; what remains goes in the README's residual-risk section. xslt, geoip and
  image-filter are part of the nginx source tree; njs is a separate source (0.8.4).

### The two targets (decided 2026-10-05)

The full reasoning is in `scans/baseline/priorities.md`, decided by judgment (reach
first, then KEV, then EPSS weighed against both scanners' severity), not by the score.

- **Version bump: CVE-2024-6119** (OpenSSL). `3.0.11-1~deb12u2` to `3.0.22-1~deb12u1`
  (denial of service in X.509 name checks; reachable when nginx is a reverse proxy that
  verifies upstream certificates). The strongest reachable exploitation signal in the
  image: EPSS 66.6%, High/High. Fixed by `apt-get upgrade`. Verified 2026-10-05 on a
  bookworm system: Debian fixed it in 3.0.14-1~deb12u2, and bookworm-security now offers
  3.0.22-1~deb12u1, so the fresh base's upgrade installs an OpenSSL well past the fix.
  Final confirmation is the rescan of the built image. Rejected alternative:
  CVE-2025-15467 is in CMS parsing, which nginx does not use.
- **Backport: CVE-2026-42945** (chosen by the owner over the mp4 fallback). Heap
  overflow in the rewrite module, potential code execution, reached through
  `rewrite`/`set`/`return` with captures — code almost every config runs. The fix is
  upstream commit `2046b45a` (landed in nginx 1.31.0, the release the advisory names),
  a single hunk resetting `e->is_args`. Staged as `build/patches/CVE-2026-42945.patch`,
  confirmed to apply cleanly to a pristine 1.25.5 (`patch -p1 --dry-run`); the diff was
  read, the binary not yet built or exercised. VEX written as `status: fixed`
  (`vex/CVE-2026-42945.openvex.json`) — the scanners never reported it, so it has
  nothing to suppress; it is the formal record of the fix.
  - Not taken (available as a second backport if wanted, in `priorities.md` and
    `build/patches/README.md`): CVE-2024-7347 (mp4, the vendor-patch fallback) and
    CVE-2026-9256 (the sibling rewrite overflow, commits `ca4f92a2` + `475732a3`).
- **Mitigated already, not a fix:** CVE-2023-44487 (HTTP/2 Rapid Reset, KEV) is
  already covered by upstream's stream-handling limit shipped in 1.25.3. It gets a
  VEX / residual-risk note, never a patch, and must not be presented as open or as
  fixed by this project.

### Decided: filesystem differences outside the test's paths

- **Signing key not copied.** The original contains
  `/etc/apt/keyrings/nginx-archive-keyring.gpg`, a leftover from installing nginx from
  nginx.org's apt repository. This image builds nginx from source and never adds that
  repository, so the key is deliberately absent. Recorded in `README.md` under
  "Deliberate differences" (decided 2026-10-05).
- **Base-evolution differences** (debian-archive keyrings, tzdata) come from rebuilding
  on a current base, also recorded there. A full filesystem diff shows no other
  differences; re-run one after any build change, because the compatibility test only
  inspects the nginx paths.

## Findings worth keeping in mind

- **Scanners miss nginx's own CVEs.** The `nginx` package comes from nginx.org, but
  Trivy and Grype compare its version against Debian's fixed versions (Debian ships
  1.22.1 with backports). `1.25.5 > 1.22.1-9+deb12u2`, so the CVE looks fixed. Triage
  nginx CVEs from https://nginx.org/en/security_advisories.html, not from the reports.
  A backported fix may therefore show no before/after scan difference, leaving the VEX
  document nothing to suppress. Confirm after the real build.
  - **So the VEX "disappear" demo runs on a different CVE than the backport.** The
    brief's bonus says to VEX "one of your backport-patched CVEs" and show it vanish
    from the rescan. That cannot work here: the backport fixes an nginx CVE the
    scanners never reported, so there is nothing to make disappear. Resolution: the
    demonstrated CVE is **CVE-2023-52355** (libtiff6) — reported by both scanners,
    **no upstream fix** (so the base upgrade cannot remove it on its own), and
    genuinely `not_affected` (image-filter asks libgd for JPEG/GIF/PNG/WebP only,
    never TIFF; the module is not loaded by default). `vex/CVE-2023-52355.openvex.json`
    makes it disappear from both scanners (proven 2026-10-05 against the baseline
    image). A VEX for the backported CVE is still written, as `status: fixed`, to
    answer the brief literally — it just won't change the scan, and the README says so.
    The rule for picking a demo CVE (reported + no fix + honestly not_affected) is in
    `.claude/skills/rescan-compare-vex/SKILL.md`.
- **Rule: for a package the distribution did not build, take CVEs from its upstream
  project, never from the distribution's data.** `scans/baseline/image/foreign-packages.tsv`
  lists them (nginx and its four modules); the triage warns if their upstream CVEs are
  missing. Full rule in `.claude/skills/triage-cves/SKILL.md`. njs 0.8.4 was checked
  against its own source and GitHub advisories on 2026-10-05 (worked example in that
  skill): CVE-2026-78689 (XML `exclusiveC14n`, Critical) applies and is added as
  `config` reach (needs the njs module loaded and a `js_import` using XML c14n, e.g.
  SAML); CVE-2026-18329 (js_access bypass) is `n/a` for 0.8.4 (http `js_access` does
  not exist in 0.8.4). Both are in `review.tsv` under `nginx-module-njs`.
- **The `.deb` must be named `nginx` and register `/etc/nginx/conf.d/default.conf` as a
  conffile**, with the original's exact content. See `entrypoint/README.md`.
- **Use the original's configure flags** from `scans/baseline/image/nginx-V.txt`; they decide
  the filesystem layout.
- **Loaded versus unloaded packages** are described in their own section below.
- **Targets are chosen by danger and reach, not by severity label.** The owner's rule:
  prefer what is most likely to be exploited and what every deployment actually runs.
  `make triage` scores this; see `scripts/CLAUDE.md`.

## Loaded and unloaded packages

The original image has 149 packages (Trivy counts 144 of them). The triage score (`make triage`) weights a
vulnerability by whether nginx runs the affected code.

**Loaded (unreviewed reach 0.6; see `scripts/CLAUDE.md`):** the `nginx` package itself and the five libraries its binary
loads, taken from `ldd /usr/sbin/nginx` and saved in
`scans/baseline/image/linked-packages.txt`. A bug here is inside every running container.

| Package | What nginx uses it for |
|---|---|
| `nginx` | The server itself |
| `libssl3` (OpenSSL) | HTTPS encryption |
| `libpcre2-8-0` | Pattern matching in config rules |
| `zlib1g` | Compressing responses (gzip) |
| `libc6` | Basic system functions |
| `libcrypt1` | Password checking for basic authentication |

**Unloaded (unreviewed reach 0.3 for module libraries, 0.2 otherwise):** everything else. Installed, but the nginx program never
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
- Skills live in the repository, under `.claude/skills/`, not in the owner's account or
  Claude project: `compare-vuln-scans` (rank scan results and generate the diagrams),
  `triage-cves` (review whether nginx really runs the vulnerable code, in `review.tsv`),
  `choose-cve-fix` (step 2: decide priority and fix method per CVE by judgment —
  reach + KEV + EPSS + both severities — not a formula; writes `priorities.md`)
  and `rescan-compare-vex` (step 6: rescan, compare with the baseline, write and test
  VEX). They describe the procedure and point to the scripts in `scripts/`; keep the
  code in one place. The `probe-image-change` skill, `scripts/probe-impact.sh` and
  `make probe` were removed at the owner's request on 2026-10-05. They are in git
  history (last present in commit 2287013) if they are wanted again.
- The patched image is tagged `echo-nginx:1.25-bookworm` (the Makefile's `IMAGE`).
  `make test` and `make rescan` use it.
- The compatibility test treats the original image as the specification. Never relax a
  comparison to make it pass: either fix the image, or add the difference to `ALLOWED`
  in `test/compat_test.py` with a reason and record it in `README.md`. New scenarios
  need an `expect` so two broken servers cannot "match". See `test/README.md`.
- The CVE-2026-42945 backport is exercised by the "rewrite capture reused after a
  replacement with args" scenario in `test/compat_test.py` (custom group); it matches
  the original for benign input, confirming the patch did not change normal behaviour.
- VEX documents go in `vex/` as `<CVE>.openvex.json`, written by `scripts/make-vex.py`.

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
