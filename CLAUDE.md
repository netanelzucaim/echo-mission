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
- **nginx loads five libraries:** `libc6`, `libcrypt1`, `libpcre2-8-0`, `libssl3`,
  `zlib1g` (`scans/baseline/linked-packages.txt`). Everything else in the image is a
  tool or belongs to an optional module.
- **Targets are chosen by danger and reach, not by severity label.** The owner's rule:
  prefer what is most likely to be exploited and what every deployment actually runs.
  `make triage` scores this; see `scripts/CLAUDE.md`.

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
