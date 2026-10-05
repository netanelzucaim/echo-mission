# Project guide for Claude

Take-home assignment, "Software Engineer: Build It, Patch It, Ship It". The brief
names the company Echo, which rebuilds container images from source to patch CVEs.
Owner: Netanel Zucaim. The human-facing write-up is `README.md` (with deep-dives in
`docs/`); the `CLAUDE.md` files are the working context.

## The mission

Ship a drop-in replacement for `nginx:1.25-bookworm` with at least 2 CVEs eliminated:
at least one by **version bump** of a dependency, and at least one by **backporting** a
newer upstream commit onto the shipped nginx 1.25.x. Removing a component is allowed as
an extra and does not count. Also required: an automated compatibility test.

Deliverables: `build/` (+ `build/patches/CVE-YYYY-NNNN.patch`), `Containerfile`, `test/`,
`README.md` (build instructions, image size, per-CVE table, residual risk, surprises,
AI use). Graded on depth over breadth, triage judgment, honest residual risk and
truthful dead ends. Do not overstate what a fix achieves.

## Status: all six steps done

| # | Step | Where |
|---|---|---|
| 1 | Scan the original with Trivy and Grype | `make scan-baseline`, `scans/baseline/` |
| 2 | Triage and pick targets, by judgment | `make triage`, `docs/triage-decision.md` |
| 3 | `.deb` from source in clean `debian:bookworm-slim` | `make deb`, `build/` |
| 4 | Final image from the `.deb` | `make image`, `Containerfile`; 293 MB vs 276 MB |
| 5 | Compatibility test | `make test`: 92 checks, 91 match, 1 allowed (maintainer label), 0 mismatch |
| 6 | Bonus: rescan, diff, VEX | `make rescan`, `scans/patched/diff.md`: scanner-reported 497 → 253; 1 of 26 nginx/njs advisory CVEs fixed; CVE-2023-52355 VEX suppressed in both scanners |

`make all` runs deb, image, test, fsdiff and rescan in order.

**The two fixes:** version bump of **CVE-2024-6119** (OpenSSL, via a minimum `libssl3`
version in the nginx package) and backport of **CVE-2026-42945** (nginx rewrite module,
upstream commit `2046b45a`). Why these, and what was rejected: `scans/CLAUDE.md` and
`docs/triage-decision.md`. How they are built: `build/CLAUDE.md`.

## Where the guidance is

| File | Read it when working on |
|---|---|
| `build/CLAUDE.md` | The `.deb` build, the patches, adding another fix |
| `test/CLAUDE.md` | The compatibility test and `make fsdiff` |
| `scans/CLAUDE.md` | Triage, the chosen targets, scanner findings, VEX |
| `scripts/CLAUDE.md` | The helper scripts behind the `make` targets |
| `.claude/skills/` | `triage-cves` (rank and review reach), `choose-cve-fix` (decide targets), `rescan-compare-vex` (step 6) |

## The final image (`Containerfile`)

Decisions; do not undo them without the owner.

- **Base:** fresh `debian:bookworm-slim`, `apt-get update` and `upgrade`, the `.deb`s'
  dependencies at their newest versions. This is where the other Debian fixes come from.
- **Keep all four dynamic modules** (xslt, geoip, image-filter, njs): compatibility wins
  over removing their libraries. Measurements: `docs/modules.md`.
- **Settings copied from the original** (`scans/baseline/image/inspect.json`,
  `history.txt`). The brief requires filesystem layout, user, working directory, ports
  and entrypoint to match exactly; labels are not in that list. The `maintainer` label
  names the owner, because this image is not NGINX's. Do **not** change it back to chase
  a byte-for-byte match.
- **Startup scripts** are in `rootfs/`, extracted unchanged from the original
  (`rootfs/README.md`).
- **nginx.org's apt signing key** is fetched with the same commands as the original's
  build (`gpg1 --recv-keys` from the keyservers, export, purge gnupg1). Same key, path and
  mode; the bytes differ because the keyserver has the renewed expiry (2027, not 2024).
- **The only file differences** are from the newer Debian base (debian-archive keyrings,
  tzdata, CA store). Every deliberate difference is recorded in `docs/image-config.md`.
- The image is tagged `echo-nginx:1.25-bookworm` (the Makefile's `IMAGE`).

## Rules for working in this repo

- Never claim a fix or a match that has not been verified by a command. Say what was
  checked and what was assumed.
- Everything must be reproducible with one command through the `Makefile`.
- Do not download prebuilt nginx binaries or packages; the brief forbids it.
- Never build or run anything that triggers a CVE's bug. A backport is proven by
  applying cleanly, reading the diff, and exercising the code path with normal input.
- Record deliberate differences from the original in `docs/image-config.md` as they are
  made, and in the README if they matter to a reader.
- Keep environment-specific settings (proxies, CA bundles) out of committed files.
- Commit as Netanel Zucaim with the Claude co-author trailer, then push to `origin main`.
