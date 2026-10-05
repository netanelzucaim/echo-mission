# Project guide for Claude

Take-home assignment, "Software Engineer: Build It, Patch It, Ship It". The brief
names the company Echo, which rebuilds container images from source to patch CVEs.
Owner: Netanel Zucaim. The human-facing write-up is `README.md` (with deep-dives in
`docs/`); this file is the working context.

## The mission

Ship a drop-in replacement for `nginx:1.25-bookworm` with at least 2 CVEs eliminated:

1. At least one by **version bump** of a dependency (system library or upstream source).
2. At least one by **backporting** a patch from a newer upstream commit onto the nginx
   version being shipped (1.25.x).

Removing a vulnerable component is allowed as an extra and does not count toward the two.
Also required: an automated compatibility test (`make test`) proving the new image
behaves like the original.

Deliverables: `build/` (+ `build/patches/CVE-YYYY-NNNN.patch`), `Containerfile`, `test/`,
`README.md` (build instructions, image size, per-CVE table, residual risk, surprises,
AI use). Graded on depth over breadth, triage judgment, honest residual risk and
truthful dead ends. Do not overstate what a fix achieves.

### Status: all six steps done

| # | Step | Where |
|---|---|---|
| 1 | Scan the original with Trivy and Grype | `make scan-baseline`, `scans/baseline/` |
| 2 | Triage and pick targets, by judgment | `make triage`, `docs/triage-decision.md` (`choose-cve-fix` skill) |
| 3 | `.deb` from source in clean `debian:bookworm-slim`, patches applied | `make deb`, `build/` (pkg-oss pinned at `aaeb9a9`; njs 0.8.4 without QuickJS; nginx + 4 module `.deb`s) |
| 4 | Final image from the `.deb` | `make image`, `Containerfile`; 293 MB vs 276 MB |
| 5 | Compatibility test | `make test`: 92 checks, 91 match, 1 allowed (maintainer label), 0 mismatch |
| 6 | Bonus: rescan, diff, VEX | `make rescan`, `scans/patched/diff.md`: scanner-reported 497 → 253; of 26 nginx/njs advisory CVEs 1 fixed, 25 present; CVE-2023-52355 VEX suppressed in both scanners |

`make all` runs deb, image, test, fsdiff and rescan in order.

## Decisions (do not undo without the owner)

- **The two targets** (2026-10-05; reasoning in `docs/triage-decision.md`, by
  reach first, then KEV, then EPSS against both severities, not by the score):
  - **Version bump: CVE-2024-6119** (OpenSSL X.509 DoS, EPSS 66.6%, High/High, reached
    when nginx verifies upstream certificates). `build/patches/CVE-2024-6119.patch` makes
    the nginx package require `libssl3 (>= 3.0.14-1~deb12u2)`; the image gets 3.0.22, and
    dpkg refuses to install the `.deb` next to 3.0.11. Rejected: CVE-2025-15467 (CMS,
    never called by nginx), CVE-2024-37371 (Kerberos, only `curl` uses it).
  - **Backport: CVE-2026-42945** (rewrite-module heap overflow). Upstream commit
    `2046b45a` (nginx 1.31.0), one hunk resetting `e->is_args`. Applies cleanly to
    1.25.5; exercised by the "rewrite capture reused after a replacement with args"
    scenario in `test/compat_test.py`. VEX `status: fixed`. Not taken, available as a
    second backport: CVE-2024-7347 (mp4) and CVE-2026-9256 (sibling rewrite overflow).
  - **CVE-2023-44487** (HTTP/2 Rapid Reset, KEV, top of the ranking) is already
    mitigated by upstream commit 6ceef19 in 1.25.3. Never present it as open or as
    fixed by this project.
- **Base:** fresh `debian:bookworm-slim`, `apt-get update` and `upgrade`, `.deb`
  dependencies at their newest versions. This is where the other Debian fixes come from.
- **Keep all four dynamic modules** (xslt, geoip, image-filter, njs), built from source
  with the same `.so` files: compatibility wins over removing their libraries. What
  remains goes in residual risk. Details and measurements: `docs/modules.md`.
- **Image settings copied from the original** (`scans/baseline/image/inspect.json`,
  `history.txt`). The brief requires filesystem layout, user, working directory, ports
  and entrypoint to match exactly; labels are not in that list. The `maintainer` label
  names the owner, because this image is not NGINX's. Do **not** change it back to chase
  a byte-for-byte match. It is the one entry in `ALLOWED` in `test/compat_test.py`.
- **Startup scripts** are in `rootfs/`, extracted unchanged from the original
  (`rootfs/README.md`).
- **nginx.org's apt signing key** is fetched in the `Containerfile` with the same
  commands as the original's build (`gpg1 --recv-keys` from the keyservers, then export
  and purge gnupg1). Same key, same path and mode; the bytes differ because the
  keyserver now has the renewed expiry (2027 instead of 2024). Owner's choice
  (2026-10-06), recorded in `docs/image-config.md`.
- **Base-evolution differences** (debian-archive keyrings, tzdata, CA store) are the only
  file differences; `make fsdiff` checks this after any build change, because
  `make test` only inspects the nginx paths.

## Findings to keep in mind

- **Scanners miss nginx's own CVEs.** nginx is from nginx.org, but Trivy and Grype
  compare it with Debian's data (1.22.1 with backports), so `1.25.5 > 1.22.1-9+deb12u2`
  looks fixed. nginx CVEs come from https://nginx.org/en/security_advisories.html. A
  backport therefore shows no scan difference. Explained in `docs/scanner-blind-spot.md`.
- **So the VEX "disappear" demo uses another CVE:** CVE-2023-52355 (libtiff6), reported
  by both scanners, no fix, honestly `not_affected` (image-filter never asks libgd for
  TIFF). The backport's VEX is still written, as `status: fixed`. Rule for picking a
  demo CVE: `.claude/skills/rescan-compare-vex/SKILL.md`.
- **For a package the distribution did not build, take CVEs from its upstream project.**
  `scans/baseline/image/foreign-packages.tsv` lists them. njs is its own source: its
  CVE-2026-78689 applies (`config`), CVE-2026-18329 is `n/a` for 0.8.4. Both are in
  `review.tsv`. Method: `.claude/skills/triage-cves/SKILL.md`.
- **Loaded vs unloaded.** nginx's binary loads `libc6`, `libcrypt1`, `libpcre2-8-0`,
  `libssl3`, `zlib1g` (`scans/baseline/image/linked-packages.txt`); everything else is
  only installed. Module libraries are listed per module in `image/modules.tsv`.
- **The `.deb` must be named `nginx`** and register `/etc/nginx/conf.d/default.conf` as
  a conffile with the original's content (`rootfs/README.md`). Use the configure flags
  in `scans/baseline/image/nginx-V.txt`.

## Rules for working in this repo

- Never claim a fix or a match that has not been verified by a command. Say what was
  checked and what was assumed.
- Record deliberate differences from the original in `docs/image-config.md` (and the
  README if they matter to a reader) as they are made.
- Everything must be reproducible with one command through the `Makefile`.
- Do not download prebuilt nginx binaries or packages; the brief forbids it.
- Never build or run anything that triggers a CVE's bug. A backport is proven by
  applying cleanly, reading the diff, and exercising the code path with normal input.
- The compatibility test treats the original as the specification. Never relax a
  comparison to make it pass: fix the image, or add the difference to `ALLOWED` with a
  reason and record it. New scenarios need an `expect` (`test/README.md`).
- The patched image is tagged `echo-nginx:1.25-bookworm` (the Makefile's `IMAGE`).
- VEX documents go in `vex/` as `<CVE>.openvex.json`, written by `scripts/make-vex.py`.
- Generated files (`scans/**` except `review.tsv`) are never edited
  by hand. Layout: `scans/README.md`. Script details: `scripts/CLAUDE.md`.
- Skills, in `.claude/skills/`: `triage-cves` (merge scans, review reach, rank, diagrams),
  `choose-cve-fix` (decide targets and methods by judgment, write `docs/triage-decision.md`),
  `rescan-compare-vex` (step 6). They describe procedures and point to `scripts/`.
- Commit as Netanel Zucaim with the Claude co-author trailer, then push to `origin main`.

## Adding another CVE fix

Full procedure: `build/patches/README.md`, "Adding another fix". In short:

- Every fix is `build/patches/CVE-YYYY-NNNN.patch`. `build/prepare.sh` classifies each by
  the paths it changes: only `src/`, `auto/`, `conf/` → nginx backport (into pkg-oss's
  quilt series); only `debian/` → packaging change (version bumps); njs paths or mixed →
  error. Never edit `prepare.sh` to name a single patch.
- **Backport:** `git format-patch -1 <commit>` from github.com/nginx/nginx; check
  `patch -p1 --dry-run` on 1.25.5.
- **Version bump:** write the minimum fixed version (Debian tracker, bookworm row) into
  the package that needs it: `Depends:` in pkg-oss `debian/debian/nginx.control.in`, or
  `MODULE_DEPENDS_<module>=,<lib> (>= <ver>)` in `debian/Makefile.module-<module>`. No
  fixed version in bookworm → residual risk, not a bump.
- Then `make all`, a VEX for a backport, and update the README table, `docs/triage-decision.md`
  and `build/patches/README.md`.
