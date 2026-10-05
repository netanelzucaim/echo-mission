# build/: the from-source `.deb` build

`make deb` builds `build/Dockerfile` in a clean `debian:bookworm-slim` and copies five
packages into `out/`: `nginx` and the four module packages (xslt, geoip, image-filter,
njs). The human guide is `build/README.md`; the patch list is `build/patches/README.md`.

## How the build works

- It drives nginx's own packaging, **pkg-oss, pinned at `aaeb9a9`**: the commit that
  shipped nginx 1.25.5 with njs 0.8.4. Its latest commit targets nginx 1.31 and needs
  QuickJS, so do not move the pin.
- `prepare.sh` clones pkg-oss, applies every `patches/CVE-*.patch`, applies
  `echo-pkg-oss.patch`, copies `changelog/`, and vendors the njs 0.8.4 source from its
  git tag. It compiles nothing; the Dockerfile runs `make` afterwards.
- `echo-pkg-oss.patch` does three things: static Debian changelogs (pkg-oss would fetch
  `xslscript` over the network), njs module **and** CLI built without QuickJS (the
  original's `/usr/bin/njs` links only libedit), and njs package release 3 (matching the
  original's version string).
- The packages must match the original: package name `nginx`, versions identical
  (`1.25.5-1~bookworm`, njs `1.25.5+0.8.4-3~bookworm`), the configure flags in
  `scans/baseline/image/nginx-V.txt`, and `/etc/nginx/conf.d/default.conf` registered as
  a conffile with the original's content (the startup scripts depend on it; see
  `rootfs/README.md`).

## The two patches

- `patches/CVE-2026-42945.patch`, **backport**: upstream commit `2046b45a` (nginx
  1.31.0), one hunk resetting `e->is_args` in `ngx_http_script_regex_end_code`. Applies
  cleanly to 1.25.5; goes into pkg-oss's quilt series.
- `patches/CVE-2024-6119.patch`, **version bump**: changes pkg-oss's
  `debian/debian/nginx.control.in` so the nginx package requires
  `libssl3 (>= 3.0.14-1~deb12u2)`, Debian's fixed version. Check with
  `dpkg-deb -f out/nginx_*.deb Depends`. A fresh bookworm-slim has no `libssl3`; it is
  installed as an nginx dependency (3.0.22 today), and dpkg refuses the `.deb` next to
  3.0.11. Never rely on the build "happening to" download a fixed version.

## Adding another fix

Full procedure: `patches/README.md`, "Adding another fix". In short:

- Every fix is `patches/CVE-YYYY-NNNN.patch`. `prepare.sh` classifies each by the paths
  it changes: only `src/`, `auto/`, `conf/` → nginx backport (quilt series); only
  `debian/` → packaging change (version bumps); njs paths or mixed → error. Never edit
  `prepare.sh` to name a single patch.
- **Backport:** `git format-patch -1 <commit>` from github.com/nginx/nginx; check
  `patch -p1 --dry-run` on the 1.25.5 source.
- **Version bump:** the minimum fixed version (Debian tracker, bookworm row) goes into
  the package that needs the library: `Depends:` in `debian/debian/nginx.control.in`, or
  `MODULE_DEPENDS_<module>=,<lib> (>= <ver>)` in `debian/Makefile.module-<module>` (the
  leading comma is needed). No fixed version in bookworm → residual risk, not a bump.
- Then `make all`, a VEX for a backport (`scans/CLAUDE.md`), and update the README's
  per-CVE table, `docs/triage-decision.md` and `patches/README.md`.
