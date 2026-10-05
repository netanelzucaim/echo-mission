# Patches applied during the build

Each file is named after the CVE it fixes and is applied by `build/prepare.sh` during
the from-source build (step 3). The brief's build step is "apply your patches: version
bump(s) + backport(s)"; there is one of each.

| File | CVE | Kind | Fixes | Source of the fix | Status |
|---|---|---|---|---|---|
| `CVE-2024-6119.patch` | CVE-2024-6119 | **Version bump** | Denial of service in OpenSSL's X.509 name checks, reachable when nginx verifies an upstream server's certificate | Debian's fixed `libssl3 3.0.14-1~deb12u2`. The patch changes nginx's *packaging*: the nginx package now requires `libssl3 (>= 3.0.14-1~deb12u2)` instead of any 3.0 | built `.deb` declares it; dpkg refuses to install it next to OpenSSL 3.0.11 |
| `CVE-2026-42945.patch` | CVE-2026-42945 | **Backport** | Heap buffer overflow in `ngx_http_rewrite_module` (potential code execution) reached through `rewrite`/`set`/`return` with captures | upstream commit `2046b45aa0c6` ("Rewrite: fixed escaping and possible buffer overrun"), which landed in nginx 1.31.0 — the release the advisory names as the fix | applies cleanly to 1.25.5 |

**CVE-2024-6119.patch** (version bump). nginx loads OpenSSL from Debian, so the fix
is a newer Debian package, not a code change. The patch makes that requirement part of
the package: without it, the nginx package accepts any OpenSSL 3.0, and the fixed version
arrives only because the build happens to download current packages. With it, the
built `.deb` declares `libssl3 (>= 3.0.14-1~deb12u2)`, apt must install a fixed OpenSSL
(this image gets 3.0.22), and on a system that still has 3.0.11 dpkg refuses:
"nginx depends on libssl3 (>= 3.0.14-1~deb12u2); however: Version of libssl3 on system
is 3.0.11-1~deb12u2". Check it with `dpkg-deb -f out/nginx_*.deb Depends`.

**CVE-2026-42945.patch** (backport) is **the** backport for the assignment, chosen on 2026-10-05 (reasoning in
`scans/baseline/priorities.md`). It fixes a bug in code almost every config runs, whose
worst case is code execution. The patch is one hunk: it resets `e->is_args` in
`ngx_http_script_regex_end_code`, so a capture used after a rewrite replacement that
contained arguments is no longer escaped into an undersized buffer.

Verified: `patch -p1 --dry-run` applies cleanly to a pristine 1.25.5 tree, the build
log shows the patch applied, and the built image passes `make test`, including a
scenario that runs the patched rewrite path with output identical to the original.

To re-verify:

```sh
cd <nginx-1.25.5 source>
patch -p1 --dry-run < build/patches/CVE-2026-42945.patch
```

## Not shipped (available if a second backport is wanted)

- **CVE-2024-7347** (mp4 over-read, low): nginx's own vendor-published patch
  (`nginx.org/download/patch.2024.mp4.txt`). The clean fallback that was not chosen; it
  is in git history and described in `priorities.md`.
- **CVE-2026-9256** (rewrite overlapping-captures overflow, a sibling of CVE-2026-42945):
  upstream commits `ca4f92a2` + `475732a3` (nginx 1.31.1). A natural second rewrite
  backport if more coverage is wanted.

## Adding another fix

Pick the CVE first (the `choose-cve-fix` skill and `scans/baseline/priorities.md`).
Then follow the part that matches where the CVE lives. Name the file after the CVE,
`CVE-YYYY-NNNN.patch`, and put it in this folder. `build/prepare.sh` applies every
`CVE-*.patch` here and decides how from the paths the patch changes, so no script
needs editing.

### A. Backport: the CVE is in nginx's own code

1. Check nginx.org's advisory lists 1.25.5 in its "Vulnerable" range
   (<https://nginx.org/en/security_advisories.html>).
2. Find the upstream fix in <https://github.com/nginx/nginx>: the commit that went into
   the first release the advisory calls "Not vulnerable". Read it.
3. Export it: `git format-patch -1 <commit> --stdout > build/patches/CVE-YYYY-NNNN.patch`.
4. Check it applies to the shipped source: download `nginx-1.25.5.tar.gz` from nginx.org,
   unpack it, and run `patch -p1 --dry-run < CVE-YYYY-NNNN.patch` inside it. If it does
   not apply, adapt the hunk by hand and say so at the top of the patch.

`prepare.sh` treats a patch that changes only `src/`, `auto/` or `conf/` as nginx source
and adds it to pkg-oss's quilt series, which applies it during the build.

### B. Version bump: the CVE is in a Debian library

1. Find the version Debian fixed it in, in the bookworm row of
   `https://security-tracker.debian.org/tracker/CVE-YYYY-NNNN`. If bookworm has no fixed
   version yet, a version bump is not possible: record it as residual risk.
2. Write the minimum version into the package that needs the library, in pkg-oss's
   packaging (clone <https://github.com/nginx/pkg-oss> and check out `aaeb9a9`):
   - a library the nginx program loads (`libssl3`, `libpcre2-8-0`, `zlib1g`, `libc6`,
     `libcrypt1`): add `<library> (>= <fixed version>)` to `Depends:` of the nginx
     package in `debian/debian/nginx.control.in`, as `CVE-2024-6119.patch` does;
   - a library only a module needs (for example `libxml2` for xslt): set
     `MODULE_DEPENDS_<module>=,<library> (>= <fixed version>)` in
     `debian/Makefile.module-<module>` (`<module>` with `_` for `-`, e.g. `image_filter`).
3. Save the change as the patch: `git diff --src-prefix=a/ --dst-prefix=b/`, with a few
   lines at the top saying which CVE, which fixed version, and why.

`prepare.sh` treats a patch that changes only `debian/` paths as packaging and applies
it to pkg-oss. Tools no package of ours depends on (`curl`, `perl`) cannot be pinned
this way; they get whatever version the fresh base installs.

### C. Backport into njs

The njs source is a separate project, and `prepare.sh` does not apply patches to it
yet: it stops with an error rather than build without the fix. To add one, list the
patch in `MODULE_PATCHES_njs` in `debian/Makefile.module-njs` (through
`build/echo-pkg-oss.patch`), the way pkg-oss patches other module sources.

### Then, for every fix

1. `make deb`. For a backport, the build log shows the patch being applied; for a
   version bump, `dpkg-deb -f out/nginx_*.deb Depends` shows the minimum version.
2. `make image`.
3. `make test` must report 0 mismatches. For a backport, add a scenario to
   `test/compat_test.py` that runs the patched code path with normal input and has an
   `expect`, as the rewrite scenario does.
4. `make fsdiff` must report no unexpected differences.
5. `make rescan`. A version-bumped CVE should be "no longer reported". A backported
   nginx CVE never appears in the scans (`docs/scanner-blind-spot.md`).
6. For a backport, write its VEX record:
   `python3 scripts/make-vex.py --cve CVE-YYYY-NNNN --package nginx --scan-dir scans/patched --note "..."`,
   then run `make rescan` again.
7. Add the CVE to the per-CVE table in the main `README.md`, to
   `scans/baseline/priorities.md`, and to the table at the top of this file.
