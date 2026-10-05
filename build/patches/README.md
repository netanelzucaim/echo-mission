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
