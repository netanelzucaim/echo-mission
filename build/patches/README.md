# Backport patches

Each file is named after the CVE it fixes and is applied to the nginx **1.25.5**
source during the from-source build (step 3). It is adapted from a newer upstream
commit so the image can stay on the 1.25 line.

| File | CVE | Fixes | Upstream source | Status |
|---|---|---|---|---|
| `CVE-2026-42945.patch` | CVE-2026-42945 | Heap buffer overflow in `ngx_http_rewrite_module` (potential code execution) reached through `rewrite`/`set`/`return` with captures | upstream commit `2046b45aa0c6` ("Rewrite: fixed escaping and possible buffer overrun"), which landed in nginx 1.31.0 — the release the advisory names as the fix | applies cleanly to 1.25.5 |

This is **the** backport for the assignment, chosen on 2026-10-05 (reasoning in
`scans/baseline/priorities.md`). It fixes a bug in code almost every config runs, whose
worst case is code execution. The patch is one hunk: it resets `e->is_args` in
`ngx_http_script_regex_end_code`, so a capture used after a rewrite replacement that
contained arguments is no longer escaped into an undersized buffer.

Verified by `patch -p1 --dry-run` against a pristine 1.25.5 tree (applies cleanly). The
diff was read; the patched binary has not been built or exercised yet — the
compatibility test (a rewrite scenario, to be added when the build lands) and the
post-build rescan are what close that gap.

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
