# Backport patches

Each file is named after the CVE it fixes and is applied to the nginx **1.25.5**
source during the from-source build (step 3). They are adapted from newer upstream
commits so the image can stay on the 1.25 line.

These are the **candidates** from the triage decision (`scans/baseline/priorities.md`);
the owner's final pick for the required backport is between the two. Both were
confirmed to apply to a clean 1.25.5 tree with `patch -p1 --dry-run`. Applicability
was verified; the patched binary has not been built or exercised yet (that is what the
compatibility test and the post-build rescan cover).

| File | CVE | Fixes | Upstream source | Status |
|---|---|---|---|---|
| `CVE-2024-7347.patch` | CVE-2024-7347 | Buffer over-read in `ngx_http_mp4_module` (low; worker crash) | nginx's vendor-published patch `patch.2024.mp4.txt` (fixed in 1.26.2 / 1.27.1) | applies cleanly |
| `CVE-2026-42945.patch` | CVE-2026-42945 (+ CVE-2026-9256) | Heap overflow in `ngx_http_rewrite_module` (potential code execution) | upstream commits `2046b45a`, `475732a3`, `ca4f92a2` (fixed in 1.30.1 / 1.31.0+) | applies cleanly |

To re-verify:

```sh
cd <nginx-1.25.5 source>
patch -p1 --dry-run < build/patches/CVE-2024-7347.patch
patch -p1 --dry-run < build/patches/CVE-2026-42945.patch
```
