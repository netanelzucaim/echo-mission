# Probe: fresh base with the libraries, minus image-filter's

Same as `../probe-libraries/`, but without `libgd3`, the library
`nginx-module-image-filter` needs. Scanned on 2026-10-05 with Trivy 0.75.0 (database of
2026-10-05) and Grype 0.120.0, to answer: what would removing image-filter remove?
This is not the final image, and it is not the configuration being shipped.

In the original image, removing only `nginx-module-image-filter` (with
`apt-get remove --auto-remove`) takes 31 libraries with it. Of image-filter's 32
libraries only `libbsd0` stays, because njs needs it, and it has no CVEs.

| Image | Packages | Unique CVEs | Critical or High | CVEs in image-filter's libraries |
|---|---|---|---|---|
| Original (`scans/baseline/`) | 149 | 497 | 203 | 166 |
| Fresh base, all modules' libraries (`../probe-libraries/`) | 144 | 250 | 79 | 89 |
| Fresh base, without image-filter's libraries (this folder) | 113 | 161 | 54 | 0 |

The two fresh-base probes differ by exactly the 89 CVEs in image-filter's libraries;
no other CVE appears or disappears between them.
