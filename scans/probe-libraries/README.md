# Probe: fresh base with the libraries only, no nginx

Scanned on 2026-10-05 to measure what the version bumps alone achieve, before the
patched nginx packages exist. This is not the final image.

Contents of the probe image: `debian:bookworm-slim`, `apt-get upgrade`, the helper
packages the `Containerfile` installs (`gettext-base`, `curl`, `ca-certificates`), and
the Debian libraries that nginx and its four modules depend on (`libssl3`,
`libpcre2-8-0`, `zlib1g`, `libgd3`, `libxslt1.1`, `libxml2`, `libgeoip1`, `libedit2`).
It has 144 packages, and all 37 module-only libraries from the baseline are present.

Scanners: Trivy 0.75.0 (database of 2026-10-05) and Grype 0.120.0. The baseline was
scanned a day earlier, so its Trivy database is one day older.

| | Baseline | Probe |
|---|---|---|
| Unique CVEs, whole image | 497 | 250 |
| Critical or High, whole image | 203 | 79 |
| CVEs in the four modules' libraries | 208 | 101 |
| CVEs in image-filter's libraries | 166 | 89 |
| Critical or High in image-filter's libraries | 65 | 25 |

Files: `trivy.json`, `grype.json`, `packages.tsv`, and `triage.md` / `triage.csv` from
`scripts/compare-scans.py`. The probe image was built by hand in the Claude cloud
workspace; there is no `make` target for it. The final-image scan in step 6 replaces
these numbers.
