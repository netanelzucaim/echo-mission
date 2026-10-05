# scripts/

Helper scripts. Each one is wired to a `make` target; add a target for any new script.

| Script | Make target | Purpose |
|---|---|---|
| `scan-baseline.sh` | `make scan-baseline` | Pull the original image, save its metadata into `scans/baseline/image/` and scan it with Trivy and Grype into `scans/baseline/reports/` |
| `probe-impact.sh` | `make probe REMOVE="pkg"` | Measure what removing packages and/or updating Debian packages would change; prints a table and cleans up after itself |
| `compare-scans.py` | `make triage` | Merge a Trivy and a Grype JSON report and rank vulnerabilities by danger and reach into `triage.md` and `triage.csv`, and write the statistics diagrams to `stats.md` |

## scan-baseline.sh

- Needs only Docker. Uses `trivy` and `grype` from `PATH` if present, otherwise runs
  them as containers.
- Scans a `docker save` tarball so both tools see the same image bytes, then deletes it.
- Options through the environment: `IMAGE`, `OUT`, `PLATFORM` (for example
  `linux/amd64`), `MODULES` (optional module packages; default every `nginx-module-*`).
- If `docker pull` fails but the image exists locally, it warns and scans the local
  copy. Docker Hub rate limits (HTTP 429) made this necessary.
- The containerized-scanner path has not been run successfully yet. It failed in the
  Claude cloud workspace because of the proxy certificate, and has not been tried on
  the owner's Mac.
- When step 6 arrives, reuse this script for the patched image through `IMAGE` and
  `OUT` rather than writing a second one.

## compare-scans.py

- Python 3 standard library only.
- Ranking is by danger and reach, not by severity label: `score = 100 x danger x reach`.
  - Danger = 0.6 x exploitation (1 if in CISA KEV, else the EPSS probability) + 0.4 x
    severity (average of both scanners, a missing scanner counts as 0).
  - Reach = 1.0 if the affected package is `nginx` itself or a library its binary loads, 0.4 if it
    only sits in the image, plus 0.05 per extra affected package (max +0.15).
  - The owner chose this over "Critical in both first" on 2026-10-05, because the
    top-severity findings were mostly in libraries nginx never runs.
- Reach comes from `linked-packages.txt` next to the Trivy report or in `../image/` (written by
  `scan-baseline.sh` from `ldd /usr/sbin/nginx`), or from `--linked FILE`. Without it
  the script warns and treats every package as "only sits in the image".
- "Loaded" means the library is loaded, not that the vulnerable function is called.
  Read the advisory before claiming nginx is affected.
- Also writes `stats.md`: Mermaid diagrams and tables computed from the data. The
  owner wants diagrams produced by the script so the next image gets the same ones;
  do not write statistics diagrams by hand. If `modules.tsv` (module, package) is next
  to the Trivy report or in `../image/`, or `--modules FILE` is given, it adds a
  per-module table. `scan-baseline.sh` writes that file for every `nginx-module-*`
  package, or for the packages named in `MODULES`.
- `make triage` passes `--out-dir scans/baseline` so the three result files land at the
  top of the folder, not inside `reports/`.
- Matches by vulnerability ID. A Grype match with a non-CVE ID is mapped to its related
  CVE when there is one.
- It ranks only what the scanners report. nginx's own CVEs are not in the list.
- The same script is also saved as the owner's `compare-vuln-scans` skill. Keep the two
  in step when changing the ranking.

## probe-impact.sh

- Builds three throwaway variants of `IMAGE`: packages removed, Debian packages
  updated, and both. Scans those and the original with Trivy and Grype, merges each
  pair with `compare-scans.py`, and prints one comparison table.
- Always deletes the variant images and all scan output on exit, including on failure.
  `KEEP=1` is the only way to keep them.
- The "updated" variants need network access during `docker build`. On a network with
  a TLS-intercepting proxy, pass `PROBE_PRELUDE` (extra Dockerfile lines, for example to
  trust the proxy CA) and `PROBE_BUILD_FLAGS`. In the Claude cloud workspace also pass
  `TRIVY_FLAGS="--db-repository mirror.gcr.io/aquasec/trivy-db:2"`.
- It upgrades the original image in place, so nginx itself stays at the original
  version. It estimates the effect of the fresh base; it is not the final image.

## Conventions

- Shell scripts: `set -euo pipefail`, `cd` to the repo root, fail with a clear message.
- No workspace-specific settings (proxies, CA bundles) in committed scripts.
