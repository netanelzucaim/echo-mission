# scripts/

Helper scripts. Each one is wired to a `make` target; add a target for any new script.

| Script | Make target | Purpose |
|---|---|---|
| `scan-baseline.sh` | `make scan-baseline` | Pull the original image, save its metadata, scan it with Trivy and Grype into `scans/baseline/` |
| `compare-scans.py` | `make triage` | Merge a Trivy and a Grype JSON report and rank vulnerabilities by danger and reach into `triage.md` and `triage.csv` |

## scan-baseline.sh

- Needs only Docker. Uses `trivy` and `grype` from `PATH` if present, otherwise runs
  them as containers.
- Scans a `docker save` tarball so both tools see the same image bytes, then deletes it.
- Options through the environment: `IMAGE`, `OUT`, `PLATFORM` (for example
  `linux/amd64`).
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
  - Reach = 1.0 if the affected package is a library the nginx binary loads, 0.4 if it
    only sits in the image, plus 0.05 per extra affected package (max +0.15).
  - The owner chose this over "Critical in both first" on 2026-10-05, because the
    top-severity findings were mostly in libraries nginx never runs.
- Reach comes from `linked-packages.txt` next to the Trivy report (written by
  `scan-baseline.sh` from `ldd /usr/sbin/nginx`), or from `--linked FILE`. Without it
  the script warns and treats every package as "only sits in the image".
- "Loaded" means the library is loaded, not that the vulnerable function is called.
  Read the advisory before claiming nginx is affected.
- Matches by vulnerability ID. A Grype match with a non-CVE ID is mapped to its related
  CVE when there is one.
- It ranks only what the scanners report. nginx's own CVEs are not in the list.
- The same script is also saved as the owner's `compare-vuln-scans` skill. Keep the two
  in step when changing the ranking.

## Conventions

- Shell scripts: `set -euo pipefail`, `cd` to the repo root, fail with a clear message.
- No workspace-specific settings (proxies, CA bundles) in committed scripts.
