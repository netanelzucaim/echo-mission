# scripts/

Helper scripts. Each one is wired to a `make` target; add a target for any new script.

| Script | Make target | Purpose |
|---|---|---|
| `scan-baseline.sh` | `make scan-baseline` | Pull the original image, save its metadata, scan it with Trivy and Grype into `scans/baseline/` |
| `compare-scans.py` | `make triage` | Merge a Trivy and a Grype JSON report and rank vulnerabilities by urgency into `triage.md` and `triage.csv` |

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
- Ranking: highest severity from either scanner, then agreement (reported by both, and
  the lower of the two severities), then known-exploited, fix available, EPSS, CVSS.
  "Critical in both" is always first.
- Matches by vulnerability ID. A Grype match with a non-CVE ID is mapped to its related
  CVE when there is one.
- It ranks only what the scanners report. It does not know whether nginx uses the
  affected library. A planned improvement is a "used by the main program" column that
  ranks linked libraries above the rest.
- The same script is also saved as the owner's `compare-vuln-scans` skill. Keep the two
  in step when changing the ranking.

## Conventions

- Shell scripts: `set -euo pipefail`, `cd` to the repo root, fail with a clear message.
- No workspace-specific settings (proxies, CA bundles) in committed scripts.
