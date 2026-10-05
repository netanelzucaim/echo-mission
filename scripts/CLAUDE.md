# scripts/

Helper scripts. Each one is wired to a `make` target; add a target for any new script.

| Script | Make target | Purpose |
|---|---|---|
| `scan-baseline.sh` | `make scan-baseline` | Pull the original image, save its metadata into `scans/baseline/image/` and scan it with Trivy and Grype into `scans/baseline/reports/` |
| `fix-method.py` | `make fix-plan` | Step 2: propose version bump, backport, remove, accept or none for each CVE; writes `scans/baseline/fix-plan.md` |
| `rescan-compare.sh` | `make rescan IMAGE=<image>` | Step 6: scan the patched image into `scans/patched/`, rank it, rescan with `vex/*.json` applied, compare with the baseline |
| `diff-scans.py` | (called by `make rescan`) | Compare two scan folders and check the VEX result; writes `diff.md` and `diff.csv` |
| `make-vex.py` | (run by hand) | Write an OpenVEX file for one CVE into `vex/` |
| `compare-scans.py` | `make triage` | Merge a Trivy and a Grype JSON report and rank vulnerabilities by danger and reach into `triage.md` and `triage.csv`, and write the statistics diagrams to `stats.md` |

## scan-baseline.sh

- Needs only Docker. Uses `trivy` and `grype` from `PATH` if present, otherwise runs
  them as containers.
- Scans a `docker save` tarball so both tools see the same image bytes, then deletes it.
- Options through the environment: `IMAGE`, `OUT`, `PLATFORM` (for example
  `linux/amd64`), `MODULES` (optional module packages; default every `nginx-module-*`).
- Writes `image/foreign-packages.tsv`: packages the distribution does not have, or only
  has in older versions than the one installed. It runs `apt-get update` inside a
  throwaway container, so it needs network there; `DOCKER_RUN_FLAGS` and `APT_PREP` are
  for networks behind a proxy. Without network the file says "not checked". For the
  original image it lists exactly `nginx` and its four module packages.
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
  - Reach comes from a reviewed verdict in `review.tsv` (always 1.0, common 0.8, config
    0.5, manual 0.2, unused 0.05, n/a 0), per CVE or per package (`pkg:NAME`). Without one:
    0.6 for a library nginx loads, 0.3 for a module-only package, 0.2 otherwise. How to
    review is in `.claude/skills/triage-cves/`. Changed on 2026-10-05 from "loaded 1.0,
    other 0.4", because "loaded" put CMS and 32-bit-only OpenSSL bugs at the top.
  - `review.tsv` can also add CVEs no scanner reports (nginx.org advisories).
  - Every CVE gets an explanation: `triage-details.md` and the `explanation` column.
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
- It ranks what the scanners report plus the CVEs added through `review.tsv`.
- It reads `foreign-packages.tsv` and writes a "Packages that are not from the
  distribution" section into `triage.md`. If such a package has no CVE added from its
  upstream advisories, it prints a WARNING: the scanners' answer for that package is
  not valid, because they compare it with the distribution's version numbers.
- The skill `.claude/skills/compare-vuln-scans/` describes how to use this script. It
  points here and carries no copy of the code.

## fix-method.py

- Answers the triage step's three questions per CVE: where it lives, whether a fix
  exists and in which version, and the fix method.
- Two inputs: the top N scanner findings from `triage.csv` (or CVE IDs given as
  arguments), and nginx's own advisories filtered to the shipped version. The second is
  needed because the scanners do not report nginx's own CVEs.
- The advisories page is downloaded once to `image/nginx-security-advisories.html` and
  reused; `--refresh` fetches it again. Without network and without the saved copy the
  nginx section is empty and the script warns.
- Decision rules are in the script's docstring and in
  `.claude/skills/choose-cve-fix/SKILL.md`. Project policy is "modules are kept", so a
  module-only library without a fix gives ACCEPT; `--remove-modules` gives REMOVE.
- "Where it lives" for nginx advisories comes from the module name in the advisory
  title, checked against the configure flags in `image/nginx-V.txt`.
- It shows each CVE's reviewed reach verdict from `triage.csv` (written by
  `make triage` from `review.tsv`), so run `make triage` before `make fix-plan`.
- It does not read patches. Its output is a proposal.

## rescan-compare.sh, diff-scans.py, make-vex.py

- `rescan-compare.sh` reuses `scan-baseline.sh` with `IMAGE` and `OUT`, so the patched
  scan has the same `reports/` and `image/` layout as the baseline. The name
  `scan-baseline.sh` is historical; it scans any image.
- The VEX scan writes `reports/trivy-vex.*` and `reports/grype-vex.*` next to the plain
  reports. `VEX=""` skips it; by default every `vex/*.json` is applied.
- `diff-scans.py` matches by CVE ID: "no longer reported", "still reported", "new". Its
  VEX table says per scanner `suppressed`, `never reported` or `STILL REPORTED`.
- `make-vex.py` reads package versions from `<scan-dir>/image/packages.tsv` and uses
  the bare package purl as the product. That form was tested to work in both Trivy
  0.75.0 and Grype 0.120.0; the image-plus-subcomponent form did not work in Trivy.
- Tested on 2026-10-05 against a stand-in image (the original with one module
  removed) and throwaway VEX files, covering `suppressed` and `never reported`. Not
  yet run on the real patched image, which does not exist.
- The skill `.claude/skills/rescan-compare-vex/` describes the procedure.

## Conventions

- Shell scripts: `set -euo pipefail`, `cd` to the repo root, fail with a clear message.
- No workspace-specific settings (proxies, CA bundles) in committed scripts.
