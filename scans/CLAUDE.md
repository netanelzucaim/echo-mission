# scans/: triage, the chosen targets, VEX

Folder layout and how each file is made: `scans/README.md`. Everything here is generated
by a `make` target and never edited by hand, except `baseline/review.tsv` (reach
verdicts, written with the `triage-cves` skill). The decision built on it is
`docs/triage-decision.md` (the `choose-cve-fix` skill). Script details:
`scripts/CLAUDE.md`.

## The two targets (decided 2026-10-05)

Chosen by judgment: reach first, then known-exploited (KEV), then EPSS against both
scanners' severities. The danger-and-reach score only sorts the candidates.

- **Version bump: CVE-2024-6119** (OpenSSL X.509 name-check DoS). EPSS 66.6%, High in
  both scanners, reached when nginx verifies an upstream server's certificate. Rejected
  alternatives: CVE-2025-15467 (CMS parsing, never called by nginx) and CVE-2024-37371
  (Kerberos, only `curl` uses it).
- **Backport: CVE-2026-42945** (rewrite-module heap overflow, potential code execution),
  reached through `rewrite`/`set`/`return` with captures, code almost every config runs.
  Not taken, available as a second backport: CVE-2024-7347 (mp4) and CVE-2026-9256 (the
  sibling rewrite overflow, commits `ca4f92a2` + `475732a3`).
- **CVE-2023-44487** (HTTP/2 Rapid Reset, KEV) tops the ranking, but upstream commit
  6ceef19 in 1.25.3 already mitigates it. Never present it as open or as fixed by this
  project.

## Findings

- **The scanners miss nginx's own CVEs.** nginx comes from nginx.org, but Trivy and Grype
  compare it with Debian's data (1.22.1 with backports), so `1.25.5 > 1.22.1-9+deb12u2`
  looks fixed. nginx CVEs come from https://nginx.org/en/security_advisories.html and are
  added to `review.tsv` by hand (24 for nginx). Explained in `docs/scanner-blind-spot.md`.
- **For any package the distribution did not build, take CVEs from its upstream
  project.** `baseline/image/foreign-packages.tsv` lists them (nginx and its four
  modules). njs is its own source: CVE-2026-78689 applies (`config`), CVE-2026-18329 is
  `n/a` for 0.8.4. Both are in `review.tsv`.
- **Loaded vs installed.** nginx's binary loads `libc6`, `libcrypt1`, `libpcre2-8-0`,
  `libssl3` and `zlib1g` (`baseline/image/linked-packages.txt`); everything else is only
  installed. Module libraries are listed per module in `baseline/image/modules.tsv`.
- **Counting.** Compare scanner-reported CVEs only (497 → 253). The 26 advisory CVEs are
  never in a scan, so they would wrongly look "gone"; `diff-scans.py` lists them
  separately and counts one fixed only when a VEX says `status: fixed`.

## VEX

- Files go in `vex/` as `<CVE>.openvex.json`, written by `scripts/make-vex.py` against
  `scans/patched` (the package version must be the patched image's).
- `CVE-2026-42945.openvex.json` (`status: fixed`) is the backport's record. It changes
  nothing in the scan, because the scanners never report that CVE.
- `CVE-2023-52355.openvex.json` (`not_affected`, libtiff6) is the demonstration that VEX
  works: reported by both scanners, no Debian fix, and genuinely unreachable
  (image-filter never asks libgd for TIFF). It disappears from both scanners. Rule for
  choosing such a CVE: `.claude/skills/rescan-compare-vex/SKILL.md`.
- Never use VEX to hide a CVE that is not fixed or not truly unaffected.
