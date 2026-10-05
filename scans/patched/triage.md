# Vulnerabilities ranked by danger and reach

Inputs: `trivy.json`, `grype.json`. Full list: `triage.csv`; every score explained: `triage-details.md`.

| | Count |
|---|---|
| Unique vulnerabilities | 253 |
| Reported by both scanners | 220 |
| Trivy only | 17 |
| Grype only | 16 |
| Added from the review, missed by both scanners | 0 |
| Critical in both | 2 |
| Known exploited (KEV) | 1 |
| In a library the main program loads | 36 |
| ...of those, with a fix available | 0 |
| Reach checked by a person | 0 (0 one by one, 0 through a package-level verdict) |

Reach verdicts: not reviewed 253.

Libraries the main program loads: `libc6`, `libcrypt1`, `libpcre2-8-0`, `libssl3`, `nginx`, `zlib1g`.

## Packages that are not from the distribution

**Not checked.** The scan could not compare the installed packages with the distribution's repositories (no network). Until it can, assume the main program may be one of them and take its CVEs from the upstream project's advisories.

## Top 40

| # | ID | Score | Danger | Reach | Verdict | Packages | Fix | KEV | EPSS |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2023-44487 | 45.0 | 0.75 | 0.60 | not reviewed | nginx | no | yes | 100.0% |
| 2 | CVE-2026-5450 | 18.3 | 0.30 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.7% |
| 3 | CVE-2026-84782 | 18.1 | 0.30 | 0.60 | not reviewed | libssl3, openssl | no |  | 0.4% |
| 4 | CVE-2026-85091 | 15.2 | 0.25 | 0.60 | not reviewed | zlib1g | no |  | 0.6% |
| 5 | CVE-2026-5928 | 15.2 | 0.25 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.5% |
| 6 | CVE-2026-5435 | 15.1 | 0.25 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.4% |
| 7 | CVE-2026-19499 | 15.1 | 0.25 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.3% |
| 8 | CVE-2023-6879 | 12.2 | 0.41 | 0.30 | not reviewed | libaom3 | no |  | 1.2% |
| 9 | CVE-2026-6238 | 12.2 | 0.20 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.4% |
| 10 | CVE-2026-80489 | 12.1 | 0.20 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.4% |
| 11 | CVE-2026-77117 | 12.1 | 0.20 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.4% |
| 12 | CVE-2026-75806 | 12.1 | 0.20 | 0.60 | not reviewed | libssl3, openssl | no |  | 0.4% |
| 13 | CVE-2026-8674 | 12.1 | 0.20 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.3% |
| 14 | CVE-2026-6791 | 12.1 | 0.20 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.3% |
| 15 | CVE-2026-89092 | 12.1 | 0.20 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.3% |
| 16 | CVE-2026-19542 | 12.1 | 0.20 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.2% |
| 17 | CVE-2026-75805 | 12.1 | 0.20 | 0.60 | not reviewed | libssl3, openssl | no |  | 0.2% |
| 18 | CVE-2026-27171 | 12.1 | 0.20 | 0.60 | not reviewed | zlib1g | no |  | 0.2% |
| 19 | CVE-2026-6653 | 12.1 | 0.40 | 0.30 | not reviewed | libxml2 | no |  | 0.4% |
| 20 | CVE-2026-18374 | 12.1 | 0.20 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.1% |
| 21 | CVE-2026-86805 | 12.0 | 0.20 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.1% |
| 22 | CVE-2023-45853 | 12.0 | 0.20 | 0.60 | not reviewed | zlib1g | no |  | 0.0% |
| 23 | CVE-2009-4487 | 10.6 | 0.18 | 0.60 | not reviewed | nginx | no |  | 29.5% |
| 24 | CVE-2026-52490 | 10.6 | 0.35 | 0.30 | not reviewed | libtiff6 | no |  | 0.5% |
| 25 | CVE-2011-3389 | 9.8 | 0.49 | 0.20 | not reviewed | libgnutls30 | no |  | 73.3% |
| 26 | CVE-2023-52355 | 9.3 | 0.31 | 0.30 | not reviewed | libtiff6 | no |  | 1.8% |
| 27 | CVE-2026-32740 | 9.1 | 0.30 | 0.30 | not reviewed | libheif1 | no |  | 0.8% |
| 28 | CVE-2023-39616 | 9.1 | 0.30 | 0.30 | not reviewed | libaom3 | no |  | 0.7% |
| 29 | CVE-2026-32882 | 9.1 | 0.30 | 0.30 | not reviewed | libheif1 | no |  | 0.7% |
| 30 | CVE-2026-35189 | 9.1 | 0.15 | 0.60 | not reviewed | libssl3, openssl | no |  | 0.3% |
| 31 | CVE-2026-54872 | 9.1 | 0.15 | 0.60 | not reviewed | libssl3, openssl | no |  | 0.3% |
| 32 | CVE-2026-77696 | 9.1 | 0.15 | 0.60 | not reviewed | libssl3, openssl | no |  | 0.2% |
| 33 | CVE-2026-32741 | 9.1 | 0.30 | 0.30 | not reviewed | libheif1 | no |  | 0.4% |
| 34 | CVE-2026-41071 | 9.1 | 0.30 | 0.30 | not reviewed | libheif1 | no |  | 0.4% |
| 35 | CVE-2026-74860 | 9.1 | 0.30 | 0.30 | not reviewed | libxml2 | no |  | 0.4% |
| 36 | CVE-2026-12912 | 9.1 | 0.30 | 0.30 | not reviewed | libtiff6 | no |  | 0.4% |
| 37 | CVE-2025-68431 | 9.1 | 0.30 | 0.30 | not reviewed | libheif1 | no |  | 0.4% |
| 38 | CVE-2026-6368 | 9.1 | 0.15 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.1% |
| 39 | CVE-2026-95818 | 9.0 | 0.15 | 0.60 | not reviewed | libc-bin, libc6 | no |  | 0.1% |
| 40 | CVE-2026-88806 | 9.0 | 0.30 | 0.30 | not reviewed | libx11-6, libx11-data | no |  | 0.2% |

## Why each is ranked where it is

**CVE-2023-44487**: #1, score 45.0 = 100 x danger 0.750 x reach 0.60. Danger: on CISA's known-exploited list, so exploitation counts as 1.0 (x 0.6 = 0.600); severity Trivy -, Grype High (a missing scanner counts as 0) (x 0.4 = 0.150). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `nginx`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-5450**: #2, score 18.3 = 100 x danger 0.304 x reach 0.60. Danger: EPSS 0.7% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.004); severity Trivy Medium, Grype Critical (x 0.4 = 0.300). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-84782**: #3, score 18.1 = 100 x danger 0.302 x reach 0.60. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libssl3`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-85091**: #4, score 15.2 = 100 x danger 0.254 x reach 0.60. Danger: EPSS 0.6% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.004); severity Trivy Medium, Grype High (x 0.4 = 0.250). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `zlib1g`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-5928**: #5, score 15.2 = 100 x danger 0.253 x reach 0.60. Danger: EPSS 0.5% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.003); severity Trivy Medium, Grype High (x 0.4 = 0.250). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-5435**: #6, score 15.1 = 100 x danger 0.252 x reach 0.60. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype High (x 0.4 = 0.250). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-19499**: #7, score 15.1 = 100 x danger 0.252 x reach 0.60. Danger: EPSS 0.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype High (x 0.4 = 0.250). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2023-6879**: #8, score 12.2 = 100 x danger 0.407 x reach 0.30. Danger: EPSS 1.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.007); severity Trivy Critical, Grype Critical (x 0.4 = 0.400). Reach 0.30 (not reviewed, default for where the package sits): `libaom3` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

**CVE-2026-6238**: #9, score 12.2 = 100 x danger 0.203 x reach 0.60. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.003); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-80489**: #10, score 12.1 = 100 x danger 0.202 x reach 0.60. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-77117**: #11, score 12.1 = 100 x danger 0.202 x reach 0.60. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-75806**: #12, score 12.1 = 100 x danger 0.202 x reach 0.60. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libssl3`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-8674**: #13, score 12.1 = 100 x danger 0.202 x reach 0.60. Danger: EPSS 0.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-6791**: #14, score 12.1 = 100 x danger 0.202 x reach 0.60. Danger: EPSS 0.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-89092**: #15, score 12.1 = 100 x danger 0.202 x reach 0.60. Danger: EPSS 0.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-19542**: #16, score 12.1 = 100 x danger 0.201 x reach 0.60. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-75805**: #17, score 12.1 = 100 x danger 0.201 x reach 0.60. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libssl3`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-27171**: #18, score 12.1 = 100 x danger 0.201 x reach 0.60. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `zlib1g`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-6653**: #19, score 12.1 = 100 x danger 0.402 x reach 0.30. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Critical, Grype Critical (x 0.4 = 0.400). Reach 0.30 (not reviewed, default for where the package sits): `libxml2` is installed only for `nginx-module-njs`, `nginx-module-xslt`, which no default config loads. Fix: no fixed package version yet.

**CVE-2026-18374**: #20, score 12.1 = 100 x danger 0.201 x reach 0.60. Danger: EPSS 0.1% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-86805**: #21, score 12.0 = 100 x danger 0.201 x reach 0.60. Danger: EPSS 0.1% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2023-45853**: #22, score 12.0 = 100 x danger 0.200 x reach 0.60. Danger: EPSS 0.0% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.000); severity Trivy Critical, Grype - (a missing scanner counts as 0) (x 0.4 = 0.200). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `zlib1g`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2009-4487**: #23, score 10.6 = 100 x danger 0.177 x reach 0.60. Danger: EPSS 29.5% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.177); severity Trivy -, Grype Negligible/Unknown (a missing scanner counts as 0) (x 0.4 = 0.000). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `nginx`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-52490**: #24, score 10.6 = 100 x danger 0.353 x reach 0.30. Danger: EPSS 0.5% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.003); severity Trivy High, Grype Critical (x 0.4 = 0.350). Reach 0.30 (not reviewed, default for where the package sits): `libtiff6` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

**CVE-2011-3389**: #25, score 9.8 = 100 x danger 0.490 x reach 0.20. Danger: EPSS 73.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.440); severity Trivy Low, Grype Negligible/Unknown (x 0.4 = 0.050). Reach 0.20 (not reviewed, default for where the package sits): `libgnutls30` is used by other programs in the image, not by nginx. Fix: no fixed package version yet.

**CVE-2023-52355**: #26, score 9.3 = 100 x danger 0.311 x reach 0.30. Danger: EPSS 1.8% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.011); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.30 (not reviewed, default for where the package sits): `libtiff6` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

**CVE-2026-32740**: #27, score 9.1 = 100 x danger 0.305 x reach 0.30. Danger: EPSS 0.8% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.005); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.30 (not reviewed, default for where the package sits): `libheif1` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

**CVE-2023-39616**: #28, score 9.1 = 100 x danger 0.304 x reach 0.30. Danger: EPSS 0.7% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.004); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.30 (not reviewed, default for where the package sits): `libaom3` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

**CVE-2026-32882**: #29, score 9.1 = 100 x danger 0.304 x reach 0.30. Danger: EPSS 0.7% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.004); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.30 (not reviewed, default for where the package sits): `libheif1` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

**CVE-2026-35189**: #30, score 9.1 = 100 x danger 0.152 x reach 0.60. Danger: EPSS 0.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Low, Grype Medium (x 0.4 = 0.150). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libssl3`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-54872**: #31, score 9.1 = 100 x danger 0.152 x reach 0.60. Danger: EPSS 0.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype Low (x 0.4 = 0.150). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libssl3`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-77696**: #32, score 9.1 = 100 x danger 0.151 x reach 0.60. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Low (x 0.4 = 0.150). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libssl3`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-32741**: #33, score 9.1 = 100 x danger 0.303 x reach 0.30. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.003); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.30 (not reviewed, default for where the package sits): `libheif1` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

**CVE-2026-41071**: #34, score 9.1 = 100 x danger 0.303 x reach 0.30. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.003); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.30 (not reviewed, default for where the package sits): `libheif1` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

**CVE-2026-74860**: #35, score 9.1 = 100 x danger 0.303 x reach 0.30. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.003); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.30 (not reviewed, default for where the package sits): `libxml2` is installed only for `nginx-module-njs`, `nginx-module-xslt`, which no default config loads. Fix: no fixed package version yet.

**CVE-2026-12912**: #36, score 9.1 = 100 x danger 0.303 x reach 0.30. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.003); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.30 (not reviewed, default for where the package sits): `libtiff6` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

**CVE-2025-68431**: #37, score 9.1 = 100 x danger 0.303 x reach 0.30. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.003); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.30 (not reviewed, default for where the package sits): `libheif1` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

**CVE-2026-6368**: #38, score 9.1 = 100 x danger 0.151 x reach 0.60. Danger: EPSS 0.1% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Low (x 0.4 = 0.150). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-95818**: #39, score 9.0 = 100 x danger 0.151 x reach 0.60. Danger: EPSS 0.1% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Low (x 0.4 = 0.150). Reach 0.60 (not reviewed, default for where the package sits): nginx loads `libc6`, but whether it calls the vulnerable code was not checked. Fix: no fixed package version yet.

**CVE-2026-88806**: #40, score 9.0 = 100 x danger 0.301 x reach 0.30. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.30 (not reviewed, default for where the package sits): `libx11-6`, `libx11-data` is installed only for `nginx-module-image-filter`, which no default config loads. Fix: no fixed package version yet.

Score = 100 x danger x reach. Danger = 0.6 x exploitation (1 if known exploited, else EPSS) + 0.4 x severity. Reach comes from a person's review of whether this image runs the vulnerable code (always 1.0, common 0.8, config 0.5, manual 0.2, unused 0.05, n/a 0); without a review it is 0.6 for a library nginx loads, 0.3 for a module-only package and 0.2 for anything else. The weights are judgment calls, not measurements. Vulnerabilities that neither the scanners nor the review list are not here.
