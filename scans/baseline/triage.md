# Trivy vs Grype: vulnerabilities ranked by urgency

Inputs: `trivy.json`, `grype.json`. Full list: `triage.csv`.

| | Count |
|---|---|
| Unique vulnerabilities (either scanner) | 497 |
| Reported by both | 468 |
| Trivy only | 26 |
| Grype only | 3 |
| Both report, same severity | 275 |
| Both report, different severity | 193 |
| **Critical in both** | **15** |
| Critical in both, fix available | 10 |

## Top 40

| # | ID | Trivy | Grype | Packages | Fix | KEV | EPSS |
|---|---|---|---|---|---|---|---|
| 1 | CVE-2024-37371 | Critical | Critical | libgssapi-krb5-2, libk5crypto3, libkrb5-3, libkrb5support0 | yes |  | 1.9% |
| 2 | CVE-2024-45492 | Critical | Critical | libexpat1 | yes |  | 1.4% |
| 3 | CVE-2024-5171 | Critical | Critical | libaom3 | yes |  | 1.3% |
| 4 | CVE-2024-56171 | Critical | Critical | libxml2 | yes |  | 1.2% |
| 5 | CVE-2024-45491 | Critical | Critical | libexpat1 | yes |  | 1.1% |
| 6 | CVE-2026-42010 | Critical | Critical | libgnutls30 | yes |  | 0.9% |
| 7 | CVE-2026-33845 | Critical | Critical | libgnutls30 | yes |  | 0.9% |
| 8 | CVE-2025-0838 | Critical | Critical | libabsl20220623 | yes |  | 0.6% |
| 9 | CVE-2025-48174 | Critical | Critical | libavif15 | yes |  | 0.4% |
| 10 | CVE-2026-31789 | Critical | Critical | libssl3, openssl | yes |  | 0.3% |
| 11 | CVE-2023-6879 | Critical | Critical | libaom3 | no |  | 1.2% |
| 12 | CVE-2026-8376 | Critical | Critical | perl-base | no |  | 0.5% |
| 13 | CVE-2026-13221 | Critical | Critical | perl-base | no |  | 0.4% |
| 14 | CVE-2026-42496 | Critical | Critical | perl-base | no |  | 0.4% |
| 15 | CVE-2026-6653 | Critical | Critical | libxml2 | no |  | 0.4% |
| 16 | CVE-2025-15467 | High | Critical | libssl3, openssl | yes |  | 52.4% |
| 17 | CVE-2025-49796 | High | Critical | libxml2 | yes |  | 1.6% |
| 18 | CVE-2025-49794 | High | Critical | libxml2 | yes |  | 0.8% |
| 19 | CVE-2026-7598 | High | Critical | libssh2-1 | yes |  | 0.8% |
| 20 | CVE-2026-52490 | High | Critical | libtiff6 | no |  | 0.5% |
| 21 | CVE-2026-8927 | High | Critical | curl, libcurl4 | no |  | 0.5% |
| 22 | CVE-2026-57433 | High | Critical | perl-base | no |  | 0.4% |
| 23 | CVE-2026-34182 | Medium | Critical | libssl3, openssl | yes |  | 1.1% |
| 24 | CVE-2026-19931 | Medium | Critical | curl, libcurl4 | no |  | 0.7% |
| 25 | CVE-2026-5450 | Medium | Critical | libc-bin, libc6 | no |  | 0.7% |
| 26 | CVE-2026-11856 | Medium | Critical | curl, libcurl4 | no |  | 0.7% |
| 27 | CVE-2026-8924 | Medium | Critical | curl, libcurl4 | no |  | 0.7% |
| 28 | CVE-2026-10536 | Medium | Critical | curl, libcurl4 | no |  | 0.6% |
| 29 | CVE-2026-12087 | Medium | Critical | perl-base | no |  | 0.4% |
| 30 | CVE-2024-5535 | Low | Critical | libssl3, openssl | yes |  | 5.6% |
| 31 | CVE-2026-75803 | Low | Critical | libssl3, openssl | yes |  | 0.2% |
| 32 | CVE-2026-18924 | Low | Critical | curl, libcurl4 | no |  | 0.6% |
| 33 | CVE-2023-45853 | Critical | - | zlib1g | no |  | 0.0% |
| 34 | CVE-2025-27363 | High | High | libfreetype6 | yes | yes | 27.8% |
| 35 | CVE-2023-50387 | High | High | libsystemd0, libudev1 | yes |  | 100.0% |
| 36 | CVE-2023-50868 | High | High | libsystemd0, libudev1 | yes |  | 73.7% |
| 37 | CVE-2024-6119 | High | High | libssl3, openssl | yes |  | 66.6% |
| 38 | CVE-2026-45447 | High | High | libssl3, openssl | yes |  | 4.0% |
| 39 | CVE-2026-28388 | High | High | libssl3, openssl | yes |  | 2.5% |
| 40 | CVE-2026-28389 | High | High | libssl3, openssl | yes |  | 2.4% |

Ranking: highest severity from either scanner, then agreement between the two (both report it, lower of the two severities), then known-exploited, fix available, EPSS, CVSS.
