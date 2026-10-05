# Trivy vs Grype: vulnerabilities ranked by danger and reach

Inputs: `trivy.json`, `grype.json`. Full list: `triage.csv`.

| | Count |
|---|---|
| Unique vulnerabilities (either scanner) | 497 |
| Reported by both | 468 |
| Trivy only | 26 |
| Grype only | 3 |
| Both report, different severity | 193 |
| Critical in both | 15 |
| Known exploited (KEV) | 2 |
| In a library the main program loads | 91 |
| ...of those, with a fix available | 58 |

Libraries the main program loads: `libc6`, `libcrypt1`, `libpcre2-8-0`, `libssl3`, `zlib1g`.

## Top 40

| # | ID | Score | Loaded | Trivy | Grype | Packages | Fix | KEV | EPSS |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2024-6119 | 69.9 | yes | High | High | libssl3, openssl | yes |  | 66.6% |
| 2 | CVE-2025-15467 | 66.5 | yes | High | Critical | libssl3, openssl | yes |  | 52.4% |
| 3 | CVE-2024-2511 | 46.5 | yes | Low | Medium | libssl3, openssl | yes |  | 52.4% |
| 4 | CVE-2023-50387 | 40.5 | no | High | High | libsystemd0, libudev1 | yes |  | 100.0% |
| 5 | CVE-2026-31789 | 40.2 | yes | Critical | Critical | libssl3, openssl | yes |  | 0.3% |
| 6 | CVE-2025-27363 | 36.0 | no | High | High | libfreetype6 | yes | yes | 27.8% |
| 7 | CVE-2023-50868 | 33.4 | no | High | High | libsystemd0, libudev1 | yes |  | 73.7% |
| 8 | CVE-2026-45447 | 32.4 | yes | High | High | libssl3, openssl | yes |  | 4.0% |
| 9 | CVE-2026-28388 | 31.5 | yes | High | High | libssl3, openssl | yes |  | 2.5% |
| 10 | CVE-2026-28389 | 31.5 | yes | High | High | libssl3, openssl | yes |  | 2.4% |
| 11 | CVE-2026-34182 | 30.6 | yes | Medium | Critical | libssl3, openssl | yes |  | 1.1% |
| 12 | CVE-2025-69421 | 30.6 | yes | High | High | libssl3, openssl | yes |  | 1.0% |
| 13 | CVE-2026-28387 | 30.6 | yes | High | High | libssl3, openssl | yes |  | 0.9% |
| 14 | CVE-2026-28390 | 30.5 | yes | High | High | libssl3, openssl | yes |  | 0.8% |
| 15 | CVE-2026-5450 | 30.4 | yes | Medium | Critical | libc-bin, libc6 | no |  | 0.7% |
| 16 | CVE-2026-86145 | 30.2 | yes | High | High | libpcre2-8-0 | yes |  | 0.4% |
| 17 | CVE-2026-84782 | 30.2 | yes | High | High | libssl3, openssl | no |  | 0.4% |
| 18 | CVE-2026-89157 | 30.2 | yes | High | High | libpcre2-8-0 | yes |  | 0.3% |
| 19 | CVE-2026-103111 | 30.1 | yes | High | High | libpcre2-8-0 | yes |  | 0.2% |
| 20 | CVE-2026-89161 | 30.1 | yes | High | High | libpcre2-8-0 | yes |  | 0.1% |
| 21 | CVE-2023-44487 | 30.0 | no | - | High | nginx | no | yes | 100.0% |
| 22 | CVE-2024-28182 | 28.4 | no | Medium | Medium | libnghttp2-14 | yes |  | 85.0% |
| 23 | CVE-2024-5535 | 28.3 | yes | Low | Critical | libssl3, openssl | yes |  | 5.6% |
| 24 | CVE-2026-63076 | 26.0 | yes | Medium | High | libssl3, openssl | yes |  | 1.6% |
| 25 | CVE-2025-9230 | 25.9 | yes | Medium | High | libssl3, openssl | yes |  | 1.6% |
| 26 | CVE-2026-31790 | 25.6 | yes | Medium | High | libssl3, openssl | yes |  | 1.0% |
| 27 | CVE-2026-63072 | 25.5 | yes | Medium | High | libssl3, openssl | yes |  | 0.9% |
| 28 | CVE-2026-45445 | 25.4 | yes | Medium | High | libssl3, openssl | yes |  | 0.7% |
| 29 | CVE-2026-4046 | 25.4 | yes | Medium | High | libc-bin, libc6 | yes |  | 0.7% |
| 30 | CVE-2026-0915 | 25.4 | yes | Medium | High | libc-bin, libc6 | yes |  | 0.6% |
| 31 | CVE-2025-69419 | 25.4 | yes | Medium | High | libssl3, openssl | yes |  | 0.6% |
| 32 | CVE-2025-4802 | 25.4 | yes | Medium | High | libc-bin, libc6 | yes |  | 0.6% |
| 33 | CVE-2026-5928 | 25.3 | yes | Medium | High | libc-bin, libc6 | no |  | 0.5% |
| 34 | CVE-2026-5435 | 25.2 | yes | Medium | High | libc-bin, libc6 | no |  | 0.4% |
| 35 | CVE-2026-4437 | 25.2 | yes | Medium | High | libc-bin, libc6 | yes |  | 0.3% |
| 36 | CVE-2026-19499 | 25.2 | yes | Medium | High | libc-bin, libc6 | no |  | 0.3% |
| 37 | CVE-2026-75803 | 25.1 | yes | Low | Critical | libssl3, openssl | yes |  | 0.2% |
| 38 | CVE-2023-5678 | 22.7 | yes | Medium | Medium | libssl3, openssl | yes |  | 4.5% |
| 39 | CVE-2024-37371 | 22.6 | no | Critical | Critical | libgssapi-krb5-2, libk5crypto3, libkrb5-3, libkrb5support0 | yes |  | 1.9% |
| 40 | CVE-2024-0727 | 21.9 | yes | Medium | Medium | libssl3, openssl | yes |  | 3.2% |

Score = 100 x danger x reach. Danger = 0.6 x exploitation (1 if known exploited, else EPSS) + 0.4 x severity (average of both scanners). Reach = 1.0 if the main program loads the affected library, 0.4 if the package only sits in the image, plus a small bonus per extra affected package.

Limits: "loaded" means the library is loaded, not that the vulnerable function is called. That still needs reading the advisory. Vulnerabilities the scanners do not report at all are not in this list.
