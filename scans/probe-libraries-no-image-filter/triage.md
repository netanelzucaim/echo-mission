# Trivy vs Grype: vulnerabilities ranked by danger and reach

Inputs: `trivy.json`, `grype.json`. Full list: `triage.csv`.

| | Count |
|---|---|
| Unique vulnerabilities (either scanner) | 161 |
| Reported by both | 143 |
| Trivy only | 5 |
| Grype only | 13 |
| Both report, different severity | 79 |
| Critical in both | 1 |
| Known exploited (KEV) | 0 |
| In a library the main program loads | 33 |
| ...of those, with a fix available | 0 |

Libraries the main program loads: `libc6`, `libcrypt1`, `libpcre2-8-0`, `libssl3`, `nginx`, `zlib1g`.

## Top 40

| # | ID | Score | Loaded | Trivy | Grype | Packages | Fix | KEV | EPSS |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2026-5450 | 30.4 | yes | Medium | Critical | libc-bin, libc6 | no |  | 0.7% |
| 2 | CVE-2026-84782 | 30.2 | yes | High | High | libssl3, openssl | no |  | 0.4% |
| 3 | CVE-2026-85091 | 25.4 | yes | Medium | High | zlib1g | no |  | 0.6% |
| 4 | CVE-2026-5928 | 25.3 | yes | Medium | High | libc-bin, libc6 | no |  | 0.5% |
| 5 | CVE-2026-5435 | 25.2 | yes | Medium | High | libc-bin, libc6 | no |  | 0.4% |
| 6 | CVE-2026-19499 | 25.2 | yes | Medium | High | libc-bin, libc6 | no |  | 0.3% |
| 7 | CVE-2026-6238 | 20.3 | yes | Medium | Medium | libc-bin, libc6 | no |  | 0.4% |
| 8 | CVE-2026-80489 | 20.2 | yes | Medium | Medium | libc-bin, libc6 | no |  | 0.4% |
| 9 | CVE-2026-77117 | 20.2 | yes | Medium | Medium | libc-bin, libc6 | no |  | 0.4% |
| 10 | CVE-2026-75806 | 20.2 | yes | Medium | Medium | libssl3, openssl | no |  | 0.4% |
| 11 | CVE-2026-8674 | 20.2 | yes | Medium | Medium | libc-bin, libc6 | no |  | 0.3% |
| 12 | CVE-2026-6791 | 20.2 | yes | Medium | Medium | libc-bin, libc6 | no |  | 0.3% |
| 13 | CVE-2026-89092 | 20.2 | yes | Medium | Medium | libc-bin, libc6 | no |  | 0.3% |
| 14 | CVE-2026-19542 | 20.1 | yes | Medium | Medium | libc-bin, libc6 | no |  | 0.2% |
| 15 | CVE-2026-75805 | 20.1 | yes | Medium | Medium | libssl3, openssl | no |  | 0.2% |
| 16 | CVE-2026-27171 | 20.1 | yes | Medium | Medium | zlib1g | no |  | 0.2% |
| 17 | CVE-2026-18374 | 20.1 | yes | Medium | Medium | libc-bin, libc6 | no |  | 0.1% |
| 18 | CVE-2026-86805 | 20.1 | yes | Medium | Medium | libc-bin, libc6 | no |  | 0.1% |
| 19 | CVE-2023-45853 | 20.0 | yes | Critical | - | zlib1g | no |  | 0.0% |
| 20 | CVE-2011-3389 | 19.6 | no | Low | Negligible/Unknown | libgnutls30 | no |  | 73.3% |
| 21 | CVE-2026-76642 | 16.6 | no | High | High | bsdutils, libblkid1, libmount1, libsmartcols1 (+4) | no |  | 0.2% |
| 22 | CVE-2026-78408 | 16.6 | no | High | High | bsdutils, libblkid1, libmount1, libsmartcols1 (+4) | no |  | 0.2% |
| 23 | CVE-2026-78410 | 16.6 | no | High | High | bsdutils, libblkid1, libmount1, libsmartcols1 (+4) | no |  | 0.2% |
| 24 | CVE-2026-78409 | 16.6 | no | High | High | bsdutils, libblkid1, libmount1, libsmartcols1 (+4) | no |  | 0.2% |
| 25 | CVE-2026-6653 | 16.1 | no | Critical | Critical | libxml2 | no |  | 0.4% |
| 26 | CVE-2026-8927 | 15.9 | no | High | Critical | curl, libcurl4 | no |  | 0.5% |
| 27 | CVE-2026-35189 | 15.2 | yes | Low | Medium | libssl3, openssl | no |  | 0.3% |
| 28 | CVE-2026-54872 | 15.2 | yes | Medium | Low | libssl3, openssl | no |  | 0.3% |
| 29 | CVE-2026-77696 | 15.1 | yes | Medium | Low | libssl3, openssl | no |  | 0.2% |
| 30 | CVE-2025-69720 | 15.1 | no | High | High | libtinfo6, ncurses-base, ncurses-bin | no |  | 0.4% |
| 31 | CVE-2026-6368 | 15.1 | yes | Medium | Low | libc-bin, libc6 | no |  | 0.1% |
| 32 | CVE-2026-95818 | 15.1 | yes | Medium | Low | libc-bin, libc6 | no |  | 0.1% |
| 33 | CVE-2026-19931 | 13.7 | no | Medium | Critical | curl, libcurl4 | no |  | 0.7% |
| 34 | CVE-2026-11856 | 13.7 | no | Medium | Critical | curl, libcurl4 | no |  | 0.7% |
| 35 | CVE-2026-8924 | 13.7 | no | Medium | Critical | curl, libcurl4 | no |  | 0.7% |
| 36 | CVE-2026-10536 | 13.7 | no | Medium | Critical | curl, libcurl4 | no |  | 0.6% |
| 37 | CVE-2026-12064 | 13.6 | no | High | High | curl, libcurl4 | no |  | 0.4% |
| 38 | CVE-2026-6276 | 13.6 | no | High | High | curl, libcurl4 | no |  | 0.3% |
| 39 | CVE-2026-8286 | 13.6 | no | High | High | curl, libcurl4 | no |  | 0.3% |
| 40 | CVE-2026-95619 | 12.6 | no | Medium | High | gcc-12-base, libgcc-s1, libstdc++6 | no |  | 0.4% |

Score = 100 x danger x reach. Danger = 0.6 x exploitation (1 if known exploited, else EPSS) + 0.4 x severity (average of both scanners). Reach = 1.0 if the main program loads the affected library, 0.4 if the package only sits in the image, plus a small bonus per extra affected package.

Limits: "loaded" means the library is loaded, not that the vulnerable function is called. That still needs reading the advisory. Vulnerabilities the scanners do not report at all are not in this list.
