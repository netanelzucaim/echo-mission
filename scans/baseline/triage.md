# Vulnerabilities ranked by danger and reach

Inputs: `trivy.json`, `grype.json`, `review.tsv`. Full list: `triage.csv`; every score explained: `triage-details.md`.

| | Count |
|---|---|
| Unique vulnerabilities | 521 |
| Reported by both scanners | 468 |
| Trivy only | 26 |
| Grype only | 3 |
| Added from the review, missed by both scanners | 24 |
| Critical in both | 15 |
| Known exploited (KEV) | 2 |
| In a library the main program loads | 118 |
| ...of those, with a fix available | 58 |
| Reach checked by a person | 333 (137 one by one, 196 through a package-level verdict) |

Reach verdicts: common 1, config 83, manual 4, unused 227, n/a 18, unknown 1, not reviewed 187.

Libraries the main program loads: `libc6`, `libcrypt1`, `libpcre2-8-0`, `libssl3`, `nginx`, `zlib1g`.

## Top 40

| # | ID | Score | Danger | Reach | Verdict | Packages | Fix | KEV | EPSS |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2023-44487 | 60.0 | 0.75 | 0.80 | common | nginx | no | yes | 100.0% |
| 2 | CVE-2024-6119 | 35.0 | 0.70 | 0.50 | config | libssl3, openssl | yes |  | 66.6% |
| 3 | CVE-2024-2511 | 23.2 | 0.46 | 0.50 | config | libssl3, openssl | yes |  | 52.4% |
| 4 | CVE-2026-6653 | 20.1 | 0.40 | 0.50 | config | libxml2 | no |  | 0.4% |
| 5 | CVE-2025-7424 | 15.4 | 0.31 | 0.50 | config | libxslt1.1 | yes |  | 1.2% |
| 6 | CVE-2025-27113 | 15.3 | 0.31 | 0.50 | config | libxml2 | yes |  | 1.1% |
| 7 | CVE-2026-25646 | 15.2 | 0.30 | 0.50 | config | libpng16-16 | yes |  | 0.7% |
| 8 | CVE-2025-64720 | 15.1 | 0.30 | 0.50 | config | libpng16-16 | yes |  | 0.4% |
| 9 | CVE-2025-24928 | 15.1 | 0.30 | 0.50 | config | libxml2 | yes |  | 0.4% |
| 10 | CVE-2025-66293 | 15.1 | 0.30 | 0.50 | config | libpng16-16 | yes |  | 0.4% |
| 11 | CVE-2025-24855 | 15.1 | 0.30 | 0.50 | config | libxslt1.1 | yes |  | 0.4% |
| 12 | CVE-2024-55549 | 15.1 | 0.30 | 0.50 | config | libxslt1.1 | yes |  | 0.4% |
| 13 | CVE-2026-75803 | 15.1 | 0.25 | 0.60 | unknown | libssl3, openssl | yes |  | 0.2% |
| 14 | CVE-2022-49043 | 15.1 | 0.30 | 0.50 | config | libxml2 | yes |  | 0.3% |
| 15 | CVE-2025-65018 | 15.1 | 0.30 | 0.50 | config | libpng16-16 | yes |  | 0.3% |
| 16 | CVE-2026-22695 | 15.1 | 0.30 | 0.50 | config | libpng16-16 | yes |  | 0.2% |
| 17 | CVE-2026-86143 | 15.1 | 0.30 | 0.50 | config | libxml2 | no |  | 0.2% |
| 18 | CVE-2026-86144 | 15.1 | 0.30 | 0.50 | config | libxml2 | no |  | 0.2% |
| 19 | CVE-2026-86139 | 15.0 | 0.30 | 0.50 | config | libxml2 | no |  | 0.2% |
| 20 | CVE-2026-86142 | 15.0 | 0.30 | 0.50 | config | libxml2 | no |  | 0.2% |
| 21 | CVE-2026-86140 | 15.0 | 0.30 | 0.50 | config | libxml2 | no |  | 0.2% |
| 22 | CVE-2026-86138 | 15.0 | 0.30 | 0.50 | config | libxml2 | no |  | 0.1% |
| 23 | CVE-2026-22801 | 15.0 | 0.30 | 0.50 | config | libpng16-16 | yes |  | 0.1% |
| 24 | CVE-2026-42533 | 15.0 | 0.30 | 0.50 | config | nginx | upstream |  | - |
| 25 | CVE-2024-28182 | 14.2 | 0.71 | 0.20 | manual | libnghttp2-14 | yes |  | 85.0% |
| 26 | CVE-2025-6021 | 12.9 | 0.26 | 0.50 | config | libxml2 | yes |  | 1.4% |
| 27 | CVE-2026-33416 | 12.8 | 0.26 | 0.50 | config | libpng16-16 | yes |  | 1.1% |
| 28 | CVE-2025-5222 | 12.6 | 0.25 | 0.50 | config | libicu72 | yes |  | 0.4% |
| 29 | CVE-2026-33636 | 12.6 | 0.25 | 0.50 | config | libpng16-16 | yes |  | 0.4% |
| 30 | CVE-2024-34459 | 10.5 | 0.21 | 0.50 | config | libxml2 | yes |  | 1.8% |
| 31 | CVE-2023-40403 | 10.4 | 0.21 | 0.50 | config | libxslt1.1 | yes |  | 1.3% |
| 32 | CVE-2026-0990 | 10.3 | 0.21 | 0.50 | config | libxml2 | yes |  | 1.0% |
| 33 | CVE-2023-45322 | 10.2 | 0.20 | 0.50 | config | libxml2 | yes |  | 0.8% |
| 34 | CVE-2023-39615 | 10.2 | 0.20 | 0.50 | config | libxml2 | yes |  | 0.8% |
| 35 | CVE-2026-8674 | 10.1 | 0.20 | 0.50 | config | libc-bin, libc6 | no |  | 0.3% |
| 36 | CVE-2026-89156 | 10.1 | 0.20 | 0.50 | config | libpcre2-8-0 | yes |  | 0.3% |
| 37 | CVE-2026-86137 | 10.1 | 0.20 | 0.50 | config | libxml2 | no |  | 0.2% |
| 38 | CVE-2025-64505 | 10.1 | 0.20 | 0.50 | config | libpng16-16 | yes |  | 0.2% |
| 39 | CVE-2025-10911 | 10.1 | 0.20 | 0.50 | config | libxslt1.1 | no |  | 0.2% |
| 40 | CVE-2026-76781 | 10.1 | 0.20 | 0.50 | config | libxml2 | no |  | 0.2% |

## Why each is ranked where it is

**CVE-2023-44487**: #1, score 60.0 = 100 x danger 0.750 x reach 0.80. Danger: on CISA's known-exploited list, so exploitation counts as 1.0 (x 0.6 = 0.600); severity Trivy -, Grype High (a missing scanner counts as 0) (x 0.4 = 0.150). Reach 0.80, reviewed as **common** (runs under a common setup): HTTP/2 Rapid Reset reaches nginx only when HTTP/2 is switched on (the image's default config serves HTTP/1.1 on port 80), but most TLS sites switch it on. nginx 1.25.3 added "improved detection of misbehaving clients when using HTTP/2", upstream's response to this attack; whether that fully closes it was not checked against an advisory. Evidence: CHANGES line 49 (1.25.3). Fix: no fixed package version yet.

**CVE-2024-6119**: #2, score 35.0 = 100 x danger 0.699 x reach 0.50. Danger: EPSS 66.6% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.399); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed as **config** (needs a specific feature switched on): nginx calls X509_check_host() only after verifying an upstream server's certificate, which happens only with proxy_ssl_verify on (or the grpc/uwsgi/stream equivalents); off by default. Evidence: src/event/ngx_event_openssl.c:4886; src/http/ngx_http_upstream.c:1804; src/stream/ngx_stream_proxy_module.c:1140. Fix: a fixed package exists (3.0.14-1~deb12u2).

**CVE-2024-2511**: #3, score 23.2 = 100 x danger 0.465 x reach 0.50. Danger: EPSS 52.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.315); severity Trivy Low, Grype Medium (x 0.4 = 0.150). Reach 0.50, reviewed as **config** (needs a specific feature switched on): Needs the non-default SSL_OP_NO_TICKET option with TLSv1.3. nginx sets it only when ssl_session_tickets is off; the default is on. Evidence: src/http/modules/ngx_http_ssl_module.c:857-861. Fix: a fixed package exists (3.0.14-1~deb12u1).

**CVE-2026-6653**: #4, score 20.1 = 100 x danger 0.402 x reach 0.50. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Critical, Grype Critical (x 0.4 = 0.400). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: no fixed package version yet.

**CVE-2025-7424**: #5, score 15.4 = 100 x danger 0.307 x reach 0.50. Danger: EPSS 1.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.007); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Applies the admin's stylesheet to the response XML when the xslt module is loaded and xslt_stylesheet is set. Evidence: src/http/modules/ngx_http_xslt_filter_module.c (xsltApplyStylesheet). Fix: a fixed package exists (1.1.35-1+deb12u2).

**CVE-2025-27113**: #6, score 15.3 = 100 x danger 0.306 x reach 0.50. Danger: EPSS 1.1% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.006); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: a fixed package exists (2.9.14+dfsg-1.3~deb12u2).

**CVE-2026-25646**: #7, score 15.2 = 100 x danger 0.304 x reach 0.50. Danger: EPSS 0.7% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.004); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): libgd decodes PNG with it when image_filter processes a PNG response. Evidence: src/http/modules/ngx_http_image_filter_module.c (gdImageCreateFromPngPtr). Fix: a fixed package exists (1.6.39-2+deb12u3).

**CVE-2025-64720**: #8, score 15.1 = 100 x danger 0.303 x reach 0.50. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.003); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): libgd decodes PNG with it when image_filter processes a PNG response. Evidence: src/http/modules/ngx_http_image_filter_module.c (gdImageCreateFromPngPtr). Fix: a fixed package exists (1.6.39-2+deb12u1).

**CVE-2025-24928**: #9, score 15.1 = 100 x danger 0.302 x reach 0.50. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: a fixed package exists (2.9.14+dfsg-1.3~deb12u2).

**CVE-2025-66293**: #10, score 15.1 = 100 x danger 0.302 x reach 0.50. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): libgd decodes PNG with it when image_filter processes a PNG response. Evidence: src/http/modules/ngx_http_image_filter_module.c (gdImageCreateFromPngPtr). Fix: a fixed package exists (1.6.39-2+deb12u1).

**CVE-2025-24855**: #11, score 15.1 = 100 x danger 0.302 x reach 0.50. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Applies the admin's stylesheet to the response XML when the xslt module is loaded and xslt_stylesheet is set. Evidence: src/http/modules/ngx_http_xslt_filter_module.c (xsltApplyStylesheet). Fix: a fixed package exists (1.1.35-1+deb12u1).

**CVE-2024-55549**: #12, score 15.1 = 100 x danger 0.302 x reach 0.50. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Applies the admin's stylesheet to the response XML when the xslt module is loaded and xslt_stylesheet is set. Evidence: src/http/modules/ngx_http_xslt_filter_module.c (xsltApplyStylesheet). Fix: a fixed package exists (1.1.35-1+deb12u1).

**CVE-2026-75803**: #13, score 15.1 = 100 x danger 0.251 x reach 0.60. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Low, Grype Critical (x 0.4 = 0.250). Reach 0.60 (checked but not settled, default for where the package sits): nginx loads `libssl3`, but whether it calls the vulnerable code was not checked. Note: EVP_Cipher() on an empty AEAD ciphertext. nginx's own QUIC code uses EVP_CipherUpdate/Final; whether OpenSSL's TLS record layer reaches EVP_Cipher() for ChaCha20-Poly1305 records was not checked. Evidence: src/event/quic/ngx_event_quic_protection.c:495-532. Fix: a fixed package exists (3.0.22-1~deb12u1).

**CVE-2022-49043**: #14, score 15.1 = 100 x danger 0.302 x reach 0.50. Danger: EPSS 0.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: a fixed package exists (2.9.14+dfsg-1.3~deb12u2).

**CVE-2025-65018**: #15, score 15.1 = 100 x danger 0.302 x reach 0.50. Danger: EPSS 0.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): libgd decodes PNG with it when image_filter processes a PNG response. Evidence: src/http/modules/ngx_http_image_filter_module.c (gdImageCreateFromPngPtr). Fix: a fixed package exists (1.6.39-2+deb12u1).

**CVE-2026-22695**: #16, score 15.1 = 100 x danger 0.301 x reach 0.50. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): libgd decodes PNG with it when image_filter processes a PNG response. Evidence: src/http/modules/ngx_http_image_filter_module.c (gdImageCreateFromPngPtr). Fix: a fixed package exists (1.6.39-2+deb12u2).

**CVE-2026-86143**: #17, score 15.1 = 100 x danger 0.301 x reach 0.50. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: no fixed package version yet.

**CVE-2026-86144**: #18, score 15.1 = 100 x danger 0.301 x reach 0.50. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: no fixed package version yet.

**CVE-2026-86139**: #19, score 15.0 = 100 x danger 0.301 x reach 0.50. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: no fixed package version yet.

**CVE-2026-86142**: #20, score 15.0 = 100 x danger 0.301 x reach 0.50. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: no fixed package version yet.

**CVE-2026-86140**: #21, score 15.0 = 100 x danger 0.301 x reach 0.50. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: no fixed package version yet.

**CVE-2026-86138**: #22, score 15.0 = 100 x danger 0.301 x reach 0.50. Danger: EPSS 0.1% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: no fixed package version yet.

**CVE-2026-22801**: #23, score 15.0 = 100 x danger 0.301 x reach 0.50. Danger: EPSS 0.1% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy High, Grype High (x 0.4 = 0.300). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): libgd decodes PNG with it when image_filter processes a PNG response. Evidence: src/http/modules/ngx_http_image_filter_module.c (gdImageCreateFromPngPtr). Fix: a fixed package exists (1.6.39-2+deb12u2).

**CVE-2026-42533**: #24, score 15.0 = 100 x danger 0.300 x reach 0.50. Danger: no EPSS (the scanners do not report it), so exploitation counts as 0 (x 0.6 = 0.000); severity the advisory rates it High (x 0.4 = 0.300). Reach 0.50, reviewed as **config** (needs a specific feature switched on): Buffer overflow when using map with a regular expression. Needs a map block that uses a regex. Evidence: https://nginx.org/en/security_advisories.html. Fix: newer upstream version or a backported patch (not a distro package).

**CVE-2024-28182**: #25, score 14.2 = 100 x danger 0.710 x reach 0.20. Danger: EPSS 85.0% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.510); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.20, reviewed as **manual** (only reached when someone runs a tool by hand): nghttp2 CONTINUATION flood. libnghttp2 is used only by curl; nginx has its own HTTP/2 code. Evidence: image/linked-packages.txt. Fix: a fixed package exists (1.52.0-1+deb12u2).

**CVE-2025-6021**: #26, score 12.9 = 100 x danger 0.258 x reach 0.50. Danger: EPSS 1.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.008); severity Trivy Medium, Grype High (x 0.4 = 0.250). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: a fixed package exists (2.9.14+dfsg-1.3~deb12u3).

**CVE-2026-33416**: #27, score 12.8 = 100 x danger 0.256 x reach 0.50. Danger: EPSS 1.1% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.006); severity Trivy Medium, Grype High (x 0.4 = 0.250). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): libgd decodes PNG with it when image_filter processes a PNG response. Evidence: src/http/modules/ngx_http_image_filter_module.c (gdImageCreateFromPngPtr). Fix: a fixed package exists (1.6.39-2+deb12u4).

**CVE-2025-5222**: #28, score 12.6 = 100 x danger 0.253 x reach 0.50. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.003); severity Trivy Medium, Grype High (x 0.4 = 0.250). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): libxml2 uses it to convert the character encoding an XML document declares, so it is reached the same way as libxml2. Evidence: image/modules.tsv. Fix: a fixed package exists (72.1-3+deb12u1).

**CVE-2026-33636**: #29, score 12.6 = 100 x danger 0.252 x reach 0.50. Danger: EPSS 0.4% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype High (x 0.4 = 0.250). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): libgd decodes PNG with it when image_filter processes a PNG response. Evidence: src/http/modules/ngx_http_image_filter_module.c (gdImageCreateFromPngPtr). Fix: a fixed package exists (1.6.39-2+deb12u4).

**CVE-2024-34459**: #30, score 10.5 = 100 x danger 0.211 x reach 0.50. Danger: EPSS 1.8% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.011); severity Trivy Low, Grype High (x 0.4 = 0.200). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: a fixed package exists (2.9.14+dfsg-1.3~deb12u2).

**CVE-2023-40403**: #31, score 10.4 = 100 x danger 0.208 x reach 0.50. Danger: EPSS 1.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.008); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Applies the admin's stylesheet to the response XML when the xslt module is loaded and xslt_stylesheet is set. Evidence: src/http/modules/ngx_http_xslt_filter_module.c (xsltApplyStylesheet). Fix: a fixed package exists (1.1.35-1+deb12u2).

**CVE-2026-0990**: #32, score 10.3 = 100 x danger 0.206 x reach 0.50. Danger: EPSS 1.0% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.006); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: a fixed package exists (2.9.14+dfsg-1.3~deb12u6).

**CVE-2023-45322**: #33, score 10.2 = 100 x danger 0.205 x reach 0.50. Danger: EPSS 0.8% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.005); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: a fixed package exists (2.9.14+dfsg-1.3~deb12u2).

**CVE-2023-39615**: #34, score 10.2 = 100 x danger 0.205 x reach 0.50. Danger: EPSS 0.8% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.005); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: a fixed package exists (2.9.14+dfsg-1.3~deb12u2).

**CVE-2026-8674**: #35, score 10.1 = 100 x danger 0.202 x reach 0.50. Danger: EPSS 0.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.50, reviewed as **config** (needs a specific feature switched on): resolv.conf with a search domain of about 200 characters makes getaddrinfo() abort. nginx calls getaddrinfo() at startup when the config names a host; resolv.conf is set by whoever runs the container, not by a remote attacker. Evidence: src/core/ngx_inet.c. Fix: no fixed package version yet.

**CVE-2026-89156**: #36, score 10.1 = 100 x danger 0.202 x reach 0.50. Danger: EPSS 0.3% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.002); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.50, reviewed as **config** (needs a specific feature switched on): pcre2_match() reading invalid UTF after a JIT fallback. Needs pcre_jit on and a pattern in UTF mode ((*UTF) in the config); the URI it matches is attacker-controlled. Evidence: src/core/ngx_regex.c:672; no PCRE2_UTF set by nginx. Fix: a fixed package exists (10.42-1+deb12u1).

**CVE-2026-86137**: #37, score 10.1 = 100 x danger 0.201 x reach 0.50. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: no fixed package version yet.

**CVE-2025-64505**: #38, score 10.1 = 100 x danger 0.201 x reach 0.50. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): libgd decodes PNG with it when image_filter processes a PNG response. Evidence: src/http/modules/ngx_http_image_filter_module.c (gdImageCreateFromPngPtr). Fix: a fixed package exists (1.6.39-2+deb12u1).

**CVE-2025-10911**: #39, score 10.1 = 100 x danger 0.201 x reach 0.50. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Applies the admin's stylesheet to the response XML when the xslt module is loaded and xslt_stylesheet is set. Evidence: src/http/modules/ngx_http_xslt_filter_module.c (xsltApplyStylesheet). Fix: no fixed package version yet.

**CVE-2026-76781**: #40, score 10.1 = 100 x danger 0.201 x reach 0.50. Danger: EPSS 0.2% chance of exploitation in the next 30 days (anywhere, not in this image) (x 0.6 = 0.001); severity Trivy Medium, Grype Medium (x 0.4 = 0.200). Reach 0.50, reviewed for the whole package, not this CVE alone as **config** (needs a specific feature switched on): Parsed when the xslt module is loaded and a location uses xslt_stylesheet: the response body is parsed as XML with entity substitution and DTD loading switched on. njs also uses it, but only for scripts that load its xml module. Evidence: src/http/modules/ngx_http_xslt_filter_module.c:384-385. Fix: no fixed package version yet.

Score = 100 x danger x reach. Danger = 0.6 x exploitation (1 if known exploited, else EPSS) + 0.4 x severity. Reach comes from a person's review of whether this image runs the vulnerable code (always 1.0, common 0.8, config 0.5, manual 0.2, unused 0.05, n/a 0); without a review it is 0.6 for a library nginx loads, 0.3 for a module-only package and 0.2 for anything else. The weights are judgment calls, not measurements. Vulnerabilities that neither the scanners nor the review list are not here.
