# Which CVEs to fix, and how — the decision

Back to the [README](../README.md). Evidence behind it: the ranking in
[`scans/baseline/triage.csv`](../scans/baseline/triage.csv) and the reach review in
[`scans/baseline/review.tsv`](../scans/baseline/review.tsv).

This is the triage answer: the CVEs that matter most for **this** image and the
method for each. It is written by judgment, following the `choose-cve-fix` skill.
The danger-and-reach number in
[`scans/baseline/triage.md`](../scans/baseline/triage.md) was only the starting sort; the order
below is argued from four facts per CVE — **reach** (does this image run the code),
**known-exploited** (KEV), **chance of exploitation** (EPSS), and **severity** as
Trivy and Grype each rate it.

Facts as of 2026-10-05 (EPSS from FIRST, KEV from CISA's 2026-10-04 catalogue, nginx
ranges from nginx.org advisories, scanner severities from the baseline scan).

## How the order was reached

1. **Reach first.** A Critical bug in code the image never runs is not a priority.
   Everything below is reachable in this build (the relevant modules are compiled —
   `scans/baseline/image/nginx-V.txt` has `--with-http_mp4_module`, `--with-http_v3_module`,
   `--with-http_dav_module`, and the rewrite/script engine is always built).
2. **Known-exploited next.** One KEV entry is reachable (CVE-2023-44487) and it is
   handled specially — see below.
3. **Then chance (EPSS) weighed against impact (both severities).**
4. **Ties broken by reach** (`always` > `common` > `config`).

Remember the scanner-severity caveat: nginx was built by nginx.org, not Debian, so
for nginx's own CVEs the scanners are blind and the severity comes from nginx's
advisory, not from the `trivy`/`grype` columns. For the OpenSSL CVEs the scanners are
authoritative (libssl3 is Debian's).

## The two targets (what the assignment needs: one bump, one backport)

### Version bump — CVE-2024-6119 (OpenSSL, `libssl3`)

| Fact | Value |
|---|---|
| Reach | `config` — nginx calls `X509_check_host()` only after verifying an **upstream** server's certificate (`proxy_ssl_verify on`, or the grpc/uwsgi/stream equivalents). Off by default, common in real reverse-proxy setups. |
| Known-exploited | No |
| Chance (EPSS) | **66.6%** — the highest of any reachable, non-mitigated CVE in the image |
| Severity | Trivy High, Grype High |
| Fix | Debian fixed it in `3.0.14-1~deb12u2`; bookworm-security now offers `3.0.22-1~deb12u1`, and `build/patches/CVE-2024-6119.patch` makes the nginx package require `libssl3 (>= 3.0.14-1~deb12u2)`, so the image build installs a fixed OpenSSL (3.0.22; was 3.0.11) or fails. **Version bump.** |

Why this one for the bump: it is in a library nginx actually loads, it has by far the
strongest real exploitation signal (two-thirds EPSS, High from both scanners), and the
fix is a clean distribution upgrade. The same base upgrade removes most of the other
OpenSSL CVEs as a side effect; this is the one to *name* because it is the only
high-EPSS OpenSSL bug that is actually reachable here.

Rejected alternative: **CVE-2025-15467** (OpenSSL, Grype Critical, EPSS 52%) scores
high mechanically but is in CMS parsing, which nginx never calls — reach `unused`. A
higher severity label on unreachable code is not a better fix.

### Backport — chosen: CVE-2026-42945 (nginx rewrite module); CVE-2024-7347 was the fallback

Two honest candidates, and the choice is a real judgment call, so both are laid out.

**CVE-2026-42945 — heap buffer overflow in `ngx_http_rewrite_module`, potential code execution**

| Fact | Value |
|---|---|
| Reach | `config`→ effectively broad. The rewrite/script engine is always compiled; the overflow is triggered through `rewrite`/`set`/`return` with captures, which an enormous share of real configs use. |
| Severity | nginx advisory **medium**, but impact is *potential arbitrary code execution*, not a crash. (Scanners: silent — nginx is foreign.) |
| Chance (EPSS) | 3.4% (85th percentile) — low in absolute terms, but these are new 2026 bugs with little exploitation history yet. |
| Upstream fix | Commit `2046b45a` ("Rewrite: fixed escaping and possible buffer overrun"), one-line reset of `e->is_args`. Vulnerable range 0.6.27–1.30.0 includes 1.25.5; fixed in 1.30.1/1.31.0. |
| Applies to 1.25.5? | **Yes — `patch -p1 --dry-run` applies cleanly.** Verified, not assumed. The follow-ups `475732a3` and `ca4f92a2` (CVE-2026-9256, overlapping captures) also apply cleanly but are **not** shipped; only `2046b45a` is. |
| Method | **Backport.** A newer nginx is not allowed (image must stay 1.25). |

**CVE-2024-7347 — buffer over-read in `ngx_http_mp4_module`** (the safe fallback)

| Fact | Value |
|---|---|
| Reach | `config` — needs the `mp4` directive in a `location`; module is compiled but off unless configured. Narrower than rewrite. |
| Severity | nginx advisory **low**; worst case a worker crash, not code execution. |
| Chance (EPSS) | 0.3% |
| Upstream fix | **A vendor-published standalone patch** (`https://nginx.org/download/patch.2024.mp4.txt`), the cleanest possible backport starting point. Vulnerable 1.5.13–1.27.0; fixed 1.26.2/1.27.1. |
| Applies to 1.25.5? | **Yes — applies cleanly.** Verified. |
| Method | **Backport.** |

**The call.** CVE-2026-42945 is the stronger *risk reduction* — it is in code almost
every deployment runs and its worst case is code execution, versus a crash in an
opt-in media module — and backporting it
demonstrates real backporting over a vendor-handed patch. CVE-2024-7347 is the
*safest* backport: a single, nginx-published patch file, lowest chance of a
subtle mistake. **Decision: CVE-2026-42945**, chosen by the owner. The shipped patch is
upstream commit `2046b45a` alone, the fix the advisory names; CVE-2024-7347 was not
taken.

What was verified: the fix applies cleanly to the 1.25.5 source, the build applied it,
and the built image passes `make test`, including a scenario that runs the patched
rewrite path with output identical to the original. What was not done, deliberately:
exercising the bug with a trigger, which is exploit work.

## Reachable runners-up (not chosen, but real)

| CVE | Where | Reach | EPSS | nginx severity | Note |
|---|---|---|---|---|---|
| CVE-2023-44487 | nginx HTTP/2 | `common` | ~100%, **KEV** | High (Grype) | **Already mitigated** in 1.25.5. Upstream's stream-handling limit (commit 6ceef19, 1.25.3) is in the shipped binary. Do **not** claim as a fix and do **not** present as open. Needs a VEX / residual-risk note, not a patch. |
| CVE-2026-27654 | nginx DAV | `config` | **25.1%** | medium | Highest EPSS of the reachable nginx bugs. Needs DAV `COPY`/`MOVE` with `alias` — uncommon. Fix `9739e755` applies cleanly. Good third target if more are wanted. |
| CVE-2026-9256 | nginx rewrite | `config`→broad | 2.7% | medium (code exec) | Sibling of CVE-2026-42945, **not fixed here**: its commits (`ca4f92a2` + `475732a3`) apply cleanly but were not shipped. The natural next backport. |
| CVE-2026-42533 | nginx map+regex | `config` | 0.9% | **major** | Highest nginx severity label here. Needs `map` with a regex capture reused in a later string expression. Fix `0cca8e05` applies cleanly. |
| CVE-2024-31079 / 32760 / 34161 / 35200 | nginx HTTP/3 | `config` | ~0.9% | medium | HTTP/3 is compiled; reachable only with `listen ... quic`. Four separate fixes, all in 1.26.1/1.27.0. The natural second *group* if HTTP/3 is in scope. |
| CVE-2026-78689 | njs (`nginx-module-njs` 0.8.4) | `config` | — | **critical** (CVSS 9.2) | Heap overflow in njs's XML `exclusiveC14n()` namespace-prefix parser; the scanners miss it entirely (njs is a separate upstream). The 0.8.4 source contains the vulnerable code. Reach is gated hard: njs's threat model treats JS as trusted, so it needs the njs module loaded **and** a `js_import` calling XML c14n on attacker data (the nginx-saml SAML flow is the known case). The module is not loaded by default here. **No in-version fix** (first fixed in njs 1.0.1), so it is a residual-risk / module-kept item, not a bump or backport target. See the njs worked example in the `triage-cves` skill. |

## Not reachable (scored high, ruled out — recorded so the ranking is honest)

| CVE | Package | Why it is out |
|---|---|---|
| CVE-2025-15467 | OpenSSL | CMS parsing; nginx never calls CMS. `unused`. |
| CVE-2025-27363 | libfreetype6 | **KEV**, but freetype is pulled in only by the `image-filter` module and is not loaded by the default binary; no font parsing happens unless that module is enabled. `unused` for the default image — moves to residual risk because the module is kept. |
| CVE-2023-50387 / 50868 | libsystemd0/udev | EPSS ~100%, but these are BIND/DNSSEC resolver bugs; nginx does not run a DNSSEC validator. `unused`. |
| CVE-2011-3389 (BEAST) | libgnutls30 | gnutls is not loaded by nginx; a `curl`-only concern. `manual`. |

## Summary (decided 2026-10-05)

- **Bump:** CVE-2024-6119 (OpenSSL) — reachable, EPSS 66.6%, High/High, fixed by a minimum-version requirement in the nginx package (`build/patches/CVE-2024-6119.patch`).
- **Backport: CVE-2026-42945 (rewrite, code-execution potential, broad reach) — chosen**
  by the owner over the mp4 fallback. Patch `build/patches/CVE-2026-42945.patch`
  (upstream commit `2046b45a`, nginx 1.31.0) applies cleanly to 1.25.5; VEX written as
  `status: fixed`. CVE-2024-7347 (mp4, vendor patch) and CVE-2026-9256 (sibling rewrite
  overflow) remain available as a second backport if wanted.
- **Mitigated already:** CVE-2023-44487 — VEX/residual-risk note, not a fix.
- **VEX "disappear" demo:** CVE-2023-52355 (libtiff6, not_affected) — a reported, no-fix
  CVE, since the backported CVE is never in the scan. Proven on the baseline.
- The number in `triage.md` sorted the candidates; reach and the advisory reading chose them.
