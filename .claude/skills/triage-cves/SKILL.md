---
name: triage-cves
description: Score every vulnerability in a container image by danger and by whether the image really runs the vulnerable code, checking each candidate against the upstream source and advisories, and write a per-CVE explanation of its rank. Use to decide which CVEs to fix, to re-rank after a rescan, or to explain why a CVE sits where it does.
---

# Triage CVEs: a reviewed score with a reason for every rank

The scanners only match package versions. A scanner cannot tell whether the program in the image ever calls the broken function. This skill adds that check, made by reading source code and advisories, and records it so the ranking can be reproduced and every score comes with an explanation.

Two parts:

- `scripts/compare-scans.py` (run by `make triage`) does the arithmetic and writes the explanations. It is deterministic.
- `review.tsv`, next to the triage results (for the baseline, `scans/baseline/review.tsv`), holds the human judgment: one verdict per CVE or per package, with a reason and evidence. This skill tells you how to fill it.

## The score

`score = 100 x danger x reach`

**Danger (0 to 1)** = 0.6 x exploitation + 0.4 x severity

- Exploitation is 1.0 if the CVE is on CISA's known-exploited list (KEV), otherwise its EPSS probability. EPSS describes the bug in all software everywhere, not in this image. Reach is what puts it in context, so never lower or raise a verdict because of EPSS.
- Severity is the average of the two scanners' ratings (Critical 1, High 0.75, Medium 0.5, Low 0.25; a missing scanner counts as 0). A CVE added from an upstream advisory uses that advisory's severity.

**Reach (0 to 1)**: does this image actually run the vulnerable code?

| Verdict | Reach | Meaning | Example |
|---|---|---|---|
| `always` | 1.0 | Runs in every container, even with the image's default config | A bug in nginx's HTTP/1.1 request parser |
| `common` | 0.8 | Runs under a setup most production users have: TLS, HTTP/2, `proxy_pass` | HTTP/2 Rapid Reset |
| `config` | 0.5 | Needs a specific, less common feature or optional module switched on | `proxy_ssl_verify on`, `mp4`, a loaded module |
| `manual` | 0.2 | Only when someone runs a tool by hand inside the container | A libcurl bug (only the `curl` tool uses it) |
| `unused` | 0.05 | Installed, but nothing in the image calls the vulnerable code | OpenSSL CMS parsing; nginx never calls CMS |
| `n/a` | 0 | Cannot happen here: other CPU, version outside the range, component absent | A bug only on 32-bit or PowerPC |
| `unknown` | default | You checked but could not settle it; say what is missing | |

Without a review line, reach falls back to where the package sits: 0.6 for a library the main program loads, 0.3 for a package installed only for an optional module, 0.2 for anything else. These defaults sit below the reviewed values on purpose, so an unchecked CVE never outranks a checked `common` one, and above `unused`, so not checking is never rewarded.

The weights are judgment calls, not measurements. Say so whenever you present the ranking.

## The review file

Tab-separated. Lines starting with `#` are comments. Columns:

| Column | Content |
|---|---|
| `id` | A CVE ID, or `pkg:NAME` for a verdict that covers every CVE in package NAME |
| `verdict` | One of the verdicts above |
| `reason` | One or two plain sentences: which function or feature, and why it is or is not reached |
| `evidence` | Where to check: `src/file.c:line` in the upstream source of the exact shipped version, the advisory URL, or a file in the scan folder such as `image/packages.tsv` |
| `package` | Only for CVEs no scanner reports (for example from nginx.org): the package to file it under |
| `severity` | Only with `package`: the advisory's own rating (`low`, `medium`, `major`/`high`, `critical`) |

A CVE-level line always wins over a `pkg:` line. A `pkg:` verdict applies only when every package the CVE touches has one.

## Steps

1. **Run the score once.** `make triage`, or `python3 scripts/compare-scans.py TRIVY_JSON GRYPE_JSON --out-dir DIR`. Read `triage.md`.

2. **Get the upstream source of the exact shipped version**, as a source tarball from the project's own site, into the scratchpad. Never commit it. For nginx: `https://nginx.org/download/nginx-<version>.tar.gz`, with the version from `image/nginx-V.txt`. Also note the build flags in `nginx-V.txt`: a module that is not compiled in cannot be reached.

3. **Add the CVEs the scanners miss.** For software not installed from the distribution (nginx from nginx.org on Debian), the scanners compare against the wrong version list and drop its own CVEs. Fetch the project's advisory page (for nginx, `https://nginx.org/en/security_advisories.html`). Parse the version ranges with a script rather than by eye, and add one line per advisory whose vulnerable range includes the shipped version, with `package` and `severity` filled in.

4. **Choose the review scope**, in this order:
   - every CVE in a package the main program loads (`image/linked-packages.txt`);
   - every KEV CVE, and every CVE with EPSS of 5% or more, wherever it sits;
   - every advisory added in step 3;
   - then rerun and repeat for any `not reviewed` row in the top 40, until none is left. For a package that only an optional module pulls in, a `pkg:` line is usually the right level. Add CVE-level lines for the top rows where the CVE needs a feature the program never uses.

5. **Decide each verdict by these checks**, in order. Stop at the first that settles it.
   1. *Does it apply at all?* CPU architecture (the image's platform is in `image/digest.txt`), operating system, affected version range against `image/packages.tsv`, and whether the affected component is in the package at all (a server, a tool or a binding that is not installed). If not: `n/a`.
   2. *Does anything call the vulnerable function?* Take the function, API or feature named in the advisory and search the upstream source for it. No caller in the main program, and the package is a library only the main program would use: `unused`. Record the search as evidence, for example "no CMS_ calls in nginx-1.25.5/src".
   3. *Is the input under an attacker's control?* Many bugs need an attacker-chosen regex, key, file or alignment that the program only ever takes from its own config. If so: `unused`, and say where the value really comes from.
   4. *What has to be switched on?* Find the config directive or module that leads to the call (the source shows the condition around the call site). Nothing extra needed: `always`. Something most production setups have: `common`. A specific option or a loaded module: `config`.
   5. *Only a hand-run tool uses it?* `manual`.
   6. Could not settle it in reasonable time: `unknown`, with what is missing.

6. **Write the lines** into `review.tsv`. Keep the reason short and specific. When something is assumed rather than checked, write "assumed" or "not checked" in the reason.

7. **Rerun** `make triage`. The script warns about reviewed IDs that match nothing (usually a typo).

8. **Report**, in this order:
   - the top of the ranking, each with verdict and the one-line reason;
   - what moved compared with the unreviewed score, and why (for example "CVE-2025-15467 dropped from #3: CMS, never called");
   - CVEs added from upstream advisories that the scanners missed;
   - the `unknown` verdicts, which are open questions;
   - where the explanations are: `triage.md` for the top 40, `triage-details.md` and the `explanation` column of `triage.csv` for every CVE.
   Do not paste hundreds of rows.

## Rules

- **No verdict without evidence.** Every `unused` or `n/a` line says what was searched or read. If you did not look, leave the CVE unreviewed or mark it `unknown`. A wrong `unused` hides a real risk, which is worse than a missing review.
- **Search the source of the exact version shipped**, not the latest one. Call sites move between releases.
- **Read the condition around a call site**, not just its presence. `X509_check_host` exists in nginx, but it runs only after `proxy_ssl_verify on`.
- **Prefer a narrow claim.** "nginx never calls CMS functions" can be checked; "OpenSSL is safe here" cannot.
- **"Loaded" is not "called".** A library the program loads gets the 0.6 default only until someone checks.
- **Do not let EPSS or KEV change a verdict.** They are danger, not reach. KEV can still put a `config` CVE first, and that is intended.
- **A `pkg:` line is coarse.** It says the package is reached through a feature, not that every CVE's specific API is. Say so when presenting a module library at the top.
- **Do not edit the generated files** (`triage.md`, `triage.csv`, `triage-details.md`, `stats.md`). Change `review.tsv` or the script and rerun.

## Where things live

- Script: `scripts/compare-scans.py`. Options and constants are described in `scripts/CLAUDE.md`. To change a weight, edit `VERDICT_REACH` or `UNREVIEWED_REACH` and say what changed.
- Merging the two scanners and the statistics diagrams are covered by the `compare-vuln-scans` skill. This skill covers the score and the review.
