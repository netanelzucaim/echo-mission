---
name: triage-cves
description: Merge Trivy and Grype JSON reports of a container image, rank every vulnerability by danger and by whether the image really runs the vulnerable code (checked against upstream source and advisories), and generate the statistics diagrams. Use to compare scan results, decide which CVEs to fix, re-rank after a rescan, or explain why a CVE sits where it does.
---

# Triage CVEs: merge the scans, review reach, rank

Scanners only match package names and versions. They cannot tell whether the image's
program ever calls the broken function. This skill merges the two scanners' reports,
adds that check (made by reading source code and advisories), and ranks the result so
every score comes with a reason.

Two parts:

- `scripts/compare-scans.py` (run by `make triage`) does the merging, the arithmetic,
  the explanations and the diagrams. It is deterministic.
- `review.tsv`, next to the results (`scans/baseline/review.tsv`), holds the human
  judgment: one verdict per CVE or per package, with a reason and evidence. Most of
  this skill is how to fill it.

Outputs, written to the top of the scan folder:

| File | Content |
|---|---|
| `triage.md` | Summary counts, packages not from the distribution, the top 40 with their reasons |
| `triage.csv` | Every vulnerability, ranked, with its explanation in the last column |
| `stats.md` | Mermaid diagrams and tables (renders on GitHub) |

Folder layout:

```
scans/<name>/
  triage.md, triage.csv, stats.md, review.tsv   results and the review
  reports/   trivy.json, grype.json (raw scanner output)
  image/     facts about the image: packages.tsv, linked-packages.txt, modules.tsv,
             foreign-packages.tsv, nginx-V.txt, ...
```

`make scan-baseline` (`scripts/scan-baseline.sh`, with `IMAGE` and `OUT` for another
image) writes `reports/` and `image/`. If only text tables exist, rerun the scans for
JSON; do not parse tables. If the two reports come from different image digests, say so.

## The score

`score = 100 x danger x reach`

**Danger (0 to 1)** = 0.6 x exploitation + 0.4 x severity

- Exploitation is 1.0 if the CVE is on CISA's known-exploited list (KEV), otherwise its
  EPSS probability. EPSS describes the bug everywhere, not in this image; reach puts it
  in context, so never change a verdict because of EPSS or KEV.
- Severity is the average of the two scanners' ratings (Critical 1, High 0.75, Medium
  0.5, Low 0.25; a missing scanner counts as 0, so agreement raises the score). A CVE
  added from an upstream advisory uses that advisory's severity.

**Reach (0 to 1)**: does this image actually run the vulnerable code?

| Verdict | Reach | Meaning | Example |
|---|---|---|---|
| `always` | 1.0 | Runs in every container, even with the default config | A bug in nginx's HTTP/1.1 request parser |
| `common` | 0.8 | Runs under a setup most production users have: TLS, HTTP/2, `proxy_pass` | HTTP/2 Rapid Reset |
| `config` | 0.5 | Needs a specific feature or optional module switched on | `proxy_ssl_verify on`, `mp4`, a loaded module |
| `manual` | 0.2 | Only when someone runs a tool by hand in the container | A libcurl bug (only `curl` uses it) |
| `unused` | 0.05 | Installed, but nothing in the image calls the vulnerable code | OpenSSL CMS parsing; nginx never calls CMS |
| `n/a` | 0 | Cannot happen here: other CPU, version outside the range, component absent | A 32-bit-only bug |
| `unknown` | default | Checked but not settled; say what is missing | |

Without a review line, reach falls back to where the package sits: 0.6 for a library the
main program loads (`image/linked-packages.txt`, from `ldd`), 0.3 for a package installed
only for an optional module (`image/modules.tsv`), 0.2 otherwise. These sit below the
reviewed values so an unchecked CVE never outranks a checked `common` one, and above
`unused` so not checking is never rewarded. Ties go to "fix available", then CVSS.

The ranking deliberately does not put "Critical in both scanners" first: a Critical in a
library the program never runs matters less than a High in code every deployment runs.
The weights are judgment calls, not measurements. Say so when presenting the ranking.

## First rule: software not built by the distribution

A scanner decides "vulnerable or not" by comparing the installed version with the version
in which **the distribution** fixed the bug. That only works for packages the
distribution built. Here the image is Debian but nginx came from nginx.org:

| | Debian's own nginx | The nginx in the image |
|---|---|---|
| Version | 1.22.1, with Debian's backported fixes | 1.25.5 |
| A CVE counts as fixed from | Debian's patched 1.22.1 revision | upstream 1.26.2 / 1.27.1 |

The scanner sees 1.25.5 > 1.22.1-9+deb12u2 and calls the CVE fixed, but nginx.org's
1.25.5 never got Debian's patch. So **for such a package, take its CVEs from the project
that built it, for the exact installed version, never from the distribution's data.**

1. **Find those packages.** The scan writes `image/foreign-packages.tsv`. If it says "not
   checked" (no network during the scan), rescan with network; do not guess.
2. **Read the upstream advisory list.** For nginx: <https://nginx.org/en/security_advisories.html>.
   Each advisory gives "Vulnerable: X-Y" and "Not vulnerable: Z+"; compare the ranges
   with the installed version (with a script, not by eye).
3. **Add every applicable advisory** to `review.tsv` with `package` and `severity`
   filled in, so it enters the ranking. `make triage` prints a WARNING while a foreign
   package has no upstream CVE in the review.
4. **Distrust what the scanner did report for it**, in both directions: a CVE the
   distribution marks "no fix" is reported forever even if the upstream version already
   has the fix (CVE-2023-44487 here). Check the upstream changelog.
5. **Check each source separately.** Modules built from nginx's own tree (xslt, geoip,
   image-filter) share nginx's advisories. njs has its own source and its own record.
6. **Libraries are different.** OpenSSL, zlib and the rest come from Debian even though
   nginx does not, so the scanners' answer is right for them. Apply this per package.

**Worked example: njs 0.8.4.** njs has no advisories page. Its security fixes are in its
`CHANGES` file (mostly without CVE ids) and in GitHub's advisory database
(`github.com/advisories?query=njs`), so both are needed. List the security entries for
every release after 0.8.4, then `git grep` **at the 0.8.4 tag** for the vulnerable code
(search the whole tree: the XML module is in `external/`, not `src/`):

- `js_fetch_proxy` overflow: "introduced in 0.9.4" per CHANGES, so not in 0.8.4.
- CVE-2026-18329 (`js_access` bypass): needs `js_access` in the http module, which 0.8.4
  does not have → `n/a`, kept in the review with that evidence.
- CVE-2026-78689 (XML `exclusiveC14n`, Critical): present in
  `external/njs_xml_module.c` → `config`. njs's `SECURITY.md` treats JavaScript as
  trusted config ("If no `js_import` directives are present, nginx is safe"), and the
  module is not loaded by default, so it ranks mid-table and goes in residual risk.

## The review file

Tab-separated, `#` starts a comment.

| Column | Content |
|---|---|
| `id` | A CVE ID, or `pkg:NAME` for every CVE in package NAME |
| `verdict` | One of the verdicts above |
| `reason` | One or two plain sentences: which function or feature, and why it is or is not reached |
| `evidence` | Where to check: `src/file.c:line` in the shipped version's source, an advisory URL, or a file in the scan folder |
| `package` | Only for CVEs no scanner reports: the package to file it under |
| `severity` | Only with `package`: the advisory's rating (`low`, `medium`, `major`/`high`, `critical`) |

A CVE-level line always wins. A `pkg:` verdict applies only when every package the CVE
touches has one.

## Steps

1. **Run it once.** `make triage` (or `python3 scripts/compare-scans.py TRIVY_JSON
   GRYPE_JSON --out-dir DIR`; Python 3 standard library only). Read `triage.md`.
2. **Get the upstream source of the exact shipped version** into the scratchpad, never
   committed. For nginx: `https://nginx.org/download/nginx-<version>.tar.gz`, version and
   build flags from `image/nginx-V.txt` (a module not compiled in cannot be reached).
3. **Add the CVEs the scanners miss**, per the first rule above.
4. **Choose the review scope**, in order: every CVE in a package the program loads; every
   KEV CVE and every CVE with EPSS ≥ 5%; every advisory from step 3; then any `not
   reviewed` row in the top 40, rerunning until none is left. For a package only a module
   pulls in, a `pkg:` line is usually the right level.
5. **Decide each verdict** with these checks, stopping at the first that settles it:
   1. *Does it apply at all?* CPU (`image/digest.txt`), version range against
      `image/packages.tsv`, whether the component is in the package. If not: `n/a`.
   2. *Does anything call the vulnerable function?* Search the upstream source for the
      function or API the advisory names. No caller: `unused`, with the search as
      evidence ("no CMS_ calls in nginx-1.25.5/src").
   3. *Is the input attacker-controlled?* If it only ever comes from the program's own
      config: `unused`, saying where it comes from.
   4. *What must be switched on?* Read the condition around the call site. Nothing:
      `always`. Common production setup: `common`. A specific option or module: `config`.
   5. *Only a hand-run tool uses it?* `manual`.
   6. Not settled in reasonable time: `unknown`, with what is missing.
6. **Write the lines** into `review.tsv`. Write "assumed" or "not checked" in the reason
   when that is the case.
7. **Rerun** `make triage`. It warns about reviewed IDs that match nothing (usually typos).
8. **Report**, in this order: the top of the ranking with verdict and one-line reason;
   what moved and why; CVEs added from upstream advisories; the `unknown` verdicts; where
   the details are (`triage.md` top 40, `triage.csv` for every CVE, `stats.md` for the
   diagrams). Do not paste hundreds of rows or redraw diagrams.

## Rules

- **No verdict without evidence.** A wrong `unused` hides a real risk, which is worse
  than a missing review.
- **Search the exact version shipped**, not the latest. Call sites move.
- **Read the condition around a call site**, not just its presence: `X509_check_host`
  runs only after `proxy_ssl_verify on`.
- **Prefer a narrow claim.** "nginx never calls CMS functions" can be checked; "OpenSSL
  is safe here" cannot.
- **"Loaded" is not "called".** A loaded library gets the 0.6 default only until checked.
- **A `pkg:` line is coarse.** Say so when a module library sits at the top.
- **Diagrams come from the script.** Never draw statistics by hand. For a new diagram,
  add it to `write_stats()` in `scripts/compare-scans.py` and rerun, so the next image
  gets the same one.
- **Do not edit generated files** (`triage.md`, `triage.csv`, `stats.md`). Change
  `review.tsv` or the script and rerun.

## Caveats to tell the user

- A package missing from both reports is not proven safe; the scanners do not inspect code.
- EPSS and KEV describe exploitation anywhere, not in this image.
- "Fix available" means a fixed package version exists, not that it is applied.
- The weights are a judgment call; to change one, edit `VERDICT_REACH` or
  `UNREVIEWED_REACH` in the script and say what changed.

The script is `scripts/compare-scans.py`; options are in `scripts/CLAUDE.md`. This skill
carries no copy of the code. The next steps are the `choose-cve-fix` skill (pick targets)
and `rescan-compare-vex` (after the fix).
