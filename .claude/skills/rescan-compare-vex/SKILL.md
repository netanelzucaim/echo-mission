---
name: rescan-compare-vex
description: Scan a patched container image, compare it with the baseline scan, write an OpenVEX document for a backported CVE and show whether the scanners honour it. Use for the "rescan and compare" step, for before/after CVE diffs, or when asked to create or test a VEX file.
---

# Rescan, compare with the baseline, and apply VEX

This is step 6 of the assignment: prove what the fixes achieved. It scans the finished image, compares the result with the "before" scan, and handles the one case scanners cannot see on their own, a backported fix.

## Why VEX is needed

Trivy and Grype match on package name and version. A backport changes the code but not the version, so the scanner keeps reporting the CVE. A VEX document (Vulnerability Exploitability eXchange) is a small signed-off statement: "this CVE is fixed, or does not apply, in this build, and here is why". Both scanners accept it with `--vex` and drop the finding.

## Before you start

- The patched image must exist locally. Never run this against the original image and call the result "patched".
- The baseline must exist: `scans/baseline/` with `triage.csv` (from `make scan-baseline` and `make triage`).
- Use the same Trivy and Grype versions as the baseline (`scans/baseline/reports/versions.txt`), and say so if they differ.

## Steps

1. **Scan and compare.** Run `make rescan IMAGE=<patched image>`. It writes `scans/patched/` in the same layout as the baseline, plus `diff.md` and `diff.csv`. With no VEX files yet, the VEX part is skipped.
2. **Read `scans/patched/diff.md`.** Check the three groups: no longer reported, still reported, new. Anything "new" needs an explanation (an added package, or a newer scanner database).
3. **Write the VEX file for each backported CVE:**

   ```sh
   python3 scripts/make-vex.py --cve CVE-YYYY-NNNN --package nginx --scan-dir scans/patched \
     --note "Fixed by build/patches/CVE-YYYY-NNNN.patch, a backport of upstream commit <hash>"
   ```

   It writes `vex/CVE-YYYY-NNNN.openvex.json`. Name every binary package that carries the fix with a separate `--package`. Use `--status fixed` (the default) for a backport. Use `--status not_affected --justification <code>` only when the vulnerable code is present but cannot be exploited in this build.
4. **Run `make rescan IMAGE=<patched image>` again.** It now scans a second time with every `vex/*.json` applied and adds the "VEX check" table to `diff.md`.
5. **Read the VEX check table.** Each row has one of three results per scanner:
   - `suppressed`: reported without the VEX file, gone with it. This is the demonstration the assignment asks for.
   - `never reported`: the scanner did not report the CVE even without VEX, so there was nothing to suppress.
   - `STILL REPORTED`: the statement did not match. Fix the package name or version and rerun.
6. **Report to the user:** the before/after table, how many CVEs are gone and how many remain, the VEX result per scanner, and anything new. Then put the headline numbers and the per-CVE evidence links in `README.md`.

## Expect "never reported" for nginx's own CVEs — and pick a reported CVE for the "disappear" demo

In this project the scanners compare the nginx.org package with Debian's version numbers and conclude it is already fixed, so CVEs such as CVE-2024-7347 are not reported even before patching. The VEX file is then correct but has nothing to remove. Do not hide this and do not fake a "before" finding. Report it as a finding, keep the VEX file as the formal record of the fix (`--status fixed`), and point to the patch and to a test that exercises the fixed code as the real evidence.

That leaves the bonus's "show the CVE actually disappear" with nothing to show, because the backported CVE was never in the report. So **demonstrate the mechanic on a second CVE** that the scanners *do* report. Choose it with three tests, all required:

1. **Reported by the scanners** — otherwise there is nothing to suppress.
2. **No upstream fix available** — otherwise the base `apt-get upgrade` removes it from the patched scan on its own, and again there is nothing left for VEX to do. (Check the `fix_available`/`fixed_versions` columns in `triage.csv`.)
3. **Honestly `not_affected`** — the vulnerable code really is unreachable in this build, with evidence, so the statement is true. A reviewed `unused`/`n/a` verdict in `review.tsv` is the place to find these.

Worked example, verified on 2026-10-05 against the baseline image: **CVE-2023-52355** (libtiff6, High in both, no fix). image-filter links libtiff only through libgd, but its code asks libgd for JPEG/GIF/PNG/WebP, never TIFF, and the module is not loaded by default — so `not_affected` with justification `vulnerable_code_not_in_execute_path`. `vex/CVE-2023-52355.openvex.json` made it disappear from **both** scanners (Trivy dropped it; Grype moved it to `ignoredMatches`). This is the honest way to satisfy the bonus: the demonstrated CVE is a true not-affected finding, not the backport dressed up.

## Rules

- A VEX statement is a claim made in the owner's name. Write one only for a fix that is actually in the build, and put the evidence in `--note`.
- VEX files live in `vex/` and are committed. Scan output lives in `scans/patched/` and is generated; do not edit it by hand.
- One statement does not cover sibling packages. A statement for `libssl3` leaves the same CVE reported for `openssl`.
- Do not use VEX to make an unfixed CVE disappear from the report.

## What was verified about the scanners

Tested with Trivy 0.75.0 and Grype 0.120.0 on an image tarball: both honour an OpenVEX statement whose product is the bare package purl, `pkg:deb/debian/<name>@<version>`. A product that names the image with the package as a subcomponent worked in Grype but not in Trivy, so the scripts use the package purl.

## Where the scripts live

`scripts/rescan-compare.sh` (the `make rescan` target), `scripts/make-vex.py` and `scripts/diff-scans.py`. `scripts/CLAUDE.md` describes their options. This skill carries no copy of the code.
