---
name: probe-image-change
description: Measure how many vulnerabilities a container image would lose by removing a package, updating its Debian packages, or both, using throwaway image variants scanned with Trivy and Grype. Cleans up after itself. Use for "what if we remove X" or "does updating fix it" questions.
---

# Probe: what would removing or updating change?

Answers questions such as "if we remove this module, how many CVEs go away?" and "does updating fix them, or only removal?" with measured numbers, without changing the real image and without leaving files behind.

## When to use

The user is deciding whether to remove a package from a Debian or Ubuntu based container image, or wants to know what a base update alone achieves, and asks for the effect on the vulnerability count.

## What it does

1. Builds three throwaway variants of the image: packages removed, Debian packages updated, and both.
2. Scans the original and the three variants with Trivy and Grype.
3. Merges each pair of reports and prints one comparison table.
4. Deletes the variant images and every scan file it created.

## Requirements

- Docker, and Trivy and Grype either installed or runnable as containers.
- Network access during `docker build` for the two "updated" variants.

## Steps

1. Confirm which image and which package or packages. Use the exact package name as the package manager knows it (for example `nginx-module-image-filter`), not a library file name.
2. Run `make probe REMOVE="PACKAGE [PACKAGE...]"`, or `./scripts/probe-impact.sh PACKAGE [PACKAGE...]` with `IMAGE=...` for an image other than the default. It takes a few minutes: four scans with two scanners each.
3. If the build of the "updated" variants fails on the network (a TLS-intercepting proxy, for example), pass `PROBE_PRELUDE` (a file with extra Dockerfile lines that trust the proxy certificate; its folder is used as build context) and `PROBE_BUILD_FLAGS`. If Trivy cannot download its database, pass `TRIVY_FLAGS`, and tell the user if a cached database was used.
4. Report to the user:
   - the table as printed;
   - how many packages the removal takes with it, and which;
   - how many of the affected CVEs updating alone fixes, and how many only removal clears;
   - whether removing or updating has the larger effect.
5. If the result matters for a decision, put the table in `README.md` with the date and the command that produced it.

## Finish: leave nothing behind

The script deletes its variant images and scan output on exit, also when it fails. After the run, confirm it:

- `docker images | grep probe-impact` shows nothing.
- `git status` shows no new files under `scans/`.
- If earlier manual experiments left probe folders (for example `scans/probe-*`), remove them and any references to them in the README and other docs. The owner wants only the fix in the repository, not the probe results. The numbers live in the README table.

Use `KEEP=1` only when the user explicitly asks to keep the raw reports, and say where they were written.

## Caveats to tell the user

- The "updated" variants upgrade the original image in place. Software that did not come from the distribution's repositories (for example nginx from nginx.org) is not updated, so the result estimates a rebuilt image and does not replace scanning the real one.
- Removing a package also removes libraries that only it needed (`--auto-remove`). Libraries shared with something else stay, and so do their CVEs.
- A lower CVE count is not the whole decision. State what removing the package breaks for existing users.
- Counts are unique CVE IDs across both scanners, and the scanner database changes daily, so the "original" row can differ slightly from an older baseline.

## Where the script lives

The script is `scripts/probe-impact.sh` in this repository, and it uses `scripts/compare-scans.py` to merge the reports. This skill does not carry a copy. `scripts/CLAUDE.md` describes its options.
