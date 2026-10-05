# Baseline: the original image, before any change

This folder describes the untouched `nginx:1.25-bookworm` image. It is the "before"
picture that the patched image is compared with.

## Where to look

Read the files at the top. The two subfolders are raw material that scripts use;
you rarely need to open them.

```
scans/baseline/
├── README.md      this page
├── stats.md       START HERE: the numbers as diagrams and tables
├── triage.md      the top 40 vulnerabilities, ranked
├── triage.csv     all 497 vulnerabilities, ranked (opens in a spreadsheet)
├── fix-plan.md    how each CVE would be fixed: version bump, backport or remove
├── reports/       raw scanner output
└── image/         facts about the original image
```

| I want to... | Open |
|---|---|
| See the overall picture | `stats.md` |
| See which vulnerabilities matter most | `triage.md` |
| See how a CVE would be fixed, and nginx's own CVEs | `fix-plan.md` |
| Look up one CVE or one package | `triage.csv`, or `reports/trivy.txt` |
| Check a setting of the original image (port, entrypoint...) | `image/inspect.json` |
| See how the original was built | `image/history.txt` |

## reports/ : raw scanner output

| File | What it is |
|---|---|
| `trivy.json`, `grype.json` | Each scanner's full report, for scripts |
| `trivy.txt`, `grype.txt` | The same reports as tables, for people |
| `versions.txt` | Scan date, exact image, scanner versions |

## image/ : facts about the original image

| File | What it is | Used for |
|---|---|---|
| `inspect.json` | Settings: entrypoint, command, port, environment, labels, stop signal | Copying the same settings into the `Containerfile` |
| `history.txt` | The commands that built the original, layer by layer | Seeing what the `Containerfile` must reproduce |
| `nginx-V.txt` | nginx's version and compile options | Compiling the patched nginx identically |
| `packages.tsv` | All 149 installed packages with versions | Comparing versions with the new image |
| `layout.txt` | Directory listings and the `nginx` user's IDs | Checking the new image has the same files and user |
| `linked-packages.txt` | The 6 packages nginx itself runs: `nginx` and 5 libraries | The "reach" part of the ranking |
| `modules.tsv` | Each of the 4 optional modules and the packages installed only for it | The per-module table in `stats.md` |
| `digest.txt` | The image's unique fingerprint | Proving which exact image was scanned |
| `nginx-security-advisories.html` | A saved copy of nginx's own list of security advisories | Finding nginx's CVEs, which the scanners miss |

## How the files are made

Nothing here is written by hand except this page.

| Command | Writes |
|---|---|
| `make scan-baseline` | everything in `reports/` and `image/` |
| `make triage` | `stats.md`, `triage.md`, `triage.csv` |
| `make fix-plan` | `fix-plan.md` (and `image/nginx-security-advisories.html` the first time) |

## Things to know when reading the results

- The scanners only compare package names and versions with a database. They do not
  look at the code.
- nginx's own CVEs are mostly missing, because the nginx package comes from nginx.org
  and is compared with Debian's version numbers. See the main `README.md`.
