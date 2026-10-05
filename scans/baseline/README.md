# Baseline: the original image, before any change

This folder describes the untouched `nginx:1.25-bookworm` image. It is the "before"
picture that the patched image is compared with.

## Where to look

Read the three files at the top. The two subfolders are raw material that scripts use;
you rarely need to open them.

```
scans/baseline/
├── README.md      this page
├── stats.md       START HERE: the numbers as diagrams and tables
├── triage.md      the top 40 vulnerabilities, ranked
├── triage.csv     all 521 vulnerabilities, ranked (opens in a spreadsheet)
├── triage-details.md  why every vulnerability sits where it does
├── review.tsv     the human check behind the ranking (written by hand)
├── reports/       raw scanner output
└── image/         facts about the original image
```

| I want to... | Open |
|---|---|
| See the overall picture | `stats.md` |
| See which vulnerabilities matter most | `triage.md` |
| Look up one CVE or one package | `triage.csv`, or `reports/trivy.txt` |
| Know why a CVE has its rank | `triage-details.md` |
| See or change whether nginx really runs a CVE's code | `review.tsv` |
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

## How the files are made

Nothing here is written by hand except this page and `review.tsv`.

| Command | Writes |
|---|---|
| `make scan-baseline` | everything in `reports/` and `image/` |
| `make triage` | `stats.md`, `triage.md`, `triage.csv`, `triage-details.md` (reads `review.tsv`) |

`review.tsv` records, per CVE or per package, whether nginx actually runs the vulnerable
code, with a reason and where to check it. It also adds 24 nginx CVEs from nginx.org that
the scanners miss, which is why the ranking has 521 rows and `stats.md` has 497. How to
fill it is in `.claude/skills/triage-cves/SKILL.md`.

## Things to know when reading the results

- The scanners only compare package names and versions with a database. They do not
  look at the code.
- nginx's own CVEs are mostly missing, because the nginx package comes from nginx.org
  and is compared with Debian's version numbers. See the main `README.md`.
