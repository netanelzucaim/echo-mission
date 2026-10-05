# Dynamic modules are kept, including image-filter

Back to the [README](../README.md). Decided by the owner on 2026-10-05: customers whose configs load a module must keep working, so compatibility wins over removing the vulnerable libraries.

The original installs four optional module packages next to nginx. None is loaded by
default: the shipped configuration has no `load_module` line. Their libraries are in
the image only because of them, and they carry 208 of the 497 unique baseline CVEs.

| Module | What it does | Libraries it brings in | CVEs in those libraries (baseline) | Of which Critical or High |
|---|---|---|---|---|
| `nginx-module-xslt` | Transforms XML responses | 3 (`libxslt1.1`, `libxml2`, `libicu72`) | 42 | 23 |
| `nginx-module-geoip` | Country lookup from the client IP | 1 (`libgeoip1`) | 0 | 0 |
| `nginx-module-image-filter` | Resizes, crops and rotates images on the fly | 32 (`libgd3` and its image-format, font and X11 dependencies) | 166 | 65 |
| `nginx-module-njs` | nginx logic written in JavaScript | 4 (`libedit2`, `libbsd0`, `libxml2`, `libicu72`) | 34 | 20 |

Counts overlap where modules share a library. "Critical or High" means rated so by at
least one of the two scanners (by both: 20, 0, 44 and 17). Source: `scans/baseline/triage.csv` and `apt-get -s remove --auto-remove` on the module packages in the original image.

The CVEs are in the libraries, not in the modules: the libraries are written by other
projects and packaged by Debian, and the scanners report them correctly. They are
grouped by module because each module is why its libraries are installed, so keeping or
removing a module keeps or removes them. The table does not include CVEs in the module
code itself, which the scanners cannot see (the same blind
spot as nginx; see [scanner-blind-spot.md](scanner-blind-spot.md)). From njs's own advisories, njs 0.8.4 has one more:
**CVE-2026-78689** (Critical), reachable only when the njs module is loaded and a script
uses XML canonicalization (`exclusiveC14n`), so 35 for njs in all. A second njs
advisory, CVE-2026-18329, does not apply to 0.8.4. None of nginx's own 24 advisories
concern xslt, geoip or image-filter.

**What this costs, measured.** All four modules are built from source and shipped, and
their libraries stay in the image. On 2026-10-05 three throwaway variants of
the original image were built (image-filter removed, Debian packages updated, and
both), and each was scanned with both tools. The variants were deleted afterwards:

| Variant of the original image | Packages | Unique CVEs | Critical or High | CVEs in image-filter's packages |
|---|---|---|---|---|
| Original | 149 | 494 | 203 | 166 |
| image-filter removed, nothing else | 117 | 328 | 138 | 0 |
| Debian packages updated, image-filter kept (the shipped approach) | 149 | 253 | 80 | 89 |
| Updated and image-filter removed | 117 | 164 | 55 | 0 |

- Removing the module takes 32 packages with it: the module and 31 libraries.
- Updating alone fixes 77 of the 166 CVEs in those packages. The known-exploited
  CVE-2025-27363 in `libfreetype6` is one of them.
- The other 89 have no fixed version in Debian bookworm today, so only removal clears
  them. Most are in `libheif1` and `libtiff6`. These 89 are the measured price of
  keeping image-filter, accepted for the sake of compatibility.
- Updating does more than removing: 253 CVEs remain after updating alone, 328 after
  removing alone.
- "Original" shows 494 here and 497 in the baseline because the scanner database of
  2026-10-05 no longer lists three `libxml2` CVEs that it listed a day earlier.

The "updated" variants upgrade the original image in place, so they still contain the
unpatched nginx 1.25.5. They estimate the final image; the final scan replaces them.

**What I would do with more time.** Publish a second, slimmer variant without
image-filter for users who do not need it, so the default stays compatible and the
smaller attack surface is available by choice.
