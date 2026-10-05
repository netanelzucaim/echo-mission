#!/usr/bin/env python3
"""Merge a Trivy and a Grype JSON report and rank vulnerabilities by risk.

Usage:
    compare-scans.py TRIVY_JSON GRYPE_JSON [--linked FILE] [--modules FILE]
                     [--out-dir DIR] [--top N]

Writes into DIR:
    triage.md   summary and the top N vulnerabilities
    triage.csv  every vulnerability, ranked
    stats.md    the statistics as Mermaid diagrams and tables (renders on GitHub)

--modules FILE is a two-column TSV (module, package) naming the packages that are
installed only for an optional module, for example an nginx module package and the
libraries it pulls in. With it, stats.md shows what each module costs.

--linked and --modules default to linked-packages.txt and modules.tsv next to
TRIVY_JSON, or in a sibling "image" folder (../image/), whichever exists.

The ranking answers "what is most dangerous and reaches the most deployments",
not "what has the scariest severity label".

    score = 100 * danger * reach

  danger (0..1) = 0.6 * exploitation + 0.4 * severity
      exploitation = 1.0 if the CVE is in CISA's Known Exploited list (KEV),
                     otherwise its EPSS probability (chance of exploitation
                     in the next 30 days).
      severity     = average of the two scanners' severities, scaled to 0..1
                     (Critical = 1, High = 0.75, Medium = 0.5, Low = 0.25).
                     A scanner that does not report the CVE counts as 0, so
                     findings both scanners agree on score higher.

  reach (0.4..1) = how many deployments run the vulnerable code
      1.0  the affected package is a library the main program loads
           (listed in --linked), so every running container executes it;
      0.4  the package only sits in the image (a tool, or a library used by
           an optional module);
      plus 0.05 per additional affected package, up to +0.15, capped at 1.0.

Without --linked, reach cannot tell the two cases apart and every finding gets
the "sits in the image" value; the script says so.
"""
import argparse, collections, csv, json, os, sys

RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NEGLIGIBLE": 0, "UNKNOWN": 0}
NAME = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Negligible/Unknown"}
REACH_LINKED, REACH_PRESENT = 1.0, 0.4


def sev(s):
    return RANK.get((s or "UNKNOWN").upper(), 0)


def sev_name(s):
    return (s or "Unknown").capitalize()


def new_entry(vid):
    return {"id": vid, "trivy": None, "grype": None, "pkgs": set(), "fixes": set(),
            "kev": False, "epss": 0.0, "cvss": 0.0, "title": ""}


def load_trivy(path, vulns, findings):
    data = json.load(open(path))
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            findings[sev_name(v.get("Severity"))] += 1
            e = vulns.setdefault(v["VulnerabilityID"], new_entry(v["VulnerabilityID"]))
            e["trivy"] = max(e["trivy"] if e["trivy"] is not None else -1, sev(v.get("Severity")))
            e["pkgs"].add(v.get("PkgName", "?"))
            if v.get("FixedVersion"):
                e["fixes"].add(v["FixedVersion"])
            e["title"] = e["title"] or (v.get("Title") or "")
            for src in (v.get("CVSS") or {}).values():
                e["cvss"] = max(e["cvss"], src.get("V3Score") or 0.0)


def load_grype(path, vulns, findings):
    data = json.load(open(path))
    for m in data.get("matches", []) or []:
        v = m["vulnerability"]
        findings[sev_name(v.get("severity"))] += 1
        vid = v["id"]
        if not vid.startswith("CVE-"):  # e.g. GHSA ids: use the related CVE if there is one
            for r in m.get("relatedVulnerabilities", []) or []:
                if r.get("id", "").startswith("CVE-"):
                    vid = r["id"]
                    break
        e = vulns.setdefault(vid, new_entry(vid))
        e["grype"] = max(e["grype"] if e["grype"] is not None else -1, sev(v.get("severity")))
        e["pkgs"].add(m["artifact"].get("name", "?"))
        fix = v.get("fix") or {}
        if fix.get("state") == "fixed":
            e["fixes"].update(fix.get("versions") or [])
        if v.get("knownExploited"):
            e["kev"] = True
        for ep in v.get("epss") or []:
            e["epss"] = max(e["epss"], ep.get("epss") or 0.0)
        for c in v.get("cvss") or []:
            e["cvss"] = max(e["cvss"], (c.get("metrics") or {}).get("baseScore") or 0.0)


def score(e, linked):
    exploitation = 1.0 if e["kev"] else e["epss"]
    severity = ((e["trivy"] or 0) + (e["grype"] or 0)) / 8.0
    e["danger"] = 0.6 * exploitation + 0.4 * severity
    e["linked"] = sorted(e["pkgs"] & linked)
    base = REACH_LINKED if e["linked"] else REACH_PRESENT
    e["reach"] = min(1.0, base + 0.05 * min(len(e["pkgs"]) - 1, 3))
    e["score"] = 100.0 * e["danger"] * e["reach"]


def pie(title, slices):
    lines = ["```mermaid", f"pie showData title {title}"]
    lines += [f'    "{name}" : {n}' for name, n in slices if n > 0]
    return "\n".join(lines + ["```", ""])


def write_stats(path, rows, linked, modules, t_find, g_find, names):
    """Diagrams and tables for the whole report set. Everything is computed from the data."""
    hi = lambda e: max(e["trivy"] or 0, e["grype"] or 0) >= 3
    both = [e for e in rows if e["trivy"] is not None and e["grype"] is not None]
    mod_pkgs = set(p for ps in modules.values() for p in ps)
    where = lambda e: "loaded" if e["linked"] else "module" if e["pkgs"] & mod_pkgs else "other"
    groups = collections.Counter(where(e) for e in rows)
    fixed = collections.Counter((where(e), bool(e["fixes"])) for e in rows)
    t_u = sum(1 for e in rows if e["trivy"] is not None)
    g_u = sum(1 for e in rows if e["grype"] is not None)
    n = len(rows)
    with open(path, "w") as f:
        w = lambda text="": f.write(text + "\n")
        w("# Scan statistics")
        w()
        w(f"Generated by `scripts/compare-scans.py` from `{names[0]}` and `{names[1]}`. Do not edit by")
        w("hand; rerun the script. Counts are unique CVEs unless a line says \"findings\". GitHub")
        w("renders the diagrams; in a plain text editor they appear as code.")
        w()
        w(f"## How the {n} break down")
        w()
        w("```mermaid")
        w("flowchart TD")
        w(f'    T["Trivy<br/>{sum(t_find.values())} findings<br/>{t_u} unique CVEs"] --> U')
        w(f'    G["Grype<br/>{sum(g_find.values())} findings<br/>{g_u} unique CVEs"] --> U')
        w(f'    U["{n} unique CVEs"]')
        w(f'    U --> B["{len(both)} reported by both scanners"]')
        w(f'    U --> TO["{n - g_u} Trivy only"]')
        w(f'    U --> GO["{n - t_u} Grype only"]')
        w(f'    B --> BS["{sum(1 for e in both if e["trivy"] == e["grype"])} same severity"]')
        w(f'    B --> BD["{sum(1 for e in both if e["trivy"] != e["grype"])} different severity"]')
        if linked:
            w(f'    U --> L["{groups["loaded"]} in packages the main program loads"]')
            w(f'    L --> LF["{fixed[("loaded", True)]} have a fix"]')
            if modules:
                w(f'    U --> M["{groups["module"]} in optional modules\' packages"]')
                w(f'    M --> MF["{fixed[("module", True)]} have a fix"]')
            w(f'    U --> O["{groups["other"]} in other packages"]')
            w(f'    O --> OF["{fixed[("other", True)]} have a fix"]')
        w("```")
        w()
        if linked:
            w("## Where the vulnerabilities live")
            w()
            w(pie(f"Unique CVEs by where the package sits ({n})", [
                ("The main program and the libraries it loads", groups["loaded"]),
                ("Packages of optional modules", groups["module"]),
                ("Other tools and their libraries", groups["other"])]))
            per = collections.Counter(p for e in rows for p in e["linked"])
            w(pie("CVEs in loaded packages, by package", per.most_common()))
        w("## How severe")
        w()
        top = collections.Counter(NAME[max(e["trivy"] or 0, e["grype"] or 0)] for e in rows)
        w(pie(f"Unique CVEs by highest severity from either scanner ({n})",
              [(NAME[k], top[NAME[k]]) for k in (4, 3, 2, 1, 0)]))
        w("Findings per scanner (the same CVE in two packages counts twice):")
        w()
        w("| Severity | Trivy | Grype |")
        w("|---|---|---|")
        for k in ("Critical", "High", "Medium", "Low", "Negligible", "Unknown"):
            w(f"| {k} | {t_find[k]} | {g_find[k]} |")
        w(f"| **Total findings** | **{sum(t_find.values())}** | **{sum(g_find.values())}** |")
        w()
        w("## Do the scanners agree")
        w()
        w(pie(f"Agreement between Trivy and Grype ({n} unique CVEs)", [
            ("Both, same severity", sum(1 for e in both if e["trivy"] == e["grype"])),
            ("Both, different severity", sum(1 for e in both if e["trivy"] != e["grype"])),
            ("Trivy only", n - g_u), ("Grype only", n - t_u)]))
        w(f"{sum(1 for e in both if e['trivy'] == 4 and e['grype'] == 4)} CVEs are Critical in both scanners.")
        w()
        w("## Can it be fixed by updating")
        w()
        w(pie(f"Is a fixed package version available ({n} unique CVEs)", [
            ("Fix available", sum(1 for e in rows if e["fixes"])),
            ("No fix yet", sum(1 for e in rows if not e["fixes"]))]))
        w("## How likely to be exploited")
        w()
        kev = [e for e in rows if e["kev"]]
        kev_txt = ", ".join(f"{e['id']} in `{sorted(e['pkgs'])[0]}`" for e in kev)
        w("| Signal | Unique CVEs |")
        w("|---|---|")
        w(f"| On CISA's known-exploited list (KEV) | {len(kev)}{' (' + kev_txt + ')' if kev else ''} |")
        w(f"| EPSS of 10% or more | {sum(1 for e in rows if e['epss'] >= 0.10)} |")
        w(f"| EPSS of 1% or more | {sum(1 for e in rows if e['epss'] >= 0.01)} |")
        w(f"| EPSS below 1% | {sum(1 for e in rows if e['epss'] < 0.01)} |")
        w()
        if modules:
            w("## Optional modules")
            w()
            w("Packages installed only because of each module. Counts overlap where two")
            w(f"modules share a package; together they account for {groups['module']}.")
            w()
            w("| Module | Packages it brings in | CVEs in them | Critical or High | With a fix |")
            w("|---|---|---|---|---|")
            table = []
            for c, ps in modules.items():
                hit = [e for e in rows if e["pkgs"] & ps]
                table.append((len(hit), c, len(ps), sum(map(hi, hit)), sum(1 for e in hit if e["fixes"])))
            for cves, c, npk, nhi, nfix in sorted(table, reverse=True):
                w(f"| `{c}` | {npk} | {cves} | {nhi} | {nfix} |")
            w()
        w("## Packages with the most CVEs")
        w()
        w("| Package | Unique CVEs | Critical or High | Loaded by the main program |")
        w("|---|---|---|---|")
        per_pkg = collections.Counter(p for e in rows for p in e["pkgs"])
        for p, c in per_pkg.most_common(12):
            nhi = sum(1 for e in rows if p in e["pkgs"] and hi(e))
            w(f"| `{p}` | {c} | {nhi} | {'Yes' if p in linked else 'No'} |")


def label(x):
    return "-" if x is None else NAME[x]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trivy_json")
    ap.add_argument("grype_json")
    ap.add_argument("--linked", default=None,
                    help="file listing the packages the main program loads, one per line "
                         "(default: linked-packages.txt next to TRIVY_JSON or in ../image/)")
    ap.add_argument("--modules", default=None,
                    help="TSV of module<TAB>package for optional modules "
                         "(default: modules.tsv next to TRIVY_JSON or in ../image/)")
    ap.add_argument("--out-dir", default=None, help="default: directory of TRIVY_JSON")
    ap.add_argument("--top", type=int, default=40, help="rows in the markdown table")
    a = ap.parse_args()
    src_dir = os.path.dirname(os.path.abspath(a.trivy_json))
    out = a.out_dir or src_dir
    os.makedirs(out, exist_ok=True)

    def find(name):  # next to the report, or in a sibling "image" folder
        for d in (src_dir, os.path.join(os.path.dirname(src_dir), "image")):
            if os.path.exists(os.path.join(d, name)):
                return os.path.join(d, name)
        return os.path.join(src_dir, name)

    linked_path = a.linked or find("linked-packages.txt")
    linked = set()
    if os.path.exists(linked_path):
        linked = set(open(linked_path).read().split())
    else:
        print(f"warning: no linked-packages file ({linked_path}); reach is not "
              "distinguishing libraries the main program loads", file=sys.stderr)

    modules = collections.OrderedDict()
    mod_path = a.modules or find("modules.tsv")
    if os.path.exists(mod_path):
        for line in open(mod_path):
            parts = line.split()
            if len(parts) >= 2:
                modules.setdefault(parts[0], set()).add(parts[1])

    vulns = {}
    t_find, g_find = collections.Counter(), collections.Counter()
    load_trivy(a.trivy_json, vulns, t_find)
    load_grype(a.grype_json, vulns, g_find)
    for e in vulns.values():
        score(e, linked)
    rows = sorted(vulns.values(), key=lambda e: (e["score"], bool(e["fixes"]), e["cvss"], e["id"]),
                  reverse=True)

    both = [e for e in rows if e["trivy"] is not None and e["grype"] is not None]
    in_linked = [e for e in rows if e["linked"]]

    with open(os.path.join(out, "triage.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rank", "id", "score", "danger", "reach", "loaded_by_main_program", "trivy",
                    "grype", "packages", "fix_available", "fixed_versions", "known_exploited",
                    "epss", "cvss", "title"])
        for i, e in enumerate(rows, 1):
            w.writerow([i, e["id"], f'{e["score"]:.1f}', f'{e["danger"]:.3f}', f'{e["reach"]:.2f}',
                        "yes" if e["linked"] else "no", label(e["trivy"]), label(e["grype"]),
                        " ".join(sorted(e["pkgs"])), "yes" if e["fixes"] else "no",
                        " ".join(sorted(e["fixes"])), "yes" if e["kev"] else "no",
                        f'{e["epss"]:.4f}', e["cvss"], e["title"]])

    with open(os.path.join(out, "triage.md"), "w") as f:
        f.write("# Trivy vs Grype: vulnerabilities ranked by danger and reach\n\n")
        f.write(f"Inputs: `{os.path.basename(a.trivy_json)}`, `{os.path.basename(a.grype_json)}`. "
                "Full list: `triage.csv`.\n\n")
        f.write("| | Count |\n|---|---|\n")
        f.write(f"| Unique vulnerabilities (either scanner) | {len(rows)} |\n")
        f.write(f"| Reported by both | {len(both)} |\n")
        f.write(f"| Trivy only | {sum(1 for e in rows if e['grype'] is None)} |\n")
        f.write(f"| Grype only | {sum(1 for e in rows if e['trivy'] is None)} |\n")
        f.write(f"| Both report, different severity | {sum(1 for e in both if e['trivy'] != e['grype'])} |\n")
        f.write(f"| Critical in both | {sum(1 for e in both if e['trivy'] == 4 and e['grype'] == 4)} |\n")
        f.write(f"| Known exploited (KEV) | {sum(1 for e in rows if e['kev'])} |\n")
        f.write(f"| In a library the main program loads | {len(in_linked)} |\n")
        f.write(f"| ...of those, with a fix available | {sum(1 for e in in_linked if e['fixes'])} |\n\n")
        if linked:
            f.write("Libraries the main program loads: " + ", ".join(f"`{p}`" for p in sorted(linked)) + ".\n\n")
        else:
            f.write("No linked-packages file was given, so reach does not separate libraries the "
                    "main program loads from packages that only sit in the image.\n\n")
        f.write(f"## Top {min(a.top, len(rows))}\n\n")
        f.write("| # | ID | Score | Loaded | Trivy | Grype | Packages | Fix | KEV | EPSS |\n"
                "|---|---|---|---|---|---|---|---|---|---|\n")
        for i, e in enumerate(rows[: a.top], 1):
            pk = sorted(e["pkgs"])
            pk = ", ".join(pk[:4]) + (f" (+{len(pk) - 4})" if len(pk) > 4 else "")
            f.write(f"| {i} | {e['id']} | {e['score']:.1f} | {'yes' if e['linked'] else 'no'} | "
                    f"{label(e['trivy'])} | {label(e['grype'])} | {pk} | "
                    f"{'yes' if e['fixes'] else 'no'} | {'yes' if e['kev'] else ''} | "
                    f"{e['epss'] * 100:.1f}% |\n")
        f.write("\nScore = 100 x danger x reach. Danger = 0.6 x exploitation (1 if known exploited, "
                "else EPSS) + 0.4 x severity (average of both scanners). Reach = 1.0 if the main "
                "program loads the affected library, 0.4 if the package only sits in the image, "
                "plus a small bonus per extra affected package.\n\n"
                "Limits: \"loaded\" means the library is loaded, not that the vulnerable function "
                "is called. That still needs reading the advisory. Vulnerabilities the scanners "
                "do not report at all are not in this list.\n")
    write_stats(os.path.join(out, "stats.md"), rows, linked, modules, t_find, g_find,
                (os.path.basename(a.trivy_json), os.path.basename(a.grype_json)))

    print(f"{len(rows)} unique vulnerabilities, {len(both)} in both, "
          f"{len(in_linked)} in libraries the main program loads")
    print(f"wrote triage.md, triage.csv and stats.md in {out}")


if __name__ == "__main__":
    sys.exit(main())
